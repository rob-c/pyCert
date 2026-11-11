"""RFC 8555 ACME provider.

A native ACME client built on pyCertWiz's hardened :mod:`pycert.transport`
(deadlines, size limits, TLS pinning, cancellation) and ``cryptography`` for
JSON Web Signatures - no extra dependencies.  It obtains *host* certificates
from any ACME CA: Let's Encrypt, Sectigo/Jisc (with External Account Binding),
or a future UK-CA ACME service.

Flow for a new request (``submit``)::

    directory -> nonce -> account (EAB) -> new-order -> authorizations
      -> challenges (http-01 standalone/webroot, dns-01 hook/manual)
      -> finalize(CSR) -> [poll] order valid -> download certificate chain

The account key is generated once per CA profile and kept encrypted (with the
same saved secret as request keys) under ``<data_dir>/acme/<profile>/``.  The
EAB HMAC key is a secret: it lives in the secret store (account
``acme-eab:<profile>``) or an environment variable, never in the
configuration.  Nothing here logs private keys, HMAC keys or passphrases.
"""

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from .. import certs
from ..errors import CAError, NetworkError, ProtocolError, PyCertError
from ..store import STATUS_FAILED
from ..transport import Response, Transport, TransportConfig
from ..util import (
    SECRET_FILE_MODE,
    atomic_write,
    clamp_text,
    command_problem,
    ensure_dir,
    iso,
    read_private_file,
)
from .base import Capabilities, CAProvider, PingResult, PollOutcome, Progress, SubmitResult, _noop

try:  # POSIX only; elsewhere the in-process lock is all we have.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

JOSE_JSON = "application/jose+json"
PEM_CHAIN = "application/pem-certificate-chain"
PROBLEM_PREFIX = "urn:ietf:params:acme:error:"
MAX_NONCE_RETRIES = 3
MAX_RETRY_AFTER = 60.0
DNS_HOOK_TIMEOUT = 120.0
EAB_SECRET_PREFIX = "acme-eab:"
MIN_EAB_KEY_BYTES = 16
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")

#: RFC 5280 CRLReason codes for the reasons pyCertWiz offers.
REVOCATION_CODES = {
    "unspecified": 0,
    "keyCompromise": 1,
    "affiliationChanged": 3,
    "superseded": 4,
    "cessationOfOperation": 5,
}

_account_locks: "dict[str, threading.Lock]" = {}
_account_locks_guard = threading.Lock()


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def b64url(data: "bytes | str") -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_\-]*=*", text.strip()):
        raise ValueError("not a base64url value")
    value = text.strip().rstrip("=")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _int_b64(value: int) -> str:
    return b64url(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


_CURVES = {
    "secp256r1": ("P-256", "ES256", hashes.SHA256, 32),
    "secp384r1": ("P-384", "ES384", hashes.SHA384, 48),
    "secp521r1": ("P-521", "ES512", hashes.SHA512, 66),
}


def account_jwk(key: Any) -> dict:
    """The public JWK (RFC 7517) for an account key."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        numbers = key.public_key().public_numbers()
        crv, _alg, _hash, size = _CURVES[numbers.curve.name]
        return {
            "crv": crv,
            "kty": "EC",
            "x": b64url(numbers.x.to_bytes(size, "big")),
            "y": b64url(numbers.y.to_bytes(size, "big")),
        }
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = key.public_key().public_numbers()
        return {"e": _int_b64(numbers.e), "kty": "RSA", "n": _int_b64(numbers.n)}
    raise PyCertError("ACME account keys must be EC (P-256/384/521) or RSA")


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint: SHA-256 over the required members, sorted, compact."""
    if jwk.get("kty") == "EC":
        members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif jwk.get("kty") == "RSA":
        members = {k: jwk[k] for k in ("e", "kty", "n")}
    else:  # pragma: no cover - account_jwk only produces EC/RSA
        raise PyCertError("unsupported JWK type")
    return b64url(hashlib.sha256(_json_bytes(members)).digest())


def jws_algorithm(key: Any) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return _CURVES[key.curve.name][1]
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    raise PyCertError("ACME account keys must be EC or RSA")


def sign_jws(key: Any, protected: dict, payload: "dict | None") -> bytes:
    """A flattened JWS; ``payload=None`` is POST-as-GET (empty payload)."""
    protected_b64 = b64url(_json_bytes(protected))
    payload_b64 = "" if payload is None else b64url(_json_bytes(payload))
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    if isinstance(key, ec.EllipticCurvePrivateKey):
        _crv, _alg, hash_class, size = _CURVES[key.curve.name]
        r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hash_class())))
        signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:  # pragma: no cover - guarded by jws_algorithm
        raise PyCertError("unsupported account key")
    return json.dumps(
        {"protected": protected_b64, "payload": payload_b64, "signature": b64url(signature)},
        separators=(",", ":"),
    ).encode("ascii")


def eab_binding(jwk: dict, kid: str, hmac_key: bytes, url: str) -> dict:
    """RFC 8555 §7.3.4 externalAccountBinding (HS256)."""
    protected_b64 = b64url(_json_bytes({"alg": "HS256", "kid": kid, "url": url}))
    payload_b64 = b64url(_json_bytes(jwk))
    signature = hmac.new(
        hmac_key, (protected_b64 + "." + payload_b64).encode("ascii"), hashlib.sha256
    ).digest()
    return {"protected": protected_b64, "payload": payload_b64, "signature": b64url(signature)}


def dns01_value(key_authorization: str) -> str:
    return b64url(hashlib.sha256(key_authorization.encode("ascii")).digest())


def dns01_record(domain: str) -> str:
    return "_acme-challenge." + (domain[2:] if domain.startswith("*.") else domain).rstrip(".")


def decode_eab_key(value: str) -> bytes:
    try:
        key = b64url_decode(value)
    except (ValueError, binascii.Error) as exc:
        raise PyCertError("the EAB HMAC key must be base64url-encoded (as issued by the CA)") from exc
    if len(key) < MIN_EAB_KEY_BYTES:
        raise PyCertError(
            f"the EAB HMAC key is too short ({len(key)} bytes; expected at least {MIN_EAB_KEY_BYTES})"
        )
    return key


def store_eab_key(ctx: Any, profile_name: str, b64url_key: str) -> None:
    """Validate an EAB HMAC key and keep it in the secret store for *profile_name*."""
    profile = ctx.config.profile_for(profile_name)
    if profile.kind != "acme":
        raise PyCertError(f"CA profile '{profile_name}' is not an ACME CA")
    value = (b64url_key or "").strip()
    decode_eab_key(value)
    ctx.secrets.set(value, EAB_SECRET_PREFIX + profile.name)


def _problem_message(context: str, problem: dict, status: int) -> "tuple[str, str, str]":
    kind = str(problem.get("type") or "")
    short = kind[len(PROBLEM_PREFIX) :] if kind.startswith(PROBLEM_PREFIX) else kind
    detail = clamp_text(str(problem.get("detail") or ""), 500)
    parts = [detail] if detail else []
    for sub in problem.get("subproblems") or []:
        if isinstance(sub, dict):
            ident = (sub.get("identifier") or {}).get("value", "")
            parts.append(f"{ident}: {clamp_text(str(sub.get('detail') or ''), 200)}".strip(": "))
    text = "; ".join(parts) or f"HTTP {status}"
    return f"{context}: {text}" + (f" ({short})" if short else ""), short, text


class ACMEProblem(CAError):
    """An RFC 7807 problem document returned by the ACME server."""

    def __init__(self, context: str, problem: dict, status: int):
        message, short, detail = _problem_message(context, problem, status)
        super().__init__(message, status=status, detail=detail)
        self.problem_type = short
        self.problem = problem


def _identifier_values(csr: x509.CertificateSigningRequest) -> "list[str]":
    """DNS identifiers to order: the CSR's DNS SANs (or its CN), lower-case, de-duplicated."""
    names: "list[str]" = []
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        if san.get_values_for_type(x509.IPAddress) or san.get_values_for_type(x509.RFC822Name):
            raise PyCertError("ACME certificates can only name DNS hosts; remove IP and e-mail SANs")
        names = [value.lower().rstrip(".") for value in san.get_values_for_type(x509.DNSName)]
    cn = certs.name_attribute(csr.subject, NameOID.COMMON_NAME)
    if not names and cn:
        names = [cn.lower().rstrip(".")]
    if cn and cn.lower().rstrip(".") not in names:
        raise PyCertError(f"the request's common name '{cn}' must also be one of its DNS names")
    unique: "list[str]" = []
    for name in names:
        if name not in unique:
            unique.append(name)
    if not unique:
        raise PyCertError("the request names no DNS host")
    return unique


def _sleep(seconds: float, stop_event: Any) -> None:
    end = time.monotonic() + max(0.0, seconds)
    while True:
        if stop_event is not None and stop_event.is_set():
            raise PyCertError("cancelled")
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.1, remaining))


def _retry_after(response: Response, default: float) -> float:
    value = (response.headers.get("retry-after") or "").strip()
    if value.isdigit():
        return min(MAX_RETRY_AFTER, max(default, float(value)))
    return default


# ---------------------------------------------------------------------------
# Challenge responders
# ---------------------------------------------------------------------------


class _Http01Standalone:
    """A short-lived HTTP listener that serves only this order's tokens."""

    def __init__(self, bind: str, port: int, tokens: "dict[str, str]"):
        self.bind = bind
        self.port = port
        self.tokens = dict(tokens)
        self.httpd: "ThreadingHTTPServer | None" = None
        self.thread: "threading.Thread | None" = None

    def start(self) -> None:
        tokens = self.tokens

        class Handler(BaseHTTPRequestHandler):
            server_version = "pyCertWiz-acme"
            sys_version = ""

            def log_message(self, *args):  # never write to stderr
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                path = self.path.split("?", 1)[0]
                prefix = "/.well-known/acme-challenge/"
                value = tokens.get(path[len(prefix) :]) if path.startswith(prefix) else None
                body = (value or "not found").encode("ascii")
                self.send_response(200 if value else 404)
                self.send_header("Content-Type", "text/plain" if value else "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            do_HEAD = do_GET  # noqa: N815

        try:
            self.httpd = ThreadingHTTPServer((self.bind, self.port), Handler)
        except PermissionError as exc:
            raise PyCertError(
                f"cannot listen on port {self.port} for the http-01 challenge ({exc}). Run as a user allowed to "
                "bind it, forward port 80 to a high http_port, or use http_mode = 'webroot'"
            ) from exc
        except OSError as exc:
            raise PyCertError(
                f"cannot listen on {self.bind or '*'}:{self.port} for the http-01 challenge ({exc}); is another "
                "web server using it?  Use http_mode = 'webroot' to serve the token from that server instead"
            ) from exc
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
        )
        self.thread.start()

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


class _Challenges:
    """Publishes the challenge responses for one order and always cleans up."""

    def __init__(self, provider: "ACMEProvider", progress: Progress, stop_event: Any):
        self.provider = provider
        self.acme = provider.profile.acme
        self.progress = progress
        self.stop_event = stop_event
        self.http_tokens: "dict[str, str]" = {}
        self.dns_records: "list[tuple[str, str, str]]" = []  # (domain, record, value)
        self._server: "_Http01Standalone | None" = None
        self._webroot_files: "list[Path]" = []
        self._webroot_dirs: "list[Path]" = []
        self._dns_published: "list[tuple[str, str, str]]" = []

    def add(self, challenge_type: str, domain: str, token: str, key_authorization: str) -> None:
        if not _TOKEN_RE.match(token):
            raise ProtocolError("the ACME server sent a malformed challenge token; refusing to use it")
        if challenge_type == "http-01":
            self.http_tokens[token] = key_authorization
        else:
            self.dns_records.append((domain, dns01_record(domain), dns01_value(key_authorization)))

    def publish(self) -> None:
        if self.http_tokens:
            if self.acme.http_mode == "webroot":
                self._publish_webroot()
            else:
                self.progress(
                    f"Serving the http-01 challenge on {self.acme.http_bind or '*'}:{self.acme.http_port}..."
                )
                self._server = _Http01Standalone(self.acme.http_bind, self.acme.http_port, self.http_tokens)
                self._server.start()
        if self.dns_records:
            self._publish_dns()

    def _publish_webroot(self) -> None:
        root = Path(os.path.expanduser(self.acme.webroot))
        if not root.is_dir():
            raise PyCertError(f"the http-01 webroot does not exist: {root}")
        directory = root / ".well-known" / "acme-challenge"
        for part in (root / ".well-known", directory):
            if not part.exists():
                part.mkdir(mode=0o755)
                os.chmod(part, 0o755)
                self._webroot_dirs.append(part)
        for token, value in self.http_tokens.items():
            path = directory / token
            atomic_write(path, value, mode=0o644)
            self._webroot_files.append(path)
        self.progress(f"Wrote {len(self.http_tokens)} http-01 token(s) under {directory}")

    def _run_hook(self, action: str, domain: str, record: str, value: str) -> None:
        command = shlex.split(self.acme.dns_hook) + [action, domain, record, value]
        problem = command_problem(command[0])
        if problem:
            raise PyCertError(f"the dns-01 hook could not be run ({problem}: {command[0]})")
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=DNS_HOOK_TIMEOUT, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PyCertError(f"the dns-01 hook could not be run ({exc})") from exc
        if result.returncode != 0:
            detail = clamp_text((result.stderr or result.stdout or "").strip(), 300)
            raise PyCertError(
                f"the dns-01 hook failed for {record} ({action}, exit {result.returncode}): {detail}"
            )

    def _publish_dns(self) -> None:
        if self.acme.dns_hook:
            for domain, record, value in self.dns_records:
                self.progress(f"Publishing TXT {record} via the dns-01 hook...")
                self._run_hook("add", domain, record, value)
                self._dns_published.append((domain, record, value))
        else:
            confirm = getattr(self.provider.ctx, "confirm", None)
            lines = "\n".join(f'  {record}.  TXT  "{value}"' for _d, record, value in self.dns_records)
            instructions = (
                "Create these DNS TXT records, wait until they are visible on the public DNS, then continue:\n\n"
                + lines
            )
            if confirm is None:
                raise PyCertError(
                    "dns-01 validation needs either a dns_hook command (for unattended use) or an interactive "
                    "front-end to confirm the TXT records were created:\n" + lines
                )
            self.progress("Waiting for the TXT records to be created by hand...")
            if not confirm("Publish DNS TXT records", instructions):
                raise PyCertError("cancelled")
        if self.acme.dns_propagation_seconds > 0:
            self.progress(f"Waiting {self.acme.dns_propagation_seconds:.0f}s for DNS propagation...")
            _sleep(self.acme.dns_propagation_seconds, self.stop_event)

    def cleanup(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None
        for path in self._webroot_files:
            with contextlib.suppress(OSError):
                path.unlink()
        for directory in reversed(self._webroot_dirs):
            with contextlib.suppress(OSError):
                directory.rmdir()
        for domain, record, value in self._dns_published:
            try:
                self._run_hook("remove", domain, record, value)
            except PyCertError as exc:
                self.progress(f"warning: {exc}")
        self._dns_published = []


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class ACMEProvider(CAProvider):
    kind = "acme"
    label = "ACME (RFC 8555)"
    capabilities = Capabilities(
        user_certificates=False,
        host_certificates=True,
        pin=False,
        ra=False,
        host_authentication=False,
        domain_validation=True,
        revoke=True,
        revoke_needs_id=False,
        ca_info=True,
        organisation_subject=False,
        manual_approval=False,
        revocation_reasons=tuple(REVOCATION_CODES),
    )

    def __init__(self, ctx: Any, profile: Any):
        super().__init__(ctx, profile)
        ca = profile.ca
        if urlsplit(ca.base_url).scheme == "http" and not ca.allow_plaintext:
            raise NetworkError("refusing to use plaintext HTTP (set allow_plaintext to override)")
        self.transport = Transport(
            TransportConfig(
                connect_timeout=ca.connect_timeout,
                read_timeout=ca.timeout,
                deadline=ca.deadline,
                dns_timeout=ca.dns_timeout,
                retries=ca.retries,
                max_redirects=ca.max_redirects,
                max_body_bytes=ca.max_body_bytes,
                max_header_bytes=ca.max_header_bytes,
                backoff_base=ca.backoff_base,
                backoff_cap=ca.backoff_cap,
                user_agent=ca.user_agent,
                allow_plaintext=ca.allow_plaintext,
                tls_verify=ca.tls_verify,
                tls_pem=profile.tls_trust_pem(),
                use_system_trust=profile.use_system_trust(),
                tls_pins=list(ca.tls_pin_sha256),
            )
        )
        self._directory: "dict | None" = None
        self._nonce = ""
        self._key: Any = None
        self._kid = ""
        self._account_checked = False

    # -- paths ---------------------------------------------------------------
    @property
    def account_dir(self) -> Path:
        return self.ctx.config.data_dir / "acme" / self.profile.name

    @property
    def account_key_path(self) -> Path:
        return self.account_dir / "account.pem"

    @property
    def account_info_path(self) -> Path:
        return self.account_dir / "account.json"

    @contextlib.contextmanager
    def _account_lock(self):
        key = str(self.account_dir)
        with _account_locks_guard:
            lock = _account_locks.setdefault(key, threading.Lock())
        with lock:
            ensure_dir(self.ctx.config.data_dir / "acme")
            ensure_dir(self.account_dir)
            handle = None
            if fcntl is not None:
                flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                handle = os.fdopen(os.open(str(self.account_dir / ".lock"), flags, SECRET_FILE_MODE), "a+")
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if handle is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    handle.close()

    # -- HTTP ----------------------------------------------------------------
    def _json(self, response: Response, context: str) -> dict:
        try:
            data = json.loads(response.body.decode("utf-8")) if response.body else {}
        except (ValueError, UnicodeDecodeError) as exc:
            raise ProtocolError(f"{context}: the ACME server returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ProtocolError(f"{context}: the ACME server returned an unexpected JSON document")
        return data

    def _raise_problem(self, response: Response, context: str) -> None:
        try:
            problem = json.loads(response.body.decode("utf-8")) if response.body else {}
        except (ValueError, UnicodeDecodeError):
            problem = {}
        if not isinstance(problem, dict):
            problem = {}
        if not problem.get("detail") and not problem.get("type"):
            problem = {"detail": f"HTTP {response.status} {response.reason}".strip()}
        raise ACMEProblem(context, problem, response.status)

    def directory(self, *, stop_event: Any = None) -> dict:
        if self._directory is None:
            response = self.transport.request("GET", self.profile.directory_url, stop_event=stop_event)
            if response.status != 200:
                self._raise_problem(response, "fetching the ACME directory")
            data = self._json(response, "ACME directory")
            missing = [
                name for name in ("newNonce", "newAccount", "newOrder") if not isinstance(data.get(name), str)
            ]
            if missing:
                raise ProtocolError(f"the ACME directory is missing {', '.join(missing)}; is the URL right?")
            self._directory = data
        return self._directory

    def _meta(self, stop_event: Any = None) -> dict:
        meta = self.directory(stop_event=stop_event).get("meta")
        return meta if isinstance(meta, dict) else {}

    def _fresh_nonce(self, stop_event: Any) -> str:
        url = self.directory(stop_event=stop_event)["newNonce"]
        response = self.transport.request("HEAD", url, stop_event=stop_event)
        if response.status not in (200, 204):
            response = self.transport.request("GET", url, stop_event=stop_event)
        nonce = response.headers.get("replay-nonce", "")
        if not nonce:
            raise ProtocolError("the ACME server did not provide a Replay-Nonce")
        return nonce

    def _post(
        self,
        url: str,
        payload: "dict | None",
        *,
        context: str,
        use_jwk: bool = False,
        accept: str = "application/json",
        stop_event: Any = None,
    ) -> Response:
        """Signed POST (``payload=None`` is POST-as-GET) with bounded badNonce retries."""
        if self._key is None:  # pragma: no cover - callers load the account first
            raise PyCertError("no ACME account key is loaded")
        for attempt in range(1, MAX_NONCE_RETRIES + 1):
            nonce = self._nonce or self._fresh_nonce(stop_event)
            self._nonce = ""
            protected: "dict[str, Any]" = {"alg": jws_algorithm(self._key), "nonce": nonce, "url": url}
            if use_jwk or not self._kid:
                protected["jwk"] = account_jwk(self._key)
            else:
                protected["kid"] = self._kid
            response = self.transport.request(
                "POST",
                url,
                body=sign_jws(self._key, protected, payload),
                headers={"Content-Type": JOSE_JSON, "Accept": accept},
                idempotent=False,
                stop_event=stop_event,
            )
            self._nonce = response.headers.get("replay-nonce", "")
            if response.status < 400:
                return response
            try:
                problem = json.loads(response.body.decode("utf-8")) if response.body else {}
            except (ValueError, UnicodeDecodeError):
                problem = {}
            kind = str(problem.get("type", "")) if isinstance(problem, dict) else ""
            if kind == PROBLEM_PREFIX + "badNonce" and attempt < MAX_NONCE_RETRIES:
                continue
            if (
                response.status in (429, 503)
                and attempt < MAX_NONCE_RETRIES
                and response.headers.get("retry-after")
            ):
                _sleep(_retry_after(response, 1.0), stop_event)
                continue
            self._raise_problem(response, context)
        raise AssertionError("unreachable")  # pragma: no cover

    def _post_json(self, url: str, payload: "dict | None", *, context: str, stop_event: Any = None) -> dict:
        return self._json(self._post(url, payload, context=context, stop_event=stop_event), context)

    # -- reachability ----------------------------------------------------------
    def ping(self, *, stop_event: Any = None) -> PingResult:
        started = time.monotonic()
        detail = ""
        ok = False
        try:
            self._directory = None
            self.directory(stop_event=stop_event)
            ok = True
        except PyCertError as exc:
            detail = str(exc)
        return PingResult(
            ok=ok,
            latency_ms=(time.monotonic() - started) * 1000,
            detail=detail,
            tls=self._peer(),
            url=self.url,
        )

    def _peer(self) -> Any:
        der = self.transport.last_peer_certificate
        if not der:
            return None
        try:
            from ..ca import TLSPeer

            cert = x509.load_der_x509_certificate(der)
            return TLSPeer(
                subject=certs.name_to_string(cert.subject),
                issuer=certs.name_to_string(cert.issuer),
                fingerprint=certs.formatted_fingerprint(cert),
                not_after=certs.not_valid_after(cert),
            )
        except Exception:  # noqa: BLE001 - display detail only
            return None

    # -- account -----------------------------------------------------------------
    def _read_account_info(self) -> dict:
        path = self.account_info_path
        if not path.is_file():
            return {}
        try:
            data = json.loads(read_private_file(path).decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _load_or_create_key(self, progress: Progress) -> Any:
        path = self.account_key_path
        if path.is_file():
            return certs.load_private_key(read_private_file(path), self.ctx.key_passphrase())
        if self.profile.acme.account_key == "rsa":
            progress("Generating a 3072-bit RSA ACME account key...")
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        else:
            progress("Generating a P-256 ACME account key...")
            key = ec.generate_private_key(ec.SECP256R1())
        atomic_write(path, certs.key_pem(key, self.ctx.key_passphrase()), SECRET_FILE_MODE)
        return key

    def _eab_key(self) -> "bytes | None":
        acme = self.profile.acme
        value = ""
        if acme.eab_hmac_env:
            value = os.environ.get(acme.eab_hmac_env, "")
        if not value:
            value = self.ctx.secrets.get(EAB_SECRET_PREFIX + self.profile.name, allow_missing=True) or ""
        return decode_eab_key(value) if value else None

    def _contact(self) -> "list[str]":
        return ["mailto:" + email for email in self.profile.contact_emails() if email]

    def _register(self, progress: Progress, stop_event: Any) -> None:
        meta = self._meta(stop_event)
        directory = self.directory(stop_event=stop_event)
        if not self.profile.acme.terms_agreed:
            terms = meta.get("termsOfService") or "(the CA did not publish a terms URL)"
            raise PyCertError(
                f"{self.display_name} requires agreement to its terms of service before an account can be "
                f"registered.  Read {terms} and then set terms_agreed = true in [cas.{self.profile.name}] "
                f"(pycert config set cas.{self.profile.name}.terms_agreed true)"
            )
        payload: "dict[str, Any]" = {"termsOfServiceAgreed": True}
        contact = self._contact()
        if contact:
            payload["contact"] = contact
        eab_kid = self.profile.acme.eab_kid
        eab_key = self._eab_key() if eab_kid else None
        if eab_kid and eab_key is None:
            raise PyCertError(
                f"External Account Binding key id '{eab_kid}' is configured but no HMAC key is stored; run "
                f"'pycert ca eab {self.profile.name} --kid {eab_kid}' and paste the key from the CA"
            )
        if meta.get("externalAccountRequired") and not eab_kid:
            raise PyCertError(
                f"{self.display_name} requires External Account Binding: obtain a key id and HMAC key from the "
                f"CA and run 'pycert ca eab {self.profile.name} --kid KID'"
            )
        if eab_kid and eab_key is not None:
            payload["externalAccountBinding"] = eab_binding(
                account_jwk(self._key), eab_kid, eab_key, directory["newAccount"]
            )
        progress(f"Registering an ACME account with {self.display_name}...")
        self._kid = ""
        response = self._post(
            directory["newAccount"],
            payload,
            context="registering the ACME account",
            use_jwk=True,
            stop_event=stop_event,
        )
        kid = response.headers.get("location", "")
        if not kid:
            raise ProtocolError("the ACME server did not return an account URL (Location header)")
        self._kid = kid
        info = {
            "kid": kid,
            "directory": self.profile.directory_url,
            "contact": contact,
            "eab_kid": eab_kid,
            "key": jws_algorithm(self._key),
            "thumbprint": jwk_thumbprint(account_jwk(self._key)),
            "created": iso(),
        }
        atomic_write(self.account_info_path, json.dumps(info, indent=2) + "\n", SECRET_FILE_MODE)
        progress(f"ACME account registered: {kid}")

    def ensure_account(
        self, *, progress: Progress = _noop, stop_event: Any = None, verify: bool = True
    ) -> str:
        """Load (or create and register) the account for this profile; returns its URL.

        With ``verify`` the saved account is checked with the CA (and registered
        again if the CA has forgotten it); polling and revocation skip that
        round-trip and simply use the saved account.
        """
        if self._key is not None and self._kid and (self._account_checked or not verify):
            return self._kid
        with self._account_lock():
            self._key = self._load_or_create_key(progress)
            info = self._read_account_info()
            self._kid = ""
            if info.get("kid") and info.get("directory") == self.profile.directory_url:
                self._kid = str(info["kid"])
                if not verify:
                    return self._kid
                try:
                    account = self._post_json(
                        self._kid, None, context="checking the ACME account", stop_event=stop_event
                    )
                    if account.get("status") not in (None, "valid"):
                        raise PyCertError(
                            f"the ACME account {self._kid} is {account.get('status')}; delete "
                            f"{self.account_info_path} to register a new one"
                        )
                except ACMEProblem as exc:
                    if exc.problem_type not in ("accountDoesNotExist", "unauthorized") and exc.status != 404:
                        raise
                    progress("The CA no longer knows the saved ACME account; registering again...")
                    self._kid = ""
            if not self._kid:
                self._register(progress, stop_event)
            self._account_checked = True
        return self._kid

    # -- validation ------------------------------------------------------------
    def validate_request(self, spec: Any) -> None:
        super().validate_request(spec)
        if spec.san_ip or spec.san_email:
            raise PyCertError(
                f"{self.display_name} certificates can only name DNS hosts; remove IP and e-mail SANs"
            )
        names = [spec.cn] + list(spec.san_dns)
        if any(name.startswith("*.") for name in names) and self.profile.acme.challenge != "dns-01":
            raise PyCertError("wildcard names can only be validated with dns-01; set challenge = 'dns-01'")
        # The CN must be one of the certificate's DNS names (CAs and TLS clients require it).
        if spec.san_dns and spec.cn.lower() not in [name.lower() for name in spec.san_dns]:
            spec.san_dns = [spec.cn] + list(spec.san_dns)

    def subject_for(self, spec: Any) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, spec.cn)])

    def preflight(self, spec: Any, *, progress: Progress = _noop, stop_event: Any = None) -> Any:
        self.ensure_reachable(progress=progress, stop_event=stop_event)
        return self.ensure_account(progress=progress, stop_event=stop_event)

    # -- orders ------------------------------------------------------------------
    def _wait_status(
        self, url: str, *, done: "tuple[str, ...]", context: str, progress: Progress, stop_event: Any
    ) -> dict:
        deadline = time.monotonic() + self.profile.acme.validation_timeout
        interval = max(0.1, self.profile.acme.poll_interval)
        while True:
            response = self._post(url, None, context=context, stop_event=stop_event)
            obj = self._json(response, context)
            if obj.get("status") in done:
                return obj
            if time.monotonic() >= deadline:
                raise CAError(
                    f"{context}: still '{obj.get('status')}' after {self.profile.acme.validation_timeout:.0f}s; "
                    "try again later with 'pycert wait'"
                )
            _sleep(_retry_after(response, interval), stop_event)

    def _complete_authorizations(self, authz_urls: "list[str]", progress: Progress, stop_event: Any) -> None:
        thumbprint = jwk_thumbprint(account_jwk(self._key))
        pending: "list[tuple[str, str, dict]]" = []  # (authz url, domain, challenge)
        challenges = _Challenges(self, progress, stop_event)
        for url in authz_urls:
            authz = self._post_json(url, None, context="reading an ACME authorization", stop_event=stop_event)
            identifier = (authz.get("identifier") or {}).get("value", "")
            wildcard = bool(authz.get("wildcard"))
            domain = ("*." if wildcard else "") + identifier
            status = authz.get("status")
            if status == "valid":
                continue
            if status != "pending":
                raise CAError(f"the authorization for {domain} is {status}")
            wanted = "dns-01" if wildcard else self.profile.acme.challenge
            if wildcard and self.profile.acme.challenge != "dns-01":
                raise PyCertError(
                    "wildcard names can only be validated with dns-01; set challenge = 'dns-01'"
                )
            offered = [c for c in authz.get("challenges") or [] if isinstance(c, dict)]
            chosen = next((c for c in offered if c.get("type") == wanted), None)
            if chosen is None:
                kinds = ", ".join(sorted({str(c.get("type")) for c in offered})) or "none"
                raise CAError(
                    f"{self.display_name} did not offer a {wanted} challenge for {domain} (offered: {kinds})"
                )
            token = str(chosen.get("token") or "")
            challenges.add(wanted, domain, token, f"{token}.{thumbprint}")
            pending.append((url, domain, chosen))
        if not pending:
            return
        try:
            challenges.publish()
            for _url, domain, challenge in pending:
                if challenge.get("status") in ("pending", None):
                    progress(f"Asking the CA to validate {domain} ({challenge.get('type')})...")
                    self._post(
                        str(challenge["url"]),
                        {},
                        context=f"answering the challenge for {domain}",
                        stop_event=stop_event,
                    )
            for url, domain, _challenge in pending:
                authz = self._wait_status(
                    url,
                    done=("valid", "invalid", "deactivated", "expired", "revoked"),
                    context=f"validating {domain}",
                    progress=progress,
                    stop_event=stop_event,
                )
                if authz.get("status") != "valid":
                    reason = ""
                    for item in authz.get("challenges") or []:
                        if isinstance(item, dict) and isinstance(item.get("error"), dict):
                            reason = str(item["error"].get("detail") or "")
                    raise CAError(
                        f"the CA could not validate {domain}: {clamp_text(reason or str(authz.get('status')), 300)}"
                    )
                progress(f"{domain} validated")
        finally:
            challenges.cleanup()

    def _finalize(
        self,
        state: Any,
        order: dict,
        csr: x509.CertificateSigningRequest,
        progress: Progress,
        stop_event: Any,
    ) -> dict:
        order_url = state.provider["order_url"]
        if order.get("status") not in ("ready", "valid", "processing"):
            order = self._wait_status(
                order_url,
                done=("ready", "valid", "processing", "invalid"),
                context="waiting for the order",
                progress=progress,
                stop_event=stop_event,
            )
        if order.get("status") == "invalid":
            raise CAError(f"the ACME order failed: {self._order_error(order)}")
        if order.get("status") == "ready":
            progress("Finalizing the order with the CSR...")
            der = csr.public_bytes(serialization.Encoding.DER)
            order = self._post_json(
                str(order.get("finalize") or state.provider.get("finalize_url")),
                {"csr": b64url(der)},
                context="finalizing the ACME order",
                stop_event=stop_event,
            )
        if order.get("certificate"):
            state.provider["certificate_url"] = order["certificate"]
        state.server.status = str(order.get("status") or "")
        return order

    @staticmethod
    def _order_error(order: dict) -> str:
        error = order.get("error")
        if isinstance(error, dict):
            return _problem_message("order", error, 0)[2]
        return str(order.get("status"))

    def _place_order(
        self,
        state: Any,
        csr: x509.CertificateSigningRequest,
        *,
        renewal: bool,
        progress: Progress,
        stop_event: Any,
    ) -> SubmitResult:
        kid = self.ensure_account(progress=progress, stop_event=stop_event)
        identifiers = _identifier_values(csr)
        progress(f"Ordering a certificate for {', '.join(identifiers)}...")
        response = self._post(
            self.directory(stop_event=stop_event)["newOrder"],
            {"identifiers": [{"type": "dns", "value": name} for name in identifiers]},
            context="creating the ACME order",
            stop_event=stop_event,
        )
        order = self._json(response, "creating the ACME order")
        order_url = response.headers.get("location", "")
        if not order_url:
            raise ProtocolError("the ACME server did not return an order URL (Location header)")
        state.provider.update(
            {
                "kind": "acme",
                "directory": self.profile.directory_url,
                "account": kid,
                "order_url": order_url,
                "finalize_url": str(order.get("finalize") or ""),
                "authorizations": [str(url) for url in order.get("authorizations") or []],
                "identifiers": identifiers,
                "renewal": renewal,
                "ordered_at": iso(),
                "certificate_url": "",
            }
        )
        state.server.status = str(order.get("status") or "")
        state.server.last_checked = iso()
        self.ctx.store.save(state)
        if order.get("status") == "pending":
            self._complete_authorizations(state.provider["authorizations"], progress, stop_event)
        order = self._finalize(state, order, csr, progress, stop_event)
        state.server.last_checked = iso()
        self.ctx.store.save(state)
        if order.get("status") == "valid":
            return SubmitResult(True, "order finalized; the certificate has been issued")
        return SubmitResult(True, "order finalized; the certificate is being issued")

    def submit(
        self,
        state: Any,
        csr: x509.CertificateSigningRequest,
        spec: Any,
        *,
        prepared: Any = None,
        progress: Progress = _noop,
        on_pin: "Callable[[str], None] | None" = None,
        stop_event: Any = None,
    ) -> SubmitResult:
        return self._place_order(state, csr, renewal=False, progress=progress, stop_event=stop_event)

    def submit_renewal(
        self,
        state: Any,
        csr: x509.CertificateSigningRequest,
        *,
        old_certificate: x509.Certificate,
        old_key: Any,
        contact: str,
        pin: str = "",
        progress: Progress = _noop,
        on_pin: "Callable[[str], None] | None" = None,
        stop_event: Any = None,
    ) -> SubmitResult:
        return self._place_order(state, csr, renewal=True, progress=progress, stop_event=stop_event)

    # -- polling -----------------------------------------------------------------
    def _stored_csr(self, state: Any) -> x509.CertificateSigningRequest:
        return self.ctx.store.load_pending_csr(state) if state.renewal else self.ctx.store.load_csr(state)

    def poll(self, state: Any, *, progress: Progress = _noop, stop_event: Any = None) -> PollOutcome:
        order_url = (state.provider or {}).get("order_url")
        if not order_url:
            raise PyCertError(f"'{state.alias}' has no ACME order recorded; request the certificate again")
        self.ensure_account(progress=progress, stop_event=stop_event, verify=False)
        order = self._post_json(order_url, None, context="reading the ACME order", stop_event=stop_event)
        status = str(order.get("status") or "")
        state.server.status = status
        state.server.last_checked = iso()
        if status == "pending":
            progress("The order still needs domain validation; completing the challenges...")
            self._complete_authorizations(list(order.get("authorizations") or []), progress, stop_event)
            order = self._finalize(state, order, self._stored_csr(state), progress, stop_event)
            status = str(order.get("status") or "")
        elif status == "ready":
            progress("The order is ready but was never finalized; finalizing now...")
            order = self._finalize(state, order, self._stored_csr(state), progress, stop_event)
            status = str(order.get("status") or "")
        state.server.status = status
        if status == "valid":
            return self._download(state, order, progress=progress, stop_event=stop_event)
        if status == "invalid":
            detail = self._order_error(order)
            if state.renewal:
                state.notes.append(f"ACME renewal order failed: {detail}")
                state.touch()
            else:
                state.set_status(STATUS_FAILED, f"ACME order invalid: {detail}")
            self.ctx.store.save(state)
            return PollOutcome(state, status, False, f"the ACME order failed: {detail}", terminal=True)
        state.touch()
        self.ctx.store.save(state)
        message = "the CA is issuing the certificate" if status == "processing" else f"order is {status}"
        return PollOutcome(state, status or "UNKNOWN", True, message)

    def _download(self, state: Any, order: dict, *, progress: Progress, stop_event: Any) -> PollOutcome:
        cert_url = str(order.get("certificate") or state.provider.get("certificate_url") or "")
        if not cert_url:
            raise ProtocolError("the ACME order is valid but has no certificate URL")
        progress("Downloading the certificate chain...")
        response = self._post(
            cert_url, None, context="downloading the certificate", accept=PEM_CHAIN, stop_event=stop_event
        )
        chain = certs.load_certificates(response.body)
        leaf, issuers = chain[0], chain[1:]
        if state.active_spki_b64 and certs.spki_b64(leaf) != state.active_spki_b64:
            raise ProtocolError(
                "the ACME server returned a certificate whose public key does not match this request; "
                "refusing to use it"
            )
        state.provider["certificate_url"] = cert_url
        state.server.cert_id = cert_url
        self.ctx.store.save(state)
        return PollOutcome(
            state=state,
            server_status="valid",
            pending=False,
            message="certificate issued",
            certificate=leaf,
            cert_id=cert_url,
            chain=list(issuers),
        )

    # -- revocation ----------------------------------------------------------------
    def revoke(
        self,
        state: Any,
        reason: str,
        *,
        certificate: x509.Certificate,
        key: Any,
        progress: Progress = _noop,
        stop_event: Any = None,
    ) -> SubmitResult:
        code = REVOCATION_CODES.get(reason)
        if code is None:
            raise PyCertError(
                f"invalid revocation reason {reason!r}; choose one of: {', '.join(REVOCATION_CODES)}"
            )
        self.ensure_account(progress=progress, stop_event=stop_event, verify=False)
        progress(f"Requesting revocation of the certificate ({reason})...")
        der = certificate.public_bytes(serialization.Encoding.DER)
        try:
            self._post(
                self.directory(stop_event=stop_event)["revokeCert"],
                {"certificate": b64url(der), "reason": code},
                context="revoking the certificate",
                stop_event=stop_event,
            )
        except ACMEProblem as exc:
            return SubmitResult(
                False, "the CA refused the revocation", exc.detail or str(exc), exc.status or 0
            )
        return SubmitResult(True, "revocation accepted by the CA")

    # -- information ---------------------------------------------------------------
    def info(self, *, stop_event: Any = None) -> dict:
        meta = self._meta(stop_event)
        result: "dict[str, Any]" = {
            "directory": self.profile.directory_url,
            "terms_of_service": meta.get("termsOfService", ""),
            "website": meta.get("website", ""),
            "caa_identities": list(meta.get("caaIdentities") or []),
            "external_account_required": bool(meta.get("externalAccountRequired", False)),
            "profiles": dict(meta.get("profiles") or {}) if isinstance(meta.get("profiles"), dict) else {},
            "account": "",
            "account_status": "not registered",
            "terms_agreed": self.profile.acme.terms_agreed,
            "eab_kid": self.profile.acme.eab_kid,
            "eab_key_stored": False,
            "challenge": self.profile.acme.challenge,
        }
        try:
            result["eab_key_stored"] = self._eab_key() is not None
        except PyCertError:
            result["eab_key_stored"] = False
        saved = self._read_account_info()
        if (
            saved.get("kid")
            and saved.get("directory") == self.profile.directory_url
            and self.account_key_path.is_file()
        ):
            result["account"] = saved["kid"]
            result["account_created"] = saved.get("created", "")
            try:
                with self._account_lock():
                    self._key = certs.load_private_key(
                        read_private_file(self.account_key_path), self.ctx.key_passphrase()
                    )
                self._kid = str(saved["kid"])
                account = self._post_json(
                    self._kid, None, context="reading the ACME account", stop_event=stop_event
                )
                result["account_status"] = str(account.get("status") or "valid")
                result["contact"] = list(account.get("contact") or [])
            except PyCertError as exc:
                result["account_status"] = f"unknown ({exc})"
        return result


def account_summary(ctx: Any, profile_name: str) -> dict:
    """Local (offline) account details for display: URL, key type, creation date."""
    profile = ctx.config.profile_for(profile_name)
    path = ctx.config.data_dir / "acme" / profile.name / "account.json"
    if not path.is_file():
        return {"registered": False}
    try:
        data = json.loads(read_private_file(path).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {"registered": False, "error": "unreadable account.json"}
    return {
        "registered": data.get("directory") == profile.directory_url,
        "account": data.get("kid", ""),
        "key": data.get("key", ""),
        "created": data.get("created", ""),
        "directory": data.get("directory", ""),
    }


__all__ = [
    "ACMEProblem",
    "ACMEProvider",
    "REVOCATION_CODES",
    "account_jwk",
    "account_summary",
    "dns01_record",
    "dns01_value",
    "eab_binding",
    "jwk_thumbprint",
    "sign_jws",
    "store_eab_key",
]
