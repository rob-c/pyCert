"""A small RFC 8555 ACME front-end for the sandbox UK-CA emulator.

The ACME layer translates orders into the same CSR / CA-record / certificate
state used by the UK-CA protocol, so certbot, nginx and an ACME client see a
modern endpoint while the CA below it remains the UK e-Science-style listener.

Supported flow: directory -> nonce -> account -> order -> authz -> http-01 or
dns-01 challenge -> finalize -> certificate.  Challenge validation defaults to
``auto`` for a self-contained sandbox; ``http`` fetches the certbot webroot
token, and ``manual`` leaves the challenge pending for an operator.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from pycert.compat import csr_signature_valid, dataclass, field
from pycert.errors import PyCertError

from .mock_ca import ThreadingHTTPServer, _pem, _spki_b64


def b64e(data: "bytes | str") -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("base64url value must be a string")
    padding_needed = (-len(text)) % 4
    return base64.urlsafe_b64decode(text + ("=" * padding_needed))


def _json_b64(data) -> str:
    return b64e(json.dumps(data, separators=(",", ":"), sort_keys=True))


def _safe_json(data):
    try:
        return json.loads(data.decode("utf-8")) if data else {}
    except (ValueError, UnicodeDecodeError):
        raise ACMEProblem("malformed", "request payload is not valid JSON")


class ACMEProblem(Exception):
    """An RFC 7807 / RFC 8555 problem document."""

    def __init__(self, kind: str, detail: str, status: int = 400):
        super().__init__(detail)
        self.kind = kind
        self.detail = detail
        self.status = status

    def as_problem(self) -> dict:
        return {
            "type": "urn:ietf:params:acme:error:" + self.kind,
            "detail": self.detail,
            "status": self.status,
        }


@dataclass
class Account:
    id: str
    jwk: dict
    thumbprint: str
    contact: "list[str]" = field(default_factory=list)
    status: str = "valid"
    created_at: "str" = ""
    kid: str = ""
    eab_kid: str = ""


@dataclass
class Challenge:
    id: str
    authz_id: str
    type: str
    token: str
    status: str = "pending"
    validated: "str | None" = None
    error: "dict | None" = None


@dataclass
class Authorization:
    id: str
    order_id: str
    identifier: dict
    wildcard: bool = False
    status: str = "pending"
    expires: str = ""
    challenges: "list[str]" = field(default_factory=list)


@dataclass
class Order:
    id: str
    account_id: str
    identifiers: "list[dict]"
    status: str = "pending"
    expires: str = ""
    authorizations: "list[str]" = field(default_factory=list)
    finalize: str = ""
    certificate: str = ""
    backend_spki: str = ""
    backend_id: "int | None" = None
    error: "dict | None" = None
    created_at: str = ""


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint."""
    kty = jwk.get("kty")
    if kty == "RSA":
        canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        canonical = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ACMEProblem("badPublicKey", "unsupported JWK key type %r" % kty)
    return b64e(hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest())


def _jwk_public_key(jwk: dict):
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            n = int.from_bytes(b64d(jwk["n"]), "big")
            e = int.from_bytes(b64d(jwk["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}.get(jwk.get("crv"))
            if curve is None:
                raise ValueError("unsupported EC curve")
            x = int.from_bytes(b64d(jwk["x"]), "big")
            y = int.from_bytes(b64d(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64d(jwk["x"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise ACMEProblem("badPublicKey", "invalid JWK: %s" % exc)
    raise ACMEProblem("badPublicKey", "unsupported JWK")


def _verify_signature(jwk: dict, alg: str, signature: bytes, data: bytes) -> None:
    public = _jwk_public_key(jwk)
    try:
        if alg == "RS256" and isinstance(public, rsa.RSAPublicKey):
            public.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "RS384" and isinstance(public, rsa.RSAPublicKey):
            public.verify(signature, data, padding.PKCS1v15(), hashes.SHA384())
        elif alg == "RS512" and isinstance(public, rsa.RSAPublicKey):
            public.verify(signature, data, padding.PKCS1v15(), hashes.SHA512())
        elif alg in ("ES256", "ES384", "ES512") and isinstance(public, ec.EllipticCurvePublicKey):
            hash_alg = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}[alg]
            if len(signature) % 2:
                raise InvalidSignature("odd ECDSA signature length")
            half = len(signature) // 2
            der = encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
            public.verify(der, data, ec.ECDSA(hash_alg))
        elif alg == "EdDSA" and isinstance(public, ed25519.Ed25519PublicKey):
            public.verify(signature, data)
        else:
            raise ACMEProblem("badSignatureAlgorithm", "alg %r does not fit the account key" % alg)
    except InvalidSignature:
        raise ACMEProblem("unauthorized", "JWS signature verification failed", 403)
    except ACMEProblem:
        raise
    except Exception as exc:  # noqa: BLE001 - normalize malformed key/signature errors
        raise ACMEProblem("unauthorized", "JWS signature verification failed: %s" % exc, 403)


def _account_id_from_path(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


_UNSAFE_DNS = re.compile(r"[\s/?#@:]+")


def validate_dns_identifier(value: str) -> str:
    value = (value or "").strip().lower()
    if not value or len(value) > 253:
        raise ACMEProblem("rejectedIdentifier", "invalid DNS identifier")
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
        if not value:
            raise ACMEProblem("rejectedIdentifier", "empty wildcard identifier")
    if value.endswith("."):
        value = value[:-1]
    if "." not in value and not re.match(r"^[a-z0-9][a-z0-9-]*$", value):
        # ACME allows single-label names in a lab; reject only obvious abuse.
        raise ACMEProblem("rejectedIdentifier", "invalid DNS identifier %r" % value)
    if _UNSAFE_DNS.search(value) or ".." in value:
        raise ACMEProblem("rejectedIdentifier", "invalid DNS identifier %r" % value)
    for label in value.split("."):
        if not label or len(label) > 63 or not re.match(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", label):
            raise ACMEProblem("rejectedIdentifier", "invalid DNS label in %r" % value)
    return ("*." if wildcard else "") + value


class SandboxBackend:
    """Adapt the in-process UK-CA emulator to the operations ACME needs."""

    def __init__(self, ca):
        self.ca = ca
        self._lock = getattr(ca, "lock", threading.Lock())

    def submit(self, csr, email: str, names: "list[str]"):
        from .mock_ca import CSRRecord

        spki = _spki_b64(csr.public_key())
        with self._lock:
            record = self.ca.csrs.get(spki)
            if record is None:
                self.ca.next_csr_id += 1
                record = CSRRecord(
                    self.ca.next_csr_id,
                    csr,
                    email=email,
                    status="NEW",
                    kind="host" if names else "user",
                )
                self.ca.csrs[spki] = record
            if record.cert_id is None and self.ca.auto_approve:
                self.ca._sign_csr(record)
            self.ca._persist_state()
            return record

    def certificate(self, spki: str):
        with self._lock:
            record = self.ca.csrs.get(spki)
            if record is None or record.cert_id is None:
                return None
            return self.ca.certificates.get(record.cert_id)

    def chain(self, cert_id: int) -> bytes:
        with self._lock:
            record = self.ca.certificates.get(int(cert_id))
            if record is None:
                raise ACMEProblem("malformed", "unknown certificate")
            return (_pem(record.cert) + _pem(self.ca.intermediate)).encode("ascii")

    def revoke(self, cert_id: int, reason: int = 0) -> None:
        names = {0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
                 4: "superseded", 5: "cessationOfOperation", 6: "certificateHold"}
        # ca.revoke_certificate takes the CA lock itself; do not hold our
        # alias of that lock around the call.
        if not self.ca.revoke_certificate(int(cert_id), names.get(int(reason), "unspecified")):
            raise ACMEProblem("malformed", "unknown certificate")

    def find_certificate(self, cert: x509.Certificate):
        with self._lock:
            for record in self.ca.certificates.values():
                if record.cert.serial_number == cert.serial_number:
                    return record
        return None


class ACMEServer:
    """RFC 8555 state machine plus HTTP response renderer.

    ``handle(method, path, headers, body)`` is deliberately HTTP-framework
    independent so the protocol can be tested without sockets; ``start`` adds
    the TLS listener used by certbot.
    """

    def __init__(
        self,
        ca,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        public_url: "str | None" = None,
        challenge_mode: str = "auto",
        http_port: int = 80,
        auto_validate: "bool | None" = None,
        eab_credentials: "dict[str, str] | None" = None,
        require_eab: "bool | None" = None,
        state_path: "str | Path | None" = None,
    ):
        self.ca = ca
        self.backend = SandboxBackend(ca)
        self.host = host
        self.port = port
        self.challenge_mode = challenge_mode
        self.http_port = int(http_port)
        self.auto_validate = (challenge_mode == "auto") if auto_validate is None else bool(auto_validate)
        self.eab_credentials = {}
        for kid, key in (eab_credentials or {}).items():
            if isinstance(key, str):
                try:
                    key = b64d(key)
                except (ValueError, TypeError) as exc:
                    raise ValueError("invalid EAB HMAC key for %r: %s" % (kid, exc))
            if not key:
                raise ValueError("empty EAB HMAC key for %r" % kid)
            self.eab_credentials[str(kid)] = bytes(key)
        self.require_eab = bool(self.eab_credentials) if require_eab is None else bool(require_eab)
        self.state_path = Path(state_path).expanduser() if state_path is not None else None
        self.lock = threading.RLock()
        self.accounts: "dict[str, Account]" = {}
        self.accounts_by_thumbprint: "dict[str, str]" = {}
        self.orders: "dict[str, Order]" = {}
        self.authzs: "dict[str, Authorization]" = {}
        self.challenges: "dict[str, Challenge]" = {}
        self.cert_orders: "dict[int, str]" = {}
        self.nonces: "dict[str, float]" = {}
        self.nonce_ttl = 600.0
        self.httpd = None
        self._thread = None
        self._hostname = ca.hostname if hasattr(ca, "hostname") else host
        self._public_url = (public_url or "https://%s:%d" % (self._hostname, port)).rstrip("/")
        self.nonce_counter = 0
        self._load_state()

    # -- persisted ACME state ---------------------------------------------
    STATE_FORMAT = 1

    def _load_state(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text())
        except (OSError, ValueError) as exc:
            raise RuntimeError("cannot read ACME state %s: %s" % (self.state_path, exc))
        if not isinstance(data, dict) or data.get("format") not in (None, 1):
            raise RuntimeError("unsupported ACME state format in %s" % self.state_path)
        with self.lock:
            self.accounts = {}
            self.accounts_by_thumbprint = {}
            for item in data.get("accounts") or []:
                account = Account(
                    id=str(item["id"]),
                    jwk=item["jwk"],
                    thumbprint=str(item["thumbprint"]),
                    contact=list(item.get("contact") or []),
                    status=str(item.get("status") or "valid"),
                    created_at=str(item.get("created_at") or ""),
                    kid=str(item["kid"]),
                    eab_kid=str(item.get("eab_kid") or ""),
                )
                self.accounts[account.id] = account
                self.accounts_by_thumbprint[account.thumbprint] = account.id
            self.orders = {}
            for item in data.get("orders") or []:
                self.orders[str(item["id"])] = Order(
                    id=str(item["id"]),
                    account_id=str(item["account_id"]),
                    identifiers=list(item.get("identifiers") or []),
                    status=str(item.get("status") or "pending"),
                    expires=str(item.get("expires") or ""),
                    authorizations=list(item.get("authorizations") or []),
                    finalize=str(item.get("finalize") or ""),
                    certificate=str(item.get("certificate") or ""),
                    backend_spki=str(item.get("backend_spki") or ""),
                    backend_id=item.get("backend_id"),
                    error=item.get("error"),
                    created_at=str(item.get("created_at") or ""),
                )
            self.authzs = {}
            for item in data.get("authzs") or []:
                self.authzs[str(item["id"])] = Authorization(
                    id=str(item["id"]),
                    order_id=str(item["order_id"]),
                    identifier=dict(item["identifier"]),
                    wildcard=bool(item.get("wildcard")),
                    status=str(item.get("status") or "pending"),
                    expires=str(item.get("expires") or ""),
                    challenges=list(item.get("challenges") or []),
                )
            self.challenges = {}
            for item in data.get("challenges") or []:
                self.challenges[str(item["id"])] = Challenge(
                    id=str(item["id"]),
                    authz_id=str(item["authz_id"]),
                    type=str(item["type"]),
                    token=str(item["token"]),
                    status=str(item.get("status") or "pending"),
                    validated=item.get("validated"),
                    error=item.get("error"),
                )
            self.cert_orders = {int(key): str(value) for key, value in (data.get("cert_orders") or {}).items()}

    def _persist_state(self) -> None:
        if self.state_path is None:
            return
        with self.lock:
            data = {
                "format": self.STATE_FORMAT,
                "accounts": [
                    {
                        "id": account.id,
                        "jwk": account.jwk,
                        "thumbprint": account.thumbprint,
                        "contact": account.contact,
                        "status": account.status,
                        "created_at": account.created_at,
                        "kid": account.kid,
                        "eab_kid": account.eab_kid,
                    }
                    for account in self.accounts.values()
                ],
                "orders": [
                    {
                        "id": order.id,
                        "account_id": order.account_id,
                        "identifiers": order.identifiers,
                        "status": order.status,
                        "expires": order.expires,
                        "authorizations": order.authorizations,
                        "finalize": order.finalize,
                        "certificate": order.certificate,
                        "backend_spki": order.backend_spki,
                        "backend_id": order.backend_id,
                        "error": order.error,
                        "created_at": order.created_at,
                    }
                    for order in self.orders.values()
                ],
                "authzs": [
                    {
                        "id": authz.id,
                        "order_id": authz.order_id,
                        "identifier": authz.identifier,
                        "wildcard": authz.wildcard,
                        "status": authz.status,
                        "expires": authz.expires,
                        "challenges": authz.challenges,
                    }
                    for authz in self.authzs.values()
                ],
                "challenges": [
                    {
                        "id": challenge.id,
                        "authz_id": challenge.authz_id,
                        "type": challenge.type,
                        "token": challenge.token,
                        "status": challenge.status,
                        "validated": challenge.validated,
                        "error": challenge.error,
                    }
                    for challenge in self.challenges.values()
                ],
                "cert_orders": {str(key): value for key, value in self.cert_orders.items()},
            }
            text = json.dumps(data, indent=2, sort_keys=True) + "\n"
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".acme-state.", dir=str(self.state_path.parent))
            try:
                with os.fdopen(fd, "w") as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                try:
                    os.chmod(temporary, 0o600)
                except OSError:
                    pass
                os.replace(temporary, str(self.state_path))
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    # -- URLs --------------------------------------------------------------
    @property
    def base_url(self) -> str:
        if self.httpd is not None and self._public_url.endswith(":0"):
            self._public_url = "https://%s:%d" % (self._hostname, self.port)
        return self._public_url

    def url(self, path: str) -> str:
        return self.base_url + path

    def directory_url(self) -> str:
        return self.url("/acme/directory")

    # -- nonce -------------------------------------------------------------
    def new_nonce(self) -> str:
        token = secrets.token_urlsafe(24)
        with self.lock:
            now = time.time()
            for old, expiry in list(self.nonces.items()):
                if expiry <= now:
                    self.nonces.pop(old, None)
            self.nonces[token] = now + self.nonce_ttl
        return token

    def consume_nonce(self, nonce: str) -> None:
        with self.lock:
            expiry = self.nonces.pop(nonce, None)
        if expiry is None or expiry <= time.time():
            raise ACMEProblem("badNonce", "the JWS nonce is missing, expired or already used")

    # -- directory ---------------------------------------------------------
    def directory(self) -> dict:
        base = self.base_url
        return {
            "newNonce": base + "/acme/new-nonce",
            "newAccount": base + "/acme/new-account",
            "newOrder": base + "/acme/new-order",
            "revokeCert": base + "/acme/revoke-cert",
            "keyChange": base + "/acme/key-change",
            "meta": {
                "termsOfService": base + "/acme/terms",
                "website": base,
                "caaIdentities": ["sandbox.invalid"],
                "externalAccountRequired": bool(self.require_eab),
            },
        }

    # -- JWS ---------------------------------------------------------------
    def _jws(self, body: bytes, expected_url: str):
        if not body:
            raise ACMEProblem("malformed", "empty JWS body")
        try:
            envelope = json.loads(body.decode("utf-8"))
            protected_b64 = envelope["protected"]
            payload_b64 = envelope.get("payload", "")
            signature = b64d(envelope["signature"])
            protected = _safe_json(b64d(protected_b64))
        except (KeyError, ValueError, TypeError, UnicodeDecodeError) as exc:
            raise ACMEProblem("malformed", "invalid JWS envelope: %s" % exc)
        if protected.get("url") != expected_url:
            raise ACMEProblem("unauthorized", "JWS protected URL does not match the request URL", 403)
        nonce = protected.get("nonce")
        if not isinstance(nonce, str):
            raise ACMEProblem("badNonce", "JWS is missing a nonce")
        self.consume_nonce(nonce)
        alg = protected.get("alg")
        if not isinstance(alg, str):
            raise ACMEProblem("badSignatureAlgorithm", "JWS is missing alg")
        jwk = protected.get("jwk")
        kid = protected.get("kid")
        if jwk is not None and kid is not None:
            raise ACMEProblem("malformed", "JWS must contain exactly one of jwk and kid")
        if jwk is not None:
            if not isinstance(jwk, dict):
                raise ACMEProblem("badPublicKey", "jwk must be an object")
            account = None
        elif kid is not None:
            with self.lock:
                account = next((item for item in self.accounts.values() if item.kid == kid), None)
            if account is None:
                raise ACMEProblem("accountDoesNotExist", "unknown account kid", 400)
            jwk = account.jwk
        else:
            raise ACMEProblem("malformed", "JWS has neither jwk nor kid")
        signing_input = protected_b64.encode("ascii") + b"." + payload_b64.encode("ascii")
        _verify_signature(jwk, alg, signature, signing_input)
        payload = _safe_json(b64d(payload_b64)) if payload_b64 else {}
        if not isinstance(payload, dict):
            raise ACMEProblem("malformed", "JWS payload must be a JSON object")
        return account, payload, jwk

    # -- external account binding -----------------------------------------
    def _verify_eab(self, jwk: dict, payload: dict) -> str:
        binding = payload.get("externalAccountBinding")
        if binding is None:
            if self.require_eab:
                raise ACMEProblem(
                    "externalAccountRequired",
                    "this ACME server requires an externalAccountBinding",
                )
            return ""
        if not isinstance(binding, dict):
            raise ACMEProblem("malformed", "externalAccountBinding must be an object")
        try:
            protected = _safe_json(b64d(binding["protected"]))
            payload_b64 = binding["payload"]
            protected_b64 = binding["protected"]
            signature = b64d(binding["signature"])
            eab_payload = _safe_json(b64d(payload_b64))
        except (KeyError, TypeError, ValueError) as exc:
            raise ACMEProblem("malformed", "invalid externalAccountBinding: %s" % exc)
        if not isinstance(protected, dict):
            raise ACMEProblem("malformed", "EAB protected header must be an object")
        if protected.get("alg") not in ("HS256", "HS384", "HS512"):
            raise ACMEProblem("badSignatureAlgorithm", "EAB must use HS256/384/512")
        if protected.get("url") != self.url("/acme/new-account"):
            raise ACMEProblem("unauthorized", "EAB protected URL does not match new-account", 403)
        kid = str(protected.get("kid") or "")
        key = self.eab_credentials.get(kid)
        if key is None:
            raise ACMEProblem("unauthorized", "unknown EAB kid", 403)
        alg = protected["alg"]
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
        expected = hmac.new(key, (protected_b64 + "." + payload_b64).encode("ascii"), digest).digest()
        if not hmac.compare_digest(expected, signature):
            raise ACMEProblem("unauthorized", "EAB HMAC verification failed", 403)
        if not isinstance(eab_payload, dict):
            raise ACMEProblem("badPublicKey", "EAB payload must be a JWK object")
        if jwk_thumbprint(eab_payload) != jwk_thumbprint(jwk):
            raise ACMEProblem("unauthorized", "EAB payload does not match the account key", 403)
        return kid

    # -- account -----------------------------------------------------------
    def _account_object(self, account: Account) -> dict:
        return {
            "status": account.status,
            "contact": list(account.contact),
            "orders": self.url("/acme/orders/" + account.id),
            "createdAt": account.created_at,
        }

    def _new_account(self, body: bytes, expected_url: str) -> dict:
        account, payload, jwk = self._jws(body, expected_url)
        if account is not None:
            raise ACMEProblem("malformed", "new-account must use a jwk, not a kid")
        eab_kid = self._verify_eab(jwk, payload)
        thumbprint = jwk_thumbprint(jwk)
        with self.lock:
            existing_id = self.accounts_by_thumbprint.get(thumbprint)
            if existing_id:
                existing = self.accounts[existing_id]
                return {"status": 200, "location": existing.kid, "body": self._account_object(existing)}
            if payload.get("onlyReturnExisting"):
                raise ACMEProblem("accountDoesNotExist", "no account exists for this key", 400)
            contact = payload.get("contact") or []
            if not isinstance(contact, list) or any(not isinstance(item, str) for item in contact):
                raise ACMEProblem("malformed", "contact must be a list of strings")
            account_id = secrets.token_urlsafe(12)
            created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            account = Account(
                id=account_id,
                jwk=jwk,
                thumbprint=thumbprint,
                contact=list(contact),
                created_at=created,
                kid=self.url("/acme/acct/" + account_id),
                eab_kid=eab_kid,
            )
            self.accounts[account_id] = account
            self.accounts_by_thumbprint[thumbprint] = account_id
            self._persist_state()
        return {"status": 201, "location": account.kid, "body": self._account_object(account)}

    # -- orders ------------------------------------------------------------
    def _identifier(self, item) -> dict:
        if not isinstance(item, dict) or item.get("type") != "dns":
            raise ACMEProblem("unsupportedIdentifier", "only dns identifiers are supported")
        value = validate_dns_identifier(str(item.get("value") or ""))
        return {"type": "dns", "value": value}

    def _new_order(self, body: bytes, expected_url: str) -> dict:
        account, payload, _ = self._jws(body, expected_url)
        if account is None:
            raise ACMEProblem("unauthorized", "new-order requires an account kid", 403)
        identifiers = payload.get("identifiers")
        if not isinstance(identifiers, list) or not identifiers:
            raise ACMEProblem("malformed", "order must contain a non-empty identifiers list")
        normalized = [self._identifier(item) for item in identifiers]
        values = [item["value"] for item in normalized]
        if len(set(values)) != len(values):
            raise ACMEProblem("malformed", "duplicate identifiers in order")
        now = time.time()
        order_id = secrets.token_urlsafe(12)
        with self.lock:
            authz_ids = []
            for identifier in normalized:
                wildcard = identifier["value"].startswith("*.")
                authz_id = secrets.token_urlsafe(12)
                authz = Authorization(
                    id=authz_id,
                    order_id=order_id,
                    identifier={"type": "dns", "value": identifier["value"][2:] if wildcard else identifier["value"]},
                    wildcard=wildcard,
                    expires=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 7 * 86400)),
                )
                challenge_types = ["dns-01"] if wildcard else ["http-01"]
                for ctype in challenge_types:
                    challenge = Challenge(
                        id=secrets.token_urlsafe(12),
                        authz_id=authz_id,
                        type=ctype,
                        token=secrets.token_urlsafe(32),
                    )
                    self.challenges[challenge.id] = challenge
                    authz.challenges.append(challenge.id)
                self.authzs[authz_id] = authz
                authz_ids.append(authz_id)
            order = Order(
                id=order_id,
                account_id=account.id,
                identifiers=normalized,
                authorizations=authz_ids,
                expires=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 7 * 86400)),
                finalize=self.url("/acme/finalize/" + order_id),
                created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            )
            self.orders[order_id] = order
            self._persist_state()
        return {"status": 201, "location": self.url("/acme/order/" + order_id), "body": self._order_object(order)}

    # -- object rendering --------------------------------------------------
    def _challenge_object(self, challenge: Challenge) -> dict:
        result = {
            "type": challenge.type,
            "url": self.url("/acme/chall/" + challenge.id),
            "status": challenge.status,
            "token": challenge.token,
        }
        if challenge.validated:
            result["validated"] = challenge.validated
        if challenge.error:
            result["error"] = challenge.error
        return result

    def _authz_object(self, authz: Authorization) -> dict:
        result = {
            "identifier": dict(authz.identifier),
            "status": authz.status,
            "expires": authz.expires,
            "challenges": [self._challenge_object(self.challenges[cid]) for cid in authz.challenges],
        }
        if authz.wildcard:
            result["wildcard"] = True
        return result

    def _order_object(self, order: Order) -> dict:
        self._refresh_order(order)
        result = {
            "status": order.status,
            "expires": order.expires,
            "identifiers": list(order.identifiers),
            "authorizations": [self.url("/acme/authz/" + aid) for aid in order.authorizations],
            "finalize": order.finalize,
        }
        if order.certificate:
            result["certificate"] = order.certificate
        if order.error:
            result["error"] = order.error
        return result

    def _refresh_order(self, order: Order) -> None:
        if order.status in ("valid", "invalid"):
            return
        authzs = [self.authzs[aid] for aid in order.authorizations]
        if any(authz.status == "invalid" for authz in authzs):
            order.status = "invalid"
            order.error = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": "an authorization failed"}
            self._persist_state()
            return
        if order.status == "processing":
            record = self.backend.certificate(order.backend_spki) if order.backend_spki else None
            if record is not None:
                order.status = "valid"
                order.backend_id = record.id
                order.certificate = self.url("/acme/cert/" + str(record.id))
                self.cert_orders[record.id] = order.id
                self._persist_state()
            return
        if all(authz.status == "valid" for authz in authzs):
            order.status = "ready"
            self._persist_state()

    # -- authz / challenge -------------------------------------------------
    def _get_authz(self, authz_id: str, account: "Account | None") -> Authorization:
        with self.lock:
            authz = self.authzs.get(authz_id)
        if authz is None:
            raise ACMEProblem("malformed", "unknown authorization", 404)
        order = self.orders.get(authz.order_id)
        if account is not None and order is not None and order.account_id != account.id:
            raise ACMEProblem("unauthorized", "authorization belongs to another account", 403)
        return authz

    def _get_order(self, order_id: str, account: "Account | None") -> Order:
        with self.lock:
            order = self.orders.get(order_id)
        if order is None:
            raise ACMEProblem("malformed", "unknown order", 404)
        if account is not None and order.account_id != account.id:
            raise ACMEProblem("unauthorized", "order belongs to another account", 403)
        return order

    def _get_challenge(self, challenge_id: str, account: "Account | None") -> Challenge:
        with self.lock:
            challenge = self.challenges.get(challenge_id)
        if challenge is None:
            raise ACMEProblem("malformed", "unknown challenge", 404)
        self._get_authz(challenge.authz_id, account)
        return challenge

    def _key_authorization(self, challenge: Challenge) -> str:
        account = self.accounts[self.orders[self.authzs[challenge.authz_id].order_id].account_id]
        return challenge.token + "." + account.thumbprint

    def _validate_http_01(self, challenge: Challenge) -> "tuple[bool, str]":
        authz = self.authzs[challenge.authz_id]
        domain = authz.identifier["value"]
        port = "" if self.http_port == 80 else ":%d" % self.http_port
        path = "/.well-known/acme-challenge/" + challenge.token
        url = "http://%s%s%s" % (domain, port, path)
        opener = build_opener(ProxyHandler({}))
        try:
            with opener.open(Request(url, headers={"User-Agent": "pycert-acme-sandbox"}), timeout=5) as response:
                body = response.read(8192).decode("utf-8", "replace").strip()
        except (HTTPError, URLError, OSError, socket.timeout) as exc:
            return False, "http-01 validation failed for %s: %s" % (url, exc)
        expected = self._key_authorization(challenge)
        if body != expected:
            return False, "http-01 token did not match"
        return True, ""

    def _validate_challenge(self, challenge: Challenge) -> None:
        if challenge.status == "valid":
            return
        challenge.status = "processing"
        ok = True
        detail = ""
        if self.challenge_mode == "auto" or self.auto_validate:
            ok, detail = True, ""
        elif self.challenge_mode == "http" and challenge.type == "http-01":
            ok, detail = self._validate_http_01(challenge)
        elif self.challenge_mode == "http" and challenge.type == "dns-01":
            ok, detail = False, "dns-01 is not validated by the http validator"
        elif self.challenge_mode == "manual":
            challenge.status = "pending"
            return
        if ok:
            challenge.status = "valid"
            challenge.validated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.authzs[challenge.authz_id].status = "valid"
        else:
            challenge.status = "invalid"
            challenge.error = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": detail}
            self.authzs[challenge.authz_id].status = "invalid"
        self._persist_state()

    # -- finalize / certificate --------------------------------------------
    def _csr_domains(self, csr: x509.CertificateSigningRequest) -> "list[str]":
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            return [value.lower().rstrip(".") for value in san.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return [cn[0].value.lower()] if cn else []

    def _finalize(self, order_id: str, body: bytes, expected_url: str) -> dict:
        account, payload, _ = self._jws(body, expected_url)
        order = self._get_order(order_id, account)
        self._refresh_order(order)
        if order.status == "valid":
            return {"status": 200, "body": self._order_object(order)}
        if order.status != "ready":
            raise ACMEProblem("orderNotReady", "order is %s, not ready" % order.status, 403)
        csr_b64 = payload.get("csr")
        if not isinstance(csr_b64, str):
            raise ACMEProblem("badCSR", "finalize requires a CSR")
        try:
            csr = x509.load_der_x509_csr(b64d(csr_b64))
        except (ValueError, TypeError) as exc:
            raise ACMEProblem("badCSR", "could not parse CSR: %s" % exc)
        if not csr_signature_valid(csr):
            raise ACMEProblem("badCSR", "CSR signature is invalid")
        domains = self._csr_domains(csr)
        requested = [item["value"] for item in order.identifiers]
        if sorted(domains) != sorted(requested):
            raise ACMEProblem("badCSR", "CSR names %r do not match order %r" % (domains, requested))
        email = "acme@example.invalid"
        with self.lock:
            for contact in account.contact:
                if contact.startswith("mailto:"):
                    email = contact[7:]
                    break
        try:
            record = self.backend.submit(csr, email, domains)
            order.backend_spki = _spki_b64(csr.public_key())
            order.backend_id = record.cert_id
            if record.cert_id is not None:
                order.status = "valid"
                order.certificate = self.url("/acme/cert/" + str(record.cert_id))
                self.cert_orders[record.cert_id] = order.id
            else:
                order.status = "processing"
                order.backend_id = None
        except (ACMEProblem, PyCertError, ValueError) as exc:
            order.status = "invalid"
            order.error = {"type": "urn:ietf:params:acme:error:serverInternal", "detail": str(exc)}
        self._persist_state()
        return {"status": 200, "body": self._order_object(order)}

    def _certificate(self, cert_id: int, account: "Account | None") -> bytes:
        with self.lock:
            order_id = self.cert_orders.get(int(cert_id))
            order = self.orders.get(order_id) if order_id else None
        if order is None:
            raise ACMEProblem("malformed", "unknown certificate", 404)
        if account is not None and order.account_id != account.id:
            raise ACMEProblem("unauthorized", "certificate belongs to another account", 403)
        return self.backend.chain(int(cert_id))

    def _revoke(self, body: bytes, expected_url: str) -> dict:
        account, payload, _ = self._jws(body, expected_url)
        cert_b64 = payload.get("certificate")
        if not isinstance(cert_b64, str):
            raise ACMEProblem("malformed", "revoke-cert requires certificate")
        try:
            raw = b64d(cert_b64)
            if b"BEGIN CERTIFICATE" in raw:
                cert = x509.load_pem_x509_certificate(raw)
            else:
                cert = x509.load_der_x509_certificate(raw)
        except (ValueError, TypeError) as exc:
            raise ACMEProblem("malformed", "could not parse certificate: %s" % exc)
        record = self.backend.find_certificate(cert)
        if record is None:
            raise ACMEProblem("malformed", "certificate is not known to this CA", 404)
        self.backend.revoke(record.id, int(payload.get("reason", 0)))
        self._persist_state()
        return {"status": 200, "body": {}}

    # -- request handler ---------------------------------------------------
    def handle(self, method: str, path: str, headers: dict, body: bytes):
        """Return ``(status, headers, body, content_type)`` for one request."""
        method = method.upper()
        path = path.split("?", 1)[0].rstrip("/") or "/"
        response_headers = {
            "Replay-Nonce": self.new_nonce(),
            "Cache-Control": "no-store",
        }
        try:
            if path == "/acme/directory" and method == "GET":
                return 200, response_headers, json.dumps(self.directory()).encode(), "application/json"
            if path in ("/acme/new-nonce", "/acme/new-nonce/") and method in ("GET", "HEAD"):
                return 200, response_headers, b"", "application/json"
            if path == "/acme/new-account" and method == "POST":
                result = self._new_account(body, self.url(path))
            elif path == "/acme/new-order" and method == "POST":
                result = self._new_order(body, self.url(path))
            elif path.startswith("/acme/order/") and method in ("GET", "POST"):
                account = None
                if method == "POST":
                    account, _, _ = self._jws(body, self.url(path))
                order = self._get_order(path.rsplit("/", 1)[-1], account)
                result = {"status": 200, "body": self._order_object(order)}
            elif path.startswith("/acme/authz/") and method in ("GET", "POST"):
                account = None
                if method == "POST":
                    account, _, _ = self._jws(body, self.url(path))
                authz = self._get_authz(path.rsplit("/", 1)[-1], account)
                result = {"status": 200, "body": self._authz_object(authz)}
            elif path.startswith("/acme/chall/") and method in ("GET", "POST"):
                account = None
                if method == "POST":
                    account, _, _ = self._jws(body, self.url(path))
                challenge = self._get_challenge(path.rsplit("/", 1)[-1], account)
                if method == "POST":
                    self._validate_challenge(challenge)
                response_headers["Link"] = '<%s>;rel="up"' % self.url(
                    "/acme/authz/" + challenge.authz_id
                )
                result = {"status": 200, "body": self._challenge_object(challenge)}
            elif path.startswith("/acme/finalize/") and method == "POST":
                result = self._finalize(path.rsplit("/", 1)[-1], body, self.url(path))
            elif path.startswith("/acme/cert/") and method in ("GET", "POST"):
                account = None
                if method == "POST":
                    account, _, _ = self._jws(body, self.url(path))
                cert_id = int(path.rsplit("/", 1)[-1])
                data = self._certificate(cert_id, account)
                return 200, response_headers, data, "application/pem-certificate-chain"
            elif path == "/acme/revoke-cert" and method == "POST":
                result = self._revoke(body, self.url(path))
            elif path.startswith("/acme/acct/") and method in ("GET", "POST"):
                account_id = _account_id_from_path(path)
                account = self.accounts.get(account_id)
                if account is None:
                    raise ACMEProblem("accountDoesNotExist", "unknown account", 404)
                if method == "POST":
                    authenticated, _, _ = self._jws(body, self.url(path))
                    if authenticated is None or authenticated.id != account.id:
                        raise ACMEProblem("unauthorized", "account JWS does not match", 403)
                result = {"status": 200, "body": self._account_object(account)}
            elif path == "/acme/terms" and method == "GET":
                return 200, response_headers, b"Sandbox terms: certificates are for testing only.\n", "text/plain; charset=utf-8"
            elif path.startswith("/acme/orders/") and method in ("GET", "POST"):
                account = None
                if method == "POST":
                    account, _, _ = self._jws(body, self.url(path))
                account_id = path.rsplit("/", 1)[-1]
                owner = self.accounts.get(account_id)
                if owner is None:
                    raise ACMEProblem("accountDoesNotExist", "unknown account", 404)
                if account is not None and account.id != owner.id:
                    raise ACMEProblem("unauthorized", "account JWS does not match", 403)
                with self.lock:
                    urls = [
                        self.url("/acme/order/" + item.id)
                        for item in self.orders.values()
                        if item.account_id == owner.id
                    ]
                result = {"status": 200, "body": {"orders": urls}}
            elif path.startswith("/acme/key-change"):
                raise ACMEProblem("malformed", "key-change is not supported by this sandbox", 501)
            else:
                raise ACMEProblem("malformed", "not found", 404)
            status = result.get("status", 200)
            if result.get("location"):
                response_headers["Location"] = result["location"]
            return status, response_headers, json.dumps(result.get("body", {})).encode(), "application/json"
        except ACMEProblem as exc:
            response_headers["Content-Type"] = "application/problem+json"
            return exc.status, response_headers, json.dumps(exc.as_problem()).encode(), "application/problem+json"
        except Exception as exc:  # noqa: BLE001 - keep the ACME endpoint's contract
            problem = {"type": "urn:ietf:params:acme:error:serverInternal", "detail": str(exc), "status": 500}
            return 500, response_headers, json.dumps(problem).encode(), "application/problem+json"

    # -- HTTP/TLS listener -------------------------------------------------
    def start(self) -> "ACMEServer":
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _body(self):
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except ValueError:
                    length = 0
                return self.rfile.read(length) if length else b""

            def _respond(self, method):
                body = self._body()
                headers = {key.lower(): value for key, value in self.headers.items()}
                status, response_headers, payload, content_type = server.handle(method, self.path, headers, body)
                self.send_response(status)
                for key, value in response_headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                if method != "HEAD" and payload:
                    self.wfile.write(payload)
                self.close_connection = True

            def do_GET(self):
                self._respond("GET")

            def do_HEAD(self):
                self._respond("HEAD")

            def do_POST(self):
                self._respond("POST")

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.ca.server_chain_path, self.ca.server_key_path)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self._public_url = "https://%s:%d" % (self._hostname, self.port)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
