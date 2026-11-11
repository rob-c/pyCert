"""End-to-end workflows: request, wait, download, export, renew, revoke, import.

This module is the only place that knows the order of operations.  The CLI and
the GUI are thin front-ends over these functions, which keeps behaviour
identical in both and makes the whole flow testable without a display.

Every function takes an :class:`AppContext` (configuration, local store, secret
store) and an optional ``progress`` callback that receives short, human-readable
lines.  Callbacks must not raise; pyCertWiz treats progress reporting as best
effort.

No function ever logs or returns the PIN, the PKCS#12 passphrase or private key
material.  The PIN is used once to compute the hash the RA compares against, and
is then dropped.
"""

import hashlib
import os
import random
import re
import secrets as secrets_module
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from . import certs, chain
from . import csr as csr_module
from . import p12 as p12_module
from .ca import RA, CAClient
from .certs import not_valid_after, not_valid_before
from .config import CAProfile, Config
from .errors import (
    CAError,
    ChainError,
    ConfigError,
    CryptoError,
    NotFound,
    PyCertError,
    TimeoutWaiting,
)
from .p12 import P12Bundle
from .providers.base import PollOutcome
from .secrets_store import SecretStore
from .store import (
    PENDING_STATUSES,
    STATUS_DOWNLOADED,
    STATUS_FAILED,
    STATUS_IMPORTED,
    STATUS_REVOKED,
    STATUS_SIGNED,
    STATUS_SUBMITTED,
    CertInfo,
    RequestState,
    Store,
)
from .util import (
    atomic_write,
    ensure_dir,
    human_duration,
    iso,
    sha256_hex,
)

Progress = Callable[[str], None]

PIN_MIN_LENGTH = 10
PIN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1
DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")

DEFAULT_WAIT_TIMEOUT = 24 * 3600
DEFAULT_WAIT_INTERVAL = 60


def noop(_message: str) -> None:
    pass


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


@dataclass
class AppContext:
    config: Config
    store: Store
    secrets: SecretStore
    #: Front-end hook for steps a person must complete (e.g. publishing a DNS
    #: TXT record for a manual ACME dns-01 challenge).  Called with a title and
    #: instructions; returns True when the person confirms they are done.
    #: ``None`` means unattended: such steps fail with a clear error instead.
    confirm: "Callable[[str, str], bool] | None" = None
    #: Java keystore passphrases given in this session (never stored anywhere)
    keystore_passwords: dict = field(default_factory=dict)
    #: Front-end hook asking for a keystore passphrase (link -> passphrase or None)
    ask_keystore_password: "Callable[[Any], str | None] | None" = None

    @classmethod
    def from_config(cls, config: Config) -> "AppContext":  # noqa: F821
        store = Store(config.data_dir)
        ensure_dir(config.data_dir)
        ensure_dir(config.data_dir / "requests")
        secrets = SecretStore(config.secrets, config.data_dir, config.profile)
        return cls(config, store, secrets)

    # -- secrets -----------------------------------------------------------
    def p12_passphrase(self) -> str:
        return self.secrets.ensure(self.config.secrets.account)

    def key_passphrase(self) -> str:
        account = self.config.secrets.key_account or self.config.secrets.account
        return self.secrets.ensure(account)

    # -- CA profiles and providers ------------------------------------------
    def profile(self, name: "str | None" = "") -> CAProfile:
        """The CA profile *name* (empty: the primary CA)."""
        return self.config.profile_for(name)

    def provider(self, name: "str | None" = ""):
        """The protocol provider for CA profile *name* (empty: the primary CA)."""
        from .providers import create_provider

        return create_provider(self, self.profile(name))

    def provider_for(self, state: RequestState):
        return self.provider(state.ca)

    # -- network -----------------------------------------------------------
    def client(self, ca: str = "") -> CAClient:
        """A CertWizard-protocol client for CA profile *ca* (empty: the primary CA)."""
        if not ca:
            return CAClient(self.config)
        profile = self.profile(ca)
        if profile.kind != "ukca":
            raise ConfigError(f"CA profile '{ca}' is an {profile.kind} CA, not a CertWizard-protocol CA")
        return CAClient(profile)

    # -- trust -------------------------------------------------------------
    def anchors(self, ca: str = "") -> "list[x509.Certificate]":
        profile = self.profile(ca)
        if profile.primary:
            anchors = list(self.config.bundle.anchors)
            system = self.config.use_system_trust()
        else:
            anchors = list(profile.bundle.anchors)
            system = profile.use_system_trust() or not anchors
        if system:
            anchors.extend(chain.system_anchors())
        return anchors

    def build_chain(
        self, certificate: x509.Certificate, ca: str = "", extra: "list[x509.Certificate] | tuple" = ()
    ) -> chain.ChainResult:
        profile = self.profile(ca)
        bundle = self.config.bundle if profile.primary else profile.bundle
        return chain.build_chain(
            certificate,
            anchors=self.anchors(ca),
            extra=list(bundle.certificates) + list(extra),
            fetcher=chain.aia_fetch,
            allow_sha1=profile.ca.allow_sha1,
        )


# ---------------------------------------------------------------------------
# Setting up
# ---------------------------------------------------------------------------


def default_config_dir() -> Path:
    """Where a new configuration goes: ~/.config/pycert (or $XDG_CONFIG_HOME/pycert)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return Path(xdg) / "pycert" if xdg else Path.home() / ".config" / "pycert"


def create_configuration(
    directory: "str | Path | None" = None,
    *,
    profile: str = "default",
    email: str = "",
    ra: str = "",
    base_url: str = "",
    backend: str = "",
    force: bool = False,
) -> AppContext:
    """Write a new configuration and its saved secret ('pycert init' and the GUI's first run).

    The configuration goes in *directory* (default :func:`default_config_dir`)
    with the pinned UK e-Science CA chain. A random secret protecting
    pyCertWiz's own store is created in the chosen secret backend.
    """
    from .config import init_config, validate_config, write_config
    from .secrets_store import BACKENDS

    target = Path(directory).expanduser() if directory else default_config_dir()
    if target.suffix.lower() == ".toml":
        target = target.parent
    config_path = target / "pycert.toml"
    if config_path.exists() and not force:
        raise PyCertError(f"{config_path} already exists (use --force to overwrite)")
    # Check the choices before anything is written.
    email = validate_email(email) if email.strip() else ""
    ra = " ".join(parse_ra(ra)) if ra.strip() else ""
    if backend and backend not in BACKENDS:
        raise ConfigError(f"unknown secret backend {backend!r}: use one of " + ", ".join(BACKENDS))
    config = init_config(target, profile=profile)
    config.identity.email = email or config.identity.email
    config.identity.ra = ra or config.identity.ra
    if base_url:
        config.ca.base_url = base_url
    if backend:
        config.secrets.backend = backend
    validate_config(config)
    write_config(config.path, config)
    ctx = AppContext.from_config(config)
    ctx.secrets.ensure(config.secrets.account)
    return ctx


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def normalize_common_name(value: str, cert_type: str) -> str:
    name = unicodedata.normalize("NFC", " ".join(value.split()))
    if not name:
        raise PyCertError("the common name is empty")
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        raise PyCertError("the common name contains non-ASCII characters; the RA only accepts ASCII names")
    if cert_type == "host":
        candidate = name.lower().rstrip(".")
        labels = candidate.split(".")
        if len(labels) < 2:
            raise PyCertError(f"'{name}' is not a fully qualified host name (it needs a dot)")
        if len(candidate) > 253 or not all(DNS_LABEL.match(label) for label in labels):
            raise PyCertError(f"'{name}' is not a valid DNS host name")
        if re.fullmatch(r"[0-9.]+", candidate):
            raise PyCertError("an IP address is not valid as a host certificate common name")
        return candidate
    lowered = name.lower()
    words = lowered.split(" ")
    if len(words) < 2:
        raise PyCertError("a personal certificate needs at least two names, e.g. 'Jane Doe'")
    if sum(1 for word in words if len(word) >= 2) < 2:
        raise PyCertError("each part of the name must be at least two characters")
    if any(len(word) > 64 for word in words):
        raise PyCertError("the common name is too long")
    return lowered


def _normalize_name(value: str, cert_type: str, *, wildcard: bool = False) -> str:
    """Normalise a name; CAs that validate domains (ACME) also accept '*.example.org'."""
    text = " ".join(value.split())
    if wildcard and cert_type == "host" and text.startswith("*."):
        return "*." + normalize_common_name(text[2:], "host")
    return normalize_common_name(value, cert_type)


def validate_email(value: str) -> str:
    email = value.strip()
    if not email:
        raise PyCertError("an e-mail address is required")
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise PyCertError(f"'{value}' is not a valid e-mail address")
    return email


def parse_ra(text: str) -> "tuple[str, str]":
    """Split an RA string ('CLRC DL' or 'CLRC,DL') into (OU, L)."""
    parts = [p for p in re.split(r"[,\s]+", text.strip()) if p]
    if len(parts) != 2:
        raise PyCertError(f"invalid RA {text!r}: expected 'OU L', e.g. 'CLRC DL' (see 'pycert ras')")
    return parts[0], parts[1]


def generate_pin(groups: int = 3, size: int = 4) -> str:
    return "-".join("".join(secrets_module.choice(PIN_ALPHABET) for _ in range(size)) for _ in range(groups))


def pin_hash(pin: str, algorithm: str = "sha1") -> str:
    """Hash a PIN the way the RA expects (upper-case hex, as CertWizard did)."""
    if algorithm not in ("sha1", "sha256"):
        raise ConfigError(f"unsupported PIN hash: {algorithm}")
    return hashlib.new(algorithm, pin.encode("utf-8")).hexdigest().upper()


def generate_key(
    config: Config,
    progress: Progress = noop,
    *,
    algorithm: str = "",
    rsa_bits: int = 0,
    ec_curve: str = "",
):
    algorithm = (algorithm or config.keys.algorithm).lower()
    if algorithm == "rsa":
        bits = int(rsa_bits or config.keys.rsa_bits)
        if bits not in (2048, 3072, 4096, 8192):
            raise PyCertError("RSA key size must be 2048, 3072, 4096 or 8192 bits")
        progress(f"Generating a {bits}-bit RSA key (this can take a few seconds)...")
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if algorithm != "ec":
        raise PyCertError("key algorithm must be 'rsa' or 'ec'")
    name = ec_curve or config.keys.ec_curve
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    if name not in curves:
        raise PyCertError("EC curve must be P-256, P-384 or P-521")
    progress(f"Generating an {name} key...")
    return ec.generate_private_key(curves[name])


def modulus_exponent(certificate: x509.Certificate) -> str:
    """``<modulus hex>.<public exponent hex>`` as PPPK expects."""
    key = certificate.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("PPPK authentication requires an RSA certificate")
    numbers = key.public_numbers()
    return f"{numbers.n:x}.{numbers.e:x}"


def _report_pin(pin: str, on_pin: "Callable[[str], None] | None", progress: Progress) -> None:
    """Surface a generated PIN once: through the caller (GUI dialog) or progress."""
    if on_pin is not None:
        on_pin(pin)
    else:
        progress(f"PIN for the RA (quote it when asked): {pin}")


def _format(template: str, state: RequestState) -> str:
    try:
        return template.format(cn=state.cn.replace(" ", "_"), alias=state.alias.replace(" ", "_"))
    except (KeyError, ValueError) as exc:
        raise ConfigError(f"invalid filename template {template!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# Request specification
# ---------------------------------------------------------------------------


@dataclass
class RequestSpec:
    cn: str
    type: str = "user"
    email: str = ""
    alias: str = ""
    ou: str = ""
    l: str = ""
    o: str = ""
    c: str = ""
    st: str = ""
    ra: str = ""
    key_algorithm: str = ""
    rsa_bits: int = 0
    ec_curve: str = ""
    pin: str = ""
    san_dns: "list[str]" = field(default_factory=list)
    san_email: "list[str]" = field(default_factory=list)
    san_ip: "list[str]" = field(default_factory=list)
    csr_extensions: "list[str] | None" = None
    csr_hash: str = ""
    auth_alias: str = ""
    #: CA profile name; filled in by :meth:`build` (the configuration's default_ca)
    ca: str = ""
    description: str = ""
    #: linked keystore to store the certificate in once issued
    keystore: str = ""

    @classmethod
    def build(cls, config: Config, cn: str, **overrides) -> "RequestSpec":  # noqa: F821
        from .providers import capabilities_for

        profile = config.profile_for(overrides.pop("ca", "") or config.default_ca)
        caps = capabilities_for(profile.kind)
        identity = profile.identity
        spec = cls(
            cn=cn,
            type=overrides.pop("type", "user"),
            email=overrides.pop("email", "") or identity.email or (profile.contact_emails() or [""])[0],
            alias=overrides.pop("alias", ""),
            ou=overrides.pop("ou", "") or identity.ou,
            l=overrides.pop("l", "") or identity.l,
            o=overrides.pop("o", "") or identity.o,
            c=overrides.pop("c", "") or identity.c,
            st=overrides.pop("st", "") or identity.st,
            ra=overrides.pop("ra", "") or identity.ra,
            key_algorithm=overrides.pop("key_algorithm", "") or config.keys.algorithm,
            rsa_bits=overrides.pop("rsa_bits", 0) or config.keys.rsa_bits,
            ec_curve=overrides.pop("ec_curve", "") or config.keys.ec_curve,
            pin=overrides.pop("pin", ""),
            san_dns=list(overrides.pop("san_dns", []) or []),
            san_email=list(overrides.pop("san_email", []) or []),
            san_ip=list(overrides.pop("san_ip", []) or []),
            csr_extensions=overrides.pop("csr_extensions", None) or list(config.csr.extensions),
            csr_hash=overrides.pop("csr_hash", "") or config.csr.hash,
            auth_alias=overrides.pop("auth_alias", "") or "",
            ca=profile.name,
            description=str(overrides.pop("description", "") or ""),
            keystore=str(overrides.pop("keystore", "") or ""),
        )
        if spec.keystore:
            config.keystore(spec.keystore)  # must be linked
        if overrides:
            raise TypeError(f"unexpected request options: {', '.join(sorted(overrides))}")
        if spec.type not in ("user", "host"):
            raise PyCertError("certificate type must be 'user' or 'host'")
        if spec.type == "user" and not caps.user_certificates:
            raise PyCertError(f"{profile.display_name} only issues host certificates; use --type host")
        if spec.type == "host" and not caps.host_certificates:
            raise PyCertError(f"{profile.display_name} only issues personal certificates")
        spec.cn = _normalize_name(spec.cn, spec.type, wildcard=caps.domain_validation)
        spec.email = validate_email(spec.email)
        if caps.ra:
            if spec.ra:
                spec.ou, spec.l = parse_ra(spec.ra)
            if not spec.ou or not spec.l:
                raise PyCertError(
                    "an RA is required: set identity.ra / identity.ou / identity.l in the "
                    "configuration, or pass --ra 'OU L'"
                )
        if spec.type == "user" and spec.auth_alias:
            raise PyCertError("only host certificate requests can be authenticated with a certificate")
        if caps.host_authentication and spec.type == "host" and not spec.auth_alias:
            raise PyCertError(
                "host certificate requests must be authenticated by an existing certificate: "
                "pass --auth <alias> (see 'pycert list')"
            )
        if not caps.host_authentication and spec.auth_alias:
            raise PyCertError(f"{profile.display_name} does not authenticate requests with an existing certificate")
        if not caps.pin:
            spec.pin = ""
        spec.san_dns = [_normalize_name(name, "host", wildcard=caps.domain_validation) for name in spec.san_dns]
        if spec.type == "host" and spec.san_dns and spec.cn.lower() not in (n.lower() for n in spec.san_dns):
            # TLS clients ignore the CN once a SAN is present: a host certificate
            # must list its own name among the DNS SANs, first.
            spec.san_dns.insert(0, spec.cn)
        for ip in spec.san_ip:
            import ipaddress

            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise PyCertError(f"invalid IP address in SAN: {ip!r}") from exc
        for email in spec.san_email:
            validate_email(email)
        if spec.pin and len(spec.pin) < PIN_MIN_LENGTH:
            raise PyCertError(f"the PIN must be at least {PIN_MIN_LENGTH} characters")
        if not caps.organisation_subject:
            spec.o = spec.ou = spec.l = spec.st = ""
            spec.ra = ""
        return spec

    def subject(self) -> x509.Name:
        if not (self.o or self.ou or self.l):
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.cn)])
        return certs.build_subject(
            common_name=self.cn,
            organization=self.o,
            organizational_unit=self.ou,
            locality=self.l,
            country=self.c,
            state=self.st or None,
        )


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------


def _submission_message(message: str, alias: str, provider=None) -> str:
    if provider is not None and not provider.capabilities.manual_approval:
        return f"{message}. Run 'pycert wait {alias}' to collect the certificate."
    return (
        f"{message}. An RA must approve the request and a CA operator must sign it. "
        f"Run 'pycert wait {alias}' (or 'pycert status --refresh') to poll for the certificate."
    )


def create_request(
    ctx: AppContext,
    spec: RequestSpec,
    *,
    progress: Progress = noop,
    on_pin: "Callable[[str], None] | None" = None,
    wait: bool = False,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    interval: float = DEFAULT_WAIT_INTERVAL,
    export: bool = True,
    require_verified_chain: bool = True,
    stop_event=None,
) -> RequestState:
    """Create a key pair, build a CSR, submit it and optionally wait for signing."""
    alias = spec.alias or spec.cn
    if ctx.store.exists(alias):
        raise PyCertError(f"a certificate request called '{alias}' already exists (use --alias)")

    provider = ctx.provider(spec.ca)
    provider.validate_request(spec)
    progress("Preparing request...")
    prepared = provider.preflight(spec, progress=progress, stop_event=stop_event)

    key = generate_key(
        ctx.config,
        progress,
        algorithm=spec.key_algorithm,
        rsa_bits=spec.rsa_bits,
        ec_curve=spec.ec_curve,
    )
    subject = provider.subject_for(spec)
    progress(f"Building the PKCS#10 request for '{subject.rfc4514_string()}'...")
    request = csr_module.build_csr(
        key,
        subject,
        cert_type=spec.type,
        email=spec.email,
        dns_names=spec.san_dns or None,
        email_names=spec.san_email or None,
        ip_addresses=spec.san_ip or None,
        extensions=spec.csr_extensions,
        hash_name=spec.csr_hash,
    )
    if not csr_module.signature_valid(request):
        raise CryptoError("the generated CSR does not verify against its own public key")

    state = ctx.store.new_state(alias=alias, type=spec.type, cn=spec.cn, email=spec.email)
    state.ca = provider.name
    state.description = spec.description
    if spec.keystore:
        state.keystore = {"name": spec.keystore, "alias": alias, "written": ""}
    state.subject = subject.rfc4514_string()
    state.key_algorithm = certs.key_description(key.public_key())
    state.key_bits = key.key_size if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)) else 0
    state.spki_b64 = certs.spki_b64(key.public_key())
    state.public_key_sha256 = certs.key_fingerprint(key.public_key())
    state.csr_sha256 = sha256_hex(csr_module.csr_der(request))
    state.auth_alias = spec.auth_alias

    password = ctx.key_passphrase()
    ctx.store.save_key(state, key, password)
    ctx.store.save_csr(state, request)
    ctx.store.save(state)

    try:
        submission = provider.submit(
            state, request, spec, prepared=prepared, progress=progress, on_pin=on_pin, stop_event=stop_event
        )
    except PyCertError as exc:
        state.set_status(STATUS_FAILED, f"submission failed: {exc}")
        ctx.store.save(state)
        raise

    if not submission.success:
        detail = f"{submission.message}: {submission.detail}".strip(": ")
        state.set_status(STATUS_FAILED, detail)
        ctx.store.save(state)
        raise CAError(detail, status=submission.status)

    state.submitted_at = iso()
    state.set_status(STATUS_SUBMITTED, submission.message)
    ctx.store.save(state)
    progress(_submission_message(submission.message, state.alias, provider))

    if wait:
        state = wait_for_certificate(
            ctx,
            state,
            progress=progress,
            timeout=timeout,
            interval=interval,
            export=export,
            require_verified_chain=require_verified_chain,
            stop_event=stop_event,
        )
    return state


# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------


def poll_once(
    ctx: AppContext, state: RequestState, *, progress: Progress = noop, stop_event=None
) -> PollOutcome:
    """Ask the request's CA for its status (and the certificate once issued)."""
    return ctx.provider_for(state).poll(state, progress=progress, stop_event=stop_event)


def _public_key_matches(certificate: x509.Certificate, state: RequestState, ctx: AppContext) -> bool:
    if not state.active_spki_b64:
        return True
    return certs.spki_b64(certificate) == state.active_spki_b64


def wait_for_certificate(
    ctx: AppContext,
    state: RequestState,
    *,
    progress: Progress = noop,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    interval: float = DEFAULT_WAIT_INTERVAL,
    export: bool = True,
    require_verified_chain: bool = True,
    stop_event=None,
) -> RequestState:
    """Poll until the certificate is issued, then download and export it."""
    started = time.monotonic()
    deadline = started + timeout
    attempt = 0
    while True:
        if stop_event is not None and stop_event.is_set():
            raise PyCertError("cancelled")
        attempt += 1
        outcome = poll_once(ctx, state, progress=progress, stop_event=stop_event)
        state = outcome.state
        if outcome.certificate is not None:
            progress(f"Certificate issued (server status {outcome.server_status})")
            return download_and_export(
                ctx,
                state,
                stop_event=stop_event,
                certificate=outcome.certificate,
                cert_id=outcome.cert_id,
                progress=progress,
                export=export,
                require_verified_chain=require_verified_chain,
                chain_hint=getattr(outcome, "chain", None) or [],
            )
        if outcome.terminal:
            raise CAError(f"the CA reports this request as '{outcome.server_status}' ({outcome.message})")
        elapsed = time.monotonic() - started
        if elapsed >= timeout or time.monotonic() >= deadline:
            raise TimeoutWaiting(
                f"timed out after {human_duration(elapsed)} waiting for the certificate; "
                f"last status: {outcome.server_status or 'unknown'}. "
                "The request is still stored — run 'pycert wait "
                f"{state.alias}' again later (or 'pycert status --refresh')."
            )
        delay = max(1.0, interval) * (1 + random.uniform(-0.1, 0.1))
        delay = min(delay, max(1.0, deadline - time.monotonic()))
        progress(
            f"{outcome.message} — next check in {human_duration(delay)} "
            f"(attempt {attempt}, {human_duration(elapsed)} elapsed)"
        )
        # Sleep in short slices so a cancel is responsive.
        end = time.monotonic() + delay
        while time.monotonic() < end:
            if stop_event is not None and stop_event.is_set():
                raise PyCertError("cancelled")
            time.sleep(min(0.5, end - time.monotonic()))


# ---------------------------------------------------------------------------
# Download and export
# ---------------------------------------------------------------------------


def download_and_export(
    ctx: AppContext,
    state: RequestState,
    *,
    stop_event=None,
    certificate: "x509.Certificate | None" = None,
    cert_id: str = "",
    progress: Progress = noop,
    export: bool = True,
    require_verified_chain: bool = True,
    password: "str | None" = None,
    out: "Path | None" = None,
    chain_hint: "list[x509.Certificate] | None" = None,
    deploy: bool = True,
) -> RequestState:
    """Verify an issued certificate, store it with its chain, export a .p12 and deploy."""
    chain_hint = list(chain_hint or [])
    if certificate is None:
        outcome = poll_once(ctx, state, progress=progress, stop_event=stop_event)
        if outcome.certificate is None:
            raise CAError(
                f"no certificate is available yet for '{state.alias}' "
                f"(last server status: {outcome.server_status or 'unknown'})"
            )
        certificate = outcome.certificate
        cert_id = outcome.cert_id or cert_id
        chain_hint = list(getattr(outcome, "chain", None) or [])

    renewal = state.renewal
    key = (
        ctx.store.load_pending_key(state, ctx.key_passphrase())
        if renewal
        else ctx.store.load_key(state, ctx.key_passphrase())
    )
    if not certs.certificate_matches_key(certificate, key):
        raise CryptoError(
            "the issued certificate does not match the private key stored for this request; "
            "refusing to store it"
        )
    if not certs.certificate_valid_at(certificate):
        raise CryptoError(
            "the issued certificate is not valid at the current time "
            f"({not_valid_before(certificate).isoformat()} .. "
            f"{not_valid_after(certificate).isoformat()})"
        )

    issued_cn = certs.name_attribute(certificate.subject, NameOID.COMMON_NAME) or ""
    if state.keystore and not state.cert.sha256:
        # A request imported from a Java keystore (a CertWizard placeholder):
        # the issued certificate is the authority on its name and kind.
        state.cn = issued_cn or state.cn
        state.type = certs.certificate_kind(certificate, issued_cn)
    elif issued_cn.lower() != state.cn.lower():
        progress(f"warning: the CA issued common name '{issued_cn}' (requested '{state.cn}')")
        state.notes.append(f"issued CN differs from request: {issued_cn}")

    progress("Verifying the certificate chain...")
    result = ctx.build_chain(certificate, state.ca, chain_hint)
    for problem in result.problems:
        progress(f"chain problem: {problem}")

    if renewal:
        archive = ctx.store.archive_current(state)
        progress(f"Previous certificate archived in {archive}")
        ctx.store.adopt_pending(state)
        state.csr_sha256 = state.pending_csr_sha256
        state.renewal = False
        state.pending_spki_b64 = ""
        state.pending_key_sha256 = ""
        state.pending_csr_sha256 = ""
    state.spki_b64 = certs.spki_b64(key.public_key())
    state.public_key_sha256 = certs.key_fingerprint(key.public_key())

    description = certs.describe_certificate(certificate)
    state.cert = cert_info(description, result)
    state.server.cert_id = cert_id or state.server.cert_id
    state.server.status = "VALID" if result.trusted else (state.server.status or "")
    state.server.start_date = not_valid_before(certificate).strftime("%d/%m/%Y")
    state.server.end_date = not_valid_after(certificate).strftime("%d/%m/%Y")
    state.server.life_days = str((not_valid_after(certificate) - not_valid_before(certificate)).days)
    state.server.renew = (
        not_valid_after(certificate)
        - timedelta(days=max(30, (not_valid_after(certificate) - not_valid_before(certificate)).days // 5))
    ).strftime("%d/%m/%Y")
    if not result.trusted:
        state.notes.extend(f"chain: {p}" for p in result.problems)
    ctx.store.save_certificate(state, certificate, result.issuers)
    state.set_status(STATUS_SIGNED, f"certificate downloaded ({description.key})")
    ctx.store.save(state)
    progress(
        f"Certificate stored: {ctx.store.cert_path(state)} "
        f"(valid until {not_valid_after(certificate).date()})"
    )

    if not result.trusted and require_verified_chain:
        raise ChainError(
            "the certificate was stored but its chain did not validate against the configured "
            "trust anchors, so no PKCS#12 file was written:\n  "
            + "\n  ".join(result.problems or ["unknown reason"])
            + "\nUse --allow-unverified-chain only after understanding the risk."
        )

    if export:
        path = export_p12(ctx, state, password=password, out=out, progress=progress)
        state.set_status(STATUS_DOWNLOADED, f"PKCS#12 exported to {path}")
        state.touch()
        ctx.store.save(state)
    if state.keystore.get("name"):
        from .keystore import write_state

        try:
            write_state(ctx, state, progress=progress)
        except PyCertError as exc:
            # The certificate is safely stored; the next sync retries the write.
            progress(f"warning: could not update keystore '{state.keystore.get('name')}': {exc}")
            state.notes.append(f"keystore update failed: {exc}")
            ctx.store.save(state)
        state = ctx.store.get_by_slug(state.slug)
    if deploy and state.deploy:
        from .deploy import deploy_state

        try:
            deploy_state(ctx, state, progress=progress)
        except PyCertError as exc:
            # The certificate is safely stored; a deployment failure must not lose it.
            progress(f"warning: deployment failed: {exc}")
            state.notes.append(f"deployment failed: {exc}")
            ctx.store.save(state)
    return state


def export_p12(
    ctx: AppContext,
    state: RequestState,
    *,
    password: "str | None" = None,
    out: "Path | None" = None,
    progress: Progress = noop,
) -> Path:
    """Write (or re-write) the PKCS#12 bundle for a stored certificate."""
    certificate = ctx.store.load_certificate(state)
    key = (
        ctx.store.load_pending_key(state, ctx.key_passphrase())
        if state.renewal
        else ctx.store.load_key(state, ctx.key_passphrase())
    )
    chain_certs = ctx.store.load_chain(state)
    if not chain_certs:
        chain_certs = ctx.build_chain(certificate, state.ca).issuers
    if out is None:
        filename = _format(ctx.config.p12.filename_template, state)
        if not filename.lower().endswith(".p12"):
            filename += ".p12"
        # A filename template must not escape the request/export directory.
        if filename != Path(filename).name or filename in (".", ".."):
            raise ConfigError(
                "p12.filename_template produced a path with directory components (%r); "
                "use p12.export_dir to choose a directory" % filename
            )
        if ctx.config.p12.export_dir:
            directory = ensure_dir(ctx.config.resolve(ctx.config.p12.export_dir))
        else:
            directory = ctx.store.path(state)
        out = directory / filename
    out = Path(out)
    password = password or ctx.p12_passphrase()
    friendly = _format(ctx.config.p12.friendly_name, state)
    progress(f"Writing PKCS#12 bundle {out} ...")
    p12_module.write_pkcs12(
        out,
        key=key,
        certificate=certificate,
        chain=chain_certs if ctx.config.p12.include_chain else [],
        password=password,
        friendly_name=friendly,
    )
    state.p12_path = str(out)
    state.p12_sha256 = sha256_hex(out.read_bytes())
    ctx.store.save(state)
    progress("PKCS#12 written (PBES2/AES-256-CBC, HMAC-SHA256).")
    return out


# ---------------------------------------------------------------------------
# Renewal
# ---------------------------------------------------------------------------


def renew(
    ctx: AppContext,
    alias: str,
    *,
    progress: Progress = noop,
    on_pin: "Callable[[str], None] | None" = None,
    wait: bool = False,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    interval: float = DEFAULT_WAIT_INTERVAL,
    export: bool = True,
    require_verified_chain: bool = True,
    key_algorithm: str = "",
    rsa_bits: int = 0,
    ec_curve: str = "",
    email: str = "",
    san_dns: "list[str] | None" = None,
    san_email: "list[str] | None" = None,
    san_ip: "list[str] | None" = None,
    pin: str = "",
    stop_event=None,
) -> RequestState:
    """Request a renewal for an existing certificate, authenticated by its key."""
    state = ctx.store.get(alias)
    if state.renewal:
        raise PyCertError(f"'{state.alias}' already has a renewal in flight")
    try:
        old_certificate = ctx.store.load_certificate(state)
    except NotFound as exc:
        raise PyCertError(f"'{state.alias}' has no certificate to renew") from exc
    old_key = ctx.store.load_key(state, ctx.key_passphrase())
    if not certs.certificate_matches_key(old_certificate, old_key):
        raise PyCertError(f"the private key stored for '{state.alias}' does not match its certificate")

    # Keep the existing subject (with any e-mail attribute) but normalise the
    # attribute order for OpenCA.  Keep the existing SANs unless overridden.
    subject = certs.canonical_openca_name(old_certificate.subject)
    existing_dns = list(_san_values(old_certificate, x509.DNSName))
    existing_email = _san_values(old_certificate, x509.RFC822Name)
    existing_ip = [str(v) for v in _san_values(old_certificate, x509.IPAddress)]
    dns = san_dns if san_dns is not None else existing_dns
    emails = san_email if san_email is not None else existing_email
    ips = san_ip if san_ip is not None else existing_ip
    cn = certs.name_attribute(subject, NameOID.COMMON_NAME) or state.cn
    if cn.lower() != state.cn.lower():
        progress(f"note: the renewed certificate keeps the existing common name '{cn}'")

    provider = ctx.provider_for(state)
    if not provider.capabilities.host_certificates and state.type == "host":  # pragma: no cover - defensive
        raise PyCertError(f"{provider.display_name} cannot renew host certificates")
    ping = provider.ping(stop_event=stop_event)
    if not ping.ok:
        detail = f" ({ping.detail})" if ping.detail else ""
        raise CAError(f"cannot reach the CA server at {provider.url}{detail}")

    # Ask the CA what it holds for this certificate now (status, contact), as
    # CertWizard does, and refuse what the CA would refuse.
    check = check_renewal(ctx, state, email=email, progress=progress, stop_event=stop_event)
    if check.problem:
        raise PyCertError(f"cannot renew '{state.alias}': {check.problem}")
    contact = check.contact
    if check.record_email and contact.lower() != check.record_email.lower():
        progress(f"note: the CA's contact e-mail for this certificate changes from {check.record_email} to {contact}")
    if not emails and state.type == "user":  # pragma: no cover - user certs normally carry e-mail
        emails = [contact]

    key = generate_key(ctx.config, progress, algorithm=key_algorithm, rsa_bits=rsa_bits, ec_curve=ec_curve)
    request = csr_module.build_csr(
        key,
        subject,
        cert_type=state.type,
        email=contact,
        dns_names=dns or None,
        email_names=emails or None,
        ip_addresses=ips or None,
        extensions=ctx.config.csr.extensions,
        hash_name=ctx.config.csr.hash,
    )
    if pin and len(pin) < PIN_MIN_LENGTH:
        raise PyCertError(f"the PIN must be at least {PIN_MIN_LENGTH} characters")

    ctx.store.save_pending_key(state, key, ctx.key_passphrase())
    ctx.store.save_pending_csr(state, request)
    state.pending_spki_b64 = certs.spki_b64(key.public_key())
    state.pending_key_sha256 = certs.key_fingerprint(key.public_key())
    state.pending_csr_sha256 = sha256_hex(csr_module.csr_der(request))
    state.renewal = True
    state.email = contact
    ctx.store.save(state)

    try:
        submission = provider.submit_renewal(
            state,
            request,
            old_certificate=old_certificate,
            old_key=old_key,
            contact=contact,
            pin=pin,
            progress=progress,
            on_pin=on_pin,
            stop_event=stop_event,
        )
    except PyCertError as exc:
        ctx.store.discard_pending(state)
        state.renewal = False
        state.pending_spki_b64 = state.pending_key_sha256 = state.pending_csr_sha256 = ""
        state.set_status(STATUS_FAILED, f"renewal submission failed: {exc}")
        ctx.store.save(state)
        raise
    if not submission.success:
        ctx.store.discard_pending(state)
        state.renewal = False
        state.pending_spki_b64 = state.pending_key_sha256 = state.pending_csr_sha256 = ""
        detail = f"{submission.message}: {submission.detail}".strip(": ")
        state.set_status(STATUS_FAILED, detail)
        ctx.store.save(state)
        raise CAError(detail, status=submission.status)

    state.submitted_at = iso()
    state.set_status(STATUS_SUBMITTED, "renewal submitted")
    ctx.store.save(state)
    progress(_submission_message("renewal submitted", state.alias, provider))
    if wait:
        return wait_for_certificate(
            ctx,
            state,
            progress=progress,
            timeout=timeout,
            interval=interval,
            export=export,
            require_verified_chain=require_verified_chain,
            stop_event=stop_event,
        )
    return state


@dataclass
class RenewalCheck:
    """Whether a certificate can be renewed, and with which contact e-mail."""

    state: RequestState
    contact: str = ""
    record_email: str = ""  # the contact the CA holds ('' if unknown or not asked)
    asked: bool = False  # the CA was consulted
    problem: str = ""  # why the renewal would be refused ('' if it would not)

    @property
    def ok(self) -> bool:
        return not self.problem


def check_renewal(
    ctx: AppContext,
    state: "RequestState | str",
    *,
    email: str = "",
    progress: Progress = noop,
    stop_event=None,
) -> RenewalCheck:
    """Refresh the CA's record of the certificate and apply the CA's renewal rules.

    The contact defaults to the e-mail the CA holds for the certificate (as
    CertWizard does), then the one recorded locally, then the configured one.
    Network errors propagate; refusals are returned in ``problem``.
    """
    if isinstance(state, str):
        state = ctx.store.get(state)
    if state.renewal:
        return RenewalCheck(state, problem="a renewal is already in progress")
    try:
        certificate = ctx.store.load_certificate(state)
    except NotFound:
        return RenewalCheck(state, problem="there is no certificate to renew")
    provider = ctx.provider_for(state)
    asked = provider.refresh_record(state, certificate, progress=progress, stop_event=stop_event)
    if asked:
        ctx.store.save(state)
    record_email = state.server.email if asked else ""
    contact = (email or record_email or state.email or ctx.config.identity.email).strip()
    check = RenewalCheck(state, contact=contact, record_email=record_email, asked=asked)
    check.problem = provider.renewal_problem(state, certificate, contact)
    if not check.problem:
        if not contact:
            check.problem = "no contact e-mail is known for this certificate; give one"
        else:
            try:
                validate_email(contact)
            except PyCertError as exc:
                check.problem = str(exc)
    return check


def describe_record(state: RequestState) -> str:
    """One line for the CA's record of an issued certificate."""
    server = state.server
    if not server.cert_id and not server.status:
        return "the CA has no record of this certificate"
    parts = [f"CA status {server.status or 'unknown'}"]
    if server.email:
        parts.append(f"contact {server.email}")
    if server.cert_id:
        parts.append(f"certificate id {server.cert_id}")
    return ", ".join(parts)


def refresh_records(
    ctx: AppContext,
    *,
    aliases: "set[str] | None" = None,
    only_missing: bool = False,
    progress: Progress = noop,
    stop_event=None,
) -> "list[tuple[RequestState, str]]":
    """Ask the CA for its record (status, contact) of issued certificates.

    Imported certificates (from a Java keystore or a PKCS#12 file) start
    without one. ``only_missing`` skips certificates that were checked before.
    Errors are reported per certificate, never raised.
    """
    results: "list[tuple[RequestState, str]]" = []
    for state in ctx.store.list():
        if aliases is not None and state.alias not in aliases:
            continue
        if state.renewal or state.status in PENDING_STATUSES or not state.cert.sha256:
            continue
        if only_missing and state.server.last_checked:
            continue
        if stop_event is not None and stop_event.is_set():
            break
        try:
            certificate = ctx.store.load_certificate(state)
            if not ctx.provider_for(state).refresh_record(state, certificate, stop_event=stop_event):
                continue
            ctx.store.save(state)
            message = describe_record(state)
        except PyCertError as exc:
            message = f"error: {exc}"
        results.append((state, message))
        progress(f"{state.alias}: {message}")
    return results


def _san_values(certificate: x509.Certificate, kind) -> list:
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return list(san.get_values_for_type(kind))


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revoke(
    ctx: AppContext, alias: str, reason: str = "unspecified", *, progress: Progress = noop, stop_event=None
) -> RequestState:
    state = ctx.store.get(alias)
    if state.status == STATUS_REVOKED:
        raise PyCertError(f"'{state.alias}' is already marked revoked")
    if state.renewal:
        raise PyCertError(
            f"'{state.alias}' has a renewal in flight; finish it (pycert wait) or remove the "
            "pending files before revoking, so the certificate id and key cannot get mixed up"
        )
    provider = ctx.provider_for(state)
    if not provider.capabilities.revoke:
        raise PyCertError(f"{provider.display_name} does not support revocation through pyCertWiz")
    if reason not in provider.capabilities.revocation_reasons:
        raise PyCertError(
            f"invalid revocation reason {reason!r}; choose one of: "
            + ", ".join(provider.capabilities.revocation_reasons)
        )
    if provider.capabilities.revoke_needs_id and not state.server.cert_id:
        progress("Looking up the certificate id...")
        outcome = poll_once(ctx, state, progress=progress, stop_event=stop_event)
        state = outcome.state
        if not state.server.cert_id:
            raise CAError(f"the CA did not report a certificate id for '{state.alias}'")
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    if not certs.certificate_matches_key(certificate, key):
        raise PyCertError("the stored private key does not match the certificate to revoke")
    submission = provider.revoke(
        state, reason, certificate=certificate, key=key, progress=progress, stop_event=stop_event
    )
    if not submission.success:
        raise CAError(f"{submission.message}: {submission.detail}".strip(": "), status=submission.status)
    state.set_status(STATUS_REVOKED, f"revoked by this client (reason: {reason})")
    ctx.store.save(state)
    progress("Revocation accepted by the CA.")
    return state


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


def cert_info(description: "certs.CertDescription", result: chain.ChainResult) -> CertInfo:
    """The stored summary of an issued certificate and its verified chain."""
    return CertInfo(
        subject=description.subject,
        issuer=description.issuer,
        serial=description.serial,
        not_before=description.not_before.astimezone(timezone.utc).isoformat(),
        not_after=description.not_after.astimezone(timezone.utc).isoformat(),
        sha256=description.fingerprint_sha256.replace(":", "").lower(),
        key=description.key,
        sans=description.subject_alt_names,
        chain_sha256=[certs.fingerprint(c) for c in result.chain],
        verified=result.trusted,
    )


def import_p12(
    ctx: AppContext,
    path: Path,
    password: str,
    *,
    alias: str = "",
    progress: Progress = noop,
    require_verified_chain: bool = True,
    ca: str = "",
) -> RequestState:
    """Import an existing PKCS#12 bundle so it can be renewed/exported by pyCertWiz."""
    profile = ctx.profile(ca)
    progress(f"Reading {path} ...")
    bundle: P12Bundle = p12_module.read_pkcs12(Path(path), password)
    weak_key_warning = certs.key_strength_warning(bundle.key.public_key())
    if weak_key_warning:
        progress("warning: " + weak_key_warning)
    cn = certs.common_name(bundle.cert.subject)
    cert_type = "host" if "." in cn and " " not in cn else "user"
    name = alias or cn
    if ctx.store.exists(name):
        raise PyCertError(f"a certificate request called '{name}' already exists")
    result = ctx.build_chain(bundle.cert, profile.name)
    for problem in result.problems:
        progress(f"chain problem: {problem}")
    if not result.trusted and require_verified_chain:
        raise ChainError(
            "the imported certificate's chain did not validate: "
            + "; ".join(result.problems or ["no trust anchor reached"])
            + "\nUse --allow-unverified-chain to import anyway."
        )

    state = ctx.store.new_state(alias=name, type=cert_type, cn=cn, email="")
    state.ca = profile.name
    state.subject = bundle.cert.subject.rfc4514_string()
    state.key_algorithm = certs.key_description(bundle.key.public_key())
    state.key_bits = getattr(bundle.key, "key_size", 0) or 0
    state.spki_b64 = certs.spki_b64(bundle.key.public_key())
    state.public_key_sha256 = certs.key_fingerprint(bundle.key.public_key())
    ctx.store.save_key(state, bundle.key, ctx.key_passphrase())
    # Save the CSR slot empty; imported certificates have no CSR.
    description = certs.describe_certificate(bundle.cert)
    state.cert = cert_info(description, result)
    state.server.start_date = not_valid_before(bundle.cert).strftime("%d/%m/%Y")
    state.server.end_date = not_valid_after(bundle.cert).strftime("%d/%m/%Y")
    ctx.store.save_certificate(state, bundle.cert, result.issuers)
    state.set_status(STATUS_IMPORTED, f"imported from {path}")
    if not result.trusted:
        state.notes.extend(f"chain: {p}" for p in result.problems)
    if weak_key_warning:
        state.notes.append(weak_key_warning)
    ctx.store.save(state)
    progress(f"Imported '{cn}' as '{state.alias}'.")
    return state


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class VerifyReport:
    alias: str
    ok: bool
    checks: "list[tuple[str, bool, str]]" = field(default_factory=list)
    warnings: "list[str]" = field(default_factory=list)
    chain: "chain.ChainResult | None" = None

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append((name, passed, detail))
        if not passed:
            self.ok = False

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def as_dict(self) -> dict:
        return {
            "alias": self.alias,
            "ok": self.ok,
            "checks": [{"check": n, "passed": p, "detail": d} for n, p, d in self.checks],
            "warnings": list(self.warnings),
            "chain": self.chain.as_dict() if self.chain else None,
        }


def verify(
    ctx: AppContext, alias: str, *, check_p12: bool = True, now: "datetime | None" = None
) -> VerifyReport:
    report = VerifyReport(alias=alias, ok=True)
    state = ctx.store.get(alias)
    try:
        certificate = ctx.store.load_certificate(state)
    except (NotFound, CryptoError) as exc:
        report.add("certificate present", False, str(exc))
        return report
    report.add("certificate present", True, certs.name_to_string(certificate.subject))
    try:
        key = ctx.store.load_key(state, ctx.key_passphrase())
        report.add("private key present", True, certs.key_description(key.public_key()))
    except (NotFound, CryptoError) as exc:
        report.add("private key present", False, str(exc))
        key = None
    if key is not None:
        report.add(
            "key matches certificate",
            certs.certificate_matches_key(certificate, key),
            "SubjectPublicKeyInfo comparison",
        )
        warning = certs.key_strength_warning(key.public_key())
        if warning:
            report.warn(warning)
    now = now or datetime.now(timezone.utc)
    valid = certs.certificate_valid_at(certificate, now)
    report.add(
        "certificate valid now",
        valid,
        f"{not_valid_before(certificate).date()} .. {not_valid_after(certificate).date()}",
    )
    days = (not_valid_after(certificate) - now).days
    if days <= 30:
        report.warn(f"the certificate expires in {days} days; plan a renewal")
    result = ctx.build_chain(certificate, state.ca)
    report.chain = result
    report.add(
        "chain validates",
        result.trusted,
        "; ".join(result.problems) if result.problems else f"{len(result.chain)} certificates",
    )
    report.add(
        "chain is complete",
        result.complete,
        "root included" if result.complete else "chain stops before a self-signed root",
    )
    if check_p12 and state.p12_path:
        path = Path(state.p12_path)
        if path.is_file():
            try:
                bundle = p12_module.read_pkcs12(path, ctx.p12_passphrase())
                report.add(
                    "PKCS#12 readable",
                    certs.fingerprint(bundle.cert) == certs.fingerprint(certificate)
                    and (key is None or certs.public_keys_equal(bundle.key.public_key(), key.public_key())),
                    str(path),
                )
            except PyCertError as exc:
                report.add("PKCS#12 readable", False, str(exc))
        else:
            report.add("PKCS#12 readable", False, f"missing file {path}")
    return report


# ---------------------------------------------------------------------------
# Installation of PEM files (CertWizard's "Install")
# ---------------------------------------------------------------------------


def install_pem(
    ctx: AppContext,
    alias: str,
    directory: Path,
    *,
    include_chain: bool = False,
    password: "str | None" = None,
    no_passphrase: bool = False,
    progress: Progress = noop,
) -> "dict[str, Path]":
    """Write usercert.pem and userkey.pem (the GSI/Globus layout).

    The key is encrypted with *password*, a new passphrase the user chose for
    it (never the saved secret). Only when the caller has obtained the user's
    explicit confirmation may *no_passphrase* leave this single key file
    unprotected.
    """
    from .exporter import FORMATS, check_passphrase

    check_passphrase(ctx, FORMATS["key"], password, no_passphrase)
    state = ctx.store.get(alias)
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    directory = ensure_dir(Path(directory).expanduser(), 0o700)
    cert_path = directory / "usercert.pem"
    key_path = directory / "userkey.pem"
    cert_text = certs.cert_pem(certificate)
    if include_chain:
        cert_text += "".join(certs.cert_pem(c) for c in ctx.store.load_chain(state))
    atomic_write(cert_path, cert_text, mode=0o644)
    _write_single_key(ctx, key_path, key, password=password, no_passphrase=no_passphrase, progress=progress)
    progress(f"Wrote {cert_path} (mode 0644) and {key_path} (mode 0400).")
    return {"cert": cert_path, "key": key_path}


def _write_single_key(ctx, path: Path, key, *, password: "str | None", no_passphrase: bool, progress: Progress) -> None:
    if no_passphrase:
        atomic_write(path, certs.unprotected_key_pem(key, confirmed=True), mode=0o400)
        progress(f"warning: {path} has NO passphrase, as you confirmed; anyone who can read it holds the key")
        return
    atomic_write(path, certs.key_pem(key, password), mode=0o400)
    progress(f"{path.name} is protected with the new passphrase you chose; pyCertWiz does not keep it.")


def export_certificate(
    ctx: AppContext,
    alias: str,
    destination: "Path | str",
    *,
    format: str = "p12",
    encryption: str = "",
    password: "str | None" = None,
    no_passphrase: bool = False,
    include_chain: bool = True,
    overwrite: bool = False,
    progress: Progress = noop,
):
    """Export a stored certificate in *format* (see :mod:`pycert.exporter`).

    Anything with a private key needs a new passphrase chosen for this export.
    """
    from .exporter import export_material

    state = ctx.store.get(alias)
    certificate = ctx.store.load_certificate(state)
    chain_certs = ctx.store.load_chain(state) or ctx.build_chain(certificate, state.ca).issuers
    return export_material(
        alias=state.alias,
        certificate=certificate,
        chain=chain_certs,
        load_key=lambda: ctx.store.load_key(state, ctx.key_passphrase()),
        fmt=format,
        destination=destination,
        ctx=ctx,
        encryption=encryption,
        password=password,
        no_passphrase=no_passphrase,
        include_chain=include_chain,
        overwrite=overwrite,
        progress=progress,
    )


def export_pem(
    ctx: AppContext,
    alias: str,
    directory: Path,
    *,
    include_chain: bool = True,
    password: "str | None" = None,
    no_passphrase: bool = False,
    overwrite: bool = True,
    progress: Progress = noop,
) -> "dict[str, Path]":
    """Save one certificate and its private key as PEM files: ``<name>.pem`` and ``<name>.key``.

    The key is encrypted with *password*, a new passphrase chosen for this
    export, unless the user explicitly confirmed *no_passphrase* for this
    individual key file.
    """
    result = export_certificate(
        ctx,
        alias,
        directory,
        format="pem-files",
        password=password,
        no_passphrase=no_passphrase,
        include_chain=include_chain,
        overwrite=overwrite,
        progress=progress,
    )
    return result.files


# ---------------------------------------------------------------------------
# Renaming
# ---------------------------------------------------------------------------

MAX_ALIAS_LENGTH = 200


def validate_alias(name: str) -> str:
    """A usable certificate name: not empty, printable, of reasonable length."""
    alias = name.strip()
    if not alias:
        raise PyCertError("the name cannot be empty")
    if len(alias) > MAX_ALIAS_LENGTH:
        raise PyCertError(f"the name is longer than {MAX_ALIAS_LENGTH} characters")
    if any(not ch.isprintable() for ch in alias):
        raise PyCertError("the name cannot contain control characters")
    return alias


def rename_certificate(
    ctx: AppContext,
    alias: str,
    new_alias: str,
    *,
    keystore_entry: bool = False,
    progress: Progress = noop,
) -> RequestState:
    """Give a certificate a new name in pyCertWiz (and, optionally, in its Java keystore).

    The files stay where they are; references from other certificates (the
    authenticating certificate of host requests) follow the new name. With
    *keystore_entry*, the linked Java keystore entry is renamed too, so
    CertWizard shows the same name; that needs the keystore passphrase.
    """
    state = ctx.store.get(alias)
    old = state.alias
    new = validate_alias(new_alias)
    if new == old:
        return state
    clash = [s for s in ctx.store.list() if s.slug != state.slug and s.alias.lower() == new.lower()]
    if clash:
        raise PyCertError(f"another certificate is already called '{clash[0].alias}'")
    if keystore_entry:
        if not state.keystore.get("name"):
            raise PyCertError(f"'{old}' is not linked to a Java keystore")
        from . import keystore as keystore_module

        link = ctx.config.keystore(state.keystore["name"])
        if not link.write_back:
            raise PyCertError(f"keystore '{link.name}' is linked read-only; its entries are not renamed")
        java_alias = state.keystore.get("alias") or old
        password = keystore_module.keystore_password(ctx, link)
        with keystore_module.open_keystore(link.path, password) as keystore:
            keystore.rename(java_alias, new)
        state.keystore = {**state.keystore, "alias": new}
        progress(f"Renamed entry '{java_alias}' to '{new}' in Java keystore '{link.name}'")
    state.alias = new
    state.add_history(state.status, f"renamed from '{old}'")
    ctx.store.save(state)
    for other in ctx.store.list():
        if other.slug != state.slug and other.auth_alias == old:
            other.auth_alias = new
            ctx.store.save(other)
    progress(f"Renamed '{old}' to '{new}'")
    return state


# ---------------------------------------------------------------------------
# Long-running watch and batch renewal
# ---------------------------------------------------------------------------


@dataclass
class WatchReport:
    cycles: int = 0
    polled: int = 0
    downloaded: int = 0
    errors: "list[tuple[str, str]]" = field(default_factory=list)
    stopped: bool = False

    def as_dict(self):
        return {
            "cycles": self.cycles,
            "polled": self.polled,
            "downloaded": self.downloaded,
            "errors": [{"alias": alias, "error": error} for alias, error in self.errors],
            "stopped": self.stopped,
        }


def _watch_sleep(seconds, stop_event, sleep):
    end = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < end:
        if stop_event is not None and stop_event.is_set():
            return False
        sleep(min(0.2, max(0.0, end - time.monotonic())))
    return True


def watch(
    ctx: AppContext,
    *,
    interval: float = 60.0,
    export: bool = True,
    max_cycles: "int | None" = None,
    stop_event=None,
    progress: Progress = noop,
    require_verified_chain: bool = True,
    sleep=time.sleep,
) -> WatchReport:
    """Poll pending requests until stopped, downloading and exporting as they sign.

    Only requests without a stored certificate (or with a renewal in flight) are
    processed, so a request whose certificate is already stored is never
    downloaded repeatedly.
    """
    report = WatchReport()
    while True:
        if stop_event is not None and stop_event.is_set():
            report.stopped = True
            break
        report.cycles += 1
        pending = [
            state
            for state in ctx.store.pending()
            if state.active_spki_b64 and (not state.cert.sha256 or state.renewal)
        ]
        if pending:
            progress("watch: checking %d request(s)" % len(pending))
        for state in pending:
            if stop_event is not None and stop_event.is_set():  # pragma: no cover - cancellation race
                report.stopped = True
                break
            try:
                outcome = poll_once(ctx, state, progress=progress, stop_event=stop_event)
                report.polled += 1
                if outcome.certificate is not None:
                    download_and_export(
                        ctx,
                        outcome.state,
                        stop_event=stop_event,
                        certificate=outcome.certificate,
                        cert_id=outcome.cert_id,
                        progress=progress,
                        export=export,
                        require_verified_chain=require_verified_chain,
                    )
                    report.downloaded += 1
                    progress("watch: certificate ready for %s" % state.alias)
                elif outcome.terminal:
                    progress("watch: %s is %s" % (state.alias, outcome.server_status))
            except PyCertError as exc:
                report.errors.append((state.alias, str(exc)))
                progress("watch: %s: %s" % (state.alias, exc))
        if report.stopped:  # pragma: no cover - cancellation race
            break
        if max_cycles is not None and report.cycles >= max_cycles:
            break
        if pending:
            progress("watch: sleeping for %.0fs" % interval)
        delay = interval * (1 + random.uniform(-0.1, 0.1))
        if not _watch_sleep(max(1.0, delay), stop_event, sleep):  # pragma: no cover - cancellation race
            report.stopped = True
            break
    return report


def renew_due(
    ctx: AppContext,
    days: int = 30,
    *,
    dry_run: bool = False,
    progress: Progress = noop,
    on_pin=None,
    ca: str = "",
    include_manual: bool = False,
    **renew_options,
):
    """Renew every stored certificate expiring within *days*.

    Certificates with ``auto_renew`` switched off are skipped unless
    *include_manual* is true; *ca* limits the run to one CA profile.

    Returns a list of ``(state, error)`` pairs; ``error`` is None on success.
    ``dry_run`` only selects and reports what would be renewed.
    """
    due = []
    primary = ctx.config.primary_profile.name
    for state in ctx.store.list():
        if state.status == STATUS_REVOKED or state.renewal:
            continue
        if not state.auto_renew and not include_manual:
            continue
        if ca and (state.ca or primary) != ca:
            continue
        if not state.cert.not_after or not state.active_spki_b64:
            continue
        remaining = state.days_remaining
        if remaining is None or remaining > days:
            continue
        due.append(state)
    due.sort(key=lambda item: item.days_remaining if item.days_remaining is not None else 10**9)
    results = []
    for state in due:
        if dry_run:
            progress("would renew %s (%s days remaining)" % (state.alias, state.days_remaining))
            results.append((state, None))
            continue
        progress("renewing %s (%s days remaining)" % (state.alias, state.days_remaining))
        try:
            renewed = renew(ctx, state.alias, progress=progress, on_pin=on_pin, **renew_options)
            results.append((renewed, None))
        except PyCertError as exc:
            results.append((state, str(exc)))
            progress("renewal failed for %s: %s" % (state.alias, exc))
    return results


# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------


def refresh_all(ctx: AppContext, *, progress: Progress = noop) -> "list[tuple[RequestState, str]]":
    """Poll every pending request once (no downloads)."""
    results: "list[tuple[RequestState, str]]" = []
    for state in ctx.store.pending():
        try:
            outcome = poll_once(ctx, state, progress=noop)
            results.append((outcome.state, outcome.server_status or "unknown"))
            progress(f"{state.alias}: {outcome.server_status or 'unknown'} — {outcome.message}")
        except PyCertError as exc:
            results.append((state, f"error: {exc}"))
            progress(f"{state.alias}: error: {exc}")
    return results


def list_ras(ctx: AppContext, ca: str = "") -> "list[RA]":
    provider = ctx.provider(ca)
    if not provider.capabilities.ra:
        raise PyCertError(f"{provider.display_name} does not use Registration Authorities")
    return provider.ras()


def expiry_warning(state: RequestState, days: int = 30) -> "str | None":
    remaining = state.days_remaining
    if remaining is None:
        return None
    if remaining < 0:
        return f"expired {human_duration(abs(remaining) * 86400)} ago"
    if remaining <= days:
        return f"expires in {remaining} days"
    return None


def describe_state(state: RequestState) -> dict:
    return {**state.to_dict(), "days_remaining": state.days_remaining}
