"""Configuration: TOML file, dataclasses, validation, CA profiles and paths.

A pyCertWiz configuration is a plain TOML file so it can be reviewed, diffed and
version-controlled.  It describes one *primary* CA (the UK e-Science CA by
default) plus any number of additional named CA profiles:

* ``[ca]``          - the primary CA: server URL, timeouts, TLS policy, endpoints;
* ``[identity]``    - organisation / OU / locality / country, default e-mail, RA;
* ``[keys]``        - key algorithm and size;
* ``[csr]``         - hash algorithm and requested extensions;
* ``[p12]``         - output file naming;
* ``[secrets]``     - where the saved PKCS#12 passphrase lives;
* ``[[chain.certificates]]`` - the primary CA chain, either as files or inline
  PEM, each optionally pinned by SHA-256;
* ``[cas.<name>]``  - additional CA profiles.  ``kind = "ukca"`` profiles speak
  the CertWizard protocol (e.g. a test or second UK-CA instance) and accept the
  same keys as ``[ca]`` plus ``[cas.<name>.identity]`` and
  ``[[cas.<name>.chain]]``; ``kind = "acme"`` profiles describe an RFC 8555
  ACME CA (Let's Encrypt, Sectigo/Jisc with EAB, or a future UK-CA ACME
  service).  Other kinds can be supplied by plugins, see
  :mod:`pycert.providers`.

``default_ca`` names the profile used for new requests when none is given.
Every stored request records the profile it belongs to.

Nothing secret is stored in this file.  The PKCS#12 passphrase and ACME EAB
keys are held in the OS secret store (or a 0600 file, or an external command);
see :mod:`pycert.secrets_store`.
"""

import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509

from . import bundled, certs
from .errors import ConfigError
from .util import ensure_dir, normalize_fingerprint

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

TOMLDecodeError = tomllib.TOMLDecodeError
toml_loads = tomllib.loads

DEFAULT_BASE_URL = "https://cwiz-live.ca.ngs.ac.uk:443"
DEFAULT_VERSION_STRING = "CertWizard 2.2.1"
DEFAULT_USER_AGENT = "pyCertWiz/2.0"
DEFAULT_CA_NAME = "uk-escience"
DEFAULT_CA_DISPLAY_NAME = "UK e-Science CA"
CONFIG_VERSION = 2
SUPPORTED_CONFIG_VERSIONS = (1, 2)
MAX_CONFIG_BYTES = 1024 * 1024
PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
ACME_CHALLENGES = ("http-01", "dns-01")
ACME_HTTP_MODES = ("standalone", "webroot")
ACME_ACCOUNT_KEYS = ("ec", "rsa")


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


@dataclass
class Endpoints:
    csr: str = "/CSR"
    bulk: str = "/CSRs"
    lookup: str = "/resources/resource/publickey/pk"
    certificate: str = "/certificate"
    revoke: str = "/revoke"
    ping: str = "/pingservice"
    info: str = "/CA"
    motd: str = "/CA/motd/text"


@dataclass
class CAConfig:
    base_url: str = DEFAULT_BASE_URL
    version_string: str = DEFAULT_VERSION_STRING
    user_agent: str = DEFAULT_USER_AGENT
    timeout: float = 30.0  # socket read timeout (seconds)
    connect_timeout: float = 10.0
    deadline: float = 90.0  # total time per request attempt
    dns_timeout: float = 10.0
    retries: int = 2  # idempotent requests only
    max_redirects: int = 2  # same-host redirects, GET/HEAD only
    max_body_bytes: int = 8 * 1024 * 1024
    max_header_bytes: int = 128 * 1024
    backoff_base: float = 0.4
    backoff_cap: float = 8.0
    tls_verify: bool = True
    tls_trust: str = "chain"  # chain | system | both
    tls_pin_sha256: "list[str]" = field(default_factory=list)
    allow_plaintext: bool = False
    allow_sha1: bool = False
    endpoints: Endpoints = field(default_factory=Endpoints)
    name: str = DEFAULT_CA_NAME
    display_name: str = DEFAULT_CA_DISPLAY_NAME

    def url(self, name: str) -> str:
        return self.base_url.rstrip("/") + getattr(self.endpoints, name)


@dataclass
class IdentityConfig:
    c: str = "UK"
    o: str = "eScience"
    ou: str = "CLRC"
    l: str = "DL"
    st: str = ""
    email: str = ""
    ra: str = ""


@dataclass
class KeyConfig:
    algorithm: str = "rsa"  # rsa | ec
    rsa_bits: int = 3072
    ec_curve: str = "P-256"


@dataclass
class CSRConfig:
    hash: str = "sha256"
    extensions: "list[str]" = field(default_factory=lambda: ["san"])
    pin_hash: str = "sha1"  # the current CA server hashes PINs with SHA-1


@dataclass
class P12Config:
    filename_template: str = "{cn}.p12"
    friendly_name: str = "{cn}"
    export_dir: str = ""
    include_chain: bool = True


@dataclass
class PathsConfig:
    data_dir: str = ""


@dataclass
class SecretConfig:
    backend: str = "auto"  # auto | keychain | secret-service | keyring | file | command | env | prompt
    service: str = "pyCert"
    account: str = "default"
    key_account: str = ""  # empty = reuse the [secrets].account secret
    file: str = ""
    command: str = ""
    command_timeout: float = 15.0
    env_var: str = "PYCERT_P12_PASSPHRASE"


@dataclass
class ACMEConfig:
    """Settings for an RFC 8555 ACME CA profile.

    The EAB HMAC key is a secret and is never stored here: it is kept in the
    secret store under the account ``acme-eab:<profile>`` (``pycert ca eab``),
    or read from the environment variable named by ``eab_hmac_env``.
    """

    contact: "list[str]" = field(default_factory=list)  # e-mail addresses; default identity.email
    terms_agreed: bool = False
    eab_kid: str = ""
    eab_hmac_env: str = ""
    account_key: str = "ec"  # ec (P-256) | rsa (3072)
    challenge: str = "http-01"  # http-01 | dns-01
    http_mode: str = "standalone"  # standalone | webroot
    http_port: int = 80
    http_bind: str = ""
    webroot: str = ""
    dns_hook: str = ""  # '<hook> add|remove <domain> <record-name> <value>'; empty = manual
    dns_propagation_seconds: float = 0.0
    validation_timeout: float = 300.0
    poll_interval: float = 2.0


@dataclass
class KeystoreLink:
    """A Java PKCS#12 keystore kept in step with pyCertWiz's store (see :mod:`pycert.keystore`)."""

    name: str
    path: str
    ca: str = ""  # CA profile the keystore's certificates belong to (default: the primary CA)
    auto_import: bool = True  # import key entries pyCertWiz does not manage yet
    write_back: bool = True  # write issued and renewed certificates into the keystore
    # The passphrase is deliberately not configurable here: it is never stored and is
    # asked for in each session.


@dataclass
class ChainEntry:
    label: str = ""
    file: "str | None" = None
    pem: "str | None" = None
    sha256: "str | None" = None
    anchor: bool = True

    def resolved_path(self, base: Path) -> "Path | None":
        if self.file is None:
            return None
        path = Path(os.path.expandvars(os.path.expanduser(self.file)))
        return path if path.is_absolute() else (base / path)


@dataclass
class ChainBundle:
    """CA chain loaded from the configuration, with pin checking applied."""

    certificates: "list[x509.Certificate]"
    anchors: "list[x509.Certificate]"
    sources: "list[str]"

    def __post_init__(self) -> None:
        seen: "set[str]" = set()
        unique: "list[x509.Certificate]" = []
        for cert in self.certificates:
            fp = certs.fingerprint(cert)
            if fp not in seen:
                seen.add(fp)
                unique.append(cert)
        self.certificates = unique

    def pem(self) -> str:
        return "".join(certs.cert_pem(c) for c in self.certificates)

    def anchor_pem(self) -> str:
        return "".join(certs.cert_pem(c) for c in self.anchors)


def load_chain_entries(
    entries: "Sequence[ChainEntry]", base: Path, warnings: "list[str]", *, where_prefix: str = "chain.certificates"
) -> ChainBundle:
    """Load and pin-check chain entries (files relative to *base*)."""
    loaded: "list[x509.Certificate]" = []
    anchors: "list[x509.Certificate]" = []
    sources: "list[str]" = []
    for index, entry in enumerate(entries):
        where = f"{where_prefix}[{index}]"
        if entry.pem:
            data = entry.pem.encode()
            source = f"inline PEM ({entry.label or 'unnamed'})"
        else:
            path = entry.resolved_path(base)
            if path is None:
                raise ConfigError(f"{where}: either 'file' or 'pem' is required")
            if not path.is_file():
                raise ConfigError(f"{where}: certificate file not found: {path}")
            data = path.read_bytes()
            source = str(path)
        try:
            parsed = certs.load_certificates(data)
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"{where}: {exc}") from exc
        if entry.sha256:
            expected = normalize_fingerprint(entry.sha256)
            for cert in parsed:
                actual = certs.fingerprint(cert)
                if actual != expected:
                    raise ConfigError(
                        f"{where}: certificate fingerprint mismatch for {source}\n"
                        f"  expected {expected}\n  actual   {actual}\n"
                        "Refusing to use a CA certificate that does not match its pin."
                    )
        loaded.extend(parsed)
        if entry.anchor:
            anchors.extend(parsed)
        sources.append(source)
    return ChainBundle(loaded, anchors, sources)


# ---------------------------------------------------------------------------
# CA profiles
# ---------------------------------------------------------------------------


class CAProfile:
    """One CA the configuration knows about.

    The primary profile is a live view of the top-level ``[ca]``,
    ``[identity]`` and ``[chain]`` sections, so editing ``config.ca`` (the CLI's
    ``config set`` and the GUI settings dialog do) is reflected immediately.
    A profile can be passed wherever a :class:`~pycert.ca.CAClient` expects a
    configuration: it exposes ``ca``, ``tls_trust_pem()`` and
    ``use_system_trust()``.
    """

    def __init__(
        self,
        config: "Config",
        name: str,
        *,
        kind: str = "ukca",
        display_name: str = "",
        ca: "CAConfig | None" = None,
        chain: "list[ChainEntry] | None" = None,
        identity: "IdentityConfig | None" = None,
        acme: "ACMEConfig | None" = None,
        primary: bool = False,
    ):
        self._config = config
        self._name = name
        self.kind = kind
        self._display_name = display_name
        self._ca = ca if ca is not None else CAConfig(name=name, display_name=display_name)
        self._chain = list(chain or [])
        self._identity = identity
        self.acme = acme if acme is not None else ACMEConfig()
        self.primary = primary
        self._bundle: "ChainBundle | None" = None

    # -- live views ----------------------------------------------------------
    @property
    def name(self) -> str:
        return self._config.ca.name if self.primary else self._name

    @property
    def display_name(self) -> str:
        if self.primary:
            return self._config.ca.display_name or self._config.ca.name
        return self._display_name or self._name

    @display_name.setter
    def display_name(self, value: str) -> None:
        if self.primary:
            self._config.ca.display_name = value
        else:
            self._display_name = value

    @property
    def ca(self) -> CAConfig:
        return self._config.ca if self.primary else self._ca

    @property
    def chain(self) -> "list[ChainEntry]":
        return self._config.chain if self.primary else self._chain

    @chain.setter
    def chain(self, entries: "list[ChainEntry]") -> None:
        if self.primary:
            self._config.chain = list(entries)
        else:
            self._chain = list(entries)
        self.invalidate()

    @property
    def own_identity(self) -> "IdentityConfig | None":
        return None if self.primary else self._identity

    @property
    def identity(self) -> IdentityConfig:
        """The identity defaults for requests on this CA (falls back to ``[identity]``)."""
        if self.primary or self._identity is None:
            return self._config.identity
        return self._identity

    @property
    def directory_url(self) -> str:
        """The ACME directory URL (``base_url`` of an ACME profile)."""
        return self.ca.base_url

    @property
    def config(self) -> "Config":
        return self._config

    @property
    def csr(self) -> CSRConfig:
        return self._config.csr

    # -- trust ---------------------------------------------------------------
    @property
    def bundle(self) -> ChainBundle:
        if self.primary:
            return self._config.bundle
        if self._bundle is None:
            self._bundle = load_chain_entries(
                self._chain, self._config.directory, self._config.warnings, where_prefix=f"cas.{self._name}.chain"
            )
        return self._bundle

    def invalidate(self) -> None:
        self._bundle = None
        if self.primary:
            self._config.invalidate_chain_cache()

    def tls_trust_pem(self) -> str:
        if self.ca.tls_trust in ("chain", "both") and self.bundle.anchors:
            return self.bundle.anchor_pem()
        return ""

    def use_system_trust(self) -> bool:
        return self.ca.tls_trust in ("system", "both")

    def contact_emails(self) -> "list[str]":
        return list(self.acme.contact) or ([self.identity.email] if self.identity.email else [])

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CAProfile(name={self.name!r}, kind={self.kind!r}, primary={self.primary})"

    def as_dict(self) -> dict:
        data: "dict[str, Any]" = {
            "name": self.name,
            "kind": self.kind,
            "display_name": self.display_name,
            "primary": self.primary,
            "base_url": self.ca.base_url,
            "tls_trust": self.ca.tls_trust,
            "tls_verify": self.ca.tls_verify,
        }
        if self.kind == "acme":
            data["acme"] = {
                "contact": self.contact_emails(),
                "terms_agreed": self.acme.terms_agreed,
                "eab_kid": self.acme.eab_kid,
                "challenge": self.acme.challenge,
                "http_mode": self.acme.http_mode,
                "http_port": self.acme.http_port,
                "webroot": self.acme.webroot,
                "dns_hook": self.acme.dns_hook,
                "account_key": self.acme.account_key,
            }
        if not self.primary:
            data["chain"] = [
                {"label": e.label, "file": e.file, "sha256": e.sha256, "anchor": e.anchor, "pem": "<inline>" if e.pem else None}
                for e in self._chain
            ]
        return data


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------


def _expect_bool(table: dict, key: str, default: bool, where: str) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key}: expected a boolean, got {type(value).__name__}")
    return value


def _expect_list(table: dict, key: str, default: "list[str]", where: str) -> "list[str]":
    value = table.get(key, default)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}.{key}: expected a list of strings")
    return list(value)


def _section(data: dict, key: str, where: str) -> dict:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: expected a table")
    return value


class Config:
    """A loaded, validated pyCertWiz configuration."""

    def __init__(
        self,
        path: Path,
        profile: str,
        ca: CAConfig,
        identity: IdentityConfig,
        keys: KeyConfig,
        csr: CSRConfig,
        p12: P12Config,
        paths: PathsConfig,
        secrets: SecretConfig,
        chain: "list[ChainEntry]",
        warnings: "list[str] | None" = None,
        *,
        default_ca: str = "",
        extra_cas: "dict[str, CAProfile] | None" = None,
        keystores: "list[KeystoreLink] | None" = None,
    ):
        self.path = path
        self.profile = profile
        self.ca = ca
        self.identity = identity
        self.keys = keys
        self.csr = csr
        self.p12 = p12
        self.paths = paths
        self.secrets = secrets
        self.chain = chain
        self.warnings = warnings or []
        self._bundle: "ChainBundle | None" = None
        self._default_ca = default_ca
        self.primary_profile = CAProfile(self, ca.name, kind="ukca", primary=True)
        self.extra_cas: "dict[str, CAProfile]" = {}
        for name, item in (extra_cas or {}).items():
            item._config = self
            self.extra_cas[name] = item
        self.keystores: "list[KeystoreLink]" = list(keystores or [])

    def keystore(self, name: str) -> KeystoreLink:
        for link in self.keystores:
            if link.name == name:
                return link
        raise ConfigError(f"no keystore called '{name}' is linked (see 'pycert keystore list')")

    # -- CA profiles -------------------------------------------------------
    @property
    def default_ca(self) -> str:
        return self._default_ca or self.ca.name

    @default_ca.setter
    def default_ca(self, value: str) -> None:
        self._default_ca = value

    @property
    def cas(self) -> "dict[str, CAProfile]":
        """Every CA profile, primary first."""
        result = {self.primary_profile.name: self.primary_profile}
        result.update(self.extra_cas)
        return result

    def profile_for(self, name: "str | None" = "") -> CAProfile:
        """The CA profile called *name*; an empty name means the primary CA."""
        if not name:
            return self.primary_profile
        profiles = self.cas
        if name in profiles:
            return profiles[name]
        raise ConfigError(
            f"no CA profile called '{name}' is configured (known: {', '.join(profiles)}); "
            "see 'pycert ca list'"
        )

    def default_profile(self) -> CAProfile:
        return self.profile_for(self.default_ca)

    def add_ca(self, profile: CAProfile) -> CAProfile:
        if profile.name in self.cas:
            raise ConfigError(f"a CA profile called '{profile.name}' already exists")
        profile._config = self
        self.extra_cas[profile.name] = profile
        return profile

    def remove_ca(self, name: str) -> None:
        if name == self.primary_profile.name:
            raise ConfigError("the primary CA ([ca]) cannot be removed; edit it instead")
        if name not in self.extra_cas:
            raise ConfigError(f"no CA profile called '{name}' is configured")
        del self.extra_cas[name]
        if self._default_ca == name:
            self._default_ca = ""

    # -- paths -------------------------------------------------------------
    @property
    def directory(self) -> Path:
        return self.path.parent

    @property
    def data_dir(self) -> Path:
        return ensure_dir(_expand_path(self.paths.data_dir or default_data_dir()))

    def resolve(self, value: str) -> Path:
        path = Path(os.path.expandvars(os.path.expanduser(value)))
        return path if path.is_absolute() else (self.directory / path)

    # -- chain -------------------------------------------------------------
    @property
    def bundle(self) -> ChainBundle:
        if self._bundle is None:
            self._bundle = self.load_chain()
        return self._bundle

    def load_chain(self) -> ChainBundle:
        bundle = load_chain_entries(self.chain, self.directory, self.warnings)
        if not bundle.certificates:
            self.warnings.append(
                "no CA chain certificates are configured; TLS will use the system trust store "
                "and chain validation will rely on AIA fetching"
            )
        return bundle

    def tls_trust_pem(self) -> str:
        """PEM used to verify the primary CA server's TLS certificate."""
        return self.primary_profile.tls_trust_pem()

    def use_system_trust(self) -> bool:
        return self.ca.tls_trust in ("system", "both")

    # -- persistence -------------------------------------------------------
    def save(self) -> None:
        write_config(self.path, self)

    def invalidate_chain_cache(self) -> None:
        self._bundle = None
        for profile in self.extra_cas.values():
            profile._bundle = None

    def set(self, dotted: str, value: Any) -> None:
        """Set a value using a dotted key (used by ``pycert config set`` and the GUI).

        ``cas.<name>.<key>`` addresses an additional CA profile: keys of
        ``[ca]`` (``cas.x.timeout``), its ACME settings (``cas.x.acme.http_port``
        or the short form ``cas.x.http_port``) and ``display_name``.
        """
        parts = dotted.split(".")
        if dotted == "default_ca":
            if value not in self.cas:
                raise ConfigError(f"default_ca: no CA profile called '{value}'")
            self._default_ca = str(value)
            return
        target: Any = self
        if parts[0] == "cas" and len(parts) >= 3:
            profile = self.extra_cas.get(parts[1])
            if profile is None:
                raise ConfigError(f"unknown setting: {dotted} (no CA profile '{parts[1]}')")
            if parts[2] == "display_name" and len(parts) == 3:
                profile.display_name = str(value)
                return
            rest = parts[2:]
            if rest[0] == "acme":
                target, rest = profile.acme, rest[1:]
            elif rest[0] == "identity":
                if profile._identity is None:
                    profile._identity = IdentityConfig(**vars(self.identity))
                target, rest = profile._identity, rest[1:]
            elif hasattr(profile.acme, rest[0]) and not hasattr(profile.ca, rest[0]):
                target = profile.acme
            else:
                target = profile.ca
            parts = rest
        for part in parts[:-1]:
            if not hasattr(target, part):
                raise ConfigError(f"unknown setting: {dotted}")
            target = getattr(target, part)
        key = parts[-1]
        if not hasattr(target, key) or isinstance(getattr(type(target), key, None), property):
            raise ConfigError(f"unknown setting: {dotted}")
        expected = type(getattr(target, key))
        try:
            if expected is bool:
                if isinstance(value, str):
                    value = value.lower() in ("1", "true", "yes", "on")
            elif expected is int and isinstance(value, str):
                value = int(value)
            elif expected is float and isinstance(value, str):
                value = float(value)
            elif expected is list:
                value = _parse_list_value(dotted, value)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{dotted}: {exc}") from exc
        if expected is float and isinstance(value, int) and not isinstance(value, bool):
            value = float(value)
        if expected is not str and not isinstance(value, expected) and expected is not bool:
            raise ConfigError(f"{dotted}: expected {expected.__name__}")
        setattr(target, key, value)
        self.invalidate_chain_cache()

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "profile": self.profile,
            "default_ca": self.default_ca,
            "ca": {
                "name": self.ca.name,
                "display_name": self.ca.display_name,
                "base_url": self.ca.base_url,
                "version_string": self.ca.version_string,
                "user_agent": self.ca.user_agent,
                "timeout": self.ca.timeout,
                "connect_timeout": self.ca.connect_timeout,
                "deadline": self.ca.deadline,
                "dns_timeout": self.ca.dns_timeout,
                "retries": self.ca.retries,
                "max_redirects": self.ca.max_redirects,
                "max_body_bytes": self.ca.max_body_bytes,
                "max_header_bytes": self.ca.max_header_bytes,
                "backoff_base": self.ca.backoff_base,
                "backoff_cap": self.ca.backoff_cap,
                "tls_verify": self.ca.tls_verify,
                "tls_trust": self.ca.tls_trust,
                "tls_pin_sha256": self.ca.tls_pin_sha256,
                "allow_plaintext": self.ca.allow_plaintext,
                "allow_sha1": self.ca.allow_sha1,
                "endpoints": {
                    "csr": self.ca.endpoints.csr,
                    "bulk": self.ca.endpoints.bulk,
                    "lookup": self.ca.endpoints.lookup,
                    "certificate": self.ca.endpoints.certificate,
                    "revoke": self.ca.endpoints.revoke,
                    "ping": self.ca.endpoints.ping,
                    "info": self.ca.endpoints.info,
                    "motd": self.ca.endpoints.motd,
                },
            },
            "cas": {name: profile.as_dict() for name, profile in self.cas.items()},
            "keystores": [dict(vars(link)) for link in self.keystores],
            "identity": {
                "c": self.identity.c,
                "o": self.identity.o,
                "ou": self.identity.ou,
                "l": self.identity.l,
                "st": self.identity.st,
                "email": self.identity.email,
                "ra": self.identity.ra,
            },
            "keys": {
                "algorithm": self.keys.algorithm,
                "rsa_bits": self.keys.rsa_bits,
                "ec_curve": self.keys.ec_curve,
            },
            "csr": {
                "hash": self.csr.hash,
                "extensions": self.csr.extensions,
                "pin_hash": self.csr.pin_hash,
            },
            "p12": {
                "filename_template": self.p12.filename_template,
                "friendly_name": self.p12.friendly_name,
                "export_dir": self.p12.export_dir,
                "include_chain": self.p12.include_chain,
            },
            "paths": {"data_dir": str(self.data_dir)},
            "secrets": {
                "backend": self.secrets.backend,
                "service": self.secrets.service,
                "account": self.secrets.account,
                "key_account": self.secrets.key_account,
                "file": self.secrets.file,
                "command": self.secrets.command,
                "command_timeout": self.secrets.command_timeout,
                "env_var": self.secrets.env_var,
            },
            "chain": [
                {
                    "label": entry.label,
                    "file": entry.file,
                    "sha256": entry.sha256,
                    "anchor": entry.anchor,
                    "pem": "<inline>" if entry.pem else None,
                }
                for entry in self.chain
            ],
            "warnings": self.warnings,
        }


def _parse_list_value(key: str, value) -> "list[str]":
    """Accept a list, a JSON array or a comma-separated string for list settings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            import json

            try:
                parsed = json.loads(text)
            except ValueError as exc:
                raise ConfigError(f"{key}: invalid JSON list: {exc}") from exc
            if not isinstance(parsed, list):
                raise ConfigError(f"{key}: expected a list")  # pragma: no cover - defensive
            return [str(item) for item in parsed]
        return [item.strip().strip("'\"") for item in text.split(",") if item.strip()]
    raise ConfigError(f"{key}: expected a list")


def _expand_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value)))


def _get_float(table: dict, key: str, default: float, where: str) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}.{key}: expected a number")
    return float(value)


def _get_int(table: dict, key: str, default: int, where: str) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}.{key}: expected an integer")
    return value


def _get_str(table: dict, key: str, default: str, where: str) -> str:
    value = table.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"{where}.{key}: expected a string")
    return value


def default_data_dir() -> str:
    override = os.environ.get("PYCERT_DATA_DIR")
    if override:
        return override
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return str(Path(xdg) / "pycert")
    return str(Path.home() / ".local" / "share" / "pycert")


def default_config_paths() -> "list[Path]":
    """Where pyCertWiz looks for a configuration, in order.

    The current working directory is deliberately *not* searched: a pycert.toml
    planted in an untrusted directory could point the tool at an attacker's CA
    or a ``command`` secret backend.  Use ``--config ./pycert.toml`` (or
    ``PYCERT_CONFIG``) when you want a project-local file.
    """
    paths = []
    env = os.environ.get("PYCERT_CONFIG")
    if env:
        paths.append(_expand_path(env))
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        paths.append(Path(xdg) / "pycert" / "pycert.toml")
    paths.append(Path.home() / ".config" / "pycert" / "pycert.toml")
    paths.append(Path.home() / ".pycert" / "config.toml")
    seen: "list[Path]" = []
    for candidate in paths:
        if candidate not in seen:
            seen.append(candidate)
    return seen


def find_config(explicit: "str | Path | None" = None) -> Path:
    if explicit:
        path = _expand_path(str(explicit))
        if not path.is_file():
            raise ConfigError(f"configuration file not found: {path}")
        return path
    for candidate in default_config_paths():
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(p) for p in default_config_paths())
    raise ConfigError(f"no configuration file found.\nSearched: {searched}\nRun 'pycert init' to create one.")


def _parse_ca_table(ca_data: dict, where: str, *, name: str, display_name: str, tls_trust: str = "chain") -> CAConfig:
    endpoints_data = _section(ca_data, "endpoints", f"{where}.endpoints")
    ewhere = f"{where}.endpoints"
    return CAConfig(
        base_url=_get_str(ca_data, "base_url", DEFAULT_BASE_URL, where),
        version_string=_get_str(ca_data, "version_string", DEFAULT_VERSION_STRING, where),
        user_agent=_get_str(ca_data, "user_agent", DEFAULT_USER_AGENT, where),
        timeout=_get_float(ca_data, "timeout", 30.0, where),
        connect_timeout=_get_float(ca_data, "connect_timeout", 10.0, where),
        deadline=_get_float(ca_data, "deadline", 90.0, where),
        dns_timeout=_get_float(ca_data, "dns_timeout", 10.0, where),
        retries=_get_int(ca_data, "retries", 2, where),
        max_redirects=_get_int(ca_data, "max_redirects", 2, where),
        max_body_bytes=_get_int(ca_data, "max_body_bytes", 8 * 1024 * 1024, where),
        max_header_bytes=_get_int(ca_data, "max_header_bytes", 128 * 1024, where),
        backoff_base=_get_float(ca_data, "backoff_base", 0.4, where),
        backoff_cap=_get_float(ca_data, "backoff_cap", 8.0, where),
        tls_verify=_expect_bool(ca_data, "tls_verify", True, where),
        tls_trust=_get_str(ca_data, "tls_trust", tls_trust, where),
        tls_pin_sha256=_expect_list(ca_data, "tls_pin_sha256", [], where),
        allow_plaintext=_expect_bool(ca_data, "allow_plaintext", False, where),
        allow_sha1=_expect_bool(ca_data, "allow_sha1", False, where),
        endpoints=Endpoints(
            csr=_get_str(endpoints_data, "csr", "/CSR", ewhere),
            bulk=_get_str(endpoints_data, "bulk", "/CSRs", ewhere),
            lookup=_get_str(endpoints_data, "lookup", "/resources/resource/publickey/pk", ewhere),
            certificate=_get_str(endpoints_data, "certificate", "/certificate", ewhere),
            revoke=_get_str(endpoints_data, "revoke", "/revoke", ewhere),
            ping=_get_str(endpoints_data, "ping", "/pingservice", ewhere),
            info=_get_str(endpoints_data, "info", "/CA", ewhere),
            motd=_get_str(endpoints_data, "motd", "/CA/motd/text", ewhere),
        ),
        name=name,
        display_name=display_name,
    )


def _parse_identity(id_data: dict, where: str, defaults: "IdentityConfig | None" = None) -> IdentityConfig:
    base = defaults or IdentityConfig()
    return IdentityConfig(
        c=_get_str(id_data, "c", base.c, where),
        o=_get_str(id_data, "o", base.o, where),
        ou=_get_str(id_data, "ou", base.ou, where),
        l=_get_str(id_data, "l", base.l, where),
        st=_get_str(id_data, "st", base.st, where),
        email=_get_str(id_data, "email", base.email, where),
        ra=_get_str(id_data, "ra", base.ra, where),
    )


def _parse_chain_entries(raw_entries: Any, where_prefix: str) -> "list[ChainEntry]":
    if not isinstance(raw_entries, list):
        raise ConfigError(f"{where_prefix}: expected an array of tables")
    entries: "list[ChainEntry]" = []
    for index, raw in enumerate(raw_entries):
        where = f"{where_prefix}[{index}]"
        if not isinstance(raw, dict):
            raise ConfigError(f"{where}: expected a table")
        entry = ChainEntry(
            label=_get_str(raw, "label", "", where),
            file=_get_str(raw, "file", "", where) or None,
            pem=_get_str(raw, "pem", "", where) or None,
            sha256=_get_str(raw, "sha256", "", where) or None,
            anchor=_expect_bool(raw, "anchor", True, where),
        )
        if entry.file is None and entry.pem is None:
            raise ConfigError(f"{where}: either 'file' or 'pem' is required")
        if entry.file and entry.pem:
            raise ConfigError(f"{where}: use either 'file' or 'pem', not both")
        entries.append(entry)
    return entries


def _parse_acme(data: dict, where: str) -> ACMEConfig:
    defaults = ACMEConfig()
    return ACMEConfig(
        contact=_expect_list(data, "contact", [], where),
        terms_agreed=_expect_bool(data, "terms_agreed", False, where),
        eab_kid=_get_str(data, "eab_kid", "", where),
        eab_hmac_env=_get_str(data, "eab_hmac_env", "", where),
        account_key=_get_str(data, "account_key", defaults.account_key, where).lower(),
        challenge=_get_str(data, "challenge", defaults.challenge, where).lower(),
        http_mode=_get_str(data, "http_mode", defaults.http_mode, where).lower(),
        http_port=_get_int(data, "http_port", defaults.http_port, where),
        http_bind=_get_str(data, "http_bind", "", where),
        webroot=_get_str(data, "webroot", "", where),
        dns_hook=_get_str(data, "dns_hook", "", where),
        dns_propagation_seconds=_get_float(data, "dns_propagation_seconds", 0.0, where),
        validation_timeout=_get_float(data, "validation_timeout", defaults.validation_timeout, where),
        poll_interval=_get_float(data, "poll_interval", defaults.poll_interval, where),
    )


# Keys of a [cas.<name>] table that are not CAConfig settings ([cas.<name>.endpoints] is one).
_PROFILE_META_KEYS = {"kind", "display_name", "identity", "chain", "directory"}
_ACME_KEYS = set(ACMEConfig.__dataclass_fields__)


def _parse_extra_ca(name: str, data: Any, identity: IdentityConfig) -> CAProfile:
    where = f"cas.{name}"
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a table")
    if not PROFILE_NAME_RE.match(name):
        raise ConfigError(
            f"{where}: CA profile names must be lower-case letters, digits, '.', '-' or '_' (got {name!r})"
        )
    kind = _get_str(data, "kind", "ukca", where).lower()
    display_name = _get_str(data, "display_name", "", where)
    if kind == "acme":
        directory = _get_str(data, "directory", "", where) or _get_str(data, "base_url", "", where)
        if not directory:
            raise ConfigError(f"{where}.directory: the ACME directory URL is required")
        ca_table = {k: v for k, v in data.items() if k not in _ACME_KEYS and k not in _PROFILE_META_KEYS}
        ca_table["base_url"] = directory
        ca = _parse_ca_table(ca_table, where, name=name, display_name=display_name, tls_trust="system")
        acme = _parse_acme({k: v for k, v in data.items() if k in _ACME_KEYS}, where)
        own_identity = None
    else:
        ca_table = {k: v for k, v in data.items() if k not in _PROFILE_META_KEYS}
        ca = _parse_ca_table(ca_table, where, name=name, display_name=display_name)
        acme = ACMEConfig()
        own_identity = (
            _parse_identity(_section(data, "identity", f"{where}.identity"), f"{where}.identity", identity)
            if "identity" in data
            else None
        )
    chain = _parse_chain_entries(data.get("chain", []), f"{where}.chain")
    return CAProfile(
        None,  # type: ignore[arg-type] - attached by Config
        name,
        kind=kind,
        display_name=display_name,
        ca=ca,
        chain=chain,
        identity=own_identity,
        acme=acme,
    )


def load_config(explicit: "str | Path | None" = None) -> Config:
    path = find_config(explicit)
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path}: configuration file is larger than {MAX_CONFIG_BYTES} bytes")
        data = toml_loads(path.read_text(encoding="utf-8"))
    except TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except RecursionError as exc:
        raise ConfigError(f"{path}: invalid TOML: values are nested too deeply") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    warnings: "list[str]" = []
    version = data.get("version", 1)
    if version not in SUPPORTED_CONFIG_VERSIONS:
        warnings.append(f"configuration version {version} is not the supported version {CONFIG_VERSION}")
    profile = str(data.get("profile", "default"))

    ca_data = _section(data, "ca", "ca")
    ca = _parse_ca_table(
        ca_data,
        "ca",
        name=_get_str(ca_data, "name", DEFAULT_CA_NAME, "ca") or DEFAULT_CA_NAME,
        display_name=_get_str(ca_data, "display_name", DEFAULT_CA_DISPLAY_NAME, "ca"),
    )

    identity = _parse_identity(_section(data, "identity", "identity"), "identity")

    keys_data = _section(data, "keys", "keys")
    keys = KeyConfig(
        algorithm=_get_str(keys_data, "algorithm", "rsa", "keys").lower(),
        rsa_bits=_get_int(keys_data, "rsa_bits", 3072, "keys"),
        ec_curve=_get_str(keys_data, "ec_curve", "P-256", "keys"),
    )

    csr_data = _section(data, "csr", "csr")
    csr = CSRConfig(
        hash=_get_str(csr_data, "hash", "sha256", "csr").lower(),
        extensions=_expect_list(csr_data, "extensions", ["san"], "csr"),
        pin_hash=_get_str(csr_data, "pin_hash", "sha1", "csr").lower(),
    )

    p12_data = _section(data, "p12", "p12")
    p12 = P12Config(
        filename_template=_get_str(p12_data, "filename_template", "{cn}.p12", "p12"),
        friendly_name=_get_str(p12_data, "friendly_name", "{cn}", "p12"),
        export_dir=_get_str(p12_data, "export_dir", "", "p12"),
        include_chain=_expect_bool(p12_data, "include_chain", True, "p12"),
    )

    paths_data = _section(data, "paths", "paths")
    paths = PathsConfig(data_dir=_get_str(paths_data, "data_dir", "", "paths"))

    secrets_data = _section(data, "secrets", "secrets")
    secrets = SecretConfig(
        backend=_get_str(secrets_data, "backend", "auto", "secrets").lower(),
        service=_get_str(secrets_data, "service", "pyCert", "secrets"),
        account=_get_str(secrets_data, "account", "default", "secrets"),
        key_account=_get_str(secrets_data, "key_account", "", "secrets"),
        file=_get_str(secrets_data, "file", "", "secrets"),
        command=_get_str(secrets_data, "command", "", "secrets"),
        command_timeout=_get_float(secrets_data, "command_timeout", 15.0, "secrets"),
        env_var=_get_str(secrets_data, "env_var", "PYCERT_P12_PASSPHRASE", "secrets"),
    )

    chain_data = _section(data, "chain", "chain")
    entries = _parse_chain_entries(chain_data.get("certificates", []), "chain.certificates")

    extra: "dict[str, CAProfile]" = {}
    for name, table in _section(data, "cas", "cas").items():
        if name == ca.name:
            raise ConfigError(f"cas.{name}: this name is already used by the primary CA ([ca] name)")
        extra[name] = _parse_extra_ca(name, table, identity)

    raw_keystores = data.get("keystores", [])
    if not isinstance(raw_keystores, list):
        raise ConfigError("keystores: expected an array of tables ([[keystores]])")
    links: "list[KeystoreLink]" = []
    for index, raw in enumerate(raw_keystores):
        where = f"keystores[{index}]"
        if not isinstance(raw, dict):
            raise ConfigError(f"{where}: expected a table")
        links.append(
            KeystoreLink(
                name=_get_str(raw, "name", "", where),
                path=_get_str(raw, "path", "", where),
                ca=_get_str(raw, "ca", "", where),
                auto_import=_expect_bool(raw, "auto_import", True, where),
                write_back=_expect_bool(raw, "write_back", True, where),
            )
        )

    config = Config(
        path=path,
        profile=profile,
        ca=ca,
        identity=identity,
        keys=keys,
        csr=csr,
        p12=p12,
        paths=paths,
        secrets=secrets,
        chain=entries,
        warnings=warnings,
        default_ca=_get_str(data, "default_ca", "", "default_ca"),
        extra_cas=extra,
        keystores=links,
    )
    _validate(config)
    return config


def validate_config(config: Config) -> None:
    """Validate *config* in place, raising ConfigError on a fatal problem."""
    _validate(config)


def _validate_ca(ca: CAConfig, where: str, warnings: "list[str]") -> None:
    if ca.tls_trust not in ("chain", "system", "both"):
        raise ConfigError(f"{where}.tls_trust must be 'chain', 'system' or 'both'")
    if not 0 < ca.timeout <= 300:
        raise ConfigError(f"{where}.timeout must be between 0 and 300 seconds")
    if not 0 < ca.connect_timeout <= 300:
        raise ConfigError(f"{where}.connect_timeout must be between 0 and 300 seconds")
    if not 0 < ca.deadline <= 3600:
        raise ConfigError(f"{where}.deadline must be between 0 and 3600 seconds")
    if not 0 < ca.dns_timeout <= 120:
        raise ConfigError(f"{where}.dns_timeout must be between 0 and 120 seconds")
    if not 0 <= ca.retries <= 10:
        raise ConfigError(f"{where}.retries must be between 0 and 10")
    if not 0 <= ca.max_redirects <= 10:
        raise ConfigError(f"{where}.max_redirects must be between 0 and 10")
    if not 1024 <= ca.max_body_bytes <= 64 * 1024 * 1024:
        raise ConfigError(f"{where}.max_body_bytes must be between 1 KiB and 64 MiB")
    if not 1024 <= ca.max_header_bytes <= 1024 * 1024:
        raise ConfigError(f"{where}.max_header_bytes must be between 1 KiB and 1 MiB")
    if not 0 <= ca.backoff_base <= 10:
        raise ConfigError(f"{where}.backoff_base must be between 0 and 10 seconds")
    if not 0 < ca.backoff_cap <= 60:
        raise ConfigError(f"{where}.backoff_cap must be between 0 and 60 seconds")
    if ca.deadline < ca.timeout:
        warnings.append(f"{where}.deadline is smaller than {where}.timeout; a slow response may hit the deadline first")
    if not ca.tls_verify:
        warnings.append(f"{where}.tls_verify = false: the CA server's TLS certificate will NOT be verified")
    if ca.allow_plaintext:
        warnings.append(f"{where}.allow_plaintext is enabled: HTTP traffic is not confidential or authenticated")
    if ca.base_url.startswith("http://") and not ca.allow_plaintext:
        raise ConfigError(
            f"{where}.base_url uses http:// but {where}.allow_plaintext is false.\n"
            f"Use https:// or explicitly set {where}.allow_plaintext = true."
        )
    if not re.match(r"^https?://[^/\s]+", ca.base_url):
        raise ConfigError(f"{where}.base_url is not a valid URL: {ca.base_url!r}")
    for value in ca.tls_pin_sha256:
        if len(normalize_fingerprint(value)) != 64:
            raise ConfigError(f"{where}.tls_pin_sha256: not a SHA-256 fingerprint: {value!r}")


def _validate_acme(profile: CAProfile) -> None:
    where = f"cas.{profile.name}"
    acme = profile.acme
    if acme.challenge not in ACME_CHALLENGES:
        raise ConfigError(f"{where}.challenge must be one of {', '.join(ACME_CHALLENGES)}")
    if acme.http_mode not in ACME_HTTP_MODES:
        raise ConfigError(f"{where}.http_mode must be one of {', '.join(ACME_HTTP_MODES)}")
    if acme.account_key not in ACME_ACCOUNT_KEYS:
        raise ConfigError(f"{where}.account_key must be 'ec' or 'rsa'")
    if not 1 <= acme.http_port <= 65535:
        raise ConfigError(f"{where}.http_port must be between 1 and 65535")
    if acme.challenge == "http-01" and acme.http_mode == "webroot" and not acme.webroot:
        raise ConfigError(f"{where}.webroot is required when http_mode = 'webroot'")
    if not 0 <= acme.dns_propagation_seconds <= 3600:
        raise ConfigError(f"{where}.dns_propagation_seconds must be between 0 and 3600")
    if not 1 <= acme.validation_timeout <= 86400:
        raise ConfigError(f"{where}.validation_timeout must be between 1 and 86400 seconds")
    if not 0.1 <= acme.poll_interval <= 600:
        raise ConfigError(f"{where}.poll_interval must be between 0.1 and 600 seconds")
    for contact in acme.contact:
        if "@" not in contact or any(ch in contact for ch in " \t\r\n,"):
            raise ConfigError(f"{where}.contact: not an e-mail address: {contact!r}")
    if acme.eab_hmac_env and not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", acme.eab_hmac_env):
        raise ConfigError(f"{where}.eab_hmac_env must be an environment variable name")


def _validate(config: Config) -> None:
    _validate_ca(config.ca, "ca", config.warnings)
    if not PROFILE_NAME_RE.match(config.ca.name):
        raise ConfigError(
            "ca.name must be lower-case letters, digits, '.', '-' or '_' (e.g. 'uk-escience')"
        )
    if len(config.identity.c) != 2:
        raise ConfigError("identity.c must be a two-letter country code")
    if config.keys.algorithm not in ("rsa", "ec"):
        raise ConfigError("keys.algorithm must be 'rsa' or 'ec'")
    if config.keys.rsa_bits not in (2048, 3072, 4096, 8192):
        raise ConfigError("keys.rsa_bits must be 2048, 3072, 4096 or 8192")
    if config.keys.ec_curve not in ("P-256", "P-384", "P-521"):
        raise ConfigError("keys.ec_curve must be P-256, P-384 or P-521")
    if config.csr.hash not in ("sha256", "sha384", "sha512"):
        raise ConfigError("csr.hash must be sha256, sha384 or sha512")
    if config.csr.pin_hash not in ("sha1", "sha256"):
        raise ConfigError("csr.pin_hash must be sha1 or sha256")
    if config.csr.pin_hash == "sha256":
        config.warnings.append(
            "csr.pin_hash = sha256: the UK e-Science CA server hashes PINs with SHA-1; "
            "the RA will not be able to verify a SHA-256 PIN"
        )
    unknown_ext = set(config.csr.extensions) - {"san", "key_usage", "extended_key_usage", "basic_constraints"}
    if unknown_ext:
        raise ConfigError(f"csr.extensions contains unknown values: {sorted(unknown_ext)}")
    if not any(key in config.p12.filename_template for key in ("{cn}", "{alias}")):
        raise ConfigError(
            "p12.filename_template must contain {cn} or {alias} so certificates cannot "
            "silently overwrite each other (use 'pycert export --out' for a fixed name)"
        )
    from .secrets_store import BACKENDS

    if config.secrets.backend not in BACKENDS:
        raise ConfigError("secrets.backend must be one of " + ", ".join(BACKENDS))
    if config.secrets.backend == "command" and not config.secrets.command:
        raise ConfigError("secrets.command is required when secrets.backend = 'command'")
    if not 0 < config.secrets.command_timeout <= 300:
        raise ConfigError("secrets.command_timeout must be between 0 and 300 seconds")

    from .providers import known_kinds

    kinds = known_kinds()
    for name, profile in config.extra_cas.items():
        where = f"cas.{name}"
        if profile.kind not in kinds:
            raise ConfigError(
                f"{where}.kind: unknown CA kind {profile.kind!r} (available: {', '.join(sorted(kinds))})"
            )
        _validate_ca(profile.ca, where, config.warnings)
        if profile.kind == "acme":
            _validate_acme(profile)
        if profile.own_identity is not None and len(profile.own_identity.c) != 2:
            raise ConfigError(f"{where}.identity.c must be a two-letter country code")
    if config.default_ca not in config.cas:
        raise ConfigError(
            f"default_ca: no CA profile called '{config.default_ca}' (known: {', '.join(config.cas)})"
        )
    names: "set[str]" = set()
    for index, link in enumerate(config.keystores):
        where = f"keystores[{index}]"
        if not PROFILE_NAME_RE.match(link.name):
            raise ConfigError(f"{where}.name must be lower-case letters, digits, '.', '-' or '_' (got {link.name!r})")
        if link.name in names:
            raise ConfigError(f"{where}.name: a keystore called '{link.name}' is already linked")
        names.add(link.name)
        if not link.path:
            raise ConfigError(f"{where}.path: the keystore file is required")
        if link.ca and link.ca not in config.cas:
            raise ConfigError(f"{where}.ca: no CA profile called '{link.ca}'")
        if "password" in vars(link):  # pragma: no cover - guards against a future field
            raise ConfigError(f"{where}: keystore passphrases are never stored in the configuration")


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

_HEADER = """\
# pyCertWiz configuration - generated by 'pycert init'
#
# Review before use.  No secrets belong in this file: the PKCS#12 passphrase is
# kept in the OS secret store (or a 0600 file, or an external command), see
# [secrets] below.
#
# Documentation: docs/CONFIGURATION.md
"""


def _q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _toml_list(values: Sequence[str]) -> str:
    return "[" + ", ".join(_q(v) for v in values) + "]"


def _num(value: float) -> str:
    return repr(float(value))


def _render_ca_keys(lines: "list[str]", ca: CAConfig, *, defaults: "CAConfig | None" = None, full: bool = True) -> None:
    """Append ``key = value`` lines for a CAConfig (all keys, or only non-defaults)."""
    base = defaults or CAConfig()
    pairs = [
        ("version_string", _q(ca.version_string), ca.version_string != base.version_string),
        ("user_agent", _q(ca.user_agent), ca.user_agent != base.user_agent),
        ("timeout", _num(ca.timeout), ca.timeout != base.timeout),
        ("connect_timeout", _num(ca.connect_timeout), ca.connect_timeout != base.connect_timeout),
        ("deadline", _num(ca.deadline), ca.deadline != base.deadline),
        ("dns_timeout", _num(ca.dns_timeout), ca.dns_timeout != base.dns_timeout),
        ("retries", str(ca.retries), ca.retries != base.retries),
        ("max_redirects", str(ca.max_redirects), ca.max_redirects != base.max_redirects),
        ("max_body_bytes", str(ca.max_body_bytes), ca.max_body_bytes != base.max_body_bytes),
        ("max_header_bytes", str(ca.max_header_bytes), ca.max_header_bytes != base.max_header_bytes),
        ("backoff_base", _num(ca.backoff_base), ca.backoff_base != base.backoff_base),
        ("backoff_cap", _num(ca.backoff_cap), ca.backoff_cap != base.backoff_cap),
        ("tls_verify", str(ca.tls_verify).lower(), ca.tls_verify != base.tls_verify),
        ("tls_trust", _q(ca.tls_trust), ca.tls_trust != base.tls_trust),
        ("tls_pin_sha256", _toml_list(ca.tls_pin_sha256), bool(ca.tls_pin_sha256)),
        ("allow_plaintext", str(ca.allow_plaintext).lower(), ca.allow_plaintext != base.allow_plaintext),
        ("allow_sha1", str(ca.allow_sha1).lower(), ca.allow_sha1 != base.allow_sha1),
    ]
    for key, rendered, changed in pairs:
        if full or changed:
            lines.append(f"{key} = {rendered}")


def _render_endpoints(lines: "list[str]", header: str, endpoints: Endpoints, *, full: bool = True) -> None:
    base = Endpoints()
    changed = [(k, getattr(endpoints, k)) for k in vars(base) if getattr(endpoints, k) != getattr(base, k)]
    if not full and not changed:
        return
    lines.append("")
    lines.append(f"[{header}]")
    for key in vars(base):
        value = getattr(endpoints, key)
        if full or value != getattr(base, key):
            lines.append(f"{key} = {_q(value)}")


def _render_chain_entry(lines: "list[str]", header: str, entry: ChainEntry) -> None:
    lines.append("")
    lines.append(f"[[{header}]]")
    if entry.label:
        lines.append(f"label = {_q(entry.label)}")
    if entry.pem:
        lines.append("pem = '''")
        lines.append(entry.pem.strip())
        lines.append("'''")
    else:
        lines.append(f"file = {_q(entry.file or '')}")
    if entry.sha256:
        lines.append(f"sha256 = {_q(entry.sha256)}")
    if not entry.anchor:
        lines.append("anchor = false")


def _render_extra_ca(lines: "list[str]", profile: CAProfile, global_identity: IdentityConfig) -> None:
    name = profile.name
    lines.append("")
    lines.append(f"[cas.{name}]")
    lines.append(f"kind = {_q(profile.kind)}")
    if profile._display_name:
        lines.append(f"display_name = {_q(profile._display_name)}")
    if profile.kind == "acme":
        lines.append(f"directory = {_q(profile.ca.base_url)}")
        acme, base = profile.acme, ACMEConfig()
        lines.append(f"contact = {_toml_list(acme.contact)}")
        lines.append("# You must accept the CA's terms of service before an account can be registered.")
        lines.append(f"terms_agreed = {str(acme.terms_agreed).lower()}")
        lines.append("# External Account Binding: the HMAC key lives in the secret store ('pycert ca eab').")
        lines.append(f"eab_kid = {_q(acme.eab_kid)}")
        if acme.eab_hmac_env:
            lines.append(f"eab_hmac_env = {_q(acme.eab_hmac_env)}")
        lines.append(f"account_key = {_q(acme.account_key)}")
        lines.append("# http-01 (standalone listener or webroot) or dns-01 (hook command, or manual).")
        lines.append(f"challenge = {_q(acme.challenge)}")
        lines.append(f"http_mode = {_q(acme.http_mode)}")
        lines.append(f"http_port = {acme.http_port}")
        if acme.http_bind:
            lines.append(f"http_bind = {_q(acme.http_bind)}")
        lines.append(f"webroot = {_q(acme.webroot)}")
        lines.append(f"dns_hook = {_q(acme.dns_hook)}")
        if acme.dns_propagation_seconds != base.dns_propagation_seconds:
            lines.append(f"dns_propagation_seconds = {_num(acme.dns_propagation_seconds)}")
        if acme.validation_timeout != base.validation_timeout:
            lines.append(f"validation_timeout = {_num(acme.validation_timeout)}")
        if acme.poll_interval != base.poll_interval:
            lines.append(f"poll_interval = {_num(acme.poll_interval)}")
        _render_ca_keys(lines, profile.ca, defaults=CAConfig(tls_trust="system"), full=False)
    else:
        lines.append(f"base_url = {_q(profile.ca.base_url)}")
        _render_ca_keys(lines, profile.ca, full=False)
    _render_endpoints(lines, f"cas.{name}.endpoints", profile.ca.endpoints, full=False)
    identity = profile.own_identity
    if identity is not None:
        lines.append("")
        lines.append(f"[cas.{name}.identity]")
        for key in ("c", "o", "ou", "l", "st", "email", "ra"):
            value = getattr(identity, key)
            if value != getattr(global_identity, key) or key == "ra":
                lines.append(f"{key} = {_q(value)}")
    for entry in profile.chain:
        _render_chain_entry(lines, f"cas.{name}.chain", entry)


def render_config(config: Config, *, chain_comments: bool = True) -> str:
    lines: "list[str]" = [_HEADER]
    lines.append(f"version = {CONFIG_VERSION}")
    lines.append(f"profile = {_q(config.profile)}")
    lines.append("# CA profile used for new requests when --ca is not given ('pycert ca list').")
    lines.append(f"default_ca = {_q(config.default_ca)}")
    lines.append("")
    lines.append("[ca]")
    lines.append("# The primary CA: the UK e-Science CA (CertWizard protocol) by default.")
    lines.append(f"name = {_q(config.ca.name)}")
    lines.append(f"display_name = {_q(config.ca.display_name)}")
    lines.append(f"base_url = {_q(config.ca.base_url)}")
    lines.append("# Version string sent to the CA; it must match what the server expects.")
    lines.append(f"version_string = {_q(config.ca.version_string)}")
    lines.append(f"user_agent = {_q(config.ca.user_agent)}")
    lines.append(f"timeout = {config.ca.timeout!r}")
    lines.append("# Networking hardening: every request has a deadline; DNS and connect")
    lines.append("# attempts are bounded; only idempotent requests are retried.")
    lines.append(f"connect_timeout = {config.ca.connect_timeout!r}")
    lines.append(f"deadline = {config.ca.deadline!r}")
    lines.append(f"dns_timeout = {config.ca.dns_timeout!r}")
    lines.append(f"retries = {config.ca.retries}")
    lines.append(f"max_redirects = {config.ca.max_redirects}")
    lines.append(f"max_body_bytes = {config.ca.max_body_bytes}")
    lines.append(f"max_header_bytes = {config.ca.max_header_bytes}")
    lines.append(f"backoff_base = {config.ca.backoff_base!r}")
    lines.append(f"backoff_cap = {config.ca.backoff_cap!r}")
    lines.append("# Verify the server's TLS certificate. Never turn this off in production.")
    lines.append(f"tls_verify = {str(config.ca.tls_verify).lower()}")
    lines.append("# 'chain' uses the CA chain below as TLS trust anchors, 'system' uses the OS")
    lines.append("# trust store, 'both' accepts either.")
    lines.append(f"tls_trust = {_q(config.ca.tls_trust)}")
    lines.append("# Optional extra pin: SHA-256 of the server leaf certificate (defence in depth).")
    lines.append(f"tls_pin_sha256 = {_toml_list(config.ca.tls_pin_sha256)}")
    lines.append(f"allow_plaintext = {str(config.ca.allow_plaintext).lower()}")
    lines.append("# Accept SHA-1 signed certificates in the chain (historic roots only).")
    lines.append(f"allow_sha1 = {str(config.ca.allow_sha1).lower()}")
    lines.append("")
    lines.append("[ca.endpoints]")
    lines.append(f"csr = {_q(config.ca.endpoints.csr)}")
    lines.append(f"bulk = {_q(config.ca.endpoints.bulk)}")
    lines.append(f"lookup = {_q(config.ca.endpoints.lookup)}")
    lines.append(f"certificate = {_q(config.ca.endpoints.certificate)}")
    lines.append(f"revoke = {_q(config.ca.endpoints.revoke)}")
    lines.append(f"ping = {_q(config.ca.endpoints.ping)}")
    lines.append(f"info = {_q(config.ca.endpoints.info)}")
    lines.append(f"motd = {_q(config.ca.endpoints.motd)}")
    lines.append("")
    lines.append("[identity]")
    lines.append("# Organisation attributes used in the CSR subject (OpenCA expects this order).")
    lines.append(f"c = {_q(config.identity.c)}")
    lines.append(f"o = {_q(config.identity.o)}")
    lines.append(f"ou = {_q(config.identity.ou)}")
    lines.append(f"l = {_q(config.identity.l)}")
    if config.identity.st:
        lines.append(f"st = {_q(config.identity.st)}")
    lines.append("# Default e-mail address for requests (contact address, also SAN for user certs).")
    lines.append(f"email = {_q(config.identity.email)}")
    lines.append("# Default RA as 'OU L' (see 'pycert ras'); empty means the values above.")
    lines.append(f"ra = {_q(config.identity.ra)}")
    lines.append("")
    lines.append("[keys]")
    lines.append("# 'rsa' (2048/3072/4096) or 'ec' (P-256/P-384/P-521).")
    lines.append(f"algorithm = {_q(config.keys.algorithm)}")
    lines.append(f"rsa_bits = {config.keys.rsa_bits}")
    lines.append(f"ec_curve = {_q(config.keys.ec_curve)}")
    lines.append("")
    lines.append("[csr]")
    lines.append(f"hash = {_q(config.csr.hash)}")
    lines.append(f"extensions = {_toml_list(config.csr.extensions)}")
    lines.append("# The current CA hashes the PIN with SHA-1 before handing it to the RA;")
    lines.append("# changing this will break RA verification.")
    lines.append(f"pin_hash = {_q(config.csr.pin_hash)}")
    lines.append("")
    lines.append("[p12]")
    lines.append(f"filename_template = {_q(config.p12.filename_template)}")
    lines.append(f"friendly_name = {_q(config.p12.friendly_name)}")
    lines.append(f"export_dir = {_q(config.p12.export_dir)}")
    lines.append(f"include_chain = {str(config.p12.include_chain).lower()}")
    lines.append("")
    lines.append("[paths]")
    lines.append("# Private keys, CSRs, certificates and exported .p12 files live here.")
    lines.append(f"data_dir = {_q(config.paths.data_dir or default_data_dir())}")
    lines.append("")
    lines.append("[secrets]")
    lines.append("# Where the saved PKCS#12/key passphrase lives:")
    lines.append("#   auto | keychain (macOS) | secret-service (Linux) | keyring | file | command | env | prompt")
    lines.append(f"backend = {_q(config.secrets.backend)}")
    lines.append(f"service = {_q(config.secrets.service)}")
    lines.append(f"account = {_q(config.secrets.account)}")
    lines.append("# Leave key_account empty to use the same saved secret for the key at rest.")
    lines.append(f"key_account = {_q(config.secrets.key_account)}")
    lines.append(f"file = {_q(config.secrets.file)}")
    lines.append(f"command = {_q(config.secrets.command)}")
    lines.append("# Timeout for keychain/secret-tool/external command calls (seconds).")
    lines.append(f"command_timeout = {config.secrets.command_timeout!r}")
    lines.append(f"env_var = {_q(config.secrets.env_var)}")
    lines.append("")
    lines.append("[chain]")
    lines.append("# The CA chain used for path validation, TLS trust and the exported PKCS#12.")
    lines.append("# Each entry is a file path (relative to this file) or an inline 'pem' string,")
    lines.append("# optionally pinned with the SHA-256 fingerprint of the certificate.")
    for entry in config.chain:
        _render_chain_entry(lines, "chain.certificates", entry)
    for link in config.keystores:
        lines.append("")
        lines.append("[[keystores]]")
        lines.append("# A Java PKCS#12 keystore kept in step with pyCertWiz ('pycert keystore ...').")
        lines.append("# Its passphrase is never stored: pyCertWiz asks for it in each session.")
        lines.append(f"name = {_q(link.name)}")
        lines.append(f"path = {_q(link.path)}")
        if link.ca:
            lines.append(f"ca = {_q(link.ca)}")
        lines.append(f"auto_import = {str(link.auto_import).lower()}")
        lines.append(f"write_back = {str(link.write_back).lower()}")
    if config.extra_cas:
        lines.append("")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append("# Additional CA profiles ('pycert ca list').  kind = 'ukca' speaks the")
        lines.append("# CertWizard protocol; kind = 'acme' is an RFC 8555 ACME CA.")
        lines.append("# ---------------------------------------------------------------------------")
        for profile in config.extra_cas.values():
            _render_extra_ca(lines, profile, config.identity)
    lines.append("")
    return "\n".join(lines)


def write_config(path: Path, config: Config) -> Path:
    from .util import atomic_write

    path = Path(path)
    if not path.suffix:
        path = path / "pycert.toml"
    ensure_dir(path.parent, 0o755)
    text = render_config(config)
    # Round-trip check: never write a configuration that will not load.
    try:
        toml_loads(text)
    except TOMLDecodeError as exc:  # pragma: no cover - defensive
        raise ConfigError(f"internal error rendering configuration: {exc}") from exc
    atomic_write(path, text, mode=0o644)
    return path


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


_BUNDLED_LABELS = {
    "escience-root.pem": "UK e-Science Root (2007)",
    "escience-2b.pem": "UK e-Science CA 2B",
    "escience-root-2026.pem": "UK e-Science Root 2026",
    "escience-3b.pem": "UK e-Science CA 3B",
}


def bundle_chain_entries() -> "list[ChainEntry]":
    """Chain entries pointing at the bundled certificates, with pins."""
    return [
        ChainEntry(label=_BUNDLED_LABELS.get(name, name), file=f"chain/{name}", sha256=pin)
        for name, pin in bundled.PINNED.items()
    ]


def new_acme_profile(
    name: str,
    directory: str,
    *,
    display_name: str = "",
    contact: "Sequence[str]" = (),
    eab_kid: str = "",
    challenge: str = "http-01",
    http_mode: str = "standalone",
    webroot: str = "",
    http_port: int = 80,
    dns_hook: str = "",
    terms_agreed: bool = False,
    tls_trust: str = "system",
) -> CAProfile:
    """Build an ACME CA profile (validate with :func:`validate_config` after adding it)."""
    if not PROFILE_NAME_RE.match(name):
        raise ConfigError(f"invalid CA profile name {name!r}: use lower-case letters, digits, '.', '-' or '_'")
    ca = CAConfig(base_url=directory, tls_trust=tls_trust, name=name, display_name=display_name)
    acme = ACMEConfig(
        contact=list(contact),
        terms_agreed=terms_agreed,
        eab_kid=eab_kid,
        challenge=challenge,
        http_mode=http_mode,
        webroot=webroot,
        http_port=http_port,
        dns_hook=dns_hook,
    )
    return CAProfile(None, name, kind="acme", display_name=display_name, ca=ca, acme=acme)  # type: ignore[arg-type]


def new_ukca_profile(
    name: str,
    base_url: str,
    *,
    display_name: str = "",
    chain: "Sequence[ChainEntry]" = (),
    tls_trust: str = "chain",
    identity: "IdentityConfig | None" = None,
) -> CAProfile:
    """Build an additional CertWizard-protocol CA profile."""
    if not PROFILE_NAME_RE.match(name):
        raise ConfigError(f"invalid CA profile name {name!r}: use lower-case letters, digits, '.', '-' or '_'")
    ca = CAConfig(base_url=base_url, tls_trust=tls_trust, name=name, display_name=display_name)
    return CAProfile(
        None,  # type: ignore[arg-type]
        name,
        kind="ukca",
        display_name=display_name,
        ca=ca,
        chain=list(chain),
        identity=identity,
    )


def init_config(directory: Path, profile: str = "default", *, copy_chain: bool = True) -> Config:
    """Create a new configuration directory with a chain checked against pins."""
    directory = ensure_dir(_expand_path(str(directory)), 0o700)
    if copy_chain:
        chain_dir = ensure_dir(directory / "chain", 0o755)
        for name in bundled.PINNED:
            source = bundled.path_for(name)
            target = chain_dir / name
            if not target.exists():
                target.write_bytes(source.read_bytes())
    config = Config(
        path=directory / "pycert.toml",
        profile=profile,
        ca=CAConfig(),
        identity=IdentityConfig(),
        keys=KeyConfig(),
        csr=CSRConfig(),
        p12=P12Config(),
        paths=PathsConfig(data_dir=default_data_dir()),
        secrets=SecretConfig(),
        chain=bundle_chain_entries() if copy_chain else [],
    )
    # Validate the chain before writing anything so 'init' cannot produce a
    # configuration that fails to load.
    config.load_chain()
    write_config(config.path, config)
    return config
