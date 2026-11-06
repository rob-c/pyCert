"""Configuration: TOML file, dataclasses, validation, secrets and paths.

A pyCert configuration describes one CA and one identity profile.  It is a
plain TOML file so it can be reviewed, diffed and version-controlled:

* ``[ca]``          - server URL, timeouts, TLS policy, endpoint paths;
* ``[identity]``    - organisation / OU / locality / country, default e-mail, RA;
* ``[keys]``        - key algorithm and size;
* ``[csr]``         - hash algorithm and requested extensions;
* ``[p12]``         - output file naming;
* ``[secrets]``     - where the saved PKCS#12 passphrase lives;
* ``[[chain.certificates]]`` - the full CA chain, either as files or inline PEM,
  each optionally pinned by SHA-256.

Nothing secret is stored in this file.  The PKCS#12 passphrase is held in the
OS secret store (or a 0600 file, or an external command); see
:mod:`pycert.secrets_store`.
"""

from __future__ import annotations

import os
import re
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509

from . import bundled, certs
from .errors import ConfigError
from .util import ensure_dir, normalize_fingerprint

DEFAULT_BASE_URL = "https://cwiz-live.ca.ngs.ac.uk:443"
DEFAULT_VERSION_STRING = "CertWizard 2.2.1"
DEFAULT_USER_AGENT = "pyCert/1.0"
CONFIG_VERSION = 1


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
    timeout: float = 30.0
    retries: int = 2
    tls_verify: bool = True
    tls_trust: str = "chain"  # chain | system | both
    tls_pin_sha256: list[str] = field(default_factory=list)
    allow_plaintext: bool = False
    allow_sha1: bool = False
    endpoints: Endpoints = field(default_factory=Endpoints)

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
    extensions: list[str] = field(default_factory=lambda: ["san"])
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
    backend: str = "auto"  # auto | keychain | secret-service | file | command | env | prompt
    service: str = "pyCert"
    account: str = "default"
    key_account: str = ""  # empty = reuse the [secrets].account secret
    file: str = ""
    command: str = ""
    env_var: str = "PYCERT_P12_PASSPHRASE"


@dataclass
class ChainEntry:
    label: str = ""
    file: str | None = None
    pem: str | None = None
    sha256: str | None = None
    anchor: bool = True

    def resolved_path(self, base: Path) -> Path | None:
        if self.file is None:
            return None
        path = Path(os.path.expandvars(os.path.expanduser(self.file)))
        return path if path.is_absolute() else (base / path)


@dataclass
class ChainBundle:
    """CA chain loaded from the configuration, with pin checking applied."""

    certificates: list[x509.Certificate]
    anchors: list[x509.Certificate]
    sources: list[str]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        unique: list[x509.Certificate] = []
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


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _expect_bool(table: dict, key: str, default: bool, where: str) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key}: expected a boolean, got {type(value).__name__}")
    return value


def _expect_list(table: dict, key: str, default: list[str], where: str) -> list[str]:
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
    """A loaded, validated pyCert configuration."""

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
        chain: list[ChainEntry],
        warnings: list[str] | None = None,
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
        self._bundle: ChainBundle | None = None

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
        loaded: list[x509.Certificate] = []
        anchors: list[x509.Certificate] = []
        sources: list[str] = []
        for index, entry in enumerate(self.chain):
            where = f"chain.certificates[{index}]"
            if entry.pem:
                data = entry.pem.encode()
                source = f"inline PEM ({entry.label or 'unnamed'})"
            else:
                path = entry.resolved_path(self.directory)
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
        if not loaded:
            self.warnings.append(
                "no CA chain certificates are configured; TLS will use the system trust store "
                "and chain validation will rely on AIA fetching"
            )
        return ChainBundle(loaded, anchors, sources)

    def tls_trust_pem(self) -> str:
        """PEM used to verify the CA server's TLS certificate."""
        parts: list[str] = []
        if self.ca.tls_trust in ("chain", "both") and self.bundle.anchors:
            parts.append(self.bundle.anchor_pem())
        return "".join(parts)

    def use_system_trust(self) -> bool:
        return self.ca.tls_trust in ("system", "both")

    # -- persistence -------------------------------------------------------
    def save(self) -> None:
        write_config(self.path, self)

    def invalidate_chain_cache(self) -> None:
        self._bundle = None

    def set(self, dotted: str, value: Any) -> None:
        """Set a value using a dotted key (used by ``pycert config set`` and the GUI)."""
        parts = dotted.split(".")
        target: Any = self
        for part in parts[:-1]:
            if not hasattr(target, part):
                raise ConfigError(f"unknown setting: {dotted}")
            target = getattr(target, part)
        key = parts[-1]
        if not hasattr(target, key):
            raise ConfigError(f"unknown setting: {dotted}")
        expected = type(getattr(target, key))
        if expected is bool:
            if isinstance(value, str):
                value = value.lower() in ("1", "true", "yes", "on")
        elif expected is int and isinstance(value, str):
            value = int(value)
        elif expected is float and isinstance(value, str):
            value = float(value)
        elif expected is list:
            value = _parse_list_value(dotted, value)
        if expected is not str and not isinstance(value, expected) and expected is not bool:
            raise ConfigError(f"{dotted}: expected {expected.__name__}")
        setattr(target, key, value)
        self._bundle = None

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "profile": self.profile,
            "ca": {
                "base_url": self.ca.base_url,
                "version_string": self.ca.version_string,
                "user_agent": self.ca.user_agent,
                "timeout": self.ca.timeout,
                "retries": self.ca.retries,
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


def _parse_list_value(key: str, value) -> list[str]:
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
                raise ConfigError(f"{key}: expected a list")
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


def default_config_paths() -> list[Path]:
    """Where pyCert looks for a configuration, in order.

    The current working directory is deliberately *not* searched: a pycert.toml
    planted in an untrusted directory could point the tool at an attacker's CA
    or a ``command`` secret backend.  Use ``--config ./pycert.toml`` (or
    ``PYCERT_CONFIG``) when you want a project-local file.
    """
    paths = []
    env = os.environ.get("PYCERT_CONFIG")
    if env:
        paths.append(_expand_path(env))
    paths.append(Path.home() / ".config" / "pycert" / "pycert.toml")
    paths.append(Path.home() / ".pycert" / "config.toml")
    return paths


def find_config(explicit: str | Path | None = None) -> Path:
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


def load_config(explicit: str | Path | None = None) -> Config:
    path = find_config(explicit)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    warnings: list[str] = []
    version = data.get("version", 1)
    if version != CONFIG_VERSION:
        warnings.append(f"configuration version {version} is not the supported version {CONFIG_VERSION}")
    profile = str(data.get("profile", "default"))

    ca_data = _section(data, "ca", "ca")
    endpoints_data = _section(ca_data, "endpoints", "ca.endpoints")
    ca = CAConfig(
        base_url=_get_str(ca_data, "base_url", DEFAULT_BASE_URL, "ca"),
        version_string=_get_str(ca_data, "version_string", DEFAULT_VERSION_STRING, "ca"),
        user_agent=_get_str(ca_data, "user_agent", DEFAULT_USER_AGENT, "ca"),
        timeout=_get_float(ca_data, "timeout", 30.0, "ca"),
        retries=_get_int(ca_data, "retries", 2, "ca"),
        tls_verify=_expect_bool(ca_data, "tls_verify", True, "ca"),
        tls_trust=_get_str(ca_data, "tls_trust", "chain", "ca"),
        tls_pin_sha256=_expect_list(ca_data, "tls_pin_sha256", [], "ca"),
        allow_plaintext=_expect_bool(ca_data, "allow_plaintext", False, "ca"),
        allow_sha1=_expect_bool(ca_data, "allow_sha1", False, "ca"),
        endpoints=Endpoints(
            csr=_get_str(endpoints_data, "csr", "/CSR", "ca.endpoints"),
            bulk=_get_str(endpoints_data, "bulk", "/CSRs", "ca.endpoints"),
            lookup=_get_str(endpoints_data, "lookup", "/resources/resource/publickey/pk", "ca.endpoints"),
            certificate=_get_str(endpoints_data, "certificate", "/certificate", "ca.endpoints"),
            revoke=_get_str(endpoints_data, "revoke", "/revoke", "ca.endpoints"),
            ping=_get_str(endpoints_data, "ping", "/pingservice", "ca.endpoints"),
            info=_get_str(endpoints_data, "info", "/CA", "ca.endpoints"),
            motd=_get_str(endpoints_data, "motd", "/CA/motd/text", "ca.endpoints"),
        ),
    )

    id_data = _section(data, "identity", "identity")
    identity = IdentityConfig(
        c=_get_str(id_data, "c", "UK", "identity"),
        o=_get_str(id_data, "o", "eScience", "identity"),
        ou=_get_str(id_data, "ou", "CLRC", "identity"),
        l=_get_str(id_data, "l", "DL", "identity"),
        st=_get_str(id_data, "st", "", "identity"),
        email=_get_str(id_data, "email", "", "identity"),
        ra=_get_str(id_data, "ra", "", "identity"),
    )

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
        env_var=_get_str(secrets_data, "env_var", "PYCERT_P12_PASSPHRASE", "secrets"),
    )

    chain_data = _section(data, "chain", "chain")
    entries: list[ChainEntry] = []
    raw_entries = chain_data.get("certificates", [])
    if not isinstance(raw_entries, list):
        raise ConfigError("chain.certificates: expected an array of tables")
    for index, raw in enumerate(raw_entries):
        where = f"chain.certificates[{index}]"
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
    )
    _validate(config)
    return config


def validate_config(config: Config) -> None:
    """Validate *config* in place, raising ConfigError on a fatal problem."""
    _validate(config)


def _validate(config: Config) -> None:
    if config.ca.tls_trust not in ("chain", "system", "both"):
        raise ConfigError("ca.tls_trust must be 'chain', 'system' or 'both'")
    if not config.ca.tls_verify:
        config.warnings.append("ca.tls_verify = false: the CA server's TLS certificate will NOT be verified")
    if config.ca.allow_plaintext and not config.ca.base_url.startswith("http://"):
        config.warnings.append("ca.allow_plaintext is set but base_url is not http://")
    if config.ca.base_url.startswith("http://") and not config.ca.allow_plaintext:
        raise ConfigError(
            "ca.base_url uses http:// but ca.allow_plaintext is false.\n"
            "Use https:// or explicitly set ca.allow_plaintext = true."
        )
    if not re.match(r"^https?://[^/\s]+", config.ca.base_url):
        raise ConfigError(f"ca.base_url is not a valid URL: {config.ca.base_url!r}")
    for value in config.ca.tls_pin_sha256:
        if len(normalize_fingerprint(value)) != 64:
            raise ConfigError(f"ca.tls_pin_sha256: not a SHA-256 fingerprint: {value!r}")
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
    if config.secrets.backend not in (
        "auto",
        "keychain",
        "secret-service",
        "file",
        "command",
        "env",
        "prompt",
    ):
        raise ConfigError(
            "secrets.backend must be one of auto, keychain, secret-service, file, command, env, prompt"
        )
    if config.secrets.backend == "command" and not config.secrets.command:
        raise ConfigError("secrets.command is required when secrets.backend = 'command'")


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

_HEADER = """\
# pyCert configuration - generated by 'pycert init'
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


def render_config(config: Config, *, chain_comments: bool = True) -> str:
    lines: list[str] = [_HEADER]
    lines.append(f"version = {CONFIG_VERSION}")
    lines.append(f"profile = {_q(config.profile)}")
    lines.append("")
    lines.append("[ca]")
    lines.append(f"base_url = {_q(config.ca.base_url)}")
    lines.append("# Version string sent to the CA; it must match what the server expects.")
    lines.append(f"version_string = {_q(config.ca.version_string)}")
    lines.append(f"user_agent = {_q(config.ca.user_agent)}")
    lines.append(f"timeout = {config.ca.timeout!r}")
    lines.append(f"retries = {config.ca.retries}")
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
    lines.append("#   auto | keychain (macOS) | secret-service (Linux) | file | command | env | prompt")
    lines.append(f"backend = {_q(config.secrets.backend)}")
    lines.append(f"service = {_q(config.secrets.service)}")
    lines.append(f"account = {_q(config.secrets.account)}")
    lines.append("# Leave key_account empty to use the same saved secret for the key at rest.")
    lines.append(f"key_account = {_q(config.secrets.key_account)}")
    lines.append(f"file = {_q(config.secrets.file)}")
    lines.append(f"command = {_q(config.secrets.command)}")
    lines.append(f"env_var = {_q(config.secrets.env_var)}")
    lines.append("")
    lines.append("[chain]")
    lines.append("# The CA chain used for path validation, TLS trust and the exported PKCS#12.")
    lines.append("# Each entry is a file path (relative to this file) or an inline 'pem' string,")
    lines.append("# optionally pinned with the SHA-256 fingerprint of the certificate.")
    for entry in config.chain:
        lines.append("")
        lines.append("[[chain.certificates]]")
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
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:  # pragma: no cover - defensive
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


def bundle_chain_entries() -> list[ChainEntry]:
    """Chain entries pointing at the bundled certificates, with pins."""
    return [
        ChainEntry(label=_BUNDLED_LABELS.get(name, name), file=f"chain/{name}", sha256=pin)
        for name, pin in bundled.PINNED.items()
    ]


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
