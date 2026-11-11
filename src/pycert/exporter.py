"""Export a certificate, its chain and (optionally) its private key.

Formats: PKCS#12 (the standard), a PEM bundle, separate PEM files, the
private key alone, and public-only formats (certificate, full chain, DER,
PKCS#7).

Rules for anything that contains a private key:

* the user chooses a **new passphrase** for every export. pyCertWiz's own saved
  secret is never used, and is refused if typed;
* bundles (PKCS#12, a PEM bundle with the key) are always encrypted;
* a single private-key file (``key``, ``pem-files``) may be written without a
  passphrase only when the caller obtained the user's explicit confirmation
  (``no_passphrase=True``).

pyCertWiz's own copy of the PKCS#12 in its store (``workflow.export_p12``) is
separate: it is written automatically and protected with the saved secret.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from . import certs
from . import p12 as p12_module
from .errors import CryptoError, PyCertError
from .util import atomic_write, ensure_dir

Progress = Callable[[str], None]

#: Shortest passphrase accepted for an export.
MIN_PASSPHRASE = 8

PUBLIC_FILE_MODE = 0o644
SECRET_FILE_MODE = 0o600
SINGLE_KEY_MODE = 0o400


def _noop(_message: str) -> None:
    return None


@dataclass(frozen=True)
class Encryption:
    name: str
    label: str
    description: str


P12_ENCRYPTIONS: "dict[str, Encryption]" = {
    "aes256": Encryption(
        "aes256",
        "AES-256 (PBES2, PBKDF2-SHA256)",
        "Modern and strong. Read by OpenSSL 1.1+, Java 11+, current Windows and macOS.",
    ),
    "3des": Encryption(
        "3des",
        "Triple-DES (PBE-SHA1-3DES), legacy",
        "Weaker, for older software: Java 8, CertWizard's bundled Java, older Windows and macOS.",
    ),
}

KEY_ENCRYPTIONS: "dict[str, Encryption]" = {
    "pkcs8": Encryption(
        "pkcs8",
        "PKCS#8, AES-256 (ENCRYPTED PRIVATE KEY)",
        "The modern PEM key format, read by OpenSSL, Globus, nginx and Apache.",
    ),
    "traditional": Encryption(
        "traditional",
        "OpenSSL traditional, AES-256 (RSA/EC PRIVATE KEY)",
        "For older tools that only read the traditional OpenSSL key format.",
    ),
}


@dataclass(frozen=True)
class ExportFormat:
    name: str
    label: str
    description: str
    suffix: str  # '' for a directory of files
    has_key: bool
    bundle: bool  # the key travels with certificates: always encrypted
    chain_option: bool  # the "include the chain" choice applies
    encryptions: "dict[str, Encryption]" = field(default_factory=dict)

    @property
    def default_encryption(self) -> str:
        return next(iter(self.encryptions), "")

    @property
    def is_directory(self) -> bool:
        return not self.suffix


FORMATS: "dict[str, ExportFormat]" = {
    fmt.name: fmt
    for fmt in (
        ExportFormat(
            "p12",
            "PKCS#12 (.p12)",
            "Key, certificate and chain in one encrypted file. The standard for browsers, Java, "
            "Windows, macOS and most servers.",
            ".p12",
            has_key=True,
            bundle=True,
            chain_option=True,
            encryptions=P12_ENCRYPTIONS,
        ),
        ExportFormat(
            "pem-bundle",
            "PEM bundle (key + certificate + chain)",
            "One PEM file with the encrypted key first, then the certificate and its chain.",
            ".pem",
            has_key=True,
            bundle=True,
            chain_option=True,
            encryptions=KEY_ENCRYPTIONS,
        ),
        ExportFormat(
            "pem-files",
            "Separate PEM files (certificate, key)",
            "<name>.pem holds the certificate (and chain); <name>.key holds the private key.",
            "",
            has_key=True,
            bundle=False,
            chain_option=True,
            encryptions=KEY_ENCRYPTIONS,
        ),
        ExportFormat(
            "key",
            "Private key only (PEM)",
            "The private key alone, as a PEM file.",
            ".key",
            has_key=True,
            bundle=False,
            chain_option=False,
            encryptions=KEY_ENCRYPTIONS,
        ),
        ExportFormat(
            "cert",
            "Certificate only (PEM)",
            "The certificate alone. Public: no passphrase.",
            ".crt",
            has_key=False,
            bundle=False,
            chain_option=False,
        ),
        ExportFormat(
            "fullchain",
            "Certificate and chain (PEM)",
            "The certificate followed by its issuers. Public: no passphrase.",
            ".fullchain.pem",
            has_key=False,
            bundle=False,
            chain_option=False,
        ),
        ExportFormat(
            "der",
            "Certificate (DER, .cer)",
            "The certificate in binary DER form, as Windows expects. Public: no passphrase.",
            ".cer",
            has_key=False,
            bundle=False,
            chain_option=False,
        ),
        ExportFormat(
            "p7b",
            "Certificate chain (PKCS#7, .p7b)",
            "The certificate and its issuers in a PKCS#7 container. Public: no passphrase.",
            ".p7b",
            has_key=False,
            bundle=False,
            chain_option=False,
        ),
    )
}

DEFAULT_FORMAT = "p12"


def get_format(name: str) -> ExportFormat:
    try:
        return FORMATS[name]
    except KeyError:
        raise PyCertError(f"unknown export format {name!r}; choose one of: {', '.join(FORMATS)}") from None


def file_base(alias: str) -> str:
    """A file name stem for *alias* (no spaces or path separators)."""
    return alias.strip().replace(" ", "_").replace("/", "-").replace("\\", "-") or "certificate"


def default_destination(alias: str, fmt: "ExportFormat | str", directory: "Path | str") -> Path:
    fmt = get_format(fmt) if isinstance(fmt, str) else fmt
    directory = Path(directory).expanduser()
    return directory if fmt.is_directory else directory / f"{file_base(alias)}{fmt.suffix}"


def check_passphrase(ctx: Any, fmt: ExportFormat, password: "str | None", no_passphrase: bool) -> None:
    """Enforce the export passphrase rules (see the module docstring)."""
    if not fmt.has_key:
        return
    if no_passphrase:
        if fmt.bundle:
            raise PyCertError(f"a {fmt.label} is always protected with a passphrase")
        if password:
            raise PyCertError("choose either a passphrase or no passphrase for the key, not both")
        return
    if not password:
        raise PyCertError("an export containing a private key needs a new passphrase chosen for it")
    if len(password) < MIN_PASSPHRASE:
        raise PyCertError(f"the export passphrase must be at least {MIN_PASSPHRASE} characters")
    saved = ctx.secrets.get(allow_missing=True)
    if saved and hmac.compare_digest(password.encode("utf-8"), saved.encode("utf-8")):
        raise PyCertError("choose a new passphrase for the export, not pyCertWiz's own saved secret")


def key_bytes(key: Any, encryption: str, password: "str | None", *, no_passphrase: bool = False) -> bytes:
    """Serialise a private key as PEM in the chosen *encryption* format."""
    private_format = (
        serialization.PrivateFormat.TraditionalOpenSSL if encryption == "traditional" else serialization.PrivateFormat.PKCS8
    )
    if no_passphrase:
        if encryption == "traditional":
            raise PyCertError("an unencrypted key is written in PKCS#8 form; choose the PKCS#8 format")
        return certs.unprotected_key_pem(key, confirmed=True).encode("ascii")
    if not password:
        raise CryptoError("refusing to write a private key without passphrase protection")
    return key.private_bytes(
        serialization.Encoding.PEM, private_format, serialization.BestAvailableEncryption(password.encode("utf-8"))
    )


@dataclass
class ExportResult:
    format: str
    files: "dict[str, Path]"
    encryption: str = ""
    unprotected_key: bool = False

    def as_dict(self) -> dict:
        return {
            "format": self.format,
            "encryption": self.encryption,
            "unprotected_key": self.unprotected_key,
            "files": {name: str(path) for name, path in self.files.items()},
        }


def _target(path: Path, overwrite: bool) -> Path:
    if path.is_dir():
        raise PyCertError(f"{path} is a folder; choose a file name")
    if path.exists() and not overwrite:
        raise PyCertError(f"{path} already exists; choose another name or allow overwriting")
    if path.is_symlink():
        raise PyCertError(f"{path} is a symbolic link; refusing to write through it")
    ensure_dir(path.parent)
    return path


def export_material(
    *,
    alias: str,
    certificate: x509.Certificate,
    chain: "list[x509.Certificate]",
    load_key: "Callable[[], Any] | None",
    fmt: "ExportFormat | str",
    destination: "Path | str",
    ctx: Any,
    encryption: str = "",
    password: "str | None" = None,
    no_passphrase: bool = False,
    include_chain: bool = True,
    overwrite: bool = False,
    progress: Progress = _noop,
) -> ExportResult:
    """Write *certificate* (with *chain*, and the key from *load_key*) in *fmt*."""
    fmt = get_format(fmt) if isinstance(fmt, str) else fmt
    encryption = encryption or fmt.default_encryption
    if fmt.encryptions and encryption not in fmt.encryptions:
        raise PyCertError(
            f"{fmt.label} cannot use encryption {encryption!r}; choose one of: {', '.join(fmt.encryptions)}"
        )
    check_passphrase(ctx, fmt, password, no_passphrase)
    issuers = list(chain) if (include_chain or not fmt.chain_option) else []
    destination = Path(destination).expanduser()
    if destination.is_dir() and not fmt.is_directory:
        destination = default_destination(alias, fmt, destination)
    key = load_key() if fmt.has_key and load_key is not None else None
    if fmt.has_key and key is None:
        raise PyCertError("the private key is not available for this certificate")
    if key is not None and not certs.certificate_matches_key(certificate, key):
        raise CryptoError("the stored private key does not match the certificate; nothing was exported")
    if password and not password.isascii():
        progress("note: the passphrase has non-ASCII characters; some older software cannot read such files")

    try:
        files = _write(fmt, destination, alias, certificate, chain, issuers, key, encryption, password, no_passphrase, overwrite)
    except OSError as exc:
        raise PyCertError(f"cannot write the export: {exc}") from exc

    unprotected = fmt.has_key and no_passphrase
    if unprotected:
        progress(f"warning: {files['key']} has NO passphrase, as you confirmed; anyone who can read it holds the key")
    elif fmt.has_key:
        progress("The private key is protected with the new passphrase you chose; pyCertWiz does not keep it.")
    progress("Wrote " + ", ".join(str(p) for p in files.values()))
    return ExportResult(fmt.name, files, encryption if fmt.has_key else "", unprotected)


def _write(fmt, destination, alias, certificate, chain, issuers, key, encryption, password, no_passphrase, overwrite):
    files: "dict[str, Path]" = {}
    if fmt.name == "p12":
        path = _target(destination, overwrite)
        p12_module.write_pkcs12(
            path,
            key=key,
            certificate=certificate,
            chain=issuers,
            password=password,
            friendly_name=alias,
            legacy=encryption == "3des",
        )
        files["p12"] = path
    elif fmt.name == "pem-bundle":
        path = _target(destination, overwrite)
        text = key_bytes(key, encryption, password) + _pem_chain([certificate, *issuers])
        atomic_write(path, text, mode=SECRET_FILE_MODE)
        files["bundle"] = path
    elif fmt.name == "pem-files":
        ensure_dir(destination, 0o700)
        base = file_base(alias)
        cert_path = _target(destination / f"{base}.pem", overwrite)
        key_path = _target(destination / f"{base}.key", overwrite)
        atomic_write(cert_path, _pem_chain([certificate, *issuers]), mode=PUBLIC_FILE_MODE)
        atomic_write(key_path, key_bytes(key, encryption, password, no_passphrase=no_passphrase), mode=SINGLE_KEY_MODE)
        files.update(cert=cert_path, key=key_path)
    elif fmt.name == "key":
        path = _target(destination, overwrite)
        atomic_write(path, key_bytes(key, encryption, password, no_passphrase=no_passphrase), mode=SINGLE_KEY_MODE)
        files["key"] = path
    elif fmt.name == "cert":
        path = _target(destination, overwrite)
        atomic_write(path, certs.cert_pem(certificate), mode=PUBLIC_FILE_MODE)
        files["cert"] = path
    elif fmt.name == "fullchain":
        path = _target(destination, overwrite)
        atomic_write(path, _pem_chain([certificate, *chain]), mode=PUBLIC_FILE_MODE)
        files["fullchain"] = path
    elif fmt.name == "der":
        path = _target(destination, overwrite)
        atomic_write(path, certificate.public_bytes(serialization.Encoding.DER), mode=PUBLIC_FILE_MODE)
        files["cert"] = path
    else:  # p7b
        path = _target(destination, overwrite)
        atomic_write(path, pkcs7.serialize_certificates([certificate, *chain], serialization.Encoding.DER), mode=PUBLIC_FILE_MODE)
        files["p7b"] = path
    return files


def _pem_chain(certificates: "list[x509.Certificate]") -> bytes:
    return "".join(certs.cert_pem(c) for c in certificates).encode("ascii")
