"""Read Java keystores and certificate bundles for inspection.

This module is intentionally read-only.  It decodes every certificate in a
legacy certificate bundle so the GUI can show what is inside a CertWizard
``cakeystore.pkcs12``, a Java JKS/JCEKS trust store, or a PEM/DER bundle before
anything is imported or re-exported.

PKCS#12 is handled by ``cryptography``/OpenSSL, which also understands the
legacy PBE-SHA1-3DES and RC2 encryption used by Java 8.  JKS and JCEKS are
small, documented Java formats; parsing them here avoids a Java dependency.
The private keys are never returned or displayed.
"""

import hashlib
import hmac
import struct
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from . import certs
from .compat import dataclass, field
from .errors import CryptoError, PyCertError

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_CERTIFICATES = 200
JKS_MAGIC = 0xFEEDFEED
JCEKS_MAGIC = 0xCECECECE
_JKS_DIGEST_PREFIX = b"Mighty Aphrodite"


@dataclass
class BundleCertificate:
    """One certificate found in a bundle."""

    index: int
    role: str
    certificate: x509.Certificate
    alias: str = ""

    def as_dict(self) -> dict:
        payload = certs.describe_certificate(self.certificate).as_dict()
        payload.update({"index": self.index, "role": self.role, "alias": self.alias})
        return payload


@dataclass
class CertificateBundle:
    """Decoded, read-only contents of a Java or PEM certificate bundle."""

    path: str
    format: str
    certificates: "list[BundleCertificate]"
    has_private_key: bool = False
    key_description: str = ""
    warnings: "list[str]" = field(default_factory=list)
    integrity_checked: bool = False

    def __len__(self):
        return len(self.certificates)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "has_private_key": self.has_private_key,
            "key_description": self.key_description,
            "integrity_checked": self.integrity_checked,
            "warnings": list(self.warnings),
            "certificates": [entry.as_dict() for entry in self.certificates],
        }


def load_bundle(path: "str | Path", password: str = "") -> CertificateBundle:
    """Decode a PKCS#12, JKS/JCEKS, PEM or DER certificate bundle."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > MAX_BUNDLE_BYTES:
            raise CryptoError("certificate bundle is larger than %d bytes" % MAX_BUNDLE_BYTES)
        data = path.read_bytes()
    except OSError as exc:
        raise PyCertError("cannot read certificate bundle %s: %s" % (path, exc)) from exc
    return load_bundle_bytes(data, password=password, path=str(path))


def load_bundle_bytes(data: bytes, password: str = "", path: str = "") -> CertificateBundle:
    """Decode bundle content already held in memory."""
    if isinstance(data, str):  # pragma: no cover - defensive for callers
        data = data.encode("utf-8")
    if not data:
        raise CryptoError("certificate bundle is empty")
    if len(data) > MAX_BUNDLE_BYTES:
        raise CryptoError("certificate bundle is larger than %d bytes" % MAX_BUNDLE_BYTES)

    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        return _load_pem(data, path)
    if len(data) >= 4:
        magic = struct.unpack_from(">I", data, 0)[0]
        if magic in (JKS_MAGIC, JCEKS_MAGIC):
            return _load_jks(data, password, path, magic)

    try:
        return _load_pkcs12(data, password, path)
    except CryptoError as p12_error:
        # DER certificates and PKCS#7 bundles are not PKCS#12.  Try those
        # before reporting the PKCS#12 error, which may simply be a wrong
        # passphrase.
        try:
            certificates = certs.load_certificates(data)
        except PyCertError:
            raise p12_error
        return _bundle_from_certificates(certificates, "der", path)


def _load_pem(data: bytes, path: str) -> CertificateBundle:
    certificates = certs.load_certificates(data)
    has_key = b"PRIVATE KEY" in data
    warnings = []
    if has_key:
        warnings.append("the PEM bundle also contains a private key; it is not displayed")
    return _bundle_from_certificates(
        certificates, "pem", path, has_private_key=has_key, warnings=warnings
    )


def _load_pkcs12(data: bytes, password: str, path: str) -> CertificateBundle:
    try:
        key, certificate, extras = pkcs12.load_key_and_certificates(
            data, password.encode("utf-8") if password else None
        )
    except (TypeError, ValueError) as exc:
        hint = " (wrong passphrase?)" if password else " (a passphrase may be required)"
        raise CryptoError("could not decode PKCS#12 bundle%s: %s" % (hint, exc)) from exc

    extras = list(extras or [])
    entries: "list[BundleCertificate]" = []
    seen: "set[str]" = set()
    warnings: "list[str]" = []

    if key is not None and certificate is None:
        matches = [c for c in extras if certs.public_keys_equal(c, key.public_key())]
        if not matches:
            raise CryptoError("the PKCS#12 private key has no matching certificate")
        certificate = matches[0]
        extras = [c for c in extras if certs.fingerprint(c) != certs.fingerprint(certificate)]

    if certificate is not None:
        role = "leaf" if key is not None else "certificate"
        if key is not None and not certs.certificate_matches_key(certificate, key):
            role = "certificate"
            warnings.append("the PKCS#12 private key does not match its first certificate")
        _add(entries, seen, role, certificate)

    for extra in extras:
        _add(entries, seen, "chain" if key is not None else "trusted", extra)

    if not entries:
        raise CryptoError("the PKCS#12 bundle contains no certificates")
    if key is None:
        warnings.append("certificate-only PKCS#12: no private key")
    return CertificateBundle(
        path=path,
        format="pkcs12",
        certificates=entries,
        has_private_key=key is not None,
        key_description=certs.key_description(key.public_key()) if key is not None else "",
        warnings=warnings,
    )


def _load_jks(data: bytes, password: str, path: str, magic: int) -> CertificateBundle:
    if len(data) < 12:
        raise CryptoError("truncated Java keystore")
    _magic, version, count = struct.unpack_from(">III", data, 0)
    if magic not in (JKS_MAGIC, JCEKS_MAGIC) or version not in (1, 2):
        raise CryptoError("unsupported Java keystore version")
    offset = 12
    entries: "list[BundleCertificate]" = []
    seen: "set[str]" = set()
    warnings: "list[str]" = []
    key_count = 0

    for _ in range(count):
        tag, offset = _read_u32(data, offset)
        alias, offset = _read_utf(data, offset)
        _timestamp, offset = _read_u64(data, offset)
        if tag == 1:  # private key entry
            key_length, offset = _read_u32(data, offset)
            offset = _skip(data, offset, key_length)
            chain_count, offset = _read_u32(data, offset)
            key_count += 1
            for index in range(chain_count):
                _cert_type, offset = _read_utf(data, offset)
                der, offset = _read_bytes(data, offset)
                certificate = _load_der(der)
                _add(entries, seen, "leaf" if index == 0 else "chain", certificate, alias)
        elif tag == 2:  # trusted certificate entry
            _cert_type, offset = _read_utf(data, offset)
            der, offset = _read_bytes(data, offset)
            _add(entries, seen, "trusted", _load_der(der), alias)
        else:  # pragma: no cover - malformed keystore
            raise CryptoError("unsupported Java keystore entry type %d" % tag)

    if len(data) < offset + 20:
        raise CryptoError("truncated Java keystore integrity digest")
    integrity_checked = False
    if password:
        expected = hashlib.sha1(
            password.encode("utf-16-be") + _JKS_DIGEST_PREFIX + data[:offset]
        ).digest()
        if not hmac.compare_digest(expected, data[offset : offset + 20]):
            raise CryptoError("Java keystore integrity check failed (wrong password)")
        integrity_checked = True
    else:
        warnings.append("Java keystore integrity digest was not verified (no password supplied)")

    if not entries:
        raise CryptoError("the Java keystore contains no certificates")
    if key_count:
        warnings.append("private key entries are present but are not decoded or displayed")
    return CertificateBundle(
        path=path,
        format="jceks" if magic == JCEKS_MAGIC else "jks",
        certificates=entries,
        has_private_key=bool(key_count),
        key_description="Java private key entry (not decoded)" if key_count else "",
        warnings=warnings,
        integrity_checked=integrity_checked,
    )


def _bundle_from_certificates(
    certificates: "list[x509.Certificate]",
    format_name: str,
    path: str,
    *,
    has_private_key: bool = False,
    warnings: "list[str] | None" = None,
) -> CertificateBundle:
    entries: "list[BundleCertificate]" = []
    seen: "set[str]" = set()
    for certificate in certificates:
        _add(entries, seen, "certificate", certificate)
    if not entries:
        raise CryptoError("the bundle contains no certificates")
    return CertificateBundle(
        path=path,
        format=format_name,
        certificates=entries,
        has_private_key=has_private_key,
        key_description="private key present (not decoded)" if has_private_key else "",
        warnings=list(warnings or []),
    )


def _add(
    entries: "list[BundleCertificate]",
    seen: "set[str]",
    role: str,
    certificate: x509.Certificate,
    alias: str = "",
) -> None:
    fingerprint = certs.fingerprint(certificate)
    if fingerprint in seen:
        return
    if len(entries) >= MAX_BUNDLE_CERTIFICATES:
        raise CryptoError("bundle contains more than %d certificates" % MAX_BUNDLE_CERTIFICATES)
    seen.add(fingerprint)
    entries.append(BundleCertificate(len(entries), role, certificate, alias))


def _load_der(data: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise CryptoError("could not decode a certificate in the Java keystore: %s" % exc) from exc


def _read_u32(data: bytes, offset: int) -> "tuple[int, int]":
    if offset + 4 > len(data):
        raise CryptoError("truncated Java keystore")
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def _read_u64(data: bytes, offset: int) -> "tuple[int, int]":
    if offset + 8 > len(data):
        raise CryptoError("truncated Java keystore")
    return struct.unpack_from(">Q", data, offset)[0], offset + 8


def _read_bytes(data: bytes, offset: int) -> "tuple[bytes, int]":
    length, offset = _read_u32(data, offset)
    if offset + length > len(data):
        raise CryptoError("truncated Java keystore")
    return data[offset : offset + length], offset + length


def _skip(data: bytes, offset: int, length: int) -> int:
    if offset + length > len(data):
        raise CryptoError("truncated Java keystore")
    return offset + length


def _read_utf(data: bytes, offset: int) -> "tuple[str, int]":
    if offset + 2 > len(data):
        raise CryptoError("truncated Java keystore")
    length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if offset + length > len(data):
        raise CryptoError("truncated Java keystore")
    raw = data[offset : offset + length]
    offset += length
    try:
        return raw.decode("utf-8"), offset
    except UnicodeDecodeError:  # pragma: no cover - modified UTF-8 aliases are rare
        return raw.decode("utf-8", "replace").replace("\xc0\x80", "\x00"), offset
