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
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.serialization import pkcs12

try:  # cryptography >= 48 moved legacy ciphers to the decrepit namespace
    from cryptography.hazmat.decrepit.ciphers.algorithms import RC2, TripleDES
except ImportError:  # pragma: no cover - older cryptography
    try:
        from cryptography.hazmat.primitives.ciphers.algorithms import RC2, TripleDES
    except ImportError:  # pragma: no cover - RC2 is not in every cryptography build
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

        RC2 = None

from dataclasses import dataclass, field

from . import ber, certs, p12
from .errors import CryptoError, PyCertError
from .pkcs12_writer import _bmp_password, pkcs12_kdf

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_BUNDLE_CERTIFICATES = 200
JKS_MAGIC = 0xFEEDFEED
JCEKS_MAGIC = 0xCECECECE
_JKS_DIGEST_PREFIX = b"Mighty Aphrodite"


class _UnsupportedPBE(CryptoError):
    """Internal marker: let cryptography's high-level parser try this layout."""


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
    private_key: object = field(default=None, repr=False)
    key_count: int = 0
    key_aliases: "list[str]" = field(default_factory=list)
    raw_key_bags: "list[bytes]" = field(default_factory=list, repr=False)
    raw_cert_bags: "list[bytes]" = field(default_factory=list, repr=False)
    #: "pbes2" when the certificate SafeContents used modern PBES2 encryption
    encryption: str = ""

    def __len__(self):
        return len(self.certificates)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "has_private_key": self.has_private_key,
            "key_description": self.key_description,
            "integrity_checked": self.integrity_checked,
            "key_count": self.key_count,
            "key_aliases": list(self.key_aliases),
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


def load_bundle_bytes(data: bytes, password: str = "", path: str = "", *, prefer_raw: bool = False) -> CertificateBundle:
    """Decode bundle content already held in memory.

    ``prefer_raw`` keeps every PKCS#12 SafeBag (needed to edit a keystore
    entry by entry) even for single-key PBES2 files, which are otherwise fully
    decoded so their key can be described and re-encrypted.
    """
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
        return _load_pkcs12(data, password, path, prefer_raw=prefer_raw)
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


def _load_pkcs12(data: bytes, password: str, path: str, *, prefer_raw: bool = False) -> CertificateBundle:
    # The raw path understands Java's BER, legacy RC2/3DES and PBES2
    # SafeContents, and preserves all key bags for a lossless re-export.  A
    # single-key PBES2 file (pyCertWiz's own, OpenSSL 3, modern keytool) is fully
    # decoded instead, so its key can be described and re-encrypted for old Java.
    raw = _load_pkcs12_raw(data, password, path)
    if raw is not None and (prefer_raw or raw.encryption != "pbes2" or raw.key_count > 1):
        return raw
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
        integrity_checked=raw is not None and raw.integrity_checked,
        private_key=key,
        key_count=1 if key is not None else 0,
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


def _load_pkcs12_raw(data: bytes, password: str, path: str) -> "CertificateBundle | None":
    try:
        pfx = ber.parse(data)
        if pfx.tag != 0x10 or len(pfx.children) < 2:  # pragma: no cover - not a PKCS#12 PFX
            return None
        auth_info = pfx.children[1]
        if auth_info.tag != 0x10 or len(auth_info.children) < 2:
            return None
        authenticated_bytes = ber.octets(auth_info.children[1])
        integrity_checked = bool(password) and _verify_pfx_mac(pfx, authenticated_bytes, password)
        authenticated = ber.parse(authenticated_bytes)
        entries: "list[BundleCertificate]" = []
        seen: "set[str]" = set()
        raw_cert_bags: "list[bytes]" = []
        raw_key_bags: "list[bytes]" = []
        key_aliases: "list[str]" = []
        encrypted_certificates = False
        encryption = ""
        for content_info in authenticated.children:
            oid = ber.decode_oid(content_info.children[0].content)
            content = content_info.children[1]
            if oid == "1.2.840.113549.1.7.1":  # data
                safe = ber.parse(ber.octets(content))
                _collect_safe(safe, entries, seen, raw_cert_bags, raw_key_bags, key_aliases)
            elif oid == "1.2.840.113549.1.7.6":  # encryptedData
                if not password:
                    encrypted_certificates = True
                    continue
                plaintext = _decrypt_encrypted_data(content, password)
                if _uses_pbes2(content):
                    encryption = "pbes2"
                safe = ber.parse(plaintext)
                _collect_safe(safe, entries, seen, raw_cert_bags, raw_key_bags, key_aliases)
    except _UnsupportedPBE:
        return None
    except (ber.BERError, IndexError, ValueError) as exc:
        if password:
            raise CryptoError("could not decode PKCS#12 bundle: %s" % exc) from exc  # pragma: no cover - malformed PFX
        return None

    if not entries:
        if encrypted_certificates:
            raise CryptoError("the PKCS#12 certificates are encrypted; a passphrase is required")
        return None  # pragma: no cover - empty PFX
    role = "leaf" if len(raw_key_bags) == 1 else "certificate"
    if not raw_key_bags:
        role = "trusted"
    for index, entry in enumerate(entries):
        if index == 0:
            entry.role = role
        elif role == "leaf":
            entry.role = "chain"
    warnings = []
    if not password and raw_key_bags:  # pragma: no cover - raw keys plus visible certs
        warnings.append("key bags are present but encrypted; passphrase not supplied")
    if len(raw_key_bags) > 1:
        warnings.append("%d key entries are preserved in the re-export" % len(raw_key_bags))
    return CertificateBundle(
        path=path,
        format="pkcs12",
        certificates=entries,
        has_private_key=bool(raw_key_bags),
        key_description=(
            "%d Java key entries (preserved)" % len(raw_key_bags)
            if len(raw_key_bags) > 1
            else ("Java key entry (preserved)" if raw_key_bags else "")
        ),
        warnings=warnings,
        integrity_checked=integrity_checked,
        key_count=len(raw_key_bags),
        key_aliases=key_aliases,
        raw_key_bags=raw_key_bags,
        raw_cert_bags=raw_cert_bags,
        encryption=encryption,
    )


def _verify_pfx_mac(pfx, authenticated_bytes: bytes, password: str) -> bool:
    """Check the PKCS#12 MAC; True when one was present and matched (raises if it did not)."""
    if len(pfx.children) < 3:  # pragma: no cover - MAC is optional
        return False
    mac_data = pfx.children[2]
    if mac_data.tag != 0x10 or len(mac_data.children) < 2:  # pragma: no cover - malformed MAC
        return False
    digest_info = mac_data.children[0]
    if digest_info.tag != 0x10 or len(digest_info.children) < 2:  # pragma: no cover - malformed MAC
        return False
    algorithm = digest_info.children[0]
    digest = digest_info.children[1].content
    oid = ber.decode_oid(algorithm.children[0].content)
    hash_name = {
        "1.3.14.3.2.26": "sha1",
        "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512",
    }.get(oid)
    if hash_name is None:  # pragma: no cover - exotic MAC algorithm
        raise _UnsupportedPBE("unsupported PKCS#12 MAC algorithm %s" % oid)
    salt = mac_data.children[1].content
    iterations = (
        int.from_bytes(mac_data.children[2].content, "big")
        if len(mac_data.children) > 2
        else 1
    )
    hash_function = getattr(hashlib, hash_name)
    mac_key = pkcs12_kdf(
        _bmp_password(password), salt, 3, iterations, hash_function().digest_size, hash_name
    )
    expected = hmac.new(mac_key, authenticated_bytes, hash_function).digest()
    if not hmac.compare_digest(expected, digest):
        raise CryptoError("PKCS#12 integrity check failed (wrong passphrase or corrupt file)")
    return True


def _collect_safe(
    safe,
    entries: "list[BundleCertificate]",
    seen: "set[str]",
    raw_cert_bags: "list[bytes]",
    raw_key_bags: "list[bytes]",
    key_aliases: "list[str]",
) -> None:
    for bag in safe.children:
        if bag.tag != 0x10 or len(bag.children) < 2:  # pragma: no cover - malformed bag
            continue
        bag_oid = ber.decode_oid(bag.children[0].content)
        alias = _bag_alias(bag)
        if bag_oid == "1.2.840.113549.1.12.10.1.3":  # certBag
            value = bag.children[1]
            cert_bag = value.children[0] if value.children else value
            if len(cert_bag.children) < 2:  # pragma: no cover - malformed CertBag
                continue
            cert_type = ber.decode_oid(cert_bag.children[0].content)
            if cert_type != "1.2.840.113549.1.9.22.1":  # pragma: no cover - non-X.509 CertBag
                continue
            der = ber.octets(cert_bag.children[1])
            certificate = _load_der(der)
            _add(entries, seen, "certificate", certificate, alias)
            raw_cert_bags.append(bag.encoded)
        elif bag_oid == "1.2.840.113549.1.12.10.1.2":  # pkcs8ShroudedKeyBag
            raw_key_bags.append(bag.encoded)
            key_aliases.append(alias)


def _bag_alias(bag) -> str:
    for child in bag.children[2:]:
        if child.tag != 0x11:  # SET OF Attribute
            continue  # pragma: no cover - malformed attributes
        for attr in child.children:
            if attr.tag != 0x10 or len(attr.children) < 2:  # pragma: no cover - malformed attribute
                continue
            oid = ber.decode_oid(attr.children[0].content)
            if oid != "1.2.840.113549.1.9.20":
                continue
            values = attr.children[1]
            if values.children and values.children[0].tag == 0x1E:
                return values.children[0].content.decode("utf-16-be", "replace")
    return ""


def _decrypt_encrypted_data(content, password: str) -> bytes:
    encrypted_data = content.children[0] if content.children else content
    sequence = encrypted_data if encrypted_data.tag == 0x10 else encrypted_data.children[0]
    encrypted_content_info = sequence.children[1]
    algorithm = encrypted_content_info.children[1]
    encrypted = encrypted_content_info.children[2]
    oid = ber.decode_oid(algorithm.children[0].content)
    params = algorithm.children[1]
    if oid == _PBES2_OID:
        # Modern keytool (Java 8u301+) and OpenSSL 3 encrypt the certificate
        # SafeContents with PBES2/PBKDF2/AES; decoding it here keeps every key
        # entry of such keystores (the high-level parser keeps only the first).
        return _pbes2_decrypt(params, ber.octets(encrypted_content_info.children[2]), password)
    salt = params.children[0].content
    iterations = int.from_bytes(params.children[1].content, "big")
    key_length = {
        "1.2.840.113549.1.12.1.3": 24,
        "1.2.840.113549.1.12.1.4": 16,
        "1.2.840.113549.1.12.1.5": 16,
        "1.2.840.113549.1.12.1.6": 5,
    }.get(oid)
    if key_length is None:
        raise _UnsupportedPBE("unsupported PKCS#12 encryption algorithm %s" % oid)
    password_bytes = _bmp_password(password)
    key = pkcs12_kdf(password_bytes, salt, 1, iterations, key_length, "sha1")
    iv = pkcs12_kdf(password_bytes, salt, 2, iterations, 8, "sha1")
    ciphertext = ber.octets(encrypted)
    if key_length == 24:
        decryptor = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    elif key_length == 16:  # pragma: no cover - RC2-128 legacy variant
        if RC2 is None:
            raise _UnsupportedPBE("this cryptography build has no RC2 support")
        decryptor = Cipher(RC2(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
    else:
        # cryptography's RC2 wrapper only accepts 128-bit keys.  Legacy Java
        # keystores use the 40-bit PKCS#12 profile, which OpenSSL still
        # implements when its legacy provider is loaded.
        padded = _openssl_rc2_40_decrypt(ciphertext, key, iv)
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


_PBES2_OID = "1.2.840.113549.1.5.13"


def _uses_pbes2(content) -> bool:
    encrypted_data = content.children[0] if content.children else content
    sequence = encrypted_data if encrypted_data.tag == 0x10 else encrypted_data.children[0]
    algorithm = sequence.children[1].children[1]
    return ber.decode_oid(algorithm.children[0].content) == _PBES2_OID
_PBKDF2_OID = "1.2.840.113549.1.5.12"
_PBKDF2_PRFS = {
    "1.2.840.113549.2.7": "SHA1",
    "1.2.840.113549.2.8": "SHA224",
    "1.2.840.113549.2.9": "SHA256",
    "1.2.840.113549.2.10": "SHA384",
    "1.2.840.113549.2.11": "SHA512",
}
_PBES2_CIPHERS = {
    "2.16.840.1.101.3.4.1.2": 16,  # aes128-CBC
    "2.16.840.1.101.3.4.1.22": 24,  # aes192-CBC
    "2.16.840.1.101.3.4.1.42": 32,  # aes256-CBC
}


def _pbes2_decrypt(params, ciphertext: bytes, password: str) -> bytes:
    """PBES2 (RFC 8018) with PBKDF2-HMAC and AES-CBC; the password is UTF-8."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf, scheme = params.children[0], params.children[1]
    if ber.decode_oid(kdf.children[0].content) != _PBKDF2_OID:
        raise _UnsupportedPBE("unsupported PBES2 key derivation function")
    kdf_params = kdf.children[1]
    salt = kdf_params.children[0].content
    iterations = int.from_bytes(kdf_params.children[1].content, "big")
    prf = "SHA1"
    for child in kdf_params.children[2:]:
        if child.tag == 0x10:  # prf AlgorithmIdentifier (keyLength INTEGER is skipped)
            prf = _PBKDF2_PRFS.get(ber.decode_oid(child.children[0].content), "")
            if not prf:
                raise _UnsupportedPBE("unsupported PBKDF2 pseudo-random function")
    cipher_oid = ber.decode_oid(scheme.children[0].content)
    key_length = _PBES2_CIPHERS.get(cipher_oid)
    if key_length is None:
        raise _UnsupportedPBE("unsupported PBES2 cipher %s" % cipher_oid)
    iv = scheme.children[1].content
    if iterations < 1 or iterations > 10_000_000:
        raise CryptoError("implausible PBKDF2 iteration count in the bundle")
    key = PBKDF2HMAC(
        algorithm=getattr(hashes, prf)(), length=key_length, salt=salt, iterations=iterations
    ).derive(password.encode("utf-8"))
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    try:
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise CryptoError("could not decrypt the PKCS#12 certificates (wrong passphrase?)") from exc


def _openssl_rc2_40_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    base = [
        "openssl",
        "enc",
        "-d",
        "-rc2-40-cbc",
        "-nopad",
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
    ]
    attempts = [
        base + ["-provider", "legacy", "-provider", "default"],
        base,
    ]
    errors = []
    for command in attempts:
        try:
            result = subprocess.run(  # noqa: UP022 - capture_output is 3.7+
                command,
                input=ciphertext,
                stdout=subprocess.PIPE,  # noqa: UP022 - capture_output is 3.7+
                stderr=subprocess.PIPE,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - no openssl
            errors.append(str(exc))
            continue
        if result.returncode == 0:
            return result.stdout
        errors.append(result.stderr.decode("utf-8", "replace").strip())  # pragma: no cover - unsupported openssl
    raise CryptoError(
        "could not decrypt legacy RC2 PKCS#12 data; install an OpenSSL with "
        "legacy RC2 support: %s" % (errors[-1] if errors else "unknown error")
    )


def write_java_bundle(
    path: "str | Path",
    bundle: CertificateBundle,
    password: str,
    *,
    legacy: bool = True,
) -> str:
    """Write every certificate (and a matching key, if present) as PKCS#12.

    ``legacy=True`` uses PBE-SHA1-3DES + SHA-1 so the result can be read by the
    old Java CertWizard/keytool.  A bundle without a usable private key is
    written as a certificate-only PKCS#12, which is suitable for a truststore.
    """
    if not password:
        raise CryptoError("a password is required to write a Java bundle")
    certificates = [entry.certificate for entry in bundle.certificates]
    if not certificates:
        raise CryptoError("the bundle contains no certificates")
    if bundle.raw_key_bags or bundle.raw_cert_bags:
        p12.write_raw_pkcs12(
            Path(path),
            key_bags=bundle.raw_key_bags,
            cert_bags=bundle.raw_cert_bags,
            password=password,
        )
        return str(path)
    if bundle.has_private_key and bundle.private_key is None:
        raise CryptoError(
            "the bundle contains a private key that pyCertWiz cannot decode; "
            "use Save all PEM or let the Java tool convert it"
        )
    leaf = next((entry for entry in bundle.certificates if entry.role == "leaf"), None)
    key = bundle.private_key
    if key is not None and leaf is not None and certs.certificate_matches_key(leaf.certificate, key):
        chain = [
            entry.certificate
            for entry in bundle.certificates
            if certs.fingerprint(entry.certificate) != certs.fingerprint(leaf.certificate)
        ]
        p12.write_pkcs12(
            Path(path),
            key=key,
            certificate=leaf.certificate,
            chain=chain,
            password=password,
            friendly_name=certs.common_name(leaf.certificate.subject),
            legacy=legacy,
            preserve_chain=True,
        )
    else:
        p12.write_certificate_bundle(
            Path(path),
            certificates=certificates,
            password=password,
            legacy=legacy,
        )
    return str(path)


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
