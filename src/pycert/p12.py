"""PKCS#12 (.p12) writing and reading.

Writing uses pyCert's own PKCS#12 container encoder
(:mod:`pycert.pkcs12_writer`) with primitives from ``cryptography``.  This keeps
the output identical on every supported Python instead of depending on the
OpenSSL version linked into ``cryptography`` (older releases fall back to
PBES2-SHA1-3DES):

* PBES2 with PBKDF2-HMAC-SHA256 (100,000 iterations) and AES-256-CBC for the
  key bag and the encrypted SafeContents;
* an HMAC-SHA-256 integrity MAC (20,000 KDF iterations), with a SHA-1 MAC
  fallback only for readers that cannot verify HMAC-SHA-256;
* a friendly name and a localKeyID linking key and certificate.

That is readable by OpenSSL 3, Java 11+, macOS Keychain, Firefox and Windows,
and unlike CertWizard's export it does not use a 7-character password limit or
legacy RC2/3DES ciphers.

Reading accepts whatever ``cryptography``/OpenSSL can parse, including the
legacy PBE-SHA1-3DES and RC2 files that CertWizard produced, so existing
keystores can be imported for renewal.
"""

import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from . import certs
from .compat import dataclass
from .errors import CryptoError, PyCertError
from .pkcs12_writer import (
    DEFAULT_ITERATIONS,
    DEFAULT_MAC_ITERATIONS,
    encode_certificate_bundle,
    encode_pkcs12,
    encode_raw_pkcs12,
)
from .util import SECRET_FILE_MODE, atomic_write, ensure_dir

MAX_P12_BYTES = 16 * 1024 * 1024
MAX_CHAIN_CERTIFICATES = 20


@dataclass
class P12Bundle:
    key: object
    cert: x509.Certificate
    chain: "list[x509.Certificate]"

    def as_dict(self) -> dict:
        return {
            "key": certs.key_description(self.key.public_key()),
            "certificate": certs.describe_certificate(self.cert).as_dict(),
            "chain": [certs.describe_certificate(c).as_dict() for c in self.chain],
        }


def write_pkcs12(
    path: Path,
    *,
    key,
    certificate: x509.Certificate,
    chain: "list[x509.Certificate] | None" = None,
    password: str,
    friendly_name: str = "",
    verify: bool = True,
    iterations: int = DEFAULT_ITERATIONS,
    mac_iterations: int = DEFAULT_MAC_ITERATIONS,
    legacy: bool = False,
    preserve_chain: bool = False,
) -> Path:
    """Write an encrypted PKCS#12 bundle and (by default) read it back.

    ``preserve_chain`` keeps unrelated certificates from a legacy bundle
    instead of reducing the chain to the path from leaf to root.
    """
    if not password:
        raise PyCertError("refusing to write a PKCS#12 file without a password")
    if not certs.certificate_matches_key(certificate, key):
        raise CryptoError(
            "refusing to write a PKCS#12 file: the certificate's public key does not match the private key"
        )
    if chain and len(chain) > MAX_CHAIN_CERTIFICATES:
        raise PyCertError("refusing to embed more than %d chain certificates" % MAX_CHAIN_CERTIFICATES)
    chain = list(chain or []) if preserve_chain else _ordered_chain(certificate, chain or [])
    name = (friendly_name or certs.common_name(certificate.subject))[:64]
    try:
        blob = encode_pkcs12(
            key,
            certificate,
            chain,
            password,
            name,
            iterations=iterations,
            mac_iterations=mac_iterations,
            mac_hash="sha256",
            legacy=legacy,
        )
        if verify:
            try:
                bundle = read_pkcs12_bytes(blob, password)
            except CryptoError:
                # Very old readers may not know HmacPBESHA256.  The PBE stays
                # PBES2/AES-256; only the integrity MAC falls back to SHA-1.
                blob = encode_pkcs12(
                    key,
                    certificate,
                    chain,
                    password,
                    name,
                    iterations=iterations,
                    mac_iterations=mac_iterations,
                    mac_hash="sha1",
                    legacy=legacy,
                )
                bundle = read_pkcs12_bytes(blob, password)
            if certs.fingerprint(bundle.cert) != certs.fingerprint(certificate):
                raise CryptoError("PKCS#12 verification failed after writing: certificate mismatch")
            if not certs.public_keys_equal(bundle.cert, key.public_key()):
                raise CryptoError("PKCS#12 verification failed after writing: key mismatch")
            if not certs.public_keys_equal(bundle.key.public_key(), key.public_key()):
                raise CryptoError("PKCS#12 verification failed after writing: private key mismatch")
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not create PKCS#12 bundle: {exc}") from exc
    path = Path(path)
    ensure_dir(path.parent)
    atomic_write(path, blob, mode=SECRET_FILE_MODE)
    return path


def write_certificate_bundle(
    path: Path,
    *,
    certificates: "list[x509.Certificate]",
    password: str,
    friendly_name: str = "",
    verify: bool = True,
    iterations: int = DEFAULT_ITERATIONS,
    mac_iterations: int = DEFAULT_MAC_ITERATIONS,
    legacy: bool = False,
) -> Path:
    """Write a certificate-only PKCS#12 bundle (all certificates, no key)."""
    if not password:
        raise PyCertError("refusing to write a PKCS#12 file without a password")
    if not certificates:
        raise PyCertError("refusing to write an empty certificate bundle")
    if len(certificates) > MAX_CHAIN_CERTIFICATES:
        raise PyCertError("refusing to embed more than %d certificates" % MAX_CHAIN_CERTIFICATES)
    try:
        blob = encode_certificate_bundle(
            certificates,
            password,
            friendly_name=friendly_name,
            iterations=iterations,
            mac_iterations=mac_iterations,
            mac_hash="sha1" if legacy else "sha256",
            legacy=legacy,
        )
        if verify:
            key, first, extras = pkcs12.load_key_and_certificates(blob, password.encode("utf-8"))
            if key is not None:
                raise CryptoError("PKCS#12 verification failed: unexpected private key")
            found = ([first] if first is not None else []) + list(extras or [])
            expected = {certs.fingerprint(c) for c in certificates}
            actual = {certs.fingerprint(c) for c in found}
            if expected != actual:
                raise CryptoError("PKCS#12 verification failed after writing: certificate mismatch")
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not create PKCS#12 certificate bundle: {exc}") from exc
    path = Path(path)
    ensure_dir(path.parent)
    atomic_write(path, blob, mode=SECRET_FILE_MODE)
    return path


def write_raw_pkcs12(
    path: Path,
    *,
    key_bags: "list[bytes]",
    cert_bags: "list[bytes]",
    password: str,
    mac_iterations: int = DEFAULT_MAC_ITERATIONS,
) -> Path:
    """Write raw Java PKCS#12 bags while retaining every key entry."""
    if not password:
        raise PyCertError("refusing to write a PKCS#12 file without a password")
    if not cert_bags:
        raise PyCertError("refusing to write an empty certificate bundle")
    blob = encode_raw_pkcs12(
        key_bags,
        cert_bags,
        password,
        mac_iterations=mac_iterations,
    )
    path = Path(path)
    ensure_dir(path.parent)
    atomic_write(path, blob, mode=SECRET_FILE_MODE)
    return path


def read_pkcs12(path: Path, password: str) -> P12Bundle:
    try:
        size = Path(path).stat().st_size
        if size > MAX_P12_BYTES:
            raise PyCertError("PKCS#12 file is larger than %d bytes" % MAX_P12_BYTES)
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PyCertError(f"cannot read PKCS#12 file {path}: {exc}") from exc
    return read_pkcs12_bytes(data, password)


def read_pkcs12_bytes(data: bytes, password: str) -> P12Bundle:
    if len(data) > MAX_P12_BYTES:
        raise PyCertError("PKCS#12 data is larger than %d bytes" % MAX_P12_BYTES)
    try:
        key, cert, extras = pkcs12.load_key_and_certificates(data, password.encode("utf-8"))
    except ValueError as exc:
        raise CryptoError(
            f"could not open the PKCS#12 file (wrong password, or an unsupported cipher such as RC2): {exc}"
        ) from exc
    if key is None:
        raise CryptoError("the PKCS#12 file does not contain a private key")
    extras = list(extras or [])
    if cert is None:
        matches = [c for c in extras if certs.public_keys_equal(c, key.public_key())]
        if not matches:
            raise CryptoError("the PKCS#12 file has no certificate for its private key")
        cert = matches[0]  # pragma: no cover - cryptography normally returns the certificate
        extras = [c for c in extras if certs.fingerprint(c) != certs.fingerprint(cert)]  # pragma: no cover
    if not certs.certificate_matches_key(cert, key):
        raise CryptoError("the PKCS#12 file is inconsistent: the certificate does not match the private key")
    chain = _ordered_chain(cert, extras)
    return P12Bundle(key, cert, chain)


def _ordered_chain(leaf: x509.Certificate, candidates: "list[x509.Certificate]") -> "list[x509.Certificate]":
    """Order issuer certificates leaf→root, dropping the leaf and duplicates."""
    leaf_fp = certs.fingerprint(leaf)
    pool = [c for c in candidates if certs.fingerprint(c) != leaf_fp]
    ordered: "list[x509.Certificate]" = []
    seen: "set[str]" = {leaf_fp}
    current = leaf
    while True:
        issuer = next(
            (c for c in pool if c.subject == current.issuer and certs.fingerprint(c) not in seen),
            None,
        )
        if issuer is None:
            break
        # Only accept an issuer whose signature actually verifies.
        try:
            certs.verify_certificate_signature(current, issuer)
        except CryptoError:
            break
        ordered.append(issuer)
        seen.add(certs.fingerprint(issuer))
        current = issuer
    return ordered


def describe_file(path: Path) -> dict:
    import stat as stat_module

    data = Path(path).read_bytes()
    stat = Path(path).stat()
    return {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "mode": oct(stat.st_mode & 0o777),
        "private_permissions": not (stat.st_mode & (stat_module.S_IRWXG | stat_module.S_IRWXO)),
        "modified": stat.st_mtime,
    }
