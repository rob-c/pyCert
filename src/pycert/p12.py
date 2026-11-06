"""PKCS#12 (.p12) writing and reading.

Writing is delegated to ``cryptography``'s ``serialize_key_and_certificates``,
which produces a standard PKCS#12 v3 file:

* PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC for both the certificate bag
  and the shrouded private key (20 000 iterations, as implemented by OpenSSL);
* an HMAC-SHA-256 integrity MAC;
* a friendly name and a localKeyID linking key and certificate.

That is readable by OpenSSL 3, Java 11+, macOS Keychain, Firefox and Windows,
and unlike CertWizard's export it does not use a 7-character password limit or
legacy RC2/3DES ciphers.

Reading accepts whatever ``cryptography``/OpenSSL can parse, including the
legacy PBE-SHA1-3DES and RC2 files that CertWizard produced, so existing
keystores can be imported for renewal.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

from . import certs
from .errors import CryptoError, PyCertError
from .util import SECRET_FILE_MODE, atomic_write, ensure_dir


@dataclass
class P12Bundle:
    key: object
    cert: x509.Certificate
    chain: list[x509.Certificate]

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
    chain: list[x509.Certificate] | None = None,
    password: str,
    friendly_name: str = "",
    verify: bool = True,
) -> Path:
    """Write an encrypted PKCS#12 bundle and (by default) read it back."""
    if not password:
        raise PyCertError("refusing to write a PKCS#12 file without a password")
    if not certs.certificate_matches_key(certificate, key):
        raise CryptoError(
            "refusing to write a PKCS#12 file: the certificate's public key does not match the private key"
        )
    chain = _ordered_chain(certificate, chain or [])
    try:
        blob = pkcs12.serialize_key_and_certificates(
            name=(friendly_name or certs.common_name(certificate.subject))[:64].encode("utf-8"),
            key=key,
            cert=certificate,
            cas=chain or None,
            encryption_algorithm=BestAvailableEncryption(password.encode("utf-8")),
        )
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not create PKCS#12 bundle: {exc}") from exc
    path = Path(path)
    ensure_dir(path.parent)
    atomic_write(path, blob, mode=SECRET_FILE_MODE)
    if verify:
        bundle = read_pkcs12_bytes(blob, password)
        if certs.fingerprint(bundle.cert) != certs.fingerprint(certificate):
            raise CryptoError("PKCS#12 verification failed after writing: certificate mismatch")
        if not certs.public_keys_equal(bundle.cert, key.public_key()):
            raise CryptoError("PKCS#12 verification failed after writing: key mismatch")
    return path


def read_pkcs12(path: Path, password: str) -> P12Bundle:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PyCertError(f"cannot read PKCS#12 file {path}: {exc}") from exc
    return read_pkcs12_bytes(data, password)


def read_pkcs12_bytes(data: bytes, password: str) -> P12Bundle:
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
        cert = matches[0]
        extras = [c for c in extras if certs.fingerprint(c) != certs.fingerprint(cert)]
    if not certs.certificate_matches_key(cert, key):
        raise CryptoError("the PKCS#12 file is inconsistent: the certificate does not match the private key")
    chain = _ordered_chain(cert, extras)
    return P12Bundle(key, cert, chain)


def _ordered_chain(leaf: x509.Certificate, candidates: list[x509.Certificate]) -> list[x509.Certificate]:
    """Order issuer certificates leaf→root, dropping the leaf and duplicates."""
    leaf_fp = certs.fingerprint(leaf)
    pool = [c for c in candidates if certs.fingerprint(c) != leaf_fp]
    ordered: list[x509.Certificate] = []
    seen: set[str] = {leaf_fp}
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
