"""RFC 3820 proxy certificates and proxy bundles.

A proxy certificate is signed by an existing end-entity certificate and is
used for short-lived delegation (the traditional GSI/Grid use case).  pyCert
does not implement a general proxy authority: it creates a single delegated
proxy from a locally stored certificate and private key, verifies the result,
and writes a PEM bundle containing the proxy key, proxy certificate and issuer
chain.

The bundle is deliberately written with an explicit 0600 mode and can be
removed immediately after creation for tests and short-lived jobs.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from . import asn1, certs
from .compat import dataclass, not_valid_after, not_valid_before
from .errors import CryptoError, NotFound, PyCertError
from .util import SECRET_FILE_MODE, atomic_write

PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14"
PROXY_POLICY_INHERIT_ALL_OID = "1.3.6.1.5.5.7.21.1"
PROXY_POLICY_LIMITED_OID = "1.3.6.1.5.5.7.21.2"
MAX_PROXY_HOURS = 24 * 30


@dataclass
class ProxyBundle:
    path: str
    removed: bool
    subject: str
    issuer: str
    not_before: str
    not_after: str
    fingerprint: str
    chain_length: int

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "removed": self.removed,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "sha256_fingerprint": self.fingerprint,
            "chain_length": self.chain_length,
        }


def encode_proxy_cert_info(*, path_length: "int | None" = None, limited: bool = False) -> bytes:
    """DER-encode the RFC 3820 ProxyCertInfo extension.

    ``ProxyCertInfo ::= SEQUENCE {
         pCPathLenConstraint INTEGER OPTIONAL,
         proxyPolicy ProxyPolicy }``
    """
    if path_length is not None and path_length < 0:
        raise PyCertError("proxy path length must be zero or greater")
    policy_oid = PROXY_POLICY_LIMITED_OID if limited else PROXY_POLICY_INHERIT_ALL_OID
    policy = asn1.seq(asn1.oid(policy_oid))
    if path_length is None:
        return asn1.seq(policy)
    return asn1.seq(asn1.integer(path_length), policy)


def proxy_subject(issuer: x509.Certificate, *, limited: bool = False) -> x509.Name:
    """Subject of a proxy: the issuer DN plus a proxy CN (RFC 3820 style)."""
    attributes = list(issuer.subject)
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, "limited proxy" if limited else "proxy"))
    return x509.Name(attributes)


def _sign_builder(builder, issuer_key):
    if isinstance(issuer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return builder.sign(issuer_key, None)
    return builder.sign(issuer_key, hashes.SHA256())


def build_proxy_certificate(
    issuer: x509.Certificate,
    issuer_key,
    proxy_key,
    *,
    hours: int = 12,
    path_length: "int | None" = None,
    limited: bool = False,
    now: "datetime | None" = None,
) -> x509.Certificate:
    """Create a proxy certificate signed by *issuer* using *issuer_key*."""
    if hours <= 0 or hours > MAX_PROXY_HOURS:
        raise PyCertError("proxy validity must be between 1 and %d hours" % MAX_PROXY_HOURS)
    if not certs.certificate_matches_key(issuer, issuer_key):
        raise PyCertError("the issuer certificate does not match the private key")
    now = now or datetime.now(timezone.utc)
    if not certs.certificate_valid_at(issuer, now):
        raise PyCertError("the issuer certificate is outside its validity period")
    issuer_after = not_valid_after(issuer)
    not_after = min(issuer_after, now + timedelta(hours=hours))
    not_before = max(not_valid_before(issuer), now - timedelta(minutes=5))
    if not_after <= not_before:  # pragma: no cover - pathological issuer clock
        raise PyCertError("the proxy validity would be empty")
    subject = proxy_subject(issuer, limited=limited)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(proxy_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=isinstance(proxy_key, rsa.RSAPrivateKey),
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(proxy_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False
        )
    )
    try:
        issuer_eku = issuer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(issuer_eku)), critical=False)
    except x509.ExtensionNotFound:
        pass
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            ObjectIdentifier(PROXY_CERT_INFO_OID),
            encode_proxy_cert_info(path_length=path_length, limited=limited),
        ),
        critical=True,
    )
    proxy = _sign_builder(builder, issuer_key)
    certs.verify_certificate_signature(proxy, issuer)
    if not certs.certificate_matches_key(proxy, proxy_key):
        raise CryptoError("the generated proxy certificate does not match its private key")
    return proxy


def proxy_bundle_pem(proxy_key, proxy_cert, issuer_cert, chain, *, password: "str | bytes | None" = None) -> str:
    """PEM bundle: proxy key, proxy certificate, issuer, then issuer chain."""
    key_pem = certs.key_pem(proxy_key, password)
    parts = [key_pem, certs.cert_pem(proxy_cert), certs.cert_pem(issuer_cert)]
    seen = {certs.fingerprint(issuer_cert)}
    for certificate in chain or []:
        fingerprint = certs.fingerprint(certificate)
        if fingerprint not in seen:
            seen.add(fingerprint)
            parts.append(certs.cert_pem(certificate))
    return "".join(parts)


def load_proxy_bundle(path: "str | Path") -> "tuple[x509.Certificate, x509.Certificate]":
    """Load and verify a pyCert proxy bundle, returning (proxy, issuer)."""
    path = Path(path)
    if not path.is_file():
        raise NotFound("proxy bundle not found: %s" % path)
    data = path.read_bytes()
    certificates = certs.load_certificates(data)
    if len(certificates) < 2:
        raise CryptoError("proxy bundle does not contain proxy and issuer certificates")
    proxy = certificates[0]
    issuer = certificates[1]
    certs.verify_certificate_signature(proxy, issuer)
    try:
        info = proxy.extensions.get_extension_for_oid(ObjectIdentifier(PROXY_CERT_INFO_OID))
    except x509.ExtensionNotFound as exc:
        raise CryptoError("first certificate is not an RFC 3820 proxy certificate") from exc
    if not isinstance(info.value, x509.UnrecognizedExtension):  # pragma: no cover - stdlib parser shape
        raise CryptoError("proxy certificate has an unexpected ProxyCertInfo value")
    return proxy, issuer


def remove_proxy_bundle(path: "str | Path") -> bool:
    """Remove a proxy bundle if it exists; returns whether a file was removed."""
    path = Path(path)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def create_proxy_bundle(
    ctx,
    alias: str,
    out: "str | Path",
    *,
    hours: int = 12,
    path_length: "int | None" = None,
    limited: bool = False,
    rsa_bits: int = 2048,
    password: "str | bytes | None" = None,
    remove: bool = False,
    now: "datetime | None" = None,
) -> ProxyBundle:
    """Sign a proxy certificate from *alias* and write/remove its PEM bundle."""
    state = ctx.store.get(alias)
    issuer = ctx.store.load_certificate(state)
    issuer_key = ctx.store.load_key(state, ctx.key_passphrase())
    if not certs.certificate_matches_key(issuer, issuer_key):
        raise PyCertError("the stored private key does not match the certificate")
    if rsa_bits < 2048:
        raise PyCertError("proxy RSA keys must be at least 2048 bits")
    proxy_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    proxy = build_proxy_certificate(
        issuer,
        issuer_key,
        proxy_key,
        hours=hours,
        path_length=path_length,
        limited=limited,
        now=now,
    )
    chain = ctx.store.load_chain(state)
    bundle_text = proxy_bundle_pem(proxy_key, proxy, issuer, chain, password=password)
    path = Path(out).expanduser()
    atomic_write(path, bundle_text, SECRET_FILE_MODE)
    loaded_proxy, loaded_issuer = load_proxy_bundle(path)
    if loaded_proxy.fingerprint(hashes.SHA256()) != proxy.fingerprint(hashes.SHA256()):
        raise CryptoError("proxy bundle verification failed after writing")
    if loaded_issuer.fingerprint(hashes.SHA256()) != issuer.fingerprint(hashes.SHA256()):
        raise CryptoError("proxy bundle issuer verification failed after writing")
    removed = remove_proxy_bundle(path) if remove else False
    description = certs.describe_certificate(proxy)
    return ProxyBundle(
        path=str(path),
        removed=removed,
        subject=description.subject,
        issuer=description.issuer,
        not_before=description.not_before.isoformat(),
        not_after=description.not_after.isoformat(),
        fingerprint=description.fingerprint_sha256,
        chain_length=len(chain) + 1,
    )
