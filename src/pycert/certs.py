"""Certificate, key and name helpers built on ``cryptography``.

All cryptographic operations are delegated to the ``cryptography`` library
(OpenSSL-backed, audited).  This module adds the policy pyCert needs on top:

* strict loading (a PEM file containing an unexpected object is an error, not a
  surprise);
* public-key equality checks (a certificate is only accepted for a private key
  if the SubjectPublicKeyInfo matches byte-for-byte);
* accurate, human-readable descriptions used by the CLI and the GUI;
* an OpenCA-compatible ordering of Distinguished Name attributes.
"""

import base64
import ipaddress
import warnings
from datetime import datetime, timezone
from typing import Iterable, Sequence, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)

from .compat import (
    dataclass,
    load_pem_certificates,
    not_valid_after,
    not_valid_before,
    pkcs7_load_der,
    pkcs7_load_pem,
    signature_parameters,
)
from .errors import CryptoError, UnsupportedAlgorithm

PrivateKey = Union[
    rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey
]
PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey]

HASH_ALGORITHMS = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha224": hashes.SHA224,
    "sha1": hashes.SHA1,  # verification of historic chains only; never generated
}


def hash_algorithm(name: str) -> hashes.HashAlgorithm:
    try:
        return HASH_ALGORITHMS[name.lower()]()
    except KeyError as exc:
        raise UnsupportedAlgorithm(f"unsupported hash: {name}") from exc


# ---------------------------------------------------------------------------
# Loading and serialising
# ---------------------------------------------------------------------------


def load_private_key(data: bytes, password: "bytes | str | None" = None) -> PrivateKey:
    if isinstance(password, str):
        password = password.encode()
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return serialization.load_pem_private_key(data, password=password)
        return serialization.load_der_private_key(data, password=password)
    except TypeError as exc:
        raise CryptoError("private key is encrypted but no password was supplied") from exc
    except ValueError as exc:
        if b"password" in data[:200].lower() or b"ENCRYPTED" in data[:200]:
            raise CryptoError("could not decrypt private key (wrong password or unsupported format)") from exc
        raise CryptoError(f"could not load private key: {exc}") from exc


def load_public_key(data: bytes) -> PublicKey:
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return serialization.load_pem_public_key(data)
        return serialization.load_der_public_key(data)
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not load public key: {exc}") from exc


def _quietly(func, *args, **kwargs):
    """Run a parser while ignoring "non-positive serial" deprecation noise.

    Some CAs (including the UK e-Science CA) publish certificates with a serial
    of zero; those are informational, not something pyCert creates, and the
    warning would otherwise be printed for every CA listing.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return func(*args, **kwargs)


def load_certificate(data: bytes) -> x509.Certificate:
    """Load exactly one certificate from PEM or DER."""
    try:
        if b"-----BEGIN" in data:
            certs = _quietly(load_pem_certificates, data)
            if len(certs) != 1:
                raise CryptoError(f"expected one certificate, found {len(certs)}")
            return certs[0]
        return _quietly(x509.load_der_x509_certificate, data)
    except ValueError as exc:
        raise CryptoError(f"could not load certificate: {exc}") from exc


def load_certificates(data: bytes) -> "list[x509.Certificate]":
    """Load every certificate from PEM/DER, a PEM bundle, or a PKCS#7 bundle.

    AIA retrieval commonly returns PKCS#7 DER, and the Java client happily
    accepted both PEM and DER, so pyCert does too.  Order is preserved and
    duplicates are removed.
    """
    if not data or not data.strip():
        raise CryptoError("empty certificate data")
    candidates: "list[list[x509.Certificate]]" = []
    if b"-----BEGIN" in data:
        errors = []
        for loader in (
            load_pem_certificates,
            pkcs7_load_pem,
        ):
            try:
                candidates.append(list(_quietly(loader, data)))
            except Exception as exc:  # noqa: BLE001 - try the next container
                errors.append(exc)
        if not candidates:
            raise CryptoError(f"could not parse PEM data: {errors[0]}")
    else:
        try:
            candidates.append([_quietly(x509.load_der_x509_certificate, data)])
        except ValueError:
            try:
                candidates.append(list(_quietly(pkcs7_load_der, data)))
            except Exception as exc:  # noqa: BLE001
                raise CryptoError(f"could not parse DER certificate/bundle: {exc}") from exc
    result: "list[x509.Certificate]" = []
    seen: "set[str]" = set()
    for batch in candidates:
        for cert in batch:
            fp = fingerprint(cert)
            if fp not in seen:
                seen.add(fp)
                result.append(cert)
    if not result:
        raise CryptoError("no certificates found")
    return result


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def certs_pem(certs: Iterable[x509.Certificate]) -> str:
    return "".join(cert_pem(c) for c in certs)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def key_pem(key: PrivateKey, password: "str | bytes | None" = None) -> str:
    if isinstance(password, str):
        password = password.encode()
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    ).decode("ascii")


def public_pem(key: PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def spki_der(key_or_cert: "PublicKey | x509.Certificate") -> bytes:
    key = key_or_cert.public_key() if isinstance(key_or_cert, x509.Certificate) else key_or_cert
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_b64(key_or_cert: "PublicKey | x509.Certificate") -> str:
    """Base64 SPKI, the identifier the CA uses in ``/resources/resource/publickey``."""
    return base64.b64encode(spki_der(key_or_cert)).decode("ascii")


def public_keys_equal(a: "PublicKey | x509.Certificate", b: "PublicKey | x509.Certificate") -> bool:
    """Byte-for-byte SubjectPublicKeyInfo comparison (not ``==``, which may raise)."""
    return spki_der(a) == spki_der(b)


# ---------------------------------------------------------------------------
# Descriptions
# ---------------------------------------------------------------------------


def fingerprint(cert: x509.Certificate, algorithm: str = "sha256") -> str:
    return cert.fingerprint(hash_algorithm(algorithm)).hex()


def formatted_fingerprint(cert: x509.Certificate, algorithm: str = "sha256") -> str:
    raw = cert.fingerprint(hash_algorithm(algorithm))
    return ":".join(f"{b:02X}" for b in raw)


def key_fingerprint(key: PublicKey) -> str:
    import hashlib

    return hashlib.sha256(spki_der(key)).hexdigest()


def key_description(key: PublicKey) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        friendly = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
        return f"ECDSA {friendly.get(key.curve.name, key.curve.name)}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(key).__name__


def signature_description(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    algorithm = getattr(oid, "_name", oid.dotted_string)
    try:
        digest = cert.signature_hash_algorithm.name.upper()
        return f"{algorithm} ({digest})"
    except (UnsupportedAlgorithm, ValueError):
        return str(algorithm)


def name_to_string(name: x509.Name) -> str:
    from .compat import name_to_string as _name_to_string

    return _name_to_string(name)


def _san_entries(cert: x509.Certificate) -> "list[str]":
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    entries: "list[str]" = []
    for kind, values in (
        ("DNS", san.get_values_for_type(x509.DNSName)),
        ("email", san.get_values_for_type(x509.RFC822Name)),
        ("IP", [str(v) for v in san.get_values_for_type(x509.IPAddress)]),
        ("URI", san.get_values_for_type(x509.UniformResourceIdentifier)),
    ):
        entries.extend(f"{kind}:{value}" for value in values)
    for value in san.get_values_for_type(x509.DirectoryName):
        entries.append(f"dirName:{value.rfc4514_string()}")
    return entries


def _ext(cert: x509.Certificate, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def _key_usage_list(usage: "x509.KeyUsage | None") -> "list[str]":
    if usage is None:
        return []
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    )
    result = []
    for name in names:
        try:
            enabled = getattr(usage, name)
        except ValueError:
            # cryptography raises for encipher_only/decipher_only when
            # key_agreement is false; that means "not asserted".
            enabled = False
        if enabled:
            result.append(name.replace("_", " "))
    return result


def _eku_list(eku: "x509.ExtendedKeyUsage | None") -> "list[str]":
    if eku is None:
        return []
    friendly = {
        ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
        ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
        ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
        ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
        ExtendedKeyUsageOID.TIME_STAMPING: "timeStamping",
        ExtendedKeyUsageOID.OCSP_SIGNING: "OCSPSigning",
    }
    return [friendly.get(oid, oid.dotted_string) for oid in eku]


def aia_urls(cert: x509.Certificate) -> "list[str]":
    aia = _ext(cert, x509.AuthorityInformationAccess)
    if not aia:
        return []
    return [
        desc.access_location.value
        for desc in aia
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
        and isinstance(desc.access_location, x509.UniformResourceIdentifier)
    ]


def _crl_urls(cert: x509.Certificate) -> "list[str]":
    points = _ext(cert, x509.CRLDistributionPoints)
    if not points:
        return []
    urls = []
    for point in points:
        if point.full_name:
            urls.extend(
                name.value for name in point.full_name if isinstance(name, x509.UniformResourceIdentifier)
            )
    return urls


@dataclass
class CertDescription:
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    days_remaining: int
    key: str
    signature: str
    fingerprint_sha256: str
    is_ca: bool
    is_self_signed: bool
    subject_alt_names: "list[str]"
    key_usage: "list[str]"
    extended_key_usage: "list[str]"
    aia_urls: "list[str]"
    crl_urls: "list[str]"
    basic_constraints: str
    subject_key_id: str
    authority_key_id: str

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before.astimezone(timezone.utc).isoformat(),
            "not_after": self.not_after.astimezone(timezone.utc).isoformat(),
            "days_remaining": self.days_remaining,
            "key": self.key,
            "signature": self.signature,
            "sha256_fingerprint": self.fingerprint_sha256,
            "is_ca": self.is_ca,
            "is_self_signed": self.is_self_signed,
            "subject_alt_names": self.subject_alt_names,
            "key_usage": self.key_usage,
            "extended_key_usage": self.extended_key_usage,
            "aia_urls": self.aia_urls,
            "crl_urls": self.crl_urls,
            "basic_constraints": self.basic_constraints,
            "subject_key_id": self.subject_key_id,
            "authority_key_id": self.authority_key_id,
        }


def describe_certificate(cert: x509.Certificate, now: "datetime | None" = None) -> CertDescription:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return _describe_certificate(cert, now)


def _describe_certificate(cert: x509.Certificate, now: "datetime | None" = None) -> CertDescription:
    now = now or datetime.now(timezone.utc)
    not_before = not_valid_before(cert)
    not_after = not_valid_after(cert)
    basic = _ext(cert, x509.BasicConstraints)
    ski = _ext(cert, x509.SubjectKeyIdentifier)
    aki = _ext(cert, x509.AuthorityKeyIdentifier)
    return CertDescription(
        subject=name_to_string(cert.subject),
        issuer=name_to_string(cert.issuer),
        serial=f"{cert.serial_number:X}",
        not_before=not_before,
        not_after=not_after,
        days_remaining=max(0, (not_after - now).days),
        key=key_description(cert.public_key()),
        signature=signature_description(cert),
        fingerprint_sha256=formatted_fingerprint(cert),
        is_ca=bool(basic and basic.ca),
        is_self_signed=cert.subject == cert.issuer,
        subject_alt_names=_san_entries(cert),
        key_usage=_key_usage_list(_ext(cert, x509.KeyUsage)),
        extended_key_usage=_eku_list(_ext(cert, x509.ExtendedKeyUsage)),
        aia_urls=aia_urls(cert),
        crl_urls=_crl_urls(cert),
        basic_constraints=(
            f"CA={basic.ca}"
            + (f", pathlen={basic.path_length}" if basic and basic.path_length is not None else "")
            if basic
            else "not present"
        ),
        subject_key_id=ski.digest.hex() if ski else "",
        authority_key_id=(aki.key_identifier or b"").hex() if aki else "",
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def is_weak_hash(name: str) -> bool:
    return name.lower() in {"md5", "sha1"}


def verify_certificate_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify *cert* was signed by *issuer*; raises CryptoError on failure.

    Uses the signature algorithm recorded in the certificate (so RSA-PSS and
    ECDSA certificates are handled), never a guess.
    """
    if cert.issuer != issuer.subject:
        raise CryptoError(
            f"issuer name mismatch: certificate issuer is '{name_to_string(cert.issuer)}', "
            f"candidate subject is '{name_to_string(issuer.subject)}'"
        )
    public_key = issuer.public_key()
    try:
        parameters = signature_parameters(cert)
    except (UnsupportedAlgorithm, ValueError) as exc:  # pragma: no cover - exotic algorithms
        raise CryptoError(f"unsupported signature algorithm: {signature_description(cert)}") from exc
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, parameters)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:  # pragma: no cover
            raise UnsupportedAlgorithm(f"unsupported issuer key type: {type(public_key).__name__}")
    except Exception as exc:  # cryptography raises InvalidSignature / ValueError
        raise CryptoError(
            f"signature verification failed for '{name_to_string(cert.subject)}': {exc}"
        ) from exc


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    try:
        verify_certificate_signature(cert, cert)
        return True
    except CryptoError:
        return False


def certificate_valid_at(cert: x509.Certificate, when: "datetime | None" = None) -> bool:
    when = when or datetime.now(timezone.utc)
    return not_valid_before(cert) <= when <= not_valid_after(cert)


def certificate_matches_key(cert: x509.Certificate, key: PrivateKey) -> bool:
    return public_keys_equal(cert, key.public_key())


def basic_constraints_ca(cert: x509.Certificate) -> "bool | None":
    """True/False when BasicConstraints is present, None when absent."""
    basic = _ext(cert, x509.BasicConstraints)
    return None if basic is None else basic.ca


def has_name_constraints_violation(cert: x509.Certificate, issuer: x509.Certificate) -> "list[str]":
    """Very small NameConstraints check for DNS SANs (defence in depth).

    pyCert only ever consumes certificates from the configured CA, so this is a
    sanity check rather than a general-purpose path validator.  Unsupported
    constraint types are ignored on purpose.
    """
    constraints = _ext(issuer, x509.NameConstraints)
    if not constraints:
        return []
    problems = []
    permitted = constraints.permitted_subtrees or []
    for entry in _san_entries(cert):
        if not entry.startswith("DNS:"):
            continue
        host = entry[4:].lower()
        for subtree in permitted:
            if isinstance(subtree, x509.DNSName):
                base = subtree.value.lower().lstrip(".")
                if not (host == base or host.endswith("." + base)):
                    problems.append(f"DNS name {host} is outside permitted subtree .{base}")
    return problems


# ---------------------------------------------------------------------------
# Names and subjects
# ---------------------------------------------------------------------------

# Order used by the UK e-Science CA (OpenCA) when it builds a PKCS#10 subject.
OPENCA_ATTRIBUTE_ORDER = [
    NameOID.EMAIL_ADDRESS,
    NameOID.COMMON_NAME,
    NameOID.LOCALITY_NAME,
    NameOID.STATE_OR_PROVINCE_NAME,
    NameOID.ORGANIZATIONAL_UNIT_NAME,
    NameOID.ORGANIZATION_NAME,
    NameOID.COUNTRY_NAME,
]


def canonical_openca_name(name: x509.Name) -> x509.Name:
    """Re-order RDN attributes into the order OpenCA expects.

    Unknown attribute types keep their relative order at the end.  Multi-valued
    RDNs are preserved (they are rare, but silently dropping attributes from an
    existing certificate's subject would be a bug).
    """
    attributes: "list[x509.RelativeDistinguishedName]" = list(name.rdns)
    ordered: "list[x509.RelativeDistinguishedName]" = []
    used: "set[int]" = set()
    for oid in OPENCA_ATTRIBUTE_ORDER:
        for index, rdn in enumerate(attributes):
            if index in used:
                continue
            if any(attr.oid == oid for attr in rdn):
                ordered.append(rdn)
                used.add(index)
    for index, rdn in enumerate(attributes):
        if index not in used:
            ordered.append(rdn)
    return x509.Name(ordered)


def build_subject(
    *,
    common_name: str,
    organization: str,
    organizational_unit: str,
    locality: str,
    country: str,
    state: "str | None" = None,
    email: "str | None" = None,
    include_email_in_subject: bool = False,
) -> x509.Name:
    """Build the CSR subject in the same order CertWizard used.

    The email is *not* part of the DN for user certificates (it goes into the
    SAN).  Historic host certificates sometimes carry ``emailAddress`` in the
    subject; that is only done when importing/renewing such a certificate.
    """
    attributes = []
    if include_email_in_subject and email:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    attributes += [
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ]
    if state:
        attributes.insert(3, x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    return x509.Name(attributes)


def name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> "str | None":
    for attribute in name:
        if attribute.oid == oid:
            return attribute.value
    return None


def common_name(name: x509.Name) -> str:
    value = name_attribute(name, NameOID.COMMON_NAME)
    if value is None:
        raise CryptoError("certificate subject has no common name")
    return value


def subject_alt_names(cert: x509.Certificate) -> "list[str]":
    return _san_entries(cert)


def parse_ip(value: str) -> "ipaddress.IPv4Address | ipaddress.IPv6Address":
    return ipaddress.ip_address(value)


def select_sans(cert: x509.Certificate) -> Sequence[str]:
    return tuple(_san_entries(cert))
