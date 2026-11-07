"""PKCS#10 certificate signing request construction and inspection.

The CSR follows what the UK e-Science CA (OpenCA) expects and what CertWizard
produced, with the parts that were dangerous or missing fixed:

* SHA-256 signatures by default (CertWizard's template default was MD5withRSA);
* the subject alternative name is always present (e-mail for user certificates,
  DNS name for host certificates), as the CA requires;
* optional key usage / extended key usage / basic constraints, off by default
  for byte-for-byte compatibility with the existing CA, and available for CAs
  that honour CSR extensions.
"""

import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from . import certs
from .compat import csr_signature_valid, dataclass
from .errors import CryptoError

DEFAULT_HASH = "sha256"
KNOWN_EXTENSIONS = ("san", "key_usage", "extended_key_usage", "basic_constraints")


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_csr(data)
        return x509.load_der_x509_csr(data)
    except ValueError as exc:
        raise CryptoError(f"could not parse certificate signing request: {exc}") from exc


def csr_pem(csr: x509.CertificateSigningRequest) -> str:
    from cryptography.hazmat.primitives import serialization

    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def csr_der(csr: x509.CertificateSigningRequest) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return csr.public_bytes(serialization.Encoding.DER)


def build_csr(
    key,
    subject: x509.Name,
    *,
    cert_type: str = "user",
    email: str = "",
    dns_names: "list[str] | None" = None,
    email_names: "list[str] | None" = None,
    ip_addresses: "list[str] | None" = None,
    extensions: "list[str] | None" = None,
    hash_name: str = DEFAULT_HASH,
) -> x509.CertificateSigningRequest:
    """Build and sign a PKCS#10 request.

    :param cert_type: ``"user"`` (SAN = e-mail) or ``"host"`` (SAN = DNS).
    :param dns_names: extra DNS names (host certificates default to the CN).
    :param email_names: extra e-mail SANs.
    :param ip_addresses: IP SANs.
    :param extensions: subset of :data:`KNOWN_EXTENSIONS`; ``["san"]`` is enough
        for the UK e-Science CA.
    """
    if cert_type not in ("user", "host"):
        raise CryptoError(f"invalid certificate type: {cert_type!r}")
    extensions = list(extensions or ["san"])
    unknown = set(extensions) - set(KNOWN_EXTENSIONS)
    if unknown:
        raise CryptoError(f"unsupported CSR extension(s): {sorted(unknown)}")

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    # Subject alternative names -------------------------------------------------
    general_names: "list[x509.GeneralName]" = []
    for name in dns_names or []:
        general_names.append(x509.DNSName(name))
    if cert_type == "host" and not general_names:
        cn = certs.name_attribute(subject, x509.oid.NameOID.COMMON_NAME)
        if not cn:
            raise CryptoError("host certificate request needs a common name")
        general_names.append(x509.DNSName(cn))
    # For user certificates the contact e-mail is always part of the SAN (the
    # CA checks it against the <Email> element); extra e-mail SANs follow.
    if cert_type == "user" and email:
        general_names.append(x509.RFC822Name(email))
    for name in email_names or []:
        if cert_type == "user" and name == email:
            continue
        general_names.append(x509.RFC822Name(name))
    for value in ip_addresses or []:
        general_names.append(x509.IPAddress(ipaddress.ip_address(value)))
    if general_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(general_names), critical=False)

    # Optional extensions -------------------------------------------------------
    if "key_usage" in extensions:
        if isinstance(key, rsa.RSAPrivateKey):
            usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        else:
            usage = x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        builder = builder.add_extension(usage, critical=True)

    if "extended_key_usage" in extensions:
        usages = (
            [ExtendedKeyUsageOID.SERVER_AUTH]
            if cert_type == "host"
            else [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]
        )
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)

    if "basic_constraints" in extensions:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)

    try:
        return builder.sign(private_key=key, algorithm=certs.hash_algorithm(hash_name))
    except (ValueError, TypeError) as exc:
        raise CryptoError(f"could not create certificate signing request: {exc}") from exc


def signature_valid(csr: x509.CertificateSigningRequest) -> bool:
    return csr_signature_valid(csr)


@dataclass
class CSRSummary:
    subject: str
    key: str
    signature: str
    sans: "list[str]"
    signature_valid: bool

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "key": self.key,
            "signature": self.signature,
            "subject_alt_names": self.sans,
            "signature_valid": self.signature_valid,
        }


def summarize(csr: x509.CertificateSigningRequest) -> CSRSummary:
    sans: "list[str]" = []
    try:
        extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        extension = None
    if extension is not None:
        sans.extend(f"DNS:{v}" for v in extension.get_values_for_type(x509.DNSName))
        sans.extend(f"email:{v}" for v in extension.get_values_for_type(x509.RFC822Name))
        sans.extend(f"IP:{v}" for v in extension.get_values_for_type(x509.IPAddress))
    return CSRSummary(
        subject=csr.subject.rfc4514_string(),
        key=certs.key_description(csr.public_key()),
        signature=getattr(csr.signature_algorithm_oid, "_name", csr.signature_algorithm_oid.dotted_string),
        sans=sans,
        signature_valid=signature_valid(csr),
    )


def split_ec_and_rsa(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "rsa"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ec"
    raise CryptoError(f"unsupported key type: {type(key).__name__}")
