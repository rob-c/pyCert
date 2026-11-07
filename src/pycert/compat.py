"""Compatibility layer for Python 3.6+ and older versions of ``cryptography``.

pyCert supports Python 3.6 because some managed estates still run it.  That
means no ``dataclasses``, no ``tomllib``, no ``datetime.fromisoformat``, no
``subprocess.run(capture_output=...)`` and no ``datetime.UTC``.  It also means
``cryptography`` may be as old as 3.3.x, which lacks the modern convenience
attributes used elsewhere (``not_valid_before_utc``,
``signature_algorithm_parameters``, ``load_pem_x509_certificates``,
``CertificateSigningRequest.is_signature_valid``).

Everything version-specific lives here so the rest of the code can stay
readable.  Every helper has a single, documented behaviour and is covered by
tests that exercise both the modern and the fallback path (the fallback is
forced even on newer interpreters where possible).

Annotations in this project are partially quoted on purpose: syntax such as
``list[str]`` and ``X | None`` is only valid at runtime from Python 3.9/3.10,
and ``from __future__ import annotations`` does not exist on 3.6.  Quoted
annotations are part of PEP 484 and are understood by type checkers.
"""

import base64
import binascii
import re
import ssl
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Tuple

__all__ = [
    "PY36",
    "dataclass",
    "field",
    "fallback_dataclass",
    "fallback_field",
    "subprocess_run",
    "parse_iso_datetime",
    "not_valid_before",
    "not_valid_after",
    "certificate_valid_at",
    "signature_parameters",
    "csr_signature_valid",
    "name_to_string",
    "load_pem_certificates",
    "split_pem",
    "pkcs7_load_der",
    "pkcs7_load_pem",
    "set_minimum_tls_version",
    "package_data_dir",
    "merge_dicts",
    "get_ca_certificates",
]

PY36 = sys.version_info[:2] == (3, 6)


# ---------------------------------------------------------------------------
# dataclasses (3.7+) with a small, well-defined fallback for 3.6
# ---------------------------------------------------------------------------

try:  # pragma: no cover - exercised on 3.7+
    from dataclasses import dataclass, field  # type: ignore[assignment]  # novermin

    DATACLASSES_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised on 3.6
    from ._dataclasses import dataclass, field  # type: ignore[assignment]

    DATACLASSES_AVAILABLE = False

# The fallback is always importable so tests can exercise it on any version.
from ._dataclasses import dataclass as fallback_dataclass  # noqa: E402
from ._dataclasses import field as fallback_field  # noqa: E402

# ---------------------------------------------------------------------------
# subprocess (capture_output/text are 3.7+)
# ---------------------------------------------------------------------------


def subprocess_run(args, **kwargs):
    """``subprocess.run`` with the 3.7 convenience keywords translated."""
    capture = kwargs.pop("capture_output", False)
    text = kwargs.pop("text", None)
    if capture:
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
    if text is not None:
        kwargs["universal_newlines"] = text
    return subprocess.run(args, **kwargs)


# ---------------------------------------------------------------------------
# Dates (datetime.fromisoformat is 3.7+; *_utc is cryptography 42+)
# ---------------------------------------------------------------------------

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?)?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_iso_datetime(text: str) -> datetime:
    """Parse the ISO-8601 subset pyCert writes (always timezone-aware)."""
    if not isinstance(text, str):
        raise ValueError("timestamp must be a string")
    match = _ISO_RE.match(text.strip())
    if not match:
        raise ValueError(f"invalid ISO-8601 timestamp: {text!r}")
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    microsecond = int((fraction or "0").ljust(6, "0"))
    tz = timezone.utc
    if offset and offset != "Z":
        sign = 1 if offset[0] == "+" else -1
        digits = offset[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4])))
    return datetime(
        int(year),
        int(month),
        int(day),
        int(hour or 0),
        int(minute or 0),
        int(second or 0),
        microsecond,
        tzinfo=tz,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def not_valid_before(certificate) -> datetime:
    value = getattr(certificate, "not_valid_before_utc", None)  # noqa: B009
    if value is None:
        value = getattr(certificate, "not_valid_before")
    return _aware(value)


def not_valid_after(certificate) -> datetime:
    value = getattr(certificate, "not_valid_after_utc", None)  # noqa: B009
    if value is None:
        value = getattr(certificate, "not_valid_after")
    return _aware(value)


def certificate_valid_at(certificate, when: Optional[datetime] = None) -> bool:
    when = when or datetime.now(timezone.utc)
    return not_valid_before(certificate) <= when <= not_valid_after(certificate)


# ---------------------------------------------------------------------------
# cryptography compatibility
# ---------------------------------------------------------------------------

_ECDSA_OIDS = {
    "1.2.840.10045.4.1",  # ecdsa-with-SHA1
    "1.2.840.10045.4.3.1",  # ecdsa-with-SHA224
    "1.2.840.10045.4.3.2",  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3",  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4",  # ecdsa-with-SHA512
}
_RSA_PKCS1_OIDS = {
    "1.2.840.113549.1.1.4",  # md5WithRSA
    "1.2.840.113549.1.1.5",  # sha1WithRSA
    "1.2.840.113549.1.1.11",  # sha256WithRSA
    "1.2.840.113549.1.1.12",  # sha384WithRSA
    "1.2.840.113549.1.1.13",  # sha512WithRSA
    "1.2.840.113549.1.1.14",  # sha224WithRSA
}
_RSA_PSS_OID = "1.2.840.113549.1.1.10"


def signature_parameters(signed_object):
    """Return the padding/ECDSA parameters for verifying a certificate or CSR.

    Uses ``signature_algorithm_parameters`` when available (cryptography 41+)
    and derives the parameters from the signature OID on older versions.
    Raises ``cryptography.exceptions.UnsupportedAlgorithm`` for algorithms that
    older versions cannot express (notably RSA-PSS).
    """
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    parameters = getattr(signed_object, "signature_algorithm_parameters", None)
    if parameters is not None:
        return parameters
    oid = signed_object.signature_algorithm_oid.dotted_string
    if oid in _ECDSA_OIDS:
        return ec.ECDSA(signed_object.signature_hash_algorithm)
    if oid in _RSA_PKCS1_OIDS:
        return padding.PKCS1v15()
    if oid == _RSA_PSS_OID:
        raise UnsupportedAlgorithm("RSA-PSS signatures need cryptography 41 or newer")
    raise UnsupportedAlgorithm(f"unsupported signature algorithm OID {oid}")


def _verify_with_public_key(public_key, signature: bytes, data: bytes, parameters, hash_algorithm):
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, parameters, hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, parameters)
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, data)
    else:  # pragma: no cover - exotic key types
        raise ValueError(f"unsupported public key type: {type(public_key).__name__}")


def verify_signed_object(signed_object, issuer_public_key=None) -> None:
    """Verify a certificate or CSR signature (raises on failure)."""
    parameters = signature_parameters(signed_object)
    if issuer_public_key is None:
        public_key = signed_object.public_key()
        data = signed_object.tbs_certrequest_bytes
    else:
        public_key = issuer_public_key
        data = signed_object.tbs_certificate_bytes
    _verify_with_public_key(
        public_key,
        signed_object.signature,
        data,
        parameters,
        signed_object.signature_hash_algorithm,
    )


def csr_signature_valid(csr) -> bool:
    """``csr.is_signature_valid`` with a fallback for older cryptography."""
    value = getattr(csr, "is_signature_valid", None)
    if value is not None:
        return bool(value)
    try:
        verify_signed_object(csr)
        return True
    except Exception:  # noqa: BLE001 - any failure means invalid
        return False


def name_to_string(name, use_modern=True) -> str:
    """RFC 4514 string for an X.509 Name, with a fallback formatter."""
    method = getattr(name, "rfc4514_string", None) if use_modern else None
    if method is not None:
        return method()
    # Keep a local table: private cryptography mappings change between versions.
    mapping = {
        x509_oid("2.5.4.3"): "CN",
        x509_oid("2.5.4.4"): "SN",
        x509_oid("2.5.4.5"): "serialNumber",
        x509_oid("2.5.4.6"): "C",
        x509_oid("2.5.4.7"): "L",
        x509_oid("2.5.4.8"): "ST",
        x509_oid("2.5.4.9"): "street",
        x509_oid("2.5.4.10"): "O",
        x509_oid("2.5.4.11"): "OU",
        x509_oid("2.5.4.12"): "title",
        x509_oid("2.5.4.42"): "GN",
        x509_oid("1.2.840.113549.1.9.1"): "emailAddress",
        x509_oid("0.9.2342.19200300.100.1.25"): "DC",
        x509_oid("0.9.2342.19200300.100.1.1"): "UID",
    }
    parts = []
    for rdn in reversed(list(name.rdns)):
        for attribute in rdn:
            key = mapping.get(attribute.oid, attribute.oid.dotted_string)
            value = str(attribute.value)
            for char in ("\\", ",", "+", '"', "<", ">", ";", "="):
                value = value.replace(char, "\\" + char)
            parts.append(f"{key}={value}")
    return ",".join(parts)


def x509_oid(dotted):
    """Small helper so the fallback name formatter works on old cryptography."""
    from cryptography.x509 import ObjectIdentifier

    return ObjectIdentifier(dotted)


_PEM_BLOCK_RE = re.compile(
    rb"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----",
    re.DOTALL,
)


def split_pem(
    data: bytes, labels: Optional[Iterable[str]] = None, max_blocks: int = 200
) -> List[Tuple[str, bytes]]:
    """Return ``(label, der)`` pairs from a PEM bundle.

    A deliberate replacement for the 39+ ``load_pem_x509_certificates`` helper;
    it is strict about base64 and ignores text outside the blocks.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    wanted = set(labels) if labels else None
    blocks = []
    for match in _PEM_BLOCK_RE.finditer(data):
        if len(blocks) >= max_blocks:
            raise ValueError("PEM bundle contains more than %d blocks" % max_blocks)
        label = match.group(1).decode("ascii")
        if wanted is not None and label not in wanted:
            continue
        body = re.sub(rb"\s+", b"", match.group(2))
        try:
            der = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"invalid base64 in PEM block {label!r}: {exc}") from exc
        blocks.append((label, der))
    return blocks


CERTIFICATE_LABELS = ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE")


def load_pem_certificates(data: bytes, use_modern=True):
    """All X.509 certificates in a PEM bundle (new and old cryptography).

    ``use_modern=False`` forces the 3.6-era code path so it can be tested on a
    modern interpreter.
    """
    from cryptography import x509

    modern = getattr(x509, "load_pem_x509_certificates", None) if use_modern else None
    if modern is not None:
        return modern(data)
    blocks = split_pem(data, CERTIFICATE_LABELS)
    if not blocks:
        raise ValueError("no CERTIFICATE PEM block found")
    return [
        x509.load_pem_x509_certificate(
            (
                "-----BEGIN CERTIFICATE-----\n"
                + base64.encodebytes(der).decode("ascii")
                + "-----END CERTIFICATE-----\n"
            ).encode("ascii")
        )
        for _label, der in blocks
    ]


def pkcs7_load_der(data: bytes):
    """PKCS#7 certificates, or an empty list when unavailable/unsupported."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:  # pragma: no cover - cryptography < 3.2
        return []
    return list(pkcs7.load_der_pkcs7_certificates(data))


def pkcs7_load_pem(data: bytes):
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:  # pragma: no cover
        return []
    return list(pkcs7.load_pem_pkcs7_certificates(data))


# ---------------------------------------------------------------------------
# TLS (SSLContext.minimum_version is 3.7+)
# ---------------------------------------------------------------------------


def set_minimum_tls_version(context, version: str = "1.2") -> None:
    """Require at least TLS 1.2 on old and new Python versions."""
    minimum_version = getattr(context, "minimum_version", None)
    tls_version = getattr(ssl, "TLSVersion", None)
    if minimum_version is not None and tls_version is not None:
        mapping = {
            "1.2": tls_version.TLSv1_2,
            "1.3": tls_version.TLSv1_3,
        }
        if version in mapping:
            context.minimum_version = mapping[version]
        return
    options = getattr(context, "options", 0)
    options |= getattr(ssl, "OP_NO_SSLv2", 0)
    options |= getattr(ssl, "OP_NO_SSLv3", 0)
    options |= getattr(ssl, "OP_NO_TLSv1", 0)
    options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
    context.options = options


def get_ca_certificates(context) -> List[bytes]:
    """DER certificates from a default SSL context, tolerating old Pythons."""
    try:
        return list(context.get_ca_certs(binary_form=True))
    except (AttributeError, ssl.SSLError, OSError):  # pragma: no cover
        return []


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def package_data_dir() -> str:
    """Directory of bundled data files (works on 3.6 without importlib.resources)."""
    import os

    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ca")


def merge_dicts(left: dict, right: dict) -> dict:
    """``{**left, **right}`` without the 3.9 merge operator."""
    merged = dict(left)
    merged.update(right)
    return merged
