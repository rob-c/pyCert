"""Tests for the Python 3.6 / old-cryptography compatibility layer."""

import datetime as dt
import ssl
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert import bundled, certs, compat

# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("2024-01-02T03:04:05Z", dt.datetime(2024, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)),
        ("2024-01-02T03:04:05+00:00", dt.datetime(2024, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)),
        ("2024-01-02T03:04:05.123456Z", dt.datetime(2024, 1, 2, 3, 4, 5, 123456, tzinfo=dt.timezone.utc)),
        ("2024-01-02 03:04:05Z", dt.datetime(2024, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)),
        ("2024-01-02T03:04:05+02:00", dt.datetime(2024, 1, 2, 1, 4, 5, tzinfo=dt.timezone.utc)),
        ("2024-01-02T03:04:05-05:30", dt.datetime(2024, 1, 2, 8, 34, 5, tzinfo=dt.timezone.utc)),
        ("2024-01-02", dt.datetime(2024, 1, 2, tzinfo=dt.timezone.utc)),
        ("2024-01-02T03:04", dt.datetime(2024, 1, 2, 3, 4, tzinfo=dt.timezone.utc)),
    ],
)
def test_parse_iso_datetime(text, expected):
    parsed = compat.parse_iso_datetime(text)
    assert parsed == expected
    assert parsed.tzinfo is not None


@pytest.mark.parametrize(
    "text",
    ["", "not a date", "2024-13-01T00:00:00Z", "2024-01-32T00:00:00Z", "2024-01-02T25:00:00Z", "2024/01/02"],
)
def test_parse_iso_datetime_invalid(text):
    with pytest.raises(ValueError):
        compat.parse_iso_datetime(text)


class OldCert:
    def __init__(self, before, after):
        self.not_valid_before = before
        self.not_valid_after = after


class NewCert(OldCert):
    def __init__(self, before, after):
        OldCert.__init__(self, before, after)
        self.not_valid_before_utc = before.replace(tzinfo=dt.timezone.utc)
        self.not_valid_after_utc = after.replace(tzinfo=dt.timezone.utc)


def test_not_valid_dates_old_and_new():
    naive_before = dt.datetime(2024, 1, 1)
    naive_after = dt.datetime(2025, 1, 1)
    for cert in (OldCert(naive_before, naive_after), NewCert(naive_before, naive_after)):
        assert compat.not_valid_before(cert).tzinfo is dt.timezone.utc
        assert compat.not_valid_after(cert).tzinfo is dt.timezone.utc
        assert compat.certificate_valid_at(cert, dt.datetime(2024, 6, 1, tzinfo=dt.timezone.utc))
        assert not compat.certificate_valid_at(cert, dt.datetime(2023, 1, 1, tzinfo=dt.timezone.utc))


def test_real_certificate_dates_are_aware():
    for cert in bundled.certificates():
        assert compat.not_valid_before(cert).tzinfo is not None
        assert compat.not_valid_after(cert).tzinfo is not None


# ---------------------------------------------------------------------------
# PEM handling
# ---------------------------------------------------------------------------

PEM_BUNDLE = "".join(certs.cert_pem(c) for c in bundled.certificates())


def test_split_pem_bundle():
    blocks = compat.split_pem(PEM_BUNDLE.encode(), ("CERTIFICATE",))
    assert len(blocks) == 4
    assert all(label == "CERTIFICATE" and der for label, der in blocks)


def test_split_pem_ignores_other_labels():
    text = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n" + PEM_BUNDLE
    assert len(compat.split_pem(text, ("CERTIFICATE",))) == 4
    assert len(compat.split_pem(text)) == 5


def test_split_pem_tolerates_crlf_and_text():
    text = "some notes\r\n" + PEM_BUNDLE.replace("\n", "\r\n") + "trailing text\r\n"
    assert len(compat.split_pem(text, ("CERTIFICATE",))) == 4


def test_split_pem_rejects_bad_base64():
    with pytest.raises(ValueError):
        compat.split_pem("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")


def test_split_pem_empty():
    assert compat.split_pem(b"") == []


def test_load_pem_certificates_modern_and_fallback():
    modern = compat.load_pem_certificates(PEM_BUNDLE.encode())
    fallback = compat.load_pem_certificates(PEM_BUNDLE.encode(), use_modern=False)
    assert [certs.fingerprint(c) for c in modern] == [certs.fingerprint(c) for c in fallback]


def test_load_pem_certificates_no_blocks():
    with pytest.raises(ValueError):
        compat.load_pem_certificates(b"nothing here", use_modern=False)


def test_load_pem_certificates_fallback_rejects_garbage():
    with pytest.raises(ValueError):
        compat.load_pem_certificates(
            b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n", use_modern=False
        )


# ---------------------------------------------------------------------------
# cryptography helpers
# ---------------------------------------------------------------------------


class FakeOID:
    def __init__(self, dotted, name="fake"):
        self.dotted_string = dotted
        self._name = name


class FakeSigned:
    def __init__(self, dotted):
        self.signature_algorithm_oid = FakeOID(dotted)
        self.signature_hash_algorithm = hashes.SHA256()
        self.signature_algorithm_parameters = None


@pytest.mark.parametrize(
    "oid,expected_type",
    [
        ("1.2.840.113549.1.1.11", "PKCS1v15"),
        ("1.2.840.113549.1.1.5", "PKCS1v15"),
        ("1.2.840.10045.4.3.2", "ECDSA"),
        ("1.2.840.10045.4.1", "ECDSA"),
    ],
)
def test_signature_parameters_fallback(oid, expected_type):
    parameters = compat.signature_parameters(FakeSigned(oid))
    assert type(parameters).__name__ == expected_type


def test_signature_parameters_pss_on_old_cryptography_is_unsupported():
    from cryptography.exceptions import UnsupportedAlgorithm

    with pytest.raises(UnsupportedAlgorithm):
        compat.signature_parameters(FakeSigned("1.2.840.113549.1.1.10"))


def test_signature_parameters_unknown_oid():
    from cryptography.exceptions import UnsupportedAlgorithm

    with pytest.raises(UnsupportedAlgorithm):
        compat.signature_parameters(FakeSigned("1.2.3.4"))


def _csr():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "compat")])
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("compat.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )


def test_csr_signature_valid_real_and_fallback():
    csr = _csr()
    assert compat.csr_signature_valid(csr) is True

    class HiddenProperty:
        def __getattr__(self, name):
            if name == "is_signature_valid":
                raise AttributeError(name)
            return getattr(csr, name)

    assert compat.csr_signature_valid(HiddenProperty()) is True


def test_csr_signature_valid_detects_tampering():
    csr = _csr()
    tampered = bytearray(
        csr.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)
    )
    tampered[-1] ^= 0xFF
    broken = x509.load_der_x509_csr(bytes(tampered))
    assert compat.csr_signature_valid(broken) is False


def test_verify_signed_object_raises_on_bad_signature():
    from cryptography.exceptions import UnsupportedAlgorithm

    with pytest.raises((AttributeError, UnsupportedAlgorithm)):
        compat.verify_signed_object(object())


def test_name_to_string_modern_and_fallback():
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(NameOID.COMMON_NAME, "a, b"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "x@example.org"),
        ]
    )
    assert compat.name_to_string(name) == name.rfc4514_string()
    fallback = compat.name_to_string(name, use_modern=False)
    assert "CN=a\\, b" in fallback
    assert fallback.startswith("emailAddress=")


# ---------------------------------------------------------------------------
# TLS / subprocess / misc
# ---------------------------------------------------------------------------


def test_set_minimum_tls_version_modern_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    compat.set_minimum_tls_version(context)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_set_minimum_tls_version_old_context():
    class OldContext:
        options = 0

    context = OldContext()
    compat.set_minimum_tls_version(context)
    assert context.options & ssl.OP_NO_TLSv1_1
    assert context.options & ssl.OP_NO_TLSv1


def test_set_minimum_tls_version_13_on_modern():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    compat.set_minimum_tls_version(context, "1.3")
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3


def test_get_ca_certificates_from_default_context():
    context = ssl.create_default_context()
    certs_der = compat.get_ca_certificates(context)
    assert certs_der and isinstance(certs_der[0], bytes)


def test_get_ca_certificates_old_object():
    assert compat.get_ca_certificates(object()) == []


def test_subprocess_run_capture_translation():
    result = compat.subprocess_run(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "out"
    assert result.stderr.strip() == "err"


def test_subprocess_run_check_failure():
    import subprocess as sp

    with pytest.raises(sp.CalledProcessError):
        compat.subprocess_run([sys.executable, "-c", "raise SystemExit(3)"], check=True)


def test_merge_dicts():
    left = {"a": 1, "b": 2}
    merged = compat.merge_dicts(left, {"b": 3, "c": 4})
    assert merged == {"a": 1, "b": 3, "c": 4}
    assert left == {"a": 1, "b": 2}


def test_package_data_dir_exists():
    from pathlib import Path

    path = Path(compat.package_data_dir())
    assert path.is_dir()
    assert (path / "escience-root.pem").is_file()


def test_pkcs7_helpers_are_available_or_raise_cleanly():
    # Old cryptography may not ship pkcs7 (returns []); new versions raise on
    # malformed DER.  Either is acceptable, but it must not crash the process.
    try:
        result = compat.pkcs7_load_der(b"junk")
    except ValueError:
        return
    assert isinstance(result, list)


def test_py36_flag_is_boolean():
    assert isinstance(compat.PY36, bool)
