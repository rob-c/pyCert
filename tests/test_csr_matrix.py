"""CSR construction matrix across keys, SANs, extensions and hashes."""

import functools
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import certs
from pycert import csr as csr_module
from pycert.errors import CryptoError

OPENSSL = shutil.which("openssl")


@functools.cache
def _key(kind):
    if kind == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "rsa3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind == "ec521":
        return ec.generate_private_key(ec.SECP521R1())
    raise AssertionError(kind)


def subject(cn="jane doe"):
    return certs.build_subject(
        common_name=cn,
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )


@pytest.mark.parametrize("kind", ["rsa2048", "rsa3072", "ec256", "ec384", "ec521"])
@pytest.mark.parametrize("cert_type", ["user", "host"])
def test_key_and_type_matrix(kind, cert_type):
    key = _key(kind)
    cn = "host.example.ac.uk" if cert_type == "host" else "jane doe"
    request = csr_module.build_csr(key, subject(cn), cert_type=cert_type, email="jane@example.org")
    assert csr_module.signature_valid(request)
    summary = csr_module.summarize(request)
    assert summary.subject.endswith("CN=%s" % cn)
    san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if cert_type == "host":
        assert san.get_values_for_type(x509.DNSName) == [cn]
    else:
        assert san.get_values_for_type(x509.RFC822Name) == ["jane@example.org"]


@pytest.mark.parametrize(
    "dns,emails,ips,expected",
    [
        (None, None, None, ["email:jane@example.org"]),
        (
            ["a.example", "b.example"],
            None,
            None,
            ["DNS:a.example", "DNS:b.example", "email:jane@example.org"],
        ),
        (None, ["alt@example.org"], None, ["email:jane@example.org", "email:alt@example.org"]),
        (
            None,
            None,
            ["10.0.0.1", "2001:db8::1"],
            ["email:jane@example.org", "IP:10.0.0.1", "IP:2001:db8::1"],
        ),
        (
            ["a.example"],
            ["alt@example.org"],
            ["127.0.0.1"],
            ["DNS:a.example", "email:jane@example.org", "email:alt@example.org", "IP:127.0.0.1"],
        ),
    ],
)
def test_san_matrix(dns, emails, ips, expected):
    request = csr_module.build_csr(
        _key("ec256"),
        subject(),
        cert_type="user",
        email="jane@example.org",
        dns_names=dns,
        email_names=emails,
        ip_addresses=ips,
    )
    summary = csr_module.summarize(request)
    assert summary.sans == expected


EXTENSION_COMBOS = [
    ["san"],
    ["san", "key_usage"],
    ["san", "extended_key_usage"],
    ["san", "basic_constraints"],
    ["san", "key_usage", "extended_key_usage"],
    ["san", "key_usage", "basic_constraints"],
    ["key_usage"],
    ["san", "key_usage", "extended_key_usage", "basic_constraints"],
]


@pytest.mark.parametrize("extensions", EXTENSION_COMBOS)
@pytest.mark.parametrize("cert_type", ["user", "host"])
def test_extension_matrix(extensions, cert_type):
    request = csr_module.build_csr(
        _key("rsa2048"),
        subject("host.example.ac.uk" if cert_type == "host" else "jane doe"),
        cert_type=cert_type,
        email="jane@example.org",
        extensions=extensions,
    )
    labels = set()
    for extension in request.extensions:
        labels.add(extension.oid._name)
    if "san" in extensions:
        assert "subjectAltName" in labels
    if "key_usage" in extensions:
        assert "keyUsage" in labels
    if "extended_key_usage" in extensions:
        assert "extendedKeyUsage" in labels
    if "basic_constraints" in extensions:
        assert "basicConstraints" in labels


@pytest.mark.parametrize("hash_name", ["sha256", "sha384", "sha512"])
@pytest.mark.parametrize("kind", ["rsa2048", "ec384"])
def test_hash_matrix(hash_name, kind):
    request = csr_module.build_csr(_key(kind), subject(), email="jane@example.org", hash_name=hash_name)
    assert csr_module.signature_valid(request)
    assert request.signature_hash_algorithm.name == hash_name


@pytest.mark.parametrize(
    "cn,email",
    [
        ("jane doe", "jane@example.org"),
        ("jane  doe", "jane+tag@example.org"),
        ("a b", "a@b.example"),
        ("empl oyee", "employee@sub.example.org"),
    ],
)
def test_subject_variants(cn, email):
    request = csr_module.build_csr(_key("ec256"), subject(cn), email=email)
    assert certs.name_attribute(request.subject, NameOID.COMMON_NAME) == cn
    san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.RFC822Name) == [email]


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"extensions": ["bogus"]}, "unsupported"),
        ({"cert_type": "banana"}, "invalid certificate type"),
        ({"hash_name": "md5"}, "unsupported"),
    ],
)
def test_bad_build_arguments(kwargs, match):
    with pytest.raises(CryptoError, match=match):
        csr_module.build_csr(_key("ec256"), subject(), email="jane@example.org", **kwargs)


def test_host_without_common_name():
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eScience")])
    with pytest.raises(CryptoError, match="common name"):
        csr_module.build_csr(_key("ec256"), name, cert_type="host")


@pytest.mark.parametrize(
    "payload",
    [b"", b"not a csr", b"-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"],
)
def test_load_invalid_csr(payload):
    with pytest.raises(CryptoError):
        csr_module.load_csr(payload)


def test_csr_pem_der_roundtrip():
    request = csr_module.build_csr(_key("ec256"), subject(), email="jane@example.org")
    pem = csr_module.csr_pem(request)
    der = csr_module.csr_der(request)
    assert csr_module.load_csr(pem.encode()).signature == request.signature
    assert csr_module.load_csr(der).signature == request.signature
    assert csr_module.summarize(request).as_dict()["signature_valid"] is True


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
@pytest.mark.parametrize("kind", ["rsa2048", "ec384"])
def test_openssl_can_verify_our_csr(tmp_path, kind):
    request = csr_module.build_csr(_key(kind), subject(), email="jane@example.org")
    path = tmp_path / "request.csr"
    path.write_text(csr_module.csr_pem(request))
    result = subprocess.run(
        [OPENSSL, "req", "-in", str(path), "-verify", "-noout"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "verify OK" in (result.stdout + result.stderr)
