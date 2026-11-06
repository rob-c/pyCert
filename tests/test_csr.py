import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pycert import certs
from pycert import csr as csr_module
from pycert.errors import CryptoError

OPENSSL = shutil.which("openssl")


def _subject(kind="user"):
    return certs.build_subject(
        common_name="jane doe" if kind == "user" else "host.example.ac.uk",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )


@pytest.mark.parametrize("keysize", [2048, 3072])
def test_build_user_csr_rsa(keysize):
    key = rsa.generate_private_key(65537, keysize)
    request = csr_module.build_csr(
        key, _subject("user"), cert_type="user", email="jane@example.org", hash_name="sha256"
    )
    assert csr_module.signature_valid(request)
    summary = csr_module.summarize(request)
    assert summary.subject.endswith("CN=jane doe")
    assert summary.sans == ["email:jane@example.org"]
    assert summary.key == f"RSA {keysize}"
    assert "RSA" in summary.signature or summary.signature.startswith("1.2.840")


def test_build_host_csr_ec_adds_dns_san():
    key = ec.generate_private_key(ec.SECP256R1())
    request = csr_module.build_csr(key, _subject("host"), cert_type="host", email="admin@example.org")
    assert csr_module.signature_valid(request)
    san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["host.example.ac.uk"]
    assert san.get_values_for_type(x509.RFC822Name) == []
    assert csr_module.summarize(request).key == "ECDSA P-256"


def test_optional_extensions():
    key = rsa.generate_private_key(65537, 2048)
    request = csr_module.build_csr(
        key,
        _subject("user"),
        cert_type="user",
        email="jane@example.org",
        extensions=["san", "key_usage", "extended_key_usage", "basic_constraints"],
    )
    assert request.extensions.get_extension_for_class(x509.KeyUsage).critical
    usages = request.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in usages
    assert request.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_unknown_extension_is_rejected():
    key = rsa.generate_private_key(65537, 2048)
    with pytest.raises(CryptoError):
        csr_module.build_csr(key, _subject(), extensions=["not_a_thing"])


def test_multiple_sans_and_ip():
    key = rsa.generate_private_key(65537, 2048)
    request = csr_module.build_csr(
        key,
        _subject("host"),
        cert_type="host",
        dns_names=["host.example.ac.uk", "alias.example.ac.uk"],
        ip_addresses=["10.0.0.5"],
    )
    san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert len(san.get_values_for_type(x509.DNSName)) == 2
    assert str(san.get_values_for_type(x509.IPAddress)[0]) == "10.0.0.5"


def test_load_and_roundtrip(tmp_path):
    key = rsa.generate_private_key(65537, 2048)
    request = csr_module.build_csr(key, _subject(), email="jane@example.org")
    pem = csr_module.csr_pem(request)
    loaded = csr_module.load_csr(pem.encode())
    assert loaded.signature == request.signature
    with pytest.raises(CryptoError):
        csr_module.load_csr(b"not a csr")


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
def test_openssl_verifies_our_csr(tmp_path):
    key = rsa.generate_private_key(65537, 2048)
    request = csr_module.build_csr(key, _subject(), email="jane@example.org")
    path = tmp_path / "req.csr"
    path.write_text(csr_module.csr_pem(request))
    result = subprocess.run(
        [OPENSSL, "req", "-in", str(path), "-verify", "-noout"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "verify OK" in (result.stdout + result.stderr)
