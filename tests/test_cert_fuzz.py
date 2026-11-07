"""Randomised and boundary tests for certificate/key/CSR loaders."""

import base64
import random

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from pycert import bundled, certs, compat
from pycert import csr as csr_module
from pycert.errors import CryptoError


@pytest.mark.parametrize("seed", range(100))
def test_random_bytes_never_crash_loaders(seed):
    rng = random.Random(seed)
    payload = bytes(rng.randrange(256) for _ in range(rng.randint(0, 2048)))
    for loader in (
        certs.load_certificate,
        certs.load_certificates,
        csr_module.load_csr,
        certs.load_private_key,
    ):
        with pytest.raises(CryptoError):
            loader(payload)


@pytest.mark.parametrize("seed", range(50))
def test_random_pem_wrapped_bytes_never_crash(seed):
    rng = random.Random(seed + 1000)
    body = base64.b64encode(bytes(rng.randrange(256) for _ in range(64))).decode()
    pem = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % body
    with pytest.raises(CryptoError):
        certs.load_certificates(pem.encode())


def test_truncated_real_certificates_are_rejected():
    der = bundled.certificates()[0].public_bytes(Encoding.DER)
    for fraction in (0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99):
        truncated = der[: int(len(der) * fraction)]
        with pytest.raises(CryptoError):
            certs.load_certificate(truncated)


def test_truncated_pem_is_rejected():
    pem = certs.cert_pem(bundled.certificates()[0])
    for fraction in (0.1, 0.5, 0.9):
        with pytest.raises(CryptoError):
            certs.load_certificate(pem[: int(len(pem) * fraction)].encode())


@pytest.mark.parametrize(
    "pem",
    [
        b"-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        b"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n",
        b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n",
        b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END X509 CERTIFICATE-----\n",
        b"garbage\n-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
        b"\xef\xbb\xbf-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
    ],
)
def test_bad_pem_variants(pem):
    with pytest.raises(CryptoError):
        certs.load_certificates(pem)


def test_certificate_size_limit():
    with pytest.raises(CryptoError, match="larger"):
        certs.load_certificate(b"x" * (certs.MAX_CERTIFICATE_BYTES + 1))


def test_bundle_size_limit():
    with pytest.raises(CryptoError, match="larger"):
        certs.load_certificates(b"x" * (certs.MAX_BUNDLE_BYTES + 1))


def test_private_key_size_limit():
    with pytest.raises(CryptoError, match="larger"):
        certs.load_private_key(b"x" * (certs.MAX_CERTIFICATE_BYTES + 1))


def test_certificate_count_limit(monkeypatch):
    monkeypatch.setattr(certs, "MAX_CERTIFICATES", 2)
    pem = "".join(certs.cert_pem(c) for c in bundled.certificates()[:3])
    with pytest.raises(CryptoError, match="more than 2"):
        certs.load_certificates(pem.encode())


def test_split_pem_block_limit():
    pem = b"".join((b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n") for _ in range(3))
    with pytest.raises(ValueError, match="more than 2"):
        compat.split_pem(pem, max_blocks=2)


def test_duplicate_certificates_are_deduplicated():
    cert = bundled.certificates()[0]
    pem = certs.cert_pem(cert) * 5
    assert len(certs.load_certificates(pem.encode())) == 1


def test_pkcs7_der_and_pem_if_openssl_available(tmp_path):
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl CLI not available")
    pem = tmp_path / "cert.pem"
    pem.write_text(certs.cert_pem(bundled.certificates()[0]))
    der = tmp_path / "cert.p7b"
    result = subprocess.run(
        [openssl, "crl2pkcs7", "-nocrl", "-certfile", str(pem), "-outform", "DER", "-out", str(der)],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("openssl cannot create PKCS#7")
    loaded = certs.load_certificates(der.read_bytes())
    assert len(loaded) == 1


def test_private_key_wrong_password_is_crypto_error():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    data = key.private_bytes(
        Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"right"),
    )
    with pytest.raises(CryptoError):
        certs.load_private_key(data, "wrong")
