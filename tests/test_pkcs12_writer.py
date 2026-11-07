"""PKCS#12 writer tests: KDF vectors, structure, MAC and round-trips."""

import datetime as dt
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import certs
from pycert import p12 as p12_module
from pycert.errors import CryptoError
from pycert.pkcs12_writer import (
    DEFAULT_ITERATIONS,
    _bmp_password,
    encode_pkcs12,
    pkcs12_kdf,
)

OPENSSL = shutil.which("openssl")


def key(kind="ec"):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def certificate(private_key, cn="writer", issuer=None, issuer_key=None, ca=False, days=30):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key or private_key, hashes.SHA256())
    )


# RFC 7292 appendix B / golang.org/x/crypto/pkcs12 test vectors -------------
@pytest.mark.parametrize(
    "password,salt,purpose,iterations,length,expected",
    [
        (
            b"\x00\x00",
            bytes.fromhex("f37e05b518324b4b"),
            1,
            2048,
            24,
            "00f759ff47d14dd03665d5943cb3c4a39a2555c02aed66e1",
        ),
        (
            "sesame".encode("utf-16-be") + b"\x00\x00",
            b"\xff" * 8,
            1,
            2048,
            24,
            "7cd9fd3e2b3be7691a44e3bef0f9ea0fb9b897d4e325d9d1",
        ),
    ],
)
def test_pkcs12_kdf_known_answers(password, salt, purpose, iterations, length, expected):
    assert pkcs12_kdf(password, salt, purpose, iterations, length, "sha1").hex() == expected


def test_bmp_password():
    assert _bmp_password("Beavis").hex() == "0042006500610076006900730000"


@pytest.mark.parametrize("mac_hash", ["sha256", "sha1"])
@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_writer_roundtrip(tmp_path, kind, mac_hash):
    private_key = key(kind)
    leaf = certificate(private_key)
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(
        path,
        key=private_key,
        certificate=leaf,
        chain=[],
        password="secret-123",
        friendly_name="writer test",
        iterations=2000,
        mac_iterations=500,
    )
    bundle = p12_module.read_pkcs12(path, "secret-123")
    assert certs.fingerprint(bundle.cert) == certs.fingerprint(leaf)
    assert certs.public_keys_equal(bundle.key.public_key(), private_key.public_key())


def test_writer_with_chain(tmp_path):
    root_key = key()
    root = certificate(root_key, "root", ca=True, days=365)
    intermediate_key = key()
    intermediate = certificate(intermediate_key, "intermediate", issuer=root, issuer_key=root_key, ca=True)
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf", issuer=intermediate, issuer_key=intermediate_key)
    path = tmp_path / "chain.p12"
    p12_module.write_pkcs12(
        path,
        key=leaf_key,
        certificate=leaf,
        chain=[intermediate, root],
        password="secret-123",
        iterations=2000,
        mac_iterations=500,
    )
    bundle = p12_module.read_pkcs12(path, "secret-123")
    assert len(bundle.chain) == 2
    assert certs.fingerprint(bundle.chain[0]) == certs.fingerprint(intermediate)
    assert certs.fingerprint(bundle.chain[1]) == certs.fingerprint(root)


def test_mac_failure_on_tamper(tmp_path):
    private_key = key()
    leaf = certificate(private_key)
    blob = encode_pkcs12(private_key, leaf, [], "secret-123", "x", iterations=2000, mac_iterations=500)
    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF  # MAC data
    path = tmp_path / "tampered.p12"
    path.write_bytes(bytes(tampered))
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12(path, "secret-123")


def test_wrong_password(tmp_path):
    private_key = key()
    leaf = certificate(private_key)
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(
        path,
        key=private_key,
        certificate=leaf,
        chain=[],
        password="right",
        iterations=1000,
        mac_iterations=100,
    )
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12(path, "wrong")


def test_invalid_arguments():
    private_key = key()
    leaf = certificate(private_key)
    with pytest.raises(ValueError):
        encode_pkcs12(private_key, leaf, [], "", iterations=10)
    with pytest.raises(ValueError):
        encode_pkcs12(private_key, leaf, [], "pw", iterations=0)
    with pytest.raises(ValueError):
        encode_pkcs12(private_key, leaf, [], "pw", mac_iterations=0)


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
@pytest.mark.parametrize("mac_hash", ["sha256", "sha1"])
def test_openssl_sees_modern_algorithms(tmp_path, mac_hash):
    private_key = key()
    leaf = certificate(private_key)
    path = tmp_path / "x.p12"
    blob = encode_pkcs12(
        private_key,
        leaf,
        [],
        "secret-123",
        "modern",
        iterations=2000,
        mac_iterations=500,
        mac_hash=mac_hash,
    )
    path.write_bytes(blob)
    result = subprocess.run(
        [OPENSSL, "pkcs12", "-in", str(path), "-passin", "pass:secret-123", "-info", "-nodes"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "PBES2" in combined
    assert "AES-256-CBC" in combined
    assert "friendlyName: modern" in result.stdout


def test_default_iteration_is_strong():
    assert DEFAULT_ITERATIONS >= 100000


def test_mac_hash_unknown():
    private_key = key()
    leaf = certificate(private_key)
    with pytest.raises(ValueError):
        encode_pkcs12(private_key, leaf, [], "pw", mac_hash="md5")
