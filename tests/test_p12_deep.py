"""Deep PKCS#12 tests: tampering, truncation, parameters and limits."""

import datetime as dt
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import p12 as p12_module
from pycert.errors import CryptoError, PyCertError
from pycert.pkcs12_writer import DEFAULT_ITERATIONS, encode_pkcs12

OPENSSL = shutil.which("openssl")


def key(kind="ec"):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def cert(private_key, cn="deep", days=30):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .sign(private_key, hashes.SHA256())
    )


def blob(password="secret", **kwargs):
    private_key = key(kwargs.pop("kind", "ec"))
    certificate = cert(private_key)
    friendly_name = kwargs.pop("friendly_name", "deep")
    options = {"iterations": 1000, "mac_iterations": 100}
    options.update(kwargs)
    return (
        private_key,
        certificate,
        encode_pkcs12(private_key, certificate, [], password, friendly_name, **options),
    )


@pytest.mark.parametrize("mac_hash", ["sha256", "sha1"])
@pytest.mark.parametrize("iterations", [1, 2, 1000, 100000])
def test_iteration_parameters(tmp_path, mac_hash, iterations):
    private_key, certificate, data = blob(mac_hash=mac_hash, iterations=iterations, mac_iterations=iterations)
    path = tmp_path / "x.p12"
    path.write_bytes(data)
    assert p12_module.read_pkcs12(path, "secret")


@pytest.mark.parametrize(
    "password",
    ["a", "12345678", "with spaces and $ymbols", "üñïçødé", "😀-emoji-password", "p" * 200],
)
def test_password_matrix(tmp_path, password):
    private_key, certificate, data = blob(password)
    path = tmp_path / "x.p12"
    path.write_bytes(data)
    assert p12_module.read_pkcs12(path, password)


@pytest.mark.parametrize("offset", [-1, -2, -10, -32, 10, 100, 300])
def test_tampered_blob_is_rejected(tmp_path, offset):
    _private_key, _certificate, data = blob()
    tampered = bytearray(data)
    tampered[offset] ^= 0x01
    path = tmp_path / "x.p12"
    path.write_bytes(bytes(tampered))
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12(path, "secret")


@pytest.mark.parametrize("fraction", [0, 0.1, 0.25, 0.5, 0.75, 0.99])
def test_truncated_blob_is_rejected(tmp_path, fraction):
    _private_key, _certificate, data = blob()
    path = tmp_path / "x.p12"
    path.write_bytes(data[: int(len(data) * fraction)])
    with pytest.raises((CryptoError, PyCertError)):
        p12_module.read_pkcs12(path, "secret")


def test_oversize_file_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "big.p12"
    path.write_bytes(b"x" * 1024)
    monkeypatch.setattr(p12_module, "MAX_P12_BYTES", 100)
    with pytest.raises(PyCertError, match="larger"):
        p12_module.read_pkcs12(path, "secret")


def test_chain_limit(tmp_path):
    private_key = key()
    certificate = cert(private_key)
    with pytest.raises(PyCertError, match="more than"):
        p12_module.write_pkcs12(
            tmp_path / "x.p12",
            key=private_key,
            certificate=certificate,
            chain=[certificate] * 21,
            password="secret",
            iterations=1000,
            mac_iterations=100,
        )


def test_long_friendly_name_is_truncated(tmp_path):
    private_key, certificate, data = blob(friendly_name="n" * 200)
    path = tmp_path / "x.p12"
    path.write_bytes(data)
    assert p12_module.read_pkcs12(path, "secret")


@pytest.mark.skipif(OPENSSL is None, reason="openssl not available")
def test_openssl_reads_sha256_mac_and_aes(tmp_path):
    private_key, _certificate, data = blob(iterations=2000, mac_iterations=500)
    path = tmp_path / "x.p12"
    path.write_bytes(data)
    result = subprocess.run(
        [OPENSSL, "pkcs12", "-in", str(path), "-passin", "pass:secret", "-info", "-nodes"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    combined = result.stdout + result.stderr
    assert "AES-256-CBC" in combined
    assert "PBES2" in combined
    assert "MAC: sha256" in combined


def test_default_iterations_strong():
    assert DEFAULT_ITERATIONS >= 100000


def test_describe_file_modes(tmp_path):
    private_key, certificate, data = blob()
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(
        path,
        key=private_key,
        certificate=certificate,
        chain=[],
        password="secret",
        iterations=1000,
        mac_iterations=100,
    )
    info = p12_module.describe_file(path)
    assert info["private_permissions"] is True
