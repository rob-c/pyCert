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
from pycert.errors import CryptoError, PyCertError
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


def test_legacy_writer_roundtrip_and_oid(tmp_path):
    private_key = key("rsa")
    leaf = certificate(private_key, "legacy leaf")
    path = tmp_path / "legacy.p12"
    p12_module.write_pkcs12(
        path,
        key=private_key,
        certificate=leaf,
        chain=[],
        password="legacy-password",
        legacy=True,
        iterations=2000,
        mac_iterations=500,
    )
    data = path.read_bytes()
    assert bytes.fromhex("2a864886f70d010c0103") in data  # PBE-SHA1-3DES OID
    bundle = p12_module.read_pkcs12(path, "legacy-password")
    assert certs.fingerprint(bundle.cert) == certs.fingerprint(leaf)


def test_certificate_only_pkcs12_roundtrip(tmp_path):
    root_key = key()
    root = certificate(root_key, "root", ca=True)
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf", issuer=root, issuer_key=root_key)
    path = tmp_path / "certs.p12"
    p12_module.write_certificate_bundle(
        path,
        certificates=[leaf, root],
        password="certs-password",
        legacy=True,
        iterations=2000,
        mac_iterations=500,
    )
    from cryptography.hazmat.primitives.serialization import pkcs12

    key_value, cert_value, extras = pkcs12.load_key_and_certificates(path.read_bytes(), b"certs-password")
    assert key_value is None
    assert cert_value is None
    assert {certs.fingerprint(c) for c in extras} == {certs.fingerprint(leaf), certs.fingerprint(root)}


def test_certificate_only_writer_validation(tmp_path):
    with pytest.raises(PyCertError):
        p12_module.write_certificate_bundle(tmp_path / "x.p12", certificates=[], password="x")
    with pytest.raises(PyCertError):
        p12_module.write_certificate_bundle(tmp_path / "x.p12", certificates=[], password="")
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf")
    path = tmp_path / "x.p12"
    original = p12_module.pkcs12.load_key_and_certificates
    p12_module.pkcs12.load_key_and_certificates = lambda *a, **k: (leaf_key, leaf, [])
    try:
        with pytest.raises(CryptoError):
            p12_module.write_certificate_bundle(path, certificates=[leaf], password="x")
    finally:
        p12_module.pkcs12.load_key_and_certificates = original


def test_preserve_unrelated_chain_certificate(tmp_path):
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf")
    other_key = key()
    other = certificate(other_key, "other")
    path = tmp_path / "preserved.p12"
    p12_module.write_pkcs12(
        path,
        key=leaf_key,
        certificate=leaf,
        chain=[other],
        password="x-password",
        preserve_chain=True,
        iterations=2000,
        mac_iterations=500,
    )
    from cryptography.hazmat.primitives.serialization import pkcs12

    _key, _cert, extras = pkcs12.load_key_and_certificates(path.read_bytes(), b"x-password")
    assert extras and certs.fingerprint(extras[0]) == certs.fingerprint(other)


def test_certificate_only_writer_verification_failures(tmp_path, monkeypatch):
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf")
    path = tmp_path / "x.p12"
    monkeypatch.setattr(p12_module, "MAX_CHAIN_CERTIFICATES", 0)
    with pytest.raises(PyCertError):
        p12_module.write_certificate_bundle(path, certificates=[leaf], password="x")
    monkeypatch.undo()
    original = p12_module.pkcs12.load_key_and_certificates
    monkeypatch.setattr(
        p12_module.pkcs12, "load_key_and_certificates", lambda *a, **k: (leaf_key, None, [])
    )
    with pytest.raises(CryptoError):
        p12_module.write_certificate_bundle(path, certificates=[leaf], password="x")
    monkeypatch.setattr(p12_module.pkcs12, "load_key_and_certificates", original)


def test_preserve_chain_limit(tmp_path):
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf")
    other_key = key()
    other = certificate(other_key, "other")
    from pycert import p12 as p12_module

    old = p12_module.MAX_CHAIN_CERTIFICATES
    p12_module.MAX_CHAIN_CERTIFICATES = 0
    try:
        with pytest.raises(PyCertError):
            p12_module.write_pkcs12(
                tmp_path / "x.p12",
                key=leaf_key,
                certificate=leaf,
                chain=[other],
                password="x",
                preserve_chain=True,
            )
    finally:
        p12_module.MAX_CHAIN_CERTIFICATES = old


def test_certificate_bundle_writer_mismatch_and_encode_error(tmp_path, monkeypatch):
    leaf_key = key()
    leaf = certificate(leaf_key, "leaf")
    other = certificate(key(), "other")
    path = tmp_path / "x.p12"
    original = p12_module.pkcs12.load_key_and_certificates
    monkeypatch.setattr(
        p12_module.pkcs12, "load_key_and_certificates", lambda *a, **k: (None, other, [])
    )
    with pytest.raises(CryptoError, match="certificate mismatch"):
        p12_module.write_certificate_bundle(path, certificates=[leaf], password="x")
    monkeypatch.setattr(p12_module.pkcs12, "load_key_and_certificates", original)
    monkeypatch.setattr(
        p12_module, "encode_certificate_bundle", lambda *a, **k: (_ for _ in ()).throw(ValueError("bad"))
    )
    with pytest.raises(CryptoError, match="certificate bundle"):
        p12_module.write_certificate_bundle(path, certificates=[leaf], password="x")


def test_certificate_bundle_encoder_validation():
    from pycert.pkcs12_writer import encode_certificate_bundle

    with pytest.raises(ValueError, match="password"):
        encode_certificate_bundle([], "")
    with pytest.raises(ValueError, match="iteration"):
        encode_certificate_bundle([], "x", iterations=0)
    with pytest.raises(ValueError, match="at least one"):
        encode_certificate_bundle([], "x")


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
def test_openssl_reads_legacy_java_profile(tmp_path):
    private_key = key("rsa")
    leaf = certificate(private_key, "legacy java")
    path = tmp_path / "legacy-java.p12"
    p12_module.write_pkcs12(
        path,
        key=private_key,
        certificate=leaf,
        chain=[],
        password="legacy-password",
        legacy=True,
        iterations=2000,
        mac_iterations=500,
    )
    result = subprocess.run(
        [OPENSSL, "pkcs12", "-in", str(path), "-passin", "pass:legacy-password", "-info", "-nodes"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "pbeWithSHA1And3-KeyTripleDES-CBC" in (result.stdout + result.stderr)


def test_raw_pkcs12_writer_validation(tmp_path):
    from pycert.pkcs12_writer import encode_raw_pkcs12

    with pytest.raises(PyCertError):
        p12_module.write_raw_pkcs12(tmp_path / "x.p12", key_bags=[], cert_bags=[], password="x")
    with pytest.raises(PyCertError):
        p12_module.write_raw_pkcs12(tmp_path / "x.p12", key_bags=[], cert_bags=[b"c"], password="")
    with pytest.raises(ValueError, match="password"):
        encode_raw_pkcs12([], [b"c"], "")
    with pytest.raises(ValueError, match="iterations"):
        encode_raw_pkcs12([], [b"c"], "x", mac_iterations=0)
    with pytest.raises(ValueError, match="certificate bag"):
        encode_raw_pkcs12([], [], "x")


def test_raw_pkcs12_writer_roundtrip(tmp_path):
    from cryptography.hazmat.primitives.serialization import pkcs12

    from pycert.pkcs12_writer import _certificate_bag, _key_bag

    private_key = key("rsa")
    leaf = certificate(private_key, "raw writer")
    cert_bag = _certificate_bag(leaf, "raw writer", None, False)
    key_bag = _key_bag(private_key, "raw-password", 1000, "raw writer", b"id")
    path = tmp_path / "raw.p12"
    p12_module.write_raw_pkcs12(
        path,
        key_bags=[key_bag],
        cert_bags=[cert_bag],
        password="raw-password",
        mac_iterations=100,
    )
    key_value, cert_value, _extras = pkcs12.load_key_and_certificates(
        path.read_bytes(), b"raw-password"
    )
    assert key_value is not None
    assert cert_value is not None
    assert certs.common_name(cert_value.subject) == "raw writer"
