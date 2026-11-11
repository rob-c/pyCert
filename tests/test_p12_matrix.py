"""PKCS#12 write/read matrix."""

import datetime as dt
import shutil
import stat
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from openssl_support import legacy_pkcs12_args

from pycert import certs
from pycert import p12 as p12_module
from pycert.errors import CryptoError, PyCertError

OPENSSL = shutil.which("openssl")


def new_key(kind):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    raise AssertionError(kind)


def issue(cn, *, issuer=None, issuer_key=None, public_key=None, ca=False, days=30, san=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in san]), critical=False
        )
    return builder.sign(issuer_key if issuer_key else public_key, hashes.SHA256())


def pki(kind="ec256", chain_length=1):
    root_key = new_key("ec256")
    root = issue("root", issuer_key=root_key, public_key=root_key.public_key(), ca=True, days=3650)
    issuers = [root]
    if chain_length >= 2:
        intermediate_key = new_key("ec256")
        intermediate = issue(
            "intermediate",
            issuer=root,
            issuer_key=root_key,
            public_key=intermediate_key.public_key(),
            ca=True,
            days=1825,
        )
        issuers = [intermediate, root]
        issuer, issuer_key = intermediate, intermediate_key
    else:
        issuer, issuer_key = root, root_key
    leaf_key = new_key(kind)
    leaf = issue(
        "leaf.example.org",
        issuer=issuer,
        issuer_key=issuer_key,
        public_key=leaf_key.public_key(),
        days=30,
        san=["leaf.example.org"],
    )
    return leaf_key, leaf, issuers


@pytest.mark.parametrize("kind", ["rsa", "ec256", "ec384"])
@pytest.mark.parametrize("chain_length", [1, 2])
def test_key_and_chain_matrix(tmp_path, kind, chain_length):
    key, leaf, issuers = pki(kind, chain_length)
    path = tmp_path / "bundle.p12"
    p12_module.write_pkcs12(
        path, key=key, certificate=leaf, chain=issuers, password="secret-123", friendly_name="test"
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    bundle = p12_module.read_pkcs12(path, "secret-123")
    assert certs.fingerprint(bundle.cert) == certs.fingerprint(leaf)
    assert certs.key_description(bundle.key.public_key()) == certs.key_description(key.public_key())
    assert len(bundle.chain) == chain_length
    assert certs.fingerprint(bundle.chain[-1]) == certs.fingerprint(issuers[-1])


@pytest.mark.parametrize("friendly", ["", "x", "üñïçødé", "n" * 64, "n" * 65])
def test_friendly_name_matrix(tmp_path, friendly):
    key, leaf, issuers = pki("ec256", 1)
    path = tmp_path / "bundle.p12"
    p12_module.write_pkcs12(
        path, key=key, certificate=leaf, chain=issuers, password="pw-123456", friendly_name=friendly
    )
    assert p12_module.read_pkcs12(path, "pw-123456")


@pytest.mark.parametrize(
    "password",
    ["x", "short", "with spaces and $ymbols", "üñïçødé-pass", "p" * 100],
)
def test_password_matrix(tmp_path, password):
    key, leaf, issuers = pki("ec256", 1)
    path = tmp_path / "bundle.p12"
    p12_module.write_pkcs12(
        path, key=key, certificate=leaf, chain=issuers, password=password, friendly_name="x"
    )
    assert p12_module.read_pkcs12(path, password)


def test_wrong_password(tmp_path):
    key, leaf, issuers = pki("ec256", 1)
    path = tmp_path / "bundle.p12"
    p12_module.write_pkcs12(path, key=key, certificate=leaf, chain=issuers, password="right-password")
    with pytest.raises(CryptoError, match="could not open"):
        p12_module.read_pkcs12(path, "wrong-password")


def test_empty_password_is_refused(tmp_path):
    key, leaf, issuers = pki("ec256", 1)
    with pytest.raises(PyCertError, match="without a password"):
        p12_module.write_pkcs12(tmp_path / "x.p12", key=key, certificate=leaf, chain=issuers, password="")


def test_key_mismatch_is_refused(tmp_path):
    key, leaf, issuers = pki("ec256", 1)
    other = new_key("ec256")
    with pytest.raises(CryptoError, match="does not match"):
        p12_module.write_pkcs12(
            tmp_path / "x.p12", key=other, certificate=leaf, chain=issuers, password="password"
        )


def test_unrelated_chain_certificate_is_not_embedded(tmp_path):
    key, leaf, issuers = pki("ec256", 1)
    unrelated_key = new_key("ec256")
    unrelated = issue("unrelated", issuer_key=unrelated_key, public_key=unrelated_key.public_key())
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(path, key=key, certificate=leaf, chain=issuers + [unrelated], password="password")
    bundle = p12_module.read_pkcs12(path, "password")
    assert len(bundle.chain) == 1


def test_describe_file(tmp_path):
    key, leaf, issuers = pki("ec256", 1)
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(path, key=key, certificate=leaf, chain=issuers, password="password")
    info = p12_module.describe_file(path)
    assert info["private_permissions"] is True
    assert info["size"] > 0
    assert len(info["sha256"]) == 64


def test_bundle_as_dict(tmp_path):
    key, leaf, issuers = pki("ec256", 1)
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(path, key=key, certificate=leaf, chain=issuers, password="password")
    payload = p12_module.read_pkcs12(path, "password").as_dict()
    assert payload["key"].startswith("ECDSA")
    assert payload["certificate"]["subject"].endswith("CN=leaf.example.org")
    assert len(payload["chain"]) == 1


def test_read_missing_file(tmp_path):
    with pytest.raises(PyCertError, match="cannot read"):
        p12_module.read_pkcs12(tmp_path / "nope.p12", "x")


def test_read_garbage(tmp_path):
    path = tmp_path / "bad.p12"
    path.write_bytes(b"not a p12")
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12(path, "x")


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
@pytest.mark.parametrize("kind", ["rsa", "ec256"])
def test_openssl_can_read_our_p12(tmp_path, kind):
    key, leaf, issuers = pki(kind, 2)
    path = tmp_path / "x.p12"
    p12_module.write_pkcs12(path, key=key, certificate=leaf, chain=issuers, password="secret-123")
    result = subprocess.run(
        [OPENSSL, "pkcs12", "-in", str(path), "-passin", "pass:secret-123", "-info", "-nodes"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "friendlyName" in result.stdout
    assert "BEGIN PRIVATE KEY" in result.stdout


@pytest.mark.skipif(OPENSSL is None, reason="openssl CLI not available")
def test_legacy_pkcs12_import(tmp_path):
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    legacy = tmp_path / "legacy.p12"
    subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=legacy",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            OPENSSL,
            "pkcs12",
            "-export",
            *legacy_pkcs12_args(),
            "-in",
            str(cert_path),
            "-inkey",
            str(key_path),
            "-out",
            str(legacy),
            "-passout",
            "pass:legacy-pw",
        ],
        check=True,
        capture_output=True,
    )
    bundle = p12_module.read_pkcs12(legacy, "legacy-pw")
    assert certs.common_name(bundle.cert.subject) == "legacy"
