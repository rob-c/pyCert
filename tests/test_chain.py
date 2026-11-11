import datetime as dt
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from openssl_support import sha1_env

from pycert import bundled, certs, chain
from pycert.errors import ChainError


def _self_signed(name="Test Root", key=None, *, days=3650, ca=True):
    key = key or rsa.generate_private_key(65537, 2048)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=2))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def test_bundled_chains_validate_rsa_and_ecdsa():
    certs_list = bundled.certificates()
    anchors = list(certs_list)
    for leaf in (certs_list[1], certs_list[3]):  # CA 2B (RSA), CA 3B (ECDSA)
        result = chain.build_chain(leaf, anchors=anchors, extra=certs_list)
        assert result.trusted
        assert result.complete
        assert result.chain[0] is leaf
        assert not result.problems


def test_wrong_anchor_is_not_trusted():
    certs_list = bundled.certificates()
    result = chain.build_chain(certs_list[1], anchors=[certs_list[2]], extra=certs_list)
    assert not result.trusted
    assert any("trust anchor" in p for p in result.problems)


def test_missing_issuer_is_reported():
    root_key, root = _self_signed("Root")
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(root_key, hashes.SHA256())
    )
    # The root is *not* supplied at all, so no issuer can be found.
    result = chain.build_chain(leaf, anchors=[], extra=[])
    assert not result.trusted
    assert any("no issuer" in p for p in result.problems)
    assert any("trust anchor" in p for p in result.problems)


def test_forged_issuer_is_rejected():
    """A certificate with the right subject but the wrong key must not be used."""
    root_key, root = _self_signed("Root")
    other_key, other = _self_signed("Root")  # same subject, different key
    now = dt.datetime.now(dt.timezone.utc)
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(root_key, hashes.SHA256())
    )
    result = chain.build_chain(leaf, anchors=[other], extra=[other])
    assert not result.trusted
    assert result.problems


def test_expired_intermediate_anchor_is_not_trusted():
    """An intermediate configured as an anchor is still validity-checked."""
    root_key, root = _self_signed("Root")
    now = dt.datetime.now(dt.timezone.utc)
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old intermediate")]))
        .issuer_name(root.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=900))
        .not_valid_after(now - dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(intermediate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=10))
        .not_valid_after(now + dt.timedelta(days=100))
        .sign(intermediate_key, hashes.SHA256())
    )
    result = chain.build_chain(leaf, anchors=[intermediate], extra=[intermediate])
    assert not result.trusted
    assert any("not valid" in p for p in result.problems)


def test_expired_leaf_breaks_trust():
    key, root = _self_signed("Root")
    now = dt.datetime.now(dt.timezone.utc)
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old")]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=400))
        .not_valid_after(now - dt.timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    result = chain.build_chain(leaf, anchors=[root], extra=[root])
    assert not result.trusted
    assert any("not valid" in p for p in result.problems)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not available")
def test_sha1_chain_is_refused_unless_allowed(tmp_path):
    """Cryptography refuses to sign with SHA-1, so use the openssl CLI."""
    openssl = shutil.which("openssl")
    root_key_path = tmp_path / "root.key"
    root_path = tmp_path / "root.pem"
    leaf_key_path = tmp_path / "leaf.key"
    leaf_csr = tmp_path / "leaf.csr"
    leaf_path = tmp_path / "leaf.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(root_key_path),
            "-out",
            str(root_path),
            "-days",
            "30",
            "-nodes",
            "-subj",
            "/CN=Sha1 Root",
            "-sha256",
        ],
        check=True,
        capture_output=True,
        env=sha1_env(),
    )
    subprocess.run(
        [
            openssl,
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(leaf_key_path),
            "-out",
            str(leaf_csr),
            "-nodes",
            "-subj",
            "/CN=sha1 leaf",
        ],
        check=True,
        capture_output=True,
        env=sha1_env(),
    )
    signed = subprocess.run(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(leaf_csr),
            "-CA",
            str(root_path),
            "-CAkey",
            str(root_key_path),
            "-CAcreateserial",
            "-days",
            "10",
            "-sha1",
            "-out",
            str(leaf_path),
        ],
        capture_output=True,
        env=sha1_env(),
    )
    if signed.returncode != 0:  # pragma: no cover - a crypto policy that cannot be relaxed
        pytest.skip("this OpenSSL refuses to create SHA-1 signatures: " + signed.stderr.decode(errors="replace")[:200])
    root = certs.load_certificate(root_path.read_bytes())
    leaf = certs.load_certificate(leaf_path.read_bytes())
    strict = chain.build_chain(leaf, anchors=[root], extra=[root])
    assert not strict.trusted
    assert any("SHA1" in p for p in strict.problems)
    relaxed = chain.build_chain(leaf, anchors=[root], extra=[root], allow_sha1=True)
    assert relaxed.trusted


def test_aia_fetch_and_verification(ca):
    """Download the intermediate over plain HTTP and verify it against the leaf."""
    key = rsa.generate_private_key(65537, 2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aia.example.org")]))
        .sign(key, hashes.SHA256())
    )
    issued = ca.issue(csr)
    fetched = chain.aia_fetch(issued)
    assert any(c == ca.intermediate for c in fetched)
    # Only the root is configured: the intermediate must come from AIA.
    result = chain.build_chain(issued, anchors=[ca.root], extra=[], fetcher=chain.aia_fetch)
    assert result.trusted
    assert result.fetched  # recorded the URL/issuer used
    assert len(result.chain) == 3


def test_require_valid_raises():
    _, root = _self_signed("Root")
    result = chain.ChainResult([root], True, False, ["nope"])
    with pytest.raises(ChainError):
        result.require_valid()
