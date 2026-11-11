"""Coverage-oriented tests for certificate, chain and CA helpers."""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, rsa
from cryptography.x509.oid import NameOID

from pycert import certs, chain
from pycert.errors import ChainError, CryptoError


def _name(cn="coverage.example.org"):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(key, *, cn="coverage.example.org", issuer=None, issuer_key=None, days=30, san=None, ca=False, eku=None):
    now = datetime.now(timezone.utc)
    subject = _name(cn)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    signer = issuer_key or key
    algorithm = None if isinstance(signer, (ed25519.Ed25519PrivateKey,)) else hashes.SHA256()
    return builder.sign(signer, algorithm)


def test_certs_loading_and_description_edges():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _cert(key)
    assert certs.load_public_key(certs.public_pem(key.public_key()).encode()).public_numbers() == key.public_key().public_numbers()
    assert certs.load_public_key(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    with pytest.raises(CryptoError):
        certs.load_public_key(b"bad")
    with pytest.raises(CryptoError):
        certs.load_certificate((certs.cert_pem(cert) + certs.cert_pem(cert)).encode())
    assert certs.load_certificate(certs.cert_pem(cert).encode()) == cert
    with pytest.raises(CryptoError):
        certs.load_certificates(b"")
    ed = ed25519.Ed25519PrivateKey.generate()
    ed_cert = _cert(ed)
    assert certs.key_description(ed.public_key()) == "Ed25519"
    assert "ed25519" in certs.signature_description(ed_cert).lower()
    dsa_key = dsa.generate_private_key(key_size=2048)
    assert certs.key_description(dsa_key.public_key()) == "DSAPublicKey"
    outside = _cert(key, cn="outside.example.org")
    with pytest.raises(CryptoError):
        certs.verify_certificate_signature(outside, cert)
    assert not certs.is_self_signed(_cert(key, issuer=cert, issuer_key=rsa.generate_private_key(public_exponent=65537, key_size=2048)))
    assert certs.parse_ip("127.0.0.1")
    assert certs.select_sans(cert) == ()


def test_certs_directory_san_and_name_constraints():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert(
        key,
        san=[
            x509.DirectoryName(_name("directory.example.org")),
            x509.RFC822Name("mail@example.org"),
            x509.DNSName("bad.example.net"),
        ],
    )
    entries = certs.subject_alt_names(leaf)
    assert any(item.startswith("dirName:") for item in entries)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    issuer = (
        x509.CertificateBuilder()
        .subject_name(_name("constraints"))
        .issuer_name(_name("constraints"))
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.NameConstraints(permitted_subtrees=[x509.DNSName("example.org")], excluded_subtrees=None),
            critical=True,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    problems = certs.has_name_constraints_violation(leaf, issuer)
    assert any("bad.example.net" in item for item in problems)
    assert certs.common_name(_name("cn")).startswith("cn")
    with pytest.raises(CryptoError):
        certs.common_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "O")]))
    subject = certs.build_subject(
        common_name="cn",
        organization="O",
        organizational_unit="OU",
        locality="L",
        country="UK",
        state="ST",
        email="e@example.org",
        include_email_in_subject=True,
    )
    assert certs.name_attribute(subject, NameOID.EMAIL_ADDRESS) == "e@example.org"
    assert certs.name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME) == "ST"


def test_chain_fetcher_cache_and_system_anchors(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert(key, cn="root", ca=True)
    leaf = _cert(key, cn="leaf", issuer=root, issuer_key=key)
    builder = chain.ChainBuilder(anchors=[root], extra=[leaf])
    result = builder.build(leaf)
    assert result.leaf == leaf
    assert result.pem()
    fetched = chain.ChainBuilder(anchors=[root], fetcher=lambda _cert: (_ for _ in ()).throw(RuntimeError("no")))
    assert fetched._fetch_for(leaf) == []
    monkeypatch.setattr(chain, "_system_anchors_cache", [root])
    assert chain.system_anchors() == [root]
    with pytest.raises(ChainError):
        chain.ChainBuilder(anchors=[]).build(leaf).require_valid()


def test_certs_empty_bundle_and_small_keys(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(certs.x509, "load_pem_x509_certificates", lambda _data: [])
    with pytest.raises(CryptoError):
        certs.load_certificates(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----")
    from cryptography.hazmat.primitives.asymmetric import ed448

    ed448_key = ed448.Ed448PrivateKey.generate()
    assert certs.key_description(ed448_key.public_key()) == "Ed448"
    fake = SimpleNamespace(signature_algorithm_oid=SimpleNamespace(_name="FAKE", dotted_string="1.2.3"), signature_hash_algorithm=None)
    assert "FAKE" in certs.signature_description(fake)


def test_key_strength_warning_small_ec():
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        key = ec.generate_private_key(ec.SECP192R1())
    except Exception:
        pytest.skip("SECP192R1 unavailable")
    assert certs.key_strength_warning(key.public_key())


def test_chain_extra_key_ids_and_cache(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert(key, cn="root2", ca=True)
    leaf = _cert(key, cn="leaf2", issuer=root, issuer_key=key)
    builder = chain.ChainBuilder(anchors=[root])
    assert builder.build(leaf, extra=[root]).leaf == leaf
    assert chain.ChainBuilder._key_ids_consistent(leaf, root) is True
    assert chain.ChainBuilder(anchors=[root])._fetch_for(leaf) == []
    monkeypatch.setattr(chain, "_system_anchors_cache", [root])
    assert chain.system_anchors() == [root]
