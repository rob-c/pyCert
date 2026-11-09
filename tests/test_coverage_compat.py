"""Coverage-oriented tests for compatibility helpers and TOML edge cases."""

from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import compat, toml


def test_parse_iso_and_name_fallback():
    with pytest.raises(ValueError):
        compat.parse_iso_datetime(123)
    assert compat.parse_iso_datetime("2026-01-02T03:04:05Z").tzinfo is not None
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "a,b")])
    assert "CN=" in compat.name_to_string(name, use_modern=False)
    assert "a\\,b" in compat.name_to_string(name, use_modern=False)


def test_verify_signed_object_rsa_ec_and_issuer_key():
    for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP256R1())):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "compat")])
        csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256())
        compat.verify_signed_object(csr)
        assert compat.csr_signature_valid(csr)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cert")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now)
        .sign(key, hashes.SHA256())
    )
    compat.verify_signed_object(cert, key.public_key())


def test_csr_signature_fallback_returns_false():
    class Fake:
        is_signature_valid = None
        def public_key(self):
            return None

        signature = b"x"
        tbs_certrequest_bytes = b"x"
        signature_hash_algorithm = None
        signature_algorithm_oid = None

    assert compat.csr_signature_valid(Fake()) is False


def test_toml_load_and_parser_edge_cases(tmp_path):
    assert toml.load('a = 1') == {"a": 1}
    assert toml.load(b"a = 1") == {"a": 1}
    handle = tmp_path / "x.toml"
    handle.write_text("a = 1")
    assert toml.load(handle.open()) == {"a": 1}
    with pytest.raises(toml.TOMLDecodeError):
        toml.loads(123)
    assert toml.loads("a = 1 # comment\r\n")["a"] == 1
    assert toml.loads("a = [1, 2]")["a"] == [1, 2]
    assert toml.loads("a = { b = 1 }")["a"]["b"] == 1
    for bad in (
        "a = [",
        "a = { b = 1",
        "a = 'unterminated",
        'a = "unterminated',
        'a = "bad\\q"',
        "a = '''unterminated",
        "a = '''x''''''",
        "a = 1\na = 2",
        "a = [1]\n[[a]]",
        "a = {b = 1}\n[a]",
        "a = {b = 1, b = 2}",
    ):
        with pytest.raises(toml.TOMLDecodeError):
            toml.loads(bad)
    with pytest.raises(toml.TOMLDecodeError):
        toml.loads('a = "' + "x" * (toml.MAX_DOCUMENT_BYTES + 1) + '"')


def test_toml_table_and_string_edge_cases():
    assert toml.loads("a = {}")["a"] == {}
    assert toml.loads("a = {b.c = 1}")["a"]["b"]["c"] == 1
    assert toml.loads('a = """x\r\n y"""')["a"] == "x\n y"
    assert toml.loads("a = '''x\r\n y'''")["a"] == "x\n y"
    assert toml.loads('a = """x \\\n y"""')["a"] == "x y"
    for bad in (
        "a = [{b = 1}]\n[[a]]",
        "a = [1]\n[[a]]",
        "[a]\nb = 1\n[[a]]",
        'a = """x""""""',
        "a = '''x''''''",
        "a = {b.c = 1, b.c = 2}",
        "a = {b = 1}\n[a]",
    ):
        with pytest.raises(toml.TOMLDecodeError):
            toml.loads(bad)


def test_verify_with_public_key_ed_branch():
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    data = b"payload"
    signature = key.sign(data)
    compat._verify_with_public_key(key.public_key(), signature, data, None, None)
