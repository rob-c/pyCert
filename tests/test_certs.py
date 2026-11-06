import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import bundled, certs
from pycert.errors import CryptoError


def test_bundled_certificates_match_pins():
    certs_list = bundled.certificates()
    assert len(certs_list) == 4
    for cert in certs_list:
        assert certs.fingerprint(cert) in bundled.PINNED.values()
    assert "BEGIN CERTIFICATE" in bundled.pem_bundle()


def test_bundled_chain_verifies_rsa_and_ecdsa():
    root, ca2b, root2026, ca3b = bundled.certificates()
    certs.verify_certificate_signature(ca2b, root)
    certs.verify_certificate_signature(ca3b, root2026)
    with pytest.raises(CryptoError):
        certs.verify_certificate_signature(ca2b, root2026)


def test_describe_certificate_real_world():
    _, ca2b, _, _ = bundled.certificates()
    description = certs.describe_certificate(ca2b)
    assert description.is_ca
    assert description.key == "RSA 2048"
    assert "UK e-Science CA 2B" in description.subject
    assert description.days_remaining > 0
    assert description.fingerprint_sha256.count(":") == 31
    payload = description.as_dict()
    assert payload["key_usage"] and "key cert sign" in payload["key_usage"]


def test_name_helpers_and_canonical_order():
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eScience"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CLRC"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "DL"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Jane Doe"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, "jane@example.org"),
        ]
    )
    canonical = certs.canonical_openca_name(name)
    assert [a.oid for a in canonical] == [
        NameOID.EMAIL_ADDRESS,
        NameOID.COMMON_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.COUNTRY_NAME,
    ]
    assert certs.common_name(canonical) == "Jane Doe"
    assert certs.name_attribute(canonical, NameOID.EMAIL_ADDRESS) == "jane@example.org"
    # unknown attributes are preserved at the end
    extra = x509.Name(list(name) + [x509.NameAttribute(NameOID.SERIAL_NUMBER, "1234")])
    assert certs.name_attribute(certs.canonical_openca_name(extra), NameOID.SERIAL_NUMBER) == "1234"


def test_build_subject_order_and_country():
    name = certs.build_subject(
        common_name="host.example.org",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    # RFC 4514 prints RDNs most-specific-first, so the display order is reversed;
    # the DER order (what OpenCA parses) is CN, L, OU, O, C.
    assert [attr.oid for attr in name] == [
        NameOID.COMMON_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.COUNTRY_NAME,
    ]


def test_public_key_equality_uses_spki():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    same = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert certs.public_keys_equal(key.public_key(), key.public_key())
    assert not certs.public_keys_equal(key.public_key(), same.public_key())
    assert certs.spki_b64(key.public_key()) == certs.spki_b64(key.public_key())


def test_weak_hash_detection():
    assert certs.is_weak_hash("sha1")
    assert certs.is_weak_hash("MD5")
    assert not certs.is_weak_hash("sha256")


def test_key_description():
    assert certs.key_description(rsa.generate_private_key(65537, 2048).public_key()) == "RSA 2048"
    assert certs.key_description(ec.generate_private_key(ec.SECP384R1()).public_key()) == "ECDSA P-384"
