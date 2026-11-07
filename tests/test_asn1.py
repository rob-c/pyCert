"""Known-answer tests for the DER encoder used by the PKCS#12 writer."""

import pytest

from pycert import asn1


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, "020100"),
        (1, "020101"),
        (127, "02017f"),
        (128, "02020080"),
        (255, "020200ff"),
        (256, "02020100"),
        (-1, "0201ff"),
        (-128, "020180"),
        (-129, "0202ff7f"),
    ],
)
def test_integer_encoding(value, expected):
    assert asn1.integer(value).hex() == expected


@pytest.mark.parametrize(
    "length,expected",
    [
        (0, "00"),
        (1, "01"),
        (127, "7f"),
        (128, "8180"),
        (255, "81ff"),
        (256, "820100"),
        (65535, "82ffff"),
        (65536, "83010000"),
    ],
)
def test_length_encoding(length, expected):
    assert asn1.encode_length(length).hex() == expected


def test_known_oids():
    assert asn1.oid("1.2.840.113549.1.1.11").hex() == "06092a864886f70d01010b"
    assert asn1.oid("1.2.840.113549.1.7.1").hex() == "06092a864886f70d010701"
    assert asn1.oid("2.16.840.1.101.3.4.1.42").hex() == "060960864801650304012a"


def test_set_of_is_sorted():
    a = asn1.integer(2)
    b = asn1.integer(1)
    assert asn1.set_of(a, b) == asn1.set_of(b, a)
    assert asn1.set_of(a, b)[2:] == b + a


def test_sequence_and_explicit():
    encoded = asn1.seq(asn1.explicit(0, asn1.octet_string(b"x")))
    assert encoded[0] == 0x30
    assert encoded[-3:] == b"\x04\x01x"


def test_bmp_string_matches_rfc_example():
    # BMPString values in ASN.1 do not carry the KDF's null terminator.
    assert asn1.bmp_string("Beavis").hex() == "1e0c004200650061007600690073"


def test_null_and_octet_string():
    assert asn1.null() == b"\x05\x00"
    assert asn1.octet_string(b"abc") == b"\x04\x03abc"


def test_invalid_oid_and_tag():
    with pytest.raises(ValueError):
        asn1.oid("1")
    with pytest.raises(ValueError):
        asn1.tlv(asn1.UNIVERSAL, False, 31, b"")
