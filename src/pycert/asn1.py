"""Minimal DER encoder used by the PKCS#12 writer.

Only encoding is implemented: pyCert reads certificates and PKCS#12 through
``cryptography``/OpenSSL, but writes the PKCS#12 container itself so the same
modern algorithms are used on every Python version (older ``cryptography``
releases write legacy 3DES/SHA-1 PKCS#12).  The encoder is deliberately small
and covered by known-answer tests.
"""

__all__ = [
    "tlv",
    "seq",
    "set_of",
    "integer",
    "octet_string",
    "oid",
    "null",
    "bmp_string",
    "explicit",
    "implicit",
    "encode_oid",
    "encode_length",
]

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
PRINTABLE_STRING = 19
IA5_STRING = 22
BMP_STRING = 30

_EOF = "\x00"


def encode_length(length):
    if length < 0:
        raise ValueError("negative length")
    if length < 0x80:
        return bytes((length,))
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    if len(raw) > 4:
        raise ValueError("length too large")
    return bytes((0x80 | len(raw),)) + raw


def tlv(tag_class, constructed, tag_number, content):
    first = (tag_class << 6) | (0x20 if constructed else 0)
    if tag_number >= 0x1F:
        raise ValueError("high tag numbers are not used by pyCert")
    return bytes((first | tag_number,)) + encode_length(len(content)) + content


def seq(*items):
    return tlv(UNIVERSAL, True, SEQUENCE, b"".join(items))


def set_of(*items):
    # DER requires SET OF elements to be sorted by their encoding.
    return tlv(UNIVERSAL, True, SET, b"".join(sorted(items)))


def _int_content(value):
    if not isinstance(value, int):
        raise TypeError("integer expected")
    if value == 0:
        return b"\x00"
    if value > 0:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return raw
    length = ((value.bit_length() + 8) // 8) + 1
    raw = value.to_bytes(length, "big", signed=True)
    while len(raw) > 1 and raw[0] == 0xFF and raw[1] & 0x80:
        raw = raw[1:]
    return raw


def integer(value):
    return tlv(UNIVERSAL, False, INTEGER, _int_content(value))


def null():
    return tlv(UNIVERSAL, False, NULL, b"")


def octet_string(value):
    return tlv(UNIVERSAL, False, OCTET_STRING, value)


def bmp_string(value):
    return tlv(UNIVERSAL, False, BMP_STRING, value.encode("utf-16-be"))


def _base128(value):
    groups = [value & 0x7F]
    value >>= 7
    while value:
        groups.append(value & 0x7F)
        value >>= 7
    groups.reverse()
    return bytes(g | (0x80 if index < len(groups) - 1 else 0) for index, g in enumerate(groups))


def encode_oid(dotted):
    parts = [int(part) for part in dotted.split(".")]
    if len(parts) < 2 or not 0 <= parts[0] <= 2 or (parts[0] < 2 and parts[1] > 39):
        raise ValueError("invalid OID %r" % dotted)
    body = bytearray(_base128(parts[0] * 40 + parts[1]))
    for part in parts[2:]:
        body += _base128(part)
    return bytes(body)


def oid(dotted):
    return tlv(UNIVERSAL, False, OID, encode_oid(dotted))


def explicit(number, content, tag_class=CONTEXT):
    return tlv(tag_class, True, number, content)


def implicit(number, content, tag_class=CONTEXT, constructed=False):
    return tlv(tag_class, constructed, number, content)
