"""Tests for the minimal BER reader used by legacy PKCS#12 bundles."""

import pytest

from pycert import ber


def test_definite_and_indefinite_sequences_and_oid():
    node = ber.parse(bytes.fromhex("30050201013000"))
    assert "constructed" in repr(node)
    assert node.children[0].content == b"\x01"
    assert node.children[1].tag == 0x10

    indefinite = bytes.fromhex("30800201010000")
    node = ber.parse(indefinite)
    assert node.children[0].content == b"\x01"

    oid = ber.parse(bytes.fromhex("06092A864886F70D010701"))
    assert ber.decode_oid(oid.content) == "1.2.840.113549.1.7.1"


def test_context_fragments_and_first_child():
    node = ber.parse(bytes.fromhex("A00A04036162630403636465"))
    assert ber.octets(node) == b"abccde"
    assert ber.first_child(node).tag == 0x04
    with pytest.raises(ber.BERError):
        ber.first_child(node, 0x06)


def test_ber_errors():
    with pytest.raises(ber.BERError):
        ber.parse("not bytes")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x30\x00\x00")
    with pytest.raises(ber.BERError):
        ber.decode_oid(b"")
    with pytest.raises(ber.BERError):
        ber.decode_oid(b"\x2a\x86")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x1f")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x1f\x81")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x04\x80")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x30\x80")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x04")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x04\x82\x00")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x04\x02x")
    with pytest.raises(ber.BERError):
        ber.parse(b"\x30\x03\x04\x02x")
    with pytest.raises(ber.BERError):
        ber.TLV(0, False, 1, b"", [], b"").require_constructed()


def test_ber_limits(monkeypatch):
    monkeypatch.setattr(ber, "MAX_DEPTH", 1)
    with pytest.raises(ber.BERError):
        ber.parse(bytes.fromhex("30053003300100"))
    monkeypatch.undo()
    monkeypatch.setattr(ber, "MAX_NODES", 1)
    with pytest.raises(ber.BERError):
        ber.parse(bytes.fromhex("3003020101"))


def test_ber_high_tag_and_long_form():
    assert ber.parse(b"\x1f\x81\x00\x00").tag == 128
    assert ber.parse(b"\x04\x81\x01x").content == b"x"
    with pytest.raises(ber.BERError):
        ber.parse(b"")
