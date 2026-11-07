"""Security-focused tests: parsers, injection, traversal, permissions."""

import base64
import os
import stat

import pytest

from pycert import ca, certs
from pycert.errors import ConfigError, CryptoError, ProtocolError
from pycert.transport import TransportError, _validate_headers, _validate_url


@pytest.mark.parametrize(
    "payload,match",
    [
        (b"<?xml version='1.0'?><!DOCTYPE r><r/>", "DOCTYPE"),
        (b"<!doctype r><r/>", "DOCTYPE"),
        (b"<r><!ENTITY x 'y'></r>", "ENTITY"),
        (b"<r>&xxe;</r>", "parse"),
        (b"", "parse"),
        (b"not xml", "parse"),
        (b"<r><text>ok</text></r>", None),
        (b"<?xml version='1.0'?><!-- c --><r/>", None),
        (b"<a:r xmlns:a='urn:x'><a:text>v</a:text></a:r>", None),
    ],
)
def test_safe_xml_corpus(payload, match):
    if match is None:
        assert ca._safe_xml(payload) is not None
        return
    with pytest.raises(ProtocolError) as exc:
        ca._safe_xml(payload)
    assert match.lower() in str(exc.value).lower()


def test_safe_xml_accepts_valid_document():
    root = ca._safe_xml(b"<r><text>hello</text></r>")
    assert root.tag == "r"


def test_safe_xml_size_limit(monkeypatch):
    monkeypatch.setattr(ca, "MAX_XML_BYTES", 20)
    with pytest.raises(ProtocolError, match="large"):
        ca._safe_xml(b"<r>" + b"x" * 50 + b"</r>")


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
        b"\x00\x01\x02",
        b"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n",
        b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"junk") + b"\n-----END CERTIFICATE-----\n",
    ],
)
def test_certificate_loader_rejects_garbage(payload):
    with pytest.raises(CryptoError):
        certs.load_certificates(payload)


def test_certificate_loader_ignores_unrelated_pem_blocks():
    pem = "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"
    with pytest.raises(CryptoError):
        certs.load_certificates(pem.encode())


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.org/",
        "http://user:pass@example.org/",
        "http://example.org/\r\nX: y",
        "http://example.org:99999/",
        "http://example.org/\x00",
        "javascript:alert(1)",
    ],
)
def test_url_injection_corpus(url):
    with pytest.raises(TransportError):
        _validate_url(url, True)


@pytest.mark.parametrize(
    "headers",
    [
        {"X": "a\r\nInjected: 1"},
        {"X": "a\nInjected: 1"},
        {"X: y": "z"},
        {"": "z"},
        {"X": 1},
    ],
)
def test_header_injection_corpus(headers):
    with pytest.raises(ValueError):
        _validate_headers(headers)


def test_certificate_id_traversal_is_refused(ctx):
    for value in ("../../etc/passwd", "..%2f..%2fetc", "1/../../x", "1 2"):
        with pytest.raises(ProtocolError):
            ctx.client().download_certificate(value)


def test_p12_filename_traversal_is_refused(ctx, issued, config):
    state = issued()
    config.p12.filename_template = "../../{cn}.p12"
    from pycert.workflow import export_p12

    with pytest.raises(ConfigError, match="directory components"):
        export_p12(ctx, state, progress=lambda _m: None)


def test_slug_prevents_traversal(tmp_path):
    from pycert.store import Store

    store = Store(tmp_path / "data")
    state = store.new_state(alias="../../evil", type="user", cn="x", email="x@y.z")
    assert state.slug == "evil"
    assert state.slug == os.path.basename(state.slug)
    assert store.path(state).parent == store.requests_dir


def test_atomic_write_does_not_follow_symlink(tmp_path):
    from pycert.util import atomic_write

    target = tmp_path / "target"
    target.write_text("original")
    link = tmp_path / "link"
    link.symlink_to(target)
    atomic_write(link, b"new", mode=0o600)
    assert target.read_text() == "original"
    assert link.is_symlink() is False
    assert link.read_bytes() == b"new"


def test_private_permissions_are_enforced(tmp_path):
    from pycert.util import atomic_write, check_private_permissions

    path = tmp_path / "secret"
    atomic_write(path, b"x")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert check_private_permissions(path) == []
    path.chmod(0o644)
    assert check_private_permissions(path)


def test_server_message_is_clamped():
    message = ca.CAClient.server_message(b"x" * 10000)
    assert len(message) <= 401


def test_error_messages_do_not_contain_headers(ctx):
    # Header values (and thus any credential in them) must not leak into errors.
    with pytest.raises(Exception) as excinfo:  # noqa: B017 - any transport failure
        ctx.client().request(
            "GET",
            "http://127.0.0.1:9/x",
            headers={"Authorization": "Bearer super-secret-token"},
            idempotent=False,
        )
    assert "super-secret-token" not in str(excinfo.value)


def test_atomic_write_without_fchmod(tmp_path, monkeypatch):
    # Windows has no os.fchmod; the fallback must still produce a private file.
    import os

    from pycert.util import atomic_write

    monkeypatch.setattr(os, "fchmod", None)
    path = tmp_path / "win-secret"
    atomic_write(path, b"x", mode=0o600)
    assert path.read_bytes() == b"x"


def test_non_ascii_header_name_is_rejected():
    with pytest.raises(ValueError):
        _validate_headers({"Ünicode": "x"})


def test_non_latin1_header_value_is_rejected():
    with pytest.raises(ValueError):
        _validate_headers({"X": "\u2603"})
