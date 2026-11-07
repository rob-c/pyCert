"""Second-round deep transport tests: framing, redirects, TLS, resources."""

import os
import socket
import threading
import time

import pytest
from raw_server import RawServer, headers_then_chunks, raw, respond, sequence
from test_transport import _make_cert, _tls_transport, make_retry_transport, make_transport

from pycert.transport import (
    TransportError,
    _parse_retry_after,
    _same_host_redirect,
    _validate_headers,
    _validate_url,
)

# ---------------------------------------------------------------------------
# Response framing edge cases
# ---------------------------------------------------------------------------

FRAMING_CASES = [
    (
        "content-length-and-transfer-encoding",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        "both Content-Length",
    ),
    (
        "conflicting-content-length",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
        "conflicting Content-Length",
    ),
    (
        "non-numeric-content-length",
        b"HTTP/1.1 200 OK\r\nContent-Length: three\r\n\r\nabc",
        None,  # http.client rejects it; either protocol error is acceptable
    ),
    (
        "unsupported-transfer-encoding",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nabc",
        "Transfer-Encoding",
    ),
    (
        "status-101",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n",
        "status",
    ),
    (
        "status-099",
        b"HTTP/1.1 99 Nope\r\n\r\n",
        "status",
    ),
    (
        "status-600",
        b"HTTP/1.1 600 Nope\r\n\r\n",
        "status",
    ),
]


@pytest.mark.parametrize("name,payload,match", FRAMING_CASES)
def test_malformed_framing(name, payload, match):
    server = RawServer(raw(payload))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport().request("GET", server.url + "/")
        if match:
            assert match.lower() in str(exc.value).lower() or exc.value.kind == "protocol"
    finally:
        server.stop()


def test_chunk_extensions_and_trailers():
    payload = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5;name=value\r\nhello\r\n0\r\nX-Trailer: yes\r\n\r\n"
    )
    server = RawServer(raw(payload))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"hello"
    finally:
        server.stop()


def test_zero_length_chunk_with_trailers():
    payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\n\r\n"
    server = RawServer(raw(payload))
    try:
        assert make_transport().request("GET", server.url + "/").body == b""
    finally:
        server.stop()


def test_duplicate_identical_content_length_is_accepted():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"abc"
    finally:
        server.stop()


@pytest.mark.parametrize("status", [204, 205, 304])
def test_bodyless_status_codes(status):
    server = RawServer(respond(status, b"ignored", headers={"Content-Length": "7"}))
    try:
        response = make_transport().request("GET", server.url + "/")
        assert response.status == status
        assert response.body in (b"", b"ignored")
    finally:
        server.stop()


def test_head_with_content_length_does_not_read_a_body():
    server = RawServer(respond(200, b"", headers={"Content-Length": "10"}))
    try:
        response = make_transport().request("HEAD", server.url + "/")
        assert response.status == 200 and response.body == b""
    finally:
        server.stop()


def test_100_continue_is_skipped():
    payload = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    server = RawServer(raw(payload))
    try:
        response = make_transport().request("POST", server.url + "/", body=b"x", idempotent=False)
        assert response.status == 200 and response.body == b"ok"
    finally:
        server.stop()


@pytest.mark.parametrize("interim", [b"102 Processing", b"103 Early Hints", b"101 Switching Protocols"])
def test_unsupported_1xx_interim_responses_are_rejected(interim):
    payload = b"HTTP/1.1 " + interim + b"\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    server = RawServer(raw(payload))
    try:
        with pytest.raises(TransportError):
            make_transport().request("POST", server.url + "/", body=b"x", idempotent=False)
    finally:
        server.stop()


def test_more_than_five_interim_responses_is_rejected():
    payload = b"".join(b"HTTP/1.1 100 Continue\r\n\r\n" for _ in range(7))
    server = RawServer(raw(payload))
    try:
        with pytest.raises(TransportError):
            make_transport().request("GET", server.url + "/")
    finally:
        server.stop()


def test_http_10_without_length_reads_to_close():
    server = RawServer(raw(b"HTTP/1.0 200 OK\r\n\r\nbody"))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"body"
    finally:
        server.stop()


def test_large_single_header_is_rejected():
    server = RawServer(respond(200, b"", headers={"X": "a" * 70000}))
    try:
        with pytest.raises(TransportError):
            make_transport(max_header_bytes=1024 * 1024).request("GET", server.url + "/")
    finally:
        server.stop()


def test_duplicate_mixed_case_headers_last_wins():
    payload = b"HTTP/1.1 200 OK\r\nX-Test: a\r\nx-test: b\r\nContent-Length: 0\r\n\r\n"
    server = RawServer(raw(payload))
    try:
        assert make_transport().request("GET", server.url + "/").headers["x-test"] == "b"
    finally:
        server.stop()


def test_nul_and_utf8_body_bytes_are_preserved():
    body = b"\x00\x01\xff\xfe" + "café".encode()
    server = RawServer(respond(200, body))
    try:
        response = make_transport().request("GET", server.url + "/")
        assert response.body == body
    finally:
        server.stop()


def test_chunk_size_over_limit_is_rejected():
    payload = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffff\r\n" + b"x" * 20
    server = RawServer(raw(payload))
    try:
        with pytest.raises(TransportError):
            make_transport(max_body_bytes=100).request("GET", server.url + "/")
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------


REDIRECT_CASES = [
    (301, "/next"),
    (302, "next"),
    (303, "/next?x=1"),
    (307, "/next"),
    (308, "/next"),
]


@pytest.mark.parametrize("status,location", REDIRECT_CASES)
def test_redirects_are_followed_for_get(status, location):
    server = RawServer(sequence([respond(status, headers={"Location": location}), respond(200, b"ok")]))
    try:
        response = make_transport(max_redirects=2).request("GET", server.url + "/start")
        assert response.status == 200 and response.body == b"ok"
        assert len(server.requests) == 2
    finally:
        server.stop()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_post_is_not_redirected(status):
    server = RawServer(respond(status, headers={"Location": "/next"}))
    try:
        response = make_transport().request("POST", server.url + "/", body=b"x", idempotent=False)
        assert response.status == status
        assert len(server.requests) == 1
    finally:
        server.stop()


@pytest.mark.parametrize(
    "location",
    [
        "http://localhost:1/x",
        "//localhost:1/x",
        "http://127.0.0.1:1/x",
        "ftp://127.0.0.1/x",
        "https://127.0.0.1/x",
        "http://user:pass@127.0.0.1/x",
    ],
)
def test_dangerous_redirects_are_refused(location):
    server = RawServer(respond(302, headers={"Location": location}))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport(allow_plaintext=True).request("GET", server.url + "/")
        assert exc.value.kind == "redirect"
    finally:
        server.stop()


def test_redirect_location_with_control_character_is_refused():
    server = RawServer(respond(302, headers={"Location": "/x\r\nX: y"}))
    try:
        with pytest.raises(TransportError):
            make_transport().request("GET", server.url + "/")
    finally:
        server.stop()


def test_redirect_to_same_url_loop_is_detected():
    server = RawServer(respond(302, headers={"Location": "/same"}))
    try:
        with pytest.raises(TransportError, match="loop"):
            make_transport(max_redirects=10).request("GET", server.url + "/same")
    finally:
        server.stop()


def test_redirect_without_location_returns_status():
    server = RawServer(respond(307))
    try:
        assert make_transport().request("GET", server.url + "/").status == 307
    finally:
        server.stop()


def test_same_host_redirect_helpers():
    assert _same_host_redirect("http://example.org/a", "/b", True) == "http://example.org/b"
    assert (
        _same_host_redirect("http://example.org:80/a", "http://example.org/b", True) == "http://example.org/b"
    )
    with pytest.raises(TransportError):
        _same_host_redirect("http://example.org/a", "http://example.net/b", True)
    with pytest.raises(TransportError):
        _same_host_redirect("http://example.org/a", "https://example.org/b", True)
    with pytest.raises(TransportError):
        _same_host_redirect("http://example.org/a", "file:///etc/passwd", True)


# ---------------------------------------------------------------------------
# URL and header matrices
# ---------------------------------------------------------------------------

URL_VALID = [
    "https://example.org/",
    "https://example.org:8443/path?query=1",
    "https://bücher.example/",
    "https://[2001:db8::1]:443/x",
    "http://127.0.0.1:80/",
    "https://example.org/a%20b",
]


@pytest.mark.parametrize("url", URL_VALID)
def test_url_valid_matrix(url):
    parsed = _validate_url(url, True)
    assert parsed["scheme"] in ("http", "https")
    assert parsed["host"]
    assert parsed["path"].startswith("/")


URL_INVALID = [
    "ftp://example.org/",
    "file:///etc/passwd",
    "http:///nohost",
    "http://user:pass@example.org/",
    "http://example.org/\r\nX: y",
    "http://example.org:99999/",
    "http://example.org:notaport/",
    "http://example.org/\x00",
    "javascript:alert(1)",
    "http://example.org/\n",
    "",
]


@pytest.mark.parametrize("url", URL_INVALID)
def test_url_invalid_matrix(url):
    with pytest.raises(TransportError):
        _validate_url(url, True)


@pytest.mark.parametrize(
    "name,value",
    [
        ("X", "ok"),
        ("X-Test", "a b c"),
        ("X", "üñïçødé"[:4]),
        ("X", "a\tb"),
    ],
)
def test_header_values_that_are_valid(name, value):
    _validate_headers({name: value})


@pytest.mark.parametrize(
    "name,value",
    [
        ("X", "a\r\nb"),
        ("X", "a\nb"),
        ("X:Y", "z"),
        ("", "z"),
        ("Ünicode", "x"),
        ("X", "\u2603"),
        ("X", None),
    ],
)
def test_header_values_that_are_invalid(name, value):
    with pytest.raises(ValueError):
        _validate_headers({name: value})


# ---------------------------------------------------------------------------
# Retry policy details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0", 0.0),
        ("1.5", 1.5),
        ("999", 999.0),
        ("-1", 0.0),
        ("garbage", None),
        ("", None),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0.0),
        ("not a date", None),
    ],
)
def test_retry_after_matrix(value, expected):
    result = _parse_retry_after(value)
    if expected is None:
        assert result is None
    else:
        assert result == pytest.approx(expected, abs=2.0)


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504])
def test_retryable_statuses_get_three_attempts(status):
    server = RawServer(respond(status))
    transport, fake = make_retry_transport()
    try:
        response = transport.request("GET", server.url + "/")
        assert response.status == status
        assert response.attempts == 3
        assert len(server.requests) == 3
        assert fake.sleeps
    finally:
        server.stop()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 418, 501])
def test_non_retryable_statuses_get_one_attempt(status):
    server = RawServer(respond(status))
    transport, _fake = make_retry_transport()
    try:
        assert transport.request("GET", server.url + "/").attempts == 1
        assert len(server.requests) == 1
    finally:
        server.stop()


def test_no_retries_configured_returns_first_response():
    server = RawServer(respond(503))
    transport, _fake = make_retry_transport(retries=0)
    try:
        assert transport.request("GET", server.url + "/").status == 503
        assert len(server.requests) == 1
    finally:
        server.stop()


def test_retry_after_date_in_future_is_capped():
    import datetime as dt

    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60)
    header = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    server = RawServer(sequence([respond(429, headers={"Retry-After": header}), respond(200)]))
    transport, fake = make_retry_transport(backoff_cap=0.3)
    try:
        transport.request("GET", server.url + "/")
        assert sum(fake.sleeps) <= 0.4
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Deadlines, cancellation, DNS, connection handling
# ---------------------------------------------------------------------------


def test_deadline_applies_across_body_chunks():
    pieces = [b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"] + [b"x"] * 100
    server = RawServer(headers_then_chunks(pieces[0], pieces[1:], delay=0.02))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport(read_timeout=1.0, deadline=0.2).request("GET", server.url + "/")
        assert exc.value.kind == "timeout"
    finally:
        server.stop()


def test_cancellation_between_retries():
    server = RawServer(respond(503))
    transport = make_transport(retries=2, backoff_base=0.2, backoff_cap=0.2)
    event = threading.Event()

    def cancel():
        time.sleep(0.01)
        event.set()

    threading.Thread(target=cancel, daemon=True).start()
    try:
        with pytest.raises(TransportError, match="cancelled"):
            transport.request("GET", server.url + "/", stop_event=event)
    finally:
        server.stop()


def test_dns_cache_is_bounded(monkeypatch):
    transport = make_transport()
    calls = {"n": 0}

    def fake(host, port, *args, **kwargs):
        calls["n"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    for index in range(200):
        transport._default_resolve("host-%d.example" % index, 443, 1.0)
    assert len(transport._resolve_cache) <= 128
    assert calls["n"] >= 200


def test_connect_falls_back_to_second_address():
    server = RawServer(respond(200, b"ok"))
    transport = make_transport()
    transport._resolver = lambda host, port, timeout: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", server.port)),
    ]
    try:
        assert transport.request("GET", "http://fallback.example/").body == b"ok"
    finally:
        server.stop()


def test_resolver_exception_is_classified():
    transport = make_transport()
    transport._resolver = lambda host, port, timeout: (_ for _ in ()).throw(socket.gaierror("nope"))
    with pytest.raises(TransportError) as exc:
        transport.request("GET", "http://nope.example/")
    assert exc.value.kind == "dns" and exc.value.retryable


# ---------------------------------------------------------------------------
# TLS details and clock skew
# ---------------------------------------------------------------------------


def test_tls_peer_certificate_is_exposed(tmp_path):
    context, pem, cert = _make_cert(tmp_path, include_ip=True)
    server = RawServer(respond(200, b"ok"), tls_context=context)
    try:
        transport = _tls_transport(pem)
        response = transport.request("GET", server.url + "/")
        assert response.peer_certificate
        assert transport.last_peer_certificate == response.peer_certificate
    finally:
        server.stop()


def test_tls_pin_accepts_plain_hex_and_colons(tmp_path):
    context, pem, cert = _make_cert(tmp_path, include_ip=True)
    server = RawServer(respond(200, b"ok"), tls_context=context)
    digest = cert.fingerprint(__import__("cryptography").hazmat.primitives.hashes.SHA256()).hex()
    try:
        assert _tls_transport(pem, tls_pins=[digest]).request("GET", server.url + "/").status == 200
        assert (
            _tls_transport(pem, tls_pins=[":".join(digest[i : i + 2] for i in range(0, len(digest), 2))])
            .request("GET", server.url + "/")
            .status
            == 200
        )
    finally:
        server.stop()


def test_tls_disabled_still_captures_peer(tmp_path):
    context, _pem, _cert = _make_cert(tmp_path, include_ip=True)
    server = RawServer(respond(200, b"ok"), tls_context=context)
    try:
        transport = _tls_transport("", tls_verify=False)
        response = transport.request("GET", server.url + "/")
        assert response.peer_certificate
    finally:
        server.stop()


def test_server_clock_offset_is_ignored_when_absurd():
    server = RawServer(respond(200, b"ok", headers={"Date": "Mon, 01 Jan 1900 00:00:00 GMT"}))
    try:
        transport = make_transport()
        transport.request("GET", server.url + "/")
        assert transport.clock_offset == 0.0
    finally:
        server.stop()


def test_server_clock_offset_negative():
    import datetime as dt

    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=120)
    server = RawServer(respond(200, b"ok", headers={"Date": past.strftime("%a, %d %b %Y %H:%M:%S GMT")}))
    try:
        transport = make_transport()
        transport.request("GET", server.url + "/")
        assert -130 <= transport.clock_offset <= -110
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Resource cleanup
# ---------------------------------------------------------------------------


def _fd_count():
    for path in ("/dev/fd", "/proc/self/fd"):
        try:
            return len(os.listdir(path))
        except OSError:
            continue
    return None


def test_repeated_requests_do_not_leak_file_descriptors():
    server = RawServer(respond(200, b"ok"))
    try:
        transport = make_transport()
        baseline = _fd_count()
        for _ in range(30):
            assert transport.request("GET", server.url + "/").status == 200
        after = _fd_count()
        if baseline is not None and after is not None:
            assert after - baseline <= 4
    finally:
        server.stop()


def test_repeated_errors_do_not_leak_file_descriptors():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"))
    try:
        baseline = _fd_count()
        for _ in range(20):
            with pytest.raises(TransportError):
                make_transport(retries=0).request("GET", server.url + "/")
        after = _fd_count()
        if baseline is not None and after is not None:
            assert after - baseline <= 4
    finally:
        server.stop()


def test_many_concurrent_requests():
    server = RawServer(respond(200, b"ok"))
    errors = []

    def worker():
        try:
            assert make_transport().request("GET", server.url + "/").body == b"ok"
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        assert not errors
    finally:
        server.stop()
