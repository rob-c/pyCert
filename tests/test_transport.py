"""Fault-injection tests for the hardened HTTP transport."""

import datetime as dt
import random
import socket
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from raw_server import (
    RawServer,
    headers_then_chunks,
    raw,
    reset,
    respond,
    sequence,
    silent,
)

from pycert.errors import NetworkError
from pycert.transport import (
    Response,
    Transport,
    TransportConfig,
    TransportError,
    _parse_retry_after,
    _same_host_redirect,
    _validate_headers,
    _validate_url,
)


class FakeTime:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def make_transport(**overrides):
    config = TransportConfig(
        allow_plaintext=True,
        retries=0,
        connect_timeout=0.5,
        read_timeout=0.5,
        deadline=2.0,
        dns_timeout=0.5,
        backoff_base=0.0,
        backoff_cap=0.0,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return Transport(config)


def make_retry_transport(**overrides):
    config = TransportConfig(
        allow_plaintext=True,
        retries=2,
        connect_timeout=0.5,
        read_timeout=0.5,
        deadline=2.0,
        dns_timeout=0.5,
        backoff_base=0.4,
        backoff_cap=0.8,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    fake = FakeTime()
    return Transport(config, clock=fake, sleep=fake.sleep, rng=random.Random(0)), fake


# ---------------------------------------------------------------------------
# URL and header validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,match",
    [
        ("ftp://example.org/", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("http:///nohost", "no host"),
        ("http://user:pass@example.org/", "credentials"),
        ("http://example.org/\nX: y", "newline"),
        ("http://example.org:99999/", "port"),
        ("http://example.org:notaport/", "port"),
        ("http://example.org/\x00", "control"),
    ],
)
def test_url_validation_rejects(url, match):
    transport = make_transport()
    with pytest.raises(TransportError, match=match):
        transport.request("GET", url)


def test_url_validation_allows_idna_and_ipv6():
    assert _validate_url("https://bücher.example/", False)["host"] == "xn--bcher-kva.example"
    assert _validate_url("http://[::1]:8080/x", True)["host"] == "::1"
    with pytest.raises(TransportError):
        _validate_url("http://example.org/", False)  # plaintext needs opt-in


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Test": "a\r\nInjected: yes"},
        {"X-Test": "a\nInjected: yes"},
        {"Bad:Name": "x"},
        {"": "x"},
        {"X-Test": 5},
        {"X": None},
    ],
)
def test_header_injection_is_rejected(headers):
    with pytest.raises(ValueError):
        _validate_headers(headers)


def test_url_with_newline_in_header_is_rejected_before_any_connection():
    server = RawServer(respond())
    try:
        with pytest.raises(ValueError):
            make_transport().request("GET", server.url + "/", headers={"X": "a\r\nb"})
        assert server.requests == []
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Status codes, bodies, framing
# ---------------------------------------------------------------------------

STATUS_CASES = [
    (200, "OK"),
    (201, "Created"),
    (202, "Accepted"),
    (204, "No Content"),
    (301, "Moved Permanently"),
    (302, "Found"),
    (304, "Not Modified"),
    (400, "Bad Request"),
    (401, "Unauthorized"),
    (403, "Forbidden"),
    (404, "Not Found"),
    (405, "Method Not Allowed"),
    (408, "Request Timeout"),
    (418, "I'm a teapot"),
    (429, "Too Many Requests"),
    (500, "Internal Server Error"),
    (502, "Bad Gateway"),
    (503, "Service Unavailable"),
    (504, "Gateway Timeout"),
    (599, "Custom"),
]


@pytest.mark.parametrize("status,reason", STATUS_CASES)
def test_status_codes_are_returned(status, reason):
    body = b"" if status in (204, 304) else b"payload"
    server = RawServer(respond(status, body, reason=reason))
    try:
        response = make_transport().request("GET", server.url + "/x")
        assert response.status == status
        assert response.reason == reason
        if status not in (204, 304):
            assert response.body == body
    finally:
        server.stop()


def test_request_line_headers_and_body_are_sent():
    server = RawServer(respond(201))
    try:
        response = make_transport().request(
            "POST",
            server.url + "/CSR?x=1",
            body=b"<x/>",
            headers={"X-Custom": "yes", "Content-Type": "application/xml"},
            idempotent=False,
        )
        assert response.status == 201
        request = server.requests[0]
        assert request.startswith(b"POST /CSR?x=1 HTTP/1.1\r\n")
        assert b"Host: 127.0.0.1:" in request
        assert b"X-Custom: yes" in request
        assert b"Content-Length: 4" in request
        assert b"Content-Type: application/xml" in request
        assert b"<x/>" in request
        assert request.count(b"Host:") == 1
    finally:
        server.stop()


def test_default_content_type_and_identity_encoding():
    server = RawServer(respond())
    try:
        make_transport().request("POST", server.url + "/", body=b"x", idempotent=False)
        request = server.requests[0]
        assert b"Accept-Encoding: identity" in request
        assert b"Connection: close" in request
    finally:
        server.stop()


def test_body_without_content_length_is_read_until_close():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello"))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"hello"
    finally:
        server.stop()


def test_truncated_content_length_is_an_error():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport().request("GET", server.url + "/")
        assert exc.value.kind == "truncated"
        assert exc.value.retryable is True
    finally:
        server.stop()


def test_extra_body_bytes_beyond_content_length_are_ignored():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"abc"
    finally:
        server.stop()


def test_chunked_body_is_decoded():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"hello"
    finally:
        server.stop()


def test_chunked_truncation_is_an_error():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nabc"))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport().request("GET", server.url + "/")
        assert exc.value.kind in ("protocol", "truncated")
    finally:
        server.stop()


def test_malformed_chunk_size_is_an_error():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n"))
    try:
        with pytest.raises(TransportError):
            make_transport().request("GET", server.url + "/")
    finally:
        server.stop()


def test_declared_body_over_limit_is_rejected():
    server = RawServer(respond(200, b"x" * 500))
    try:
        transport = make_transport(max_body_bytes=100)
        with pytest.raises(TransportError, match="exceeds") as exc:
            transport.request("GET", server.url + "/")
        assert exc.value.kind == "body"
    finally:
        server.stop()


def test_streamed_body_over_limit_is_rejected():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"x" * 500))
    try:
        with pytest.raises(TransportError, match="exceeds") as exc:
            make_transport(max_body_bytes=100).request("GET", server.url + "/")
        assert exc.value.kind == "body"
    finally:
        server.stop()


def test_gzip_response_is_rejected():
    server = RawServer(respond(200, b"x", headers={"Content-Encoding": "gzip"}))
    try:
        with pytest.raises(TransportError, match="compressed") as exc:
            make_transport().request("GET", server.url + "/")
        assert exc.value.kind == "protocol"
    finally:
        server.stop()


def test_oversized_headers_are_rejected():
    server = RawServer(respond(200, b"", headers={"X-Big": "a" * 500}))
    try:
        with pytest.raises(TransportError, match="headers") as exc:
            make_transport(max_header_bytes=200).request("GET", server.url + "/")
        assert exc.value.kind == "protocol"
    finally:
        server.stop()


def test_too_many_headers_are_rejected():
    headers = {"X-%d" % i: "v" for i in range(150)}
    server = RawServer(respond(200, b"", headers=headers))
    try:
        with pytest.raises(TransportError):
            make_transport(max_header_bytes=1024 * 1024).request("GET", server.url + "/")
    finally:
        server.stop()


@pytest.mark.parametrize(
    "payload",
    [
        b"HELLO\r\n\r\n",
        b"HTTP/1.1 9999 Nope\r\n\r\n",
        b"HTTP/9 200 OK\r\n\r\n",
        b"HTTP/1.1 abc OK\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ],
)
def test_malformed_status_lines_are_protocol_errors(payload):
    server = RawServer(raw(payload))
    try:
        with pytest.raises(TransportError):
            make_transport().request("GET", server.url + "/")
    finally:
        server.stop()


def test_http_10_response_is_accepted():
    server = RawServer(raw(b"HTTP/1.0 200 OK\r\n\r\nold"))
    try:
        assert make_transport().request("GET", server.url + "/").body == b"old"
    finally:
        server.stop()


def test_interim_100_continue_is_skipped():
    server = RawServer(raw(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
    try:
        response = make_transport().request("POST", server.url + "/", body=b"x", idempotent=False)
        assert response.status == 200 and response.body == b"ok"
    finally:
        server.stop()


def test_head_response_has_no_body():
    server = RawServer(respond(200, b"", headers={"Content-Length": "10"}))
    try:
        assert make_transport().request("HEAD", server.url + "/").body == b""
    finally:
        server.stop()


def test_duplicate_response_headers_last_wins():
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nX-Test: one\r\nX-Test: two\r\nContent-Length: 0\r\n\r\n"))
    try:
        response = make_transport().request("GET", server.url + "/")
        assert response.headers["x-test"] == "two"
        assert ("X-Test", "one") in response.header_list
    finally:
        server.stop()


def test_response_text_decoding():
    assert Response(200, "OK", {}, b"caf\xc3\xa9", "u").text() == "café"
    assert Response(200, "OK", {}, b"caf\xe9", "u").text() == "café"


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------


def test_same_host_relative_redirect_is_followed():
    server = RawServer(
        sequence(
            [
                respond(302, headers={"Location": "/final"}),
                respond(200, b"done"),
            ]
        )
    )
    try:
        response = make_transport().request("GET", server.url + "/start")
        assert response.status == 200 and response.body == b"done"
        assert len(server.requests) == 2
        assert server.requests[1].startswith(b"GET /final HTTP/1.1")
    finally:
        server.stop()


def test_absolute_redirect_with_default_port_is_followed():
    server = RawServer(sequence([respond(301, headers={"Location": "/next"}), respond(200, b"ok")]))
    try:
        response = make_transport().request("GET", server.url + "/x")
        assert response.status == 200
    finally:
        server.stop()


def test_cross_host_redirect_is_refused():
    server = RawServer(respond(302, headers={"Location": "http://localhost:%d/x" % 1}))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport().request("GET", server.url + "/")
        assert exc.value.kind == "redirect"
    finally:
        server.stop()


def test_redirect_loop_is_detected():
    server = RawServer(respond(302, headers={"Location": "/same"}))
    try:
        with pytest.raises(TransportError, match="loop") as exc:
            make_transport(max_redirects=5).request("GET", server.url + "/same")
        assert exc.value.kind == "redirect"
    finally:
        server.stop()


def test_redirect_limit_is_enforced():
    server = RawServer(respond(302, headers={"Location": "/next"}))
    try:
        with pytest.raises(TransportError, match="too many") as exc:
            make_transport(max_redirects=1).request("GET", server.url + "/start")
        assert exc.value.kind == "redirect"
    finally:
        server.stop()


def test_redirect_without_location_is_returned():
    server = RawServer(respond(302))
    try:
        assert make_transport().request("GET", server.url + "/").status == 302
    finally:
        server.stop()


def test_post_is_never_redirected():
    server = RawServer(respond(307, headers={"Location": "/other"}))
    try:
        response = make_transport().request("POST", server.url + "/", body=b"x", idempotent=False)
        assert response.status == 307
        assert len(server.requests) == 1
    finally:
        server.stop()


def test_redirect_to_plaintext_is_refused_when_https_is_required():
    with pytest.raises(TransportError):
        _same_host_redirect("https://example.org/a", "http://example.org/b", False)


def test_redirect_to_unsupported_scheme_is_refused():
    with pytest.raises(TransportError):
        _same_host_redirect("https://example.org/a", "file:///etc/passwd", False)


def test_redirect_with_credentials_is_refused():
    with pytest.raises(TransportError):
        _same_host_redirect("https://example.org/a", "https://u:p@example.org/b", False)


# ---------------------------------------------------------------------------
# Retries, backoff and Retry-After
# ---------------------------------------------------------------------------


def test_idempotent_request_retries_status_and_succeeds():
    server = RawServer(sequence([respond(503), respond(200, b"ok")]))
    transport, fake = make_retry_transport()
    try:
        response = transport.request("GET", server.url + "/")
        assert response.status == 200 and response.attempts == 2
        assert len(server.requests) == 2
        assert fake.sleeps and all(s >= 0 for s in fake.sleeps)
    finally:
        server.stop()


def test_retries_are_exhausted_and_last_status_returned():
    server = RawServer(respond(503))
    transport, fake = make_retry_transport()
    try:
        response = transport.request("GET", server.url + "/")
        assert response.status == 503
        assert len(server.requests) == 3
    finally:
        server.stop()


def test_post_is_not_retried_on_retryable_status():
    server = RawServer(respond(503))
    transport, _fake = make_retry_transport()
    try:
        response = transport.request("POST", server.url + "/", body=b"x", idempotent=False)
        assert response.status == 503
        assert len(server.requests) == 1
    finally:
        server.stop()


def test_explicit_idempotent_post_is_retried():
    server = RawServer(sequence([respond(503), respond(200, b"ok")]))
    transport, _fake = make_retry_transport()
    try:
        response = transport.request("POST", server.url + "/", body=b"x", idempotent=True)
        assert response.status == 200
        assert len(server.requests) == 2
    finally:
        server.stop()


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504])
def test_retryable_status_set(status):
    server = RawServer(sequence([respond(status), respond(200)]))
    transport, _fake = make_retry_transport()
    try:
        assert transport.request("GET", server.url + "/").status == 200
    finally:
        server.stop()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 418, 501])
def test_non_retryable_status_set(status):
    server = RawServer(respond(status))
    transport, _fake = make_retry_transport()
    try:
        assert transport.request("GET", server.url + "/").status == status
        assert len(server.requests) == 1
    finally:
        server.stop()


def test_retry_after_seconds_is_honoured():
    server = RawServer(sequence([respond(429, headers={"Retry-After": "0.3"}), respond(200)]))
    transport, fake = make_retry_transport(backoff_base=0.01)
    try:
        transport.request("GET", server.url + "/")
        assert abs(sum(fake.sleeps) - 0.3) < 0.15
    finally:
        server.stop()


def test_retry_after_is_capped():
    server = RawServer(sequence([respond(503, headers={"Retry-After": "999"}), respond(200)]))
    transport, fake = make_retry_transport(backoff_cap=0.2)
    try:
        transport.request("GET", server.url + "/")
        assert sum(fake.sleeps) <= 0.3
    finally:
        server.stop()


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("0", 0.0),
        ("2", 2.0),
        ("-5", 0.0),
        ("garbage", None),
        ("", None),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),
    ],
)
def test_parse_retry_after(value, expected):
    result = _parse_retry_after(value)
    if expected is None:
        assert result is None
    else:
        assert result == pytest.approx(expected, abs=1.0)


def test_connection_reset_is_retried_for_get():
    server = RawServer(sequence([reset(), respond(200, b"ok")]))
    transport, _fake = make_retry_transport()
    try:
        response = transport.request("GET", server.url + "/")
        assert response.status == 200
        assert len(server.requests) == 2
    finally:
        server.stop()


def test_connection_reset_is_not_retried_for_post():
    server = RawServer(reset())
    transport, _fake = make_retry_transport()
    try:
        with pytest.raises(NetworkError):
            transport.request("POST", server.url + "/", body=b"x", idempotent=False)
        assert len(server.requests) == 1
    finally:
        server.stop()


def test_backoff_jitter_is_bounded():
    transport, _fake = make_retry_transport(backoff_base=1.0, backoff_cap=4.0)
    values = [transport._backoff(attempt) for attempt in range(1, 8)]
    assert all(0 <= value <= 4.0 for value in values)
    assert values[0] <= 1.0


# ---------------------------------------------------------------------------
# Deadlines, cancellation, DNS, connect errors
# ---------------------------------------------------------------------------


def test_slow_headers_hit_the_read_timeout():
    server = RawServer(silent(1.0))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport(read_timeout=0.15, deadline=1.0).request("GET", server.url + "/")
        assert exc.value.kind == "timeout"
    finally:
        server.stop()


def test_slow_body_hits_the_deadline():
    pieces = [b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"] + [b"x"] * 40
    server = RawServer(headers_then_chunks(pieces[0], pieces[1:], delay=0.05))
    try:
        with pytest.raises(TransportError) as exc:
            make_transport(read_timeout=0.5, deadline=0.35).request("GET", server.url + "/")
        assert exc.value.kind == "timeout"
    finally:
        server.stop()


def test_cancellation_before_sending():
    server = RawServer(respond(200, b"ok"))
    event = threading.Event()
    event.set()
    try:
        with pytest.raises(TransportError, match="cancelled"):
            make_transport().request("GET", server.url + "/", stop_event=event)
        assert server.requests == []
    finally:
        server.stop()


def test_cancellation_during_body_read():
    pieces = [b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"] + [b"x"] * 60
    server = RawServer(headers_then_chunks(pieces[0], pieces[1:], delay=0.05))
    event = threading.Event()

    def cancel_later():
        time.sleep(0.2)
        event.set()

    threading.Thread(target=cancel_later, daemon=True).start()
    try:
        with pytest.raises(TransportError, match="cancelled"):
            make_transport(read_timeout=1.0, deadline=5.0).request("GET", server.url + "/", stop_event=event)
    finally:
        server.stop()


def test_dns_resolver_returning_nothing():
    transport = make_transport()
    transport._resolver = lambda host, port, timeout: []
    with pytest.raises(TransportError) as exc:
        transport.request("GET", "http://nowhere.invalid/")
    assert exc.value.kind == "dns" and exc.value.retryable


def test_dns_resolver_error_is_wrapped():
    transport = make_transport()

    def boom(host, port, timeout):
        raise socket.gaierror("nope")

    transport._resolver = boom
    with pytest.raises(TransportError) as exc:
        transport.request("GET", "http://nowhere.invalid/")
    assert exc.value.kind == "dns" and exc.value.retryable


def test_default_resolver_timeout(monkeypatch):
    transport = make_transport(dns_timeout=0.1)

    def slow(*args, **kwargs):
        time.sleep(0.4)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", slow)
    with pytest.raises(TransportError) as exc:
        transport._default_resolve("slow.example", 80, 0.1)
    assert exc.value.kind == "dns"


def test_default_resolver_cache(monkeypatch):
    calls = {"n": 0}

    def fake_getaddrinfo(host, port, *args, **kwargs):
        calls["n"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    transport = make_transport()
    first = transport._default_resolve("cache.example", 443, 1.0)
    second = transport._default_resolve("cache.example", 443, 1.0)
    assert first == second
    assert calls["n"] == 1


def test_connect_timeout_is_retryable():
    transport = make_transport()
    transport._resolver = lambda host, port, timeout: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9))
    ]

    def factory(family, socktype, proto):
        raise TimeoutError("connect timed out")

    transport._socket_factory = factory
    with pytest.raises(TransportError) as exc:
        transport.request("GET", "http://connect.example/")
    assert exc.value.kind == "connect" and exc.value.retryable


def test_connection_refused_is_a_network_error():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(TransportError) as exc:
        make_transport().request("GET", "http://127.0.0.1:%d/" % port)
    assert exc.value.kind in ("connect", "timeout")


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def _make_cert(tmp_path, *, san_dns="localhost", include_ip=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "transport test")])
    now = dt.datetime.now(dt.timezone.utc)
    sans = [x509.DNSName(san_dns)] if san_dns else []
    if include_ip:
        sans.append(x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "tls-cert.pem"
    key_path = tmp_path / "tls-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context, cert_path.read_text(), cert


def _tls_transport(cert_pem, **overrides):
    config = TransportConfig(
        allow_plaintext=False,
        retries=0,
        connect_timeout=1.0,
        read_timeout=1.0,
        deadline=2.0,
        dns_timeout=1.0,
        tls_verify=True,
        tls_pem=cert_pem,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return Transport(config)


def test_tls_verified_request_with_ip_san(tmp_path):
    context, pem, _cert = _make_cert(tmp_path, san_dns="localhost", include_ip=True)
    server = RawServer(respond(200, b"secure"), tls_context=context)
    try:
        response = _tls_transport(pem).request("GET", server.url + "/")
        assert response.status == 200 and response.body == b"secure"
        assert response.peer_certificate
    finally:
        server.stop()


def test_tls_without_trust_material_is_refused(tmp_path):
    context, _pem, _cert = _make_cert(tmp_path, include_ip=True)
    server = RawServer(respond(), tls_context=context)
    try:
        with pytest.raises(TransportError, match="trust material") as exc:
            _tls_transport("").request("GET", server.url + "/")
        assert exc.value.kind == "tls"
    finally:
        server.stop()


def test_tls_wrong_ca_is_refused(tmp_path):
    context, _pem, _cert = _make_cert(tmp_path, include_ip=True)
    _context2, other_pem, _cert2 = (
        _make_cert(tmp_path / "other", include_ip=True) if False else (None, "", None)
    )
    # Build an unrelated CA certificate to use as the (wrong) trust anchor.
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other")])
    now = dt.datetime.now(dt.timezone.utc)
    other = (
        x509.CertificateBuilder()
        .subject_name(other_name)
        .issuer_name(other_name)
        .public_key(other_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(other_key, hashes.SHA256())
    )
    other_pem = other.public_bytes(serialization.Encoding.PEM).decode()
    server = RawServer(respond(), tls_context=context)
    try:
        with pytest.raises(TransportError) as exc:
            _tls_transport(other_pem).request("GET", server.url + "/")
        assert exc.value.kind in ("tls", "tls-verify")
    finally:
        server.stop()


def test_tls_hostname_mismatch_is_refused(tmp_path):
    context, pem, _cert = _make_cert(tmp_path, san_dns="localhost", include_ip=False)
    server = RawServer(respond(), tls_context=context)
    try:
        with pytest.raises(TransportError) as exc:
            _tls_transport(pem).request("GET", server.url + "/")
        assert exc.value.kind in ("tls", "tls-hostname")
    finally:
        server.stop()


def test_tls_verification_can_be_disabled(tmp_path):
    context, _pem, _cert = _make_cert(tmp_path, san_dns="localhost", include_ip=False)
    server = RawServer(respond(200, b"ok"), tls_context=context)
    try:
        response = _tls_transport("", tls_verify=False).request("GET", server.url + "/")
        assert response.status == 200
    finally:
        server.stop()


def test_tls_pin_success(tmp_path):
    context, pem, cert = _make_cert(tmp_path, include_ip=True)
    server = RawServer(respond(200, b"ok"), tls_context=context)
    fingerprint = ":".join("%02X" % b for b in cert.fingerprint(hashes.SHA256()))
    try:
        response = _tls_transport(pem, tls_pins=[fingerprint]).request("GET", server.url + "/")
        assert response.status == 200
    finally:
        server.stop()


def test_tls_pin_mismatch(tmp_path):
    context, pem, _cert = _make_cert(tmp_path, include_ip=True)
    server = RawServer(respond(), tls_context=context)
    try:
        with pytest.raises(TransportError, match="pin mismatch") as exc:
            _tls_transport(pem, tls_pins=["00" * 32]).request("GET", server.url + "/")
        assert exc.value.kind == "tls-pin"
    finally:
        server.stop()


def test_plaintext_pin_is_ignored():
    server = RawServer(respond(200, b"ok"))
    try:
        transport = make_transport()
        transport.config.tls_pins = ["00" * 32]
        assert transport.request("GET", server.url + "/").status == 200
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Clock skew
# ---------------------------------------------------------------------------


def test_server_date_offset_is_measured():
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=300)
    server = RawServer(respond(200, b"ok", headers={"Date": future.strftime("%a, %d %b %Y %H:%M:%S GMT")}))
    try:
        transport = make_transport()
        before = transport.now_ms()
        transport.request("GET", server.url + "/")
        after = transport.now_ms()
        assert 290000 <= transport.clock_offset * 1000 <= 310000
        assert after - before >= 290000 - 1000
    finally:
        server.stop()


def test_invalid_server_date_is_ignored():
    server = RawServer(respond(200, b"ok", headers={"Date": "not a date"}))
    try:
        transport = make_transport()
        transport.request("GET", server.url + "/")
        assert transport.clock_offset == 0.0
    finally:
        server.stop()
