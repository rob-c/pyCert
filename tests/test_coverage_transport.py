"""Coverage-oriented tests for transport framing, DNS and URL helpers."""

import socket
import threading
import time
from types import SimpleNamespace

import pytest
from raw_server import RawServer, headers_then_chunks, raw, respond

from pycert import transport as t
from pycert.transport import (
    Transport,
    TransportConfig,
    TransportError,
    _classify_ssl_error,
    _Deadline,
    _effective_port,
    _errno_name,
    _parse_retry_after,
    _same_host_redirect,
    _validate_url,
)


def _transport(**overrides):
    defaults = {"allow_plaintext": True, "retries": 0, "read_timeout": 2, "connect_timeout": 2, "deadline": 5}
    defaults.update(overrides)
    return Transport(TransportConfig(**defaults))


def test_deadline_and_url_helpers(monkeypatch):
    now = [0.0]
    deadline = _Deadline(1, lambda: now[0])
    assert not deadline.expired()
    now[0] = 2
    assert deadline.expired()
    with pytest.raises(TransportError):
        _validate_url(123, True)
    with pytest.raises(TransportError):
        _validate_url("https://example.org/\n", True)
    with pytest.raises(TransportError):
        _validate_url("https://example.org/\x01", True)
    with pytest.raises(TransportError):
        _validate_url("https://x:99999/", True)
    with pytest.raises(TransportError):
        _validate_url("https://user:pass@example.org/", True)
    with pytest.raises(TransportError):
        _validate_url("https://example.org:0/", True)
    with pytest.raises(TransportError):
        _validate_url("https://exa mple.org/", True)
    with pytest.raises(TransportError):
        _validate_url("https://[::1/", True)
    with pytest.raises(TransportError):
        _effective_port(__import__("urllib.parse").parse.urlsplit("https://example.org:99999"))
    with pytest.raises(TransportError):
        _same_host_redirect("https://example.org/", "https://example.org/\x01", True)
    assert _parse_retry_after("2") == 2.0
    assert _parse_retry_after("nonsense") is None
    assert _parse_retry_after("Sat, 07 Nov 2026 12:00:00 GMT") is not None
    assert _classify_ssl_error(RuntimeError("hostname mismatch"))[0] == "tls-hostname"
    assert _classify_ssl_error(RuntimeError("CERTIFICATE_VERIFY_FAILED"))[0] == "tls-verify"
    assert _classify_ssl_error(RuntimeError("other"))[0] == "tls"
    assert _errno_name(OSError(111, "refused"))


def test_ssl_context_system_trust_and_pin():
    transport = _transport(tls_verify=True, use_system_trust=True)
    assert transport.ssl_context()
    transport = _transport(tls_pins=["00"])
    with pytest.raises(TransportError):
        transport._check_pin(b"", "example.org")


def test_open_socket_error_paths(monkeypatch):
    now = [0.0]
    transport = _transport()
    deadline = _Deadline(5, lambda: now[0])
    now[0] = 10
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, deadline, None)
    now[0] = 0
    monkeypatch.setattr(transport, "_resolver", lambda *a: (_ for _ in ()).throw(socket.gaierror("no")))
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, deadline, None)
    monkeypatch.setattr(transport, "_resolver", lambda *a: (_ for _ in ()).throw(RuntimeError("no")))
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, deadline, None)
    monkeypatch.setattr(transport, "_resolver", lambda *a: [])
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, deadline, None)
    event = threading.Event()
    event.set()
    monkeypatch.setattr(transport, "_resolver", lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1))])
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, deadline, event)
    sock = SimpleNamespace(connect=lambda _addr: (_ for _ in ()).throw(TimeoutError()), close=lambda: None, settimeout=lambda _x: None)
    transport._socket_factory = lambda *a: sock
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, deadline, None)


def test_dns_cache_and_timeout(monkeypatch):
    transport = _transport()
    with pytest.raises(TransportError):
        transport._default_resolve("example.org", 80, 0)
    transport._resolve_cache[("example.org", 80)] = (time.monotonic() + 10, RuntimeError("cached"))
    with pytest.raises(TransportError):
        transport._default_resolve("example.org", 80, 1)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("dns")))
    with pytest.raises(TransportError):
        transport._default_resolve("bad.example.org", 80, 1)


def test_request_interim_headers_and_limits():
    server = RawServer(headers_then_chunks("HTTP/1.1 100 Continue\r\n\r\n", ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]))
    try:
        assert _transport().request("GET", server.url + "/").body == b"ok"
    finally:
        server.stop()
    server = RawServer(respond(200, b"x", headers={("X-%d" % i): "v" for i in range(201)}))
    try:
        with pytest.raises(TransportError):
            _transport().request("GET", server.url + "/")
    finally:
        server.stop()
    server = RawServer(respond(200, b"", headers={"Content-Length": "999999999"}))
    try:
        with pytest.raises(TransportError):
            _transport(max_body_bytes=10).request("GET", server.url + "/")
    finally:
        server.stop()
    server = RawServer(raw(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"))
    try:
        with pytest.raises(TypeError):
            _transport().request("POST", server.url + "/", body="not bytes")
    finally:
        server.stop()


def test_cancellable_sleep_and_logging():
    transport = _transport()
    event = threading.Event()
    event.set()
    with pytest.raises(TransportError):
        transport._sleep_cancellable(1, event)
    messages = []
    transport._logger = lambda event, fields: messages.append((event, fields))
    transport._log("x")
    assert messages
    transport._logger = lambda event, fields: (_ for _ in ()).throw(RuntimeError("log"))
    transport._log("x")
    transport._note_server_time(SimpleNamespace(headers={"date": "not a date"}))
    transport._note_server_time(SimpleNamespace(headers={"date": "Mon, 01 Jan 1900 00:00:00 GMT"}))


def test_duplicate_header_and_body_limit(monkeypatch):
    transport = _transport()
    headers = transport._build_headers({"scheme": "http", "host": "x", "port": 80, "path": "/"}, b"x", {"User-Agent": "custom"})
    assert ("User-Agent", "custom") in headers
    transport = _transport(max_body_bytes=1)
    server = RawServer(respond(200, b"xx"))
    try:
        with pytest.raises(TransportError):
            transport.request("GET", server.url + "/")
    finally:
        server.stop()


def test_resolver_transport_error_and_deadline():
    transport = _transport()
    def resolver(*args):
        raise TransportError("resolver", kind="dns", retryable=True)
    transport._resolver = resolver
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, _Deadline(1, lambda: 0.0), None)
    class Deadline:
        def __init__(self):
            self.values = iter([1, 0])
        def remaining(self):
            return next(self.values, 0)
    class Sock:
        def settimeout(self, _value): pass
        def connect(self, _addr): pass
        def close(self): pass
    transport._resolver = lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1))]
    transport._socket_factory = lambda *a: Sock()
    with pytest.raises(TransportError):
        transport._open_socket("x", 1, Deadline(), None)


def test_idna_and_retry_date_edges():
    with pytest.raises(TransportError):
        _validate_url("https://\ud800.example/", True)
    assert _parse_retry_after("Mon, 01 Jan 1900 00:00:00") is not None
    assert _parse_retry_after("not-a-date") is None
    with pytest.raises(TransportError):
        _same_host_redirect("http://example.org:80/", "http://example.org:99999/", True)


def test_peer_cert_exception_and_close_error(monkeypatch):
    transport = _transport()
    class BadSock:
        def getpeercert(self, binary_form=True):
            raise OSError("no peer")
        def sendall(self, _data): pass
        def close(self): raise OSError("close")
    connection = t._Connection(transport, "x", 1, tls=True, deadline=_Deadline(1, lambda: 0.0), stop_event=None)
    class Context:
        def wrap_socket(self, sock, server_hostname):
            return BadSock()
    transport._ssl_context = Context()
    transport._open_socket = lambda *a: BadSock()
    connection.connect()
    assert connection.peer_certificate == b""


def test_interim_too_many_and_close_failure(monkeypatch):
    server = RawServer(respond(200, b"ok"))
    try:
        real_close = t._Connection.close
        monkeypatch.setattr(t._Connection, "close", lambda self: (_ for _ in ()).throw(OSError("close")))
        assert _transport().request("GET", server.url + "/").body == b"ok"
        monkeypatch.setattr(t._Connection, "close", real_close)
    finally:
        server.stop()


def test_transport_deadline_body_headers_and_dates(monkeypatch):
    class Conn:
        sock = SimpleNamespace(settimeout=lambda *a: None)

        def connect(self):
            pass

        def putrequest(self, *a, **k):
            pass

        def putheader(self, *a, **k):
            pass

        def endheaders(self, *a, **k):
            pass

    monkeypatch.setattr(t, "_Connection", lambda *a, **k: Conn())
    with pytest.raises(TransportError):
        _transport(deadline=0).request("GET", "https://example.org/")
    with pytest.raises(TransportError):
        _effective_port(SimpleNamespace(port=0, scheme="https"))
    response = SimpleNamespace(headers={"date": "not-a-date"})
    transport = _transport()
    transport._note_server_time(response)
    response.headers["date"] = "Sat, 07 Nov 2026 12:00:00"
    transport._note_server_time(response)
    assert _parse_retry_after("Sun, 99 Nov 2026 12:00:00 GMT") is None
    assert _parse_retry_after("Sat, 07 Nov 2026 12:00:00") is not None


def test_transport_header_count_and_body_limit():
    headers = "".join("X-%d: y\r\n" % i for i in range(201))
    server = RawServer(raw("HTTP/1.1 200 OK\r\n%sContent-Length: 0\r\n\r\n" % headers))
    try:
        with pytest.raises(TransportError):
            _transport().request("GET", server.url + "/")
    finally:
        server.stop()
    server = RawServer(respond(200, b"hello", headers={"Content-Type": "text/plain"}))
    try:
        with pytest.raises(TransportError):
            _transport(max_body_bytes=1).request("GET", server.url + "/")
    finally:
        server.stop()
