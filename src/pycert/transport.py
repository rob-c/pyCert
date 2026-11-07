"""Hardened HTTP(S) transport.

The CA client must survive a hostile or simply broken network.  This module is a
thin, explicit layer over ``http.client`` that adds:

* **Deadlines.** A request has a total deadline, not just a socket timeout.
  Headers and body are read in bounded chunks and the deadline is checked
  between them, so a server that trickles bytes forever cannot pin a thread.
* **DNS timeouts.** Name resolution runs in a short-lived thread with a timeout
  and a small cache; a black-holed resolver cannot hang the process.
* **Truncation detection.** A short ``Content-Length`` body, an incomplete chunk,
  a malformed status line or an oversized response is a hard error, never a
  silently short buffer.
* **Bounded memory.** Body and header sizes are capped before and during reads;
  compressed responses are refused (the client asks for ``identity``).
* **Retry policy.** Only idempotent requests (GET/HEAD and explicitly marked
  POSTs such as the status lookup) are retried, with exponential backoff and
  full jitter, and only for connection errors and 408/429/500/502/503/504.
  ``Retry-After`` is honoured.  A submission is never retried.
* **Redirect policy.** At most a few same-host redirects, never for POST, never
  cross-host, never to plaintext.  This is tighter than what a browser does and
  is appropriate for a single-purpose CA client.
* **Cancellation.** A ``threading.Event`` is checked before resolving, before
  connecting, before each retry and between body chunks.
* **Server clock skew.** The ``Date`` header is used to estimate the server's
  clock offset, which the PPPK challenge needs; a badly skewed local clock then
  does not break renewal.
* **Injection.** Header names/values and URL paths are validated against CR/LF
  injection; IDNA host names and IPv6 literals are handled.

Everything is dependency-injected (resolver, socket factory, clock, sleep, RNG)
so the test suite can exercise failures deterministically without waiting.
"""

import email.utils
import errno
import http.client
import random
import socket
import ssl
import threading
import time
from datetime import timezone
from ipaddress import ip_address
from urllib.parse import urljoin, urlsplit

from .compat import dataclass, field, set_minimum_tls_version
from .errors import NetworkError

__all__ = [
    "TransportConfig",
    "Transport",
    "TransportError",
    "Response",
    "RETRYABLE_STATUS",
    "DEFAULT_USER_AGENT",
]

DEFAULT_USER_AGENT = "pyCert/1.0"
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
MAX_HEADER_COUNT = 200


class TransportError(NetworkError):
    """A network failure with a machine-readable kind and retryability."""

    def __init__(self, message, *, kind="network", retryable=False, url=""):
        super().__init__(message)
        self.kind = kind
        self.retryable = retryable
        self.url = url


@dataclass
class TransportConfig:
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    deadline: float = 90.0
    dns_timeout: float = 10.0
    retries: int = 2
    max_redirects: int = 2
    max_body_bytes: int = 8 * 1024 * 1024
    max_header_bytes: int = 128 * 1024
    backoff_base: float = 0.4
    backoff_cap: float = 8.0
    user_agent: str = DEFAULT_USER_AGENT
    allow_plaintext: bool = False
    tls_verify: bool = True
    tls_pem: str = ""
    use_system_trust: bool = False
    tls_pins: list = field(default_factory=list)
    min_tls_version: str = "1.2"


@dataclass
class Response:
    status: int
    reason: str
    headers: dict
    body: bytes
    url: str
    elapsed: float = 0.0
    peer_certificate: bytes = b""
    header_list: list = field(default_factory=list)
    attempts: int = 1

    def text(self) -> str:
        try:
            return self.body.decode("utf-8")
        except UnicodeDecodeError:
            return self.body.decode("latin-1")


class _Deadline:
    def __init__(self, seconds, clock):
        self._clock = clock
        self.end = clock() + max(0.0, seconds)

    def remaining(self):
        return self.end - self._clock()

    def expired(self):
        return self.remaining() <= 0


class _Connection(http.client.HTTPConnection):
    """HTTPConnection that uses our resolver, TLS context and pin checks."""

    def __init__(self, transport, host, port, *, tls, deadline, stop_event):
        super().__init__(host, port, timeout=transport.config.connect_timeout)
        self._transport = transport
        self._tls = tls
        self._deadline = deadline
        self._stop_event = stop_event
        self.peer_certificate = b""

    def connect(self):
        self.sock = self._transport._open_socket(self.host, self.port, self._deadline, self._stop_event)
        if self._tls:
            context = self._transport.ssl_context()
            try:
                self.sock = context.wrap_socket(self.sock, server_hostname=self.host)
            except BaseException:
                self.close()
                raise
            try:
                self.peer_certificate = self.sock.getpeercert(binary_form=True) or b""
            except (AttributeError, OSError):
                self.peer_certificate = b""
            self._transport._check_pin(self.peer_certificate, self.host)


class Transport:
    def __init__(
        self,
        config,
        *,
        ssl_context=None,
        resolver=None,
        socket_factory=None,
        clock=None,
        sleep=None,
        rng=None,
        logger=None,
    ):
        self.config = config
        self._ssl_context = ssl_context
        self._resolver = resolver or self._default_resolve
        self._socket_factory = socket_factory or socket.socket
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._rng = rng or random.Random()
        self._logger = logger
        self._resolve_cache = {}
        self._resolve_lock = threading.Lock()
        self.clock_offset = 0.0
        self.last_peer_certificate = b""
        self.last_url = ""
        self.last_error = ""

    # -- public API --------------------------------------------------------
    def request(
        self,
        method,
        url,
        *,
        body=None,
        headers=None,
        idempotent=None,
        stop_event=None,
        deadline=None,
    ):
        method = method.upper()
        if idempotent is None:
            idempotent = method in ("GET", "HEAD", "OPTIONS")
        _validate_url(url, self.config.allow_plaintext)
        headers = dict(headers or {})
        _validate_headers(headers)
        if body is not None and not isinstance(body, (bytes, bytearray)):
            raise TypeError("body must be bytes")
        if body is not None:
            body = bytes(body)
        attempts = (self.config.retries + 1) if idempotent else 1
        attempt = 0
        redirects = 0
        seen = {url}
        current_url = url
        current_method = method
        current_body = body

        while attempt < attempts:
            attempt += 1
            if stop_event is not None and stop_event.is_set():
                raise TransportError("request cancelled", kind="cancelled", url=current_url)
            attempt_deadline = _Deadline(self.config.deadline if deadline is None else deadline, self._clock)
            started = self._clock()
            try:
                while True:
                    response = self._request_once(
                        current_method,
                        current_url,
                        current_body,
                        headers,
                        attempt_deadline,
                        stop_event,
                        idempotent,
                    )
                    response.elapsed = self._clock() - started
                    self._note_server_time(response)
                    if response.status not in REDIRECT_STATUS or not idempotent:
                        break
                    target = response.headers.get("location")
                    if not target:
                        break
                    if redirects >= self.config.max_redirects:
                        raise TransportError(
                            "too many redirects (limit %d)" % self.config.max_redirects,
                            kind="redirect",
                            url=current_url,
                        )
                    next_url = _same_host_redirect(current_url, target, self.config.allow_plaintext)
                    if next_url in seen:
                        raise TransportError(
                            "redirect loop detected at %s" % next_url,
                            kind="redirect",
                            url=current_url,
                        )
                    seen.add(next_url)
                    redirects += 1
                    self._log("redirect", url=current_url, location=next_url, status=response.status)
                    current_url = next_url
                    if response.status == 303 or (
                        response.status in (301, 302) and current_method not in ("GET", "HEAD")
                    ):
                        current_method = "GET"
                        current_body = None
                response.attempts = attempt
                if idempotent and response.status in RETRYABLE_STATUS and attempt < attempts:
                    delay = self._retry_delay(attempt, response)
                    self._log("retry_status", url=current_url, status=response.status, delay=delay)
                    self._sleep_cancellable(delay, stop_event)
                    continue
                return response
            except TransportError as exc:
                if not exc.retryable or not idempotent or attempt >= attempts:
                    self.last_error = str(exc)
                    raise
                delay = self._backoff(attempt)
                self._log("retry_error", url=current_url, kind=exc.kind, delay=delay)
                self._sleep_cancellable(delay, stop_event)
        raise TransportError("request failed", kind="network", url=url)

    def now_ms(self):
        """Current time in milliseconds, corrected for measured server skew."""
        return int((time.time() + self.clock_offset) * 1000)

    # -- TLS ---------------------------------------------------------------
    def ssl_context(self):
        if self._ssl_context is not None:
            return self._ssl_context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        set_minimum_tls_version(context, self.config.min_tls_version)
        if not self.config.tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._ssl_context = context
            return context
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        loaded = False
        if self.config.tls_pem:
            context.load_verify_locations(cadata=self.config.tls_pem)
            loaded = True
        if self.config.use_system_trust:
            context.load_default_certs()
            loaded = True
        if not loaded:
            raise TransportError(
                "TLS verification is enabled but no trust material is configured",
                kind="tls",
                retryable=False,
            )
        self._ssl_context = context
        return context

    def _check_pin(self, der, host):
        self.last_peer_certificate = der
        if not self.config.tls_pins:
            return
        if not der:
            raise TransportError("the server did not present a certificate to pin", kind="tls-pin", url=host)
        actual = _fingerprint(der)
        allowed = {_normalise_fingerprint(p) for p in self.config.tls_pins}
        if actual not in allowed:
            raise TransportError(
                "TLS certificate pin mismatch for %s: got %s" % (host, _format_fingerprint(actual)),
                kind="tls-pin",
                retryable=False,
                url=host,
            )

    # -- connection and DNS ------------------------------------------------
    def _open_socket(self, host, port, deadline, stop_event):
        remaining = deadline.remaining()
        if remaining <= 0:
            raise TransportError("deadline expired before connecting", kind="timeout", retryable=True)
        try:
            addresses = self._resolver(host, port, min(self.config.dns_timeout, remaining))
        except TransportError:
            raise
        except socket.gaierror as exc:
            raise TransportError("DNS resolution failed for %s: %s" % (host, exc), kind="dns", retryable=True)
        except Exception as exc:  # noqa: BLE001 - resolver implementations vary
            raise TransportError("DNS resolution failed for %s: %s" % (host, exc), kind="dns", retryable=True)
        if not addresses:
            raise TransportError("no addresses for %s" % host, kind="dns", retryable=True)
        errors = []
        for family, socktype, proto, _canon, sockaddr in addresses:
            if stop_event is not None and stop_event.is_set():
                raise TransportError("request cancelled", kind="cancelled")
            remaining = deadline.remaining()
            if remaining <= 0:
                raise TransportError("deadline expired while connecting", kind="timeout", retryable=True)
            sock = None
            try:
                sock = self._socket_factory(family, socktype, proto)
                sock.settimeout(min(self.config.connect_timeout, remaining))
                sock.connect(sockaddr)
                return sock
            except socket.timeout:
                errors.append("timeout")
                if sock is not None:
                    sock.close()
            except OSError as exc:
                errors.append(_errno_name(exc))
                if sock is not None:
                    sock.close()
        detail = ", ".join(str(e) for e in errors) or "unknown error"
        raise TransportError(
            "could not connect to %s:%s (%s)" % (host, port, detail),
            kind="connect",
            retryable=True,
        )

    def _default_resolve(self, host, port, timeout):
        if timeout <= 0:
            raise TransportError("DNS timeout", kind="dns", retryable=True)
        key = (_idna(host), port)
        now = self._clock()
        with self._resolve_lock:
            cached = self._resolve_cache.get(key)
            if cached and cached[0] > now:
                if isinstance(cached[1], Exception):
                    raise TransportError(
                        "DNS resolution failed for %s: %s" % (key[0], cached[1]),
                        kind="dns",
                        retryable=True,
                    )
                return cached[1]
        result = {}

        def worker():
            try:
                result["addresses"] = socket.getaddrinfo(
                    key[0], port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP
                )
            except BaseException as exc:  # noqa: BLE001 - delivered to the caller
                result["error"] = exc

        thread = threading.Thread(target=worker, name="pycert-dns")
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            # The resolver thread is a daemon and will die with the process; a
            # timed-out lookup cannot be cancelled in the standard library.
            raise TransportError(
                "DNS resolution for %s timed out after %.1fs" % (key[0], timeout),
                kind="dns",
                retryable=True,
            )
        if "error" in result:
            error = result["error"]
            with self._resolve_lock:
                self._resolve_cache[key] = (now + 10.0, error)
            raise TransportError(
                "DNS resolution failed for %s: %s" % (key[0], error), kind="dns", retryable=True
            )
        addresses = result.get("addresses") or []
        with self._resolve_lock:
            self._resolve_cache[key] = (now + 60.0, addresses)
            if len(self._resolve_cache) > 128:
                self._resolve_cache.pop(next(iter(self._resolve_cache)))
        return addresses

    # -- one request attempt -----------------------------------------------
    def _request_once(self, method, url, body, headers, deadline, stop_event, idempotent):
        parts = _validate_url(url, self.config.allow_plaintext)
        host = parts["host"]
        port = parts["port"]
        tls = parts["scheme"] == "https"
        path = parts["path"]
        request_headers = self._build_headers(parts, body, headers)
        connection = _Connection(self, host, port, tls=tls, deadline=deadline, stop_event=stop_event)
        started = self._clock()
        try:
            connection.connect()
            remaining = deadline.remaining()
            if remaining <= 0:
                raise TransportError("deadline expired before sending", kind="timeout", retryable=True)
            connection.sock.settimeout(min(self.config.read_timeout, remaining))
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for name, value in request_headers:
                connection.putheader(name, value)
            connection.endheaders(body, encode_chunked=False)
            remaining = deadline.remaining()
            if remaining <= 0:
                raise TransportError("deadline expired waiting for headers", kind="timeout", retryable=True)
            connection.sock.settimeout(min(self.config.read_timeout, remaining))
            raw = connection.getresponse()
            # Consume (rare) 1xx interim responses before the final one.
            interim = 0
            while 100 <= raw.status < 200 and raw.status != 101 and interim < 5:
                raw.read()
                raw = connection.getresponse()
                interim += 1
            if 100 <= raw.status < 200:
                raise TransportError("too many interim 1xx responses", kind="protocol", retryable=False)
            if raw.version not in (10, 11):
                raise TransportError(
                    "unsupported HTTP version %r" % (raw.version,), kind="protocol", retryable=False
                )
            if not (100 <= raw.status <= 599) or raw.status == 101:
                raise TransportError(
                    "invalid or unsupported HTTP status %r" % (raw.status,),
                    kind="protocol",
                    retryable=False,
                )
            header_list = raw.getheaders()
            header_size = sum(len(k) + len(v) + 4 for k, v in header_list)
            if len(header_list) > MAX_HEADER_COUNT:
                raise TransportError(
                    "too many response headers (%d)" % len(header_list),
                    kind="protocol",
                    retryable=False,
                )
            if header_size > self.config.max_header_bytes:
                raise TransportError(
                    "response headers exceed %d bytes" % self.config.max_header_bytes,
                    kind="protocol",
                    retryable=False,
                )
            content_lengths = [value.strip() for key, value in header_list if key.lower() == "content-length"]
            transfer_encodings = [
                value.strip() for key, value in header_list if key.lower() == "transfer-encoding"
            ]
            if len(set(content_lengths)) > 1:
                raise TransportError(
                    "response has conflicting Content-Length headers", kind="protocol", retryable=False
                )
            if any(not value.isdigit() for value in content_lengths):
                raise TransportError(
                    "response has a non-numeric Content-Length", kind="protocol", retryable=False
                )
            if content_lengths and transfer_encodings:
                raise TransportError(
                    "response has both Content-Length and Transfer-Encoding", kind="protocol", retryable=False
                )
            if transfer_encodings and not transfer_encodings[-1].lower().endswith("chunked"):
                raise TransportError(
                    "unsupported Transfer-Encoding %r" % transfer_encodings[-1],
                    kind="protocol",
                    retryable=False,
                )
            response_headers = {}
            for key, value in header_list:
                response_headers[key.lower()] = value
            encoding = response_headers.get("content-encoding", "identity").strip().lower()
            if encoding not in ("", "identity"):
                raise TransportError(
                    "server sent a compressed response (%s); pyCert requires identity" % encoding,
                    kind="protocol",
                    retryable=False,
                )
            body_bytes = self._read_body(connection, raw, deadline, stop_event)
            self.last_url = url
            self.last_error = ""
            return Response(
                status=raw.status,
                reason=raw.reason or "",
                headers=response_headers,
                body=body_bytes,
                url=url,
                elapsed=self._clock() - started,
                peer_certificate=getattr(connection, "peer_certificate", b""),
                header_list=header_list,
            )
        except TransportError:
            raise
        except ssl.SSLError as exc:
            kind, retryable = _classify_ssl_error(exc)
            raise TransportError(
                "TLS error talking to %s: %s" % (host, exc), kind=kind, retryable=retryable, url=url
            )
        except socket.timeout:
            raise TransportError("timed out talking to %s" % host, kind="timeout", retryable=True, url=url)
        except (http.client.IncompleteRead, http.client.BadStatusLine, http.client.LineTooLong) as exc:
            raise TransportError(
                "malformed or truncated HTTP response from %s: %s" % (host, exc),
                kind="protocol",
                retryable=True,
                url=url,
            )
        except (ConnectionError, OSError) as exc:
            raise TransportError(
                "connection error talking to %s: %s" % (host, exc),
                kind="connect",
                retryable=True,
                url=url,
            )
        except http.client.HTTPException as exc:
            raise TransportError(
                "HTTP protocol error talking to %s: %s" % (host, exc),
                kind="protocol",
                retryable=True,
                url=url,
            )
        finally:
            try:
                connection.close()
            except Exception:  # noqa: BLE001 - closing must never mask the real error
                pass

    def _build_headers(self, parts, body, headers):
        host = parts["host"]
        header_host = host if ":" not in host else "[%s]" % host
        default_port = 443 if parts["scheme"] == "https" else 80
        if parts["port"] != default_port:
            header_host = "%s:%s" % (header_host, parts["port"])
        request_headers = [
            ("Host", header_host),
            ("User-Agent", self.config.user_agent or DEFAULT_USER_AGENT),
            ("Accept", "application/xml, text/xml, */*"),
            ("Accept-Encoding", "identity"),
            ("Connection", "close"),
        ]
        seen = {name.lower() for name, _ in request_headers}
        if body is not None and "content-length" not in {k.lower() for k in headers}:
            request_headers.append(("Content-Length", str(len(body))))
            if "content-type" not in {k.lower() for k in headers}:
                request_headers.append(("Content-Type", "application/xml; charset=utf-8"))
        for name, value in headers.items():
            lower = name.lower()
            if lower in seen:
                request_headers = [(k, v) for k, v in request_headers if k.lower() != lower]
            request_headers.append((name, value))
            seen.add(lower)
        return request_headers

    def _read_body(self, connection, raw, deadline, stop_event):
        expected = None
        if not raw.chunked and raw.length is not None:
            expected = raw.length
            if expected > self.config.max_body_bytes:
                raise TransportError(
                    "declared response body (%d bytes) exceeds the %d byte limit"
                    % (expected, self.config.max_body_bytes),
                    kind="body",
                    retryable=False,
                )
        chunks = []
        total = 0
        while True:
            if stop_event is not None and stop_event.is_set():
                raise TransportError("request cancelled while reading the body", kind="cancelled")
            remaining = deadline.remaining()
            if remaining <= 0:
                raise TransportError(
                    "deadline expired while reading the response body", kind="timeout", retryable=True
                )
            try:
                connection.sock.settimeout(min(self.config.read_timeout, remaining))
            except (AttributeError, OSError):  # pragma: no cover - socket closed
                pass
            want = min(65536, self.config.max_body_bytes - total + 1)
            if want <= 0:
                raise TransportError("response body too large", kind="body", retryable=False)
            chunk = raw.read(want)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > self.config.max_body_bytes:
                raise TransportError(
                    "response body exceeds %d bytes" % self.config.max_body_bytes,
                    kind="body",
                    retryable=False,
                )
            if expected is not None and total >= expected:
                break
        if expected is not None and total != expected:
            raise TransportError(
                "truncated response body: expected %d bytes, got %d" % (expected, total),
                kind="truncated",
                retryable=True,
            )
        return b"".join(chunks)

    # -- retry helpers -----------------------------------------------------
    def _backoff(self, attempt):
        delay = min(self.config.backoff_cap, self.config.backoff_base * (2 ** (attempt - 1)))
        # Full jitter avoids synchronised retries from many clients.
        return self._rng.uniform(0, max(0.0, delay))

    def _retry_delay(self, attempt, response):
        retry_after = _parse_retry_after(response.headers.get("retry-after"))
        if retry_after is not None:
            return min(self.config.backoff_cap, retry_after)
        return self._backoff(attempt)

    def _sleep_cancellable(self, delay, stop_event):
        end = self._clock() + max(0.0, delay)
        while self._clock() < end:
            if stop_event is not None and stop_event.is_set():
                raise TransportError("request cancelled", kind="cancelled")
            self._sleep(min(0.1, end - self._clock()))

    def _note_server_time(self, response):
        value = response.headers.get("date")
        if not value:
            return
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed is None:
                return
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            offset = parsed.timestamp() - time.time()
            if abs(offset) <= 86400:
                self.clock_offset = offset
        except (TypeError, ValueError, OverflowError):
            return

    def _log(self, event, **fields):
        if self._logger is not None:
            try:
                self._logger(event, fields)
            except Exception:  # noqa: BLE001 - logging must never break a request
                pass


# ---------------------------------------------------------------------------
# URL, header and error helpers
# ---------------------------------------------------------------------------


def _validate_url(url, allow_plaintext):
    if not isinstance(url, str):
        raise TransportError("URL must be a string", kind="url", retryable=False)
    if "\r" in url or "\n" in url:
        raise TransportError("URL contains a newline", kind="url", retryable=False)
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise TransportError("invalid URL: %s" % exc, kind="url", retryable=False)
    if parts.scheme not in ("https", "http"):
        raise TransportError("unsupported URL scheme %r" % parts.scheme, kind="url", retryable=False)
    if parts.scheme == "http" and not allow_plaintext:
        raise TransportError(
            "refusing to use plaintext HTTP (set ca.allow_plaintext to override)",
            kind="url",
            retryable=False,
        )
    if parts.username or parts.password:
        raise TransportError("URLs with credentials are not supported", kind="url", retryable=False)
    if not parts.hostname:
        raise TransportError("URL has no host", kind="url", retryable=False)
    if any(ord(ch) < 0x20 for ch in parts.path + parts.query):
        raise TransportError("URL contains control characters", kind="url", retryable=False)
    try:
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise TransportError("invalid port: %s" % exc, kind="url", retryable=False)
    if not (0 < port < 65536):
        raise TransportError("invalid port", kind="url", retryable=False)
    host = parts.hostname
    if not host or any(character.isspace() or ord(character) < 0x20 for character in host):
        raise TransportError("invalid host name", kind="url", retryable=False)
    try:
        ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, AttributeError) as exc:
            raise TransportError("invalid host name: %s" % exc, kind="url", retryable=False)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return {"scheme": parts.scheme, "host": host, "port": port, "path": path}


def _validate_headers(headers):
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("header names and values must be strings")
        if any(ch in name for ch in "\r\n:") or any(ch in value for ch in "\r\n"):
            raise ValueError("header injection attempt: %r" % name)
        if any(ord(character) < 0x20 and character != "\t" for character in value) or "\x7f" in value:
            raise ValueError("header value contains a control character: %r" % name)
        if not name.strip():
            raise ValueError("empty header name")
        try:
            name.encode("ascii")
            value.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError("header %r is not encodable in an HTTP/1.1 header" % name)


def _idna(host):
    try:
        ip_address(host)
        return host
    except ValueError:
        return host.encode("idna").decode("ascii")


def _effective_port(parts):
    try:
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise TransportError("invalid redirect port: %s" % exc, kind="redirect")
    if not 0 < port < 65536:
        raise TransportError("invalid redirect port", kind="redirect")
    return port


def _same_host_redirect(current_url, location, allow_plaintext):
    target = urljoin(current_url, location)
    parts = urlsplit(target)
    current = urlsplit(current_url)
    if parts.scheme not in ("https", "http"):
        raise TransportError("redirect to unsupported scheme %r" % parts.scheme, kind="redirect")
    if parts.scheme == "http" and not allow_plaintext:
        raise TransportError("redirect to plaintext HTTP refused", kind="redirect")
    if parts.hostname != current.hostname or _effective_port(parts) != _effective_port(current):
        raise TransportError(
            "cross-host redirect refused (%s -> %s)" % (current.hostname, parts.hostname),
            kind="redirect",
        )
    if parts.username or parts.password:
        raise TransportError("redirect with credentials refused", kind="redirect")
    if any(ord(character) < 0x20 for character in target):
        raise TransportError("redirect target contains control characters", kind="redirect")
    return target


def _normalise_fingerprint(value):
    return "".join(ch for ch in str(value).lower() if ch in "0123456789abcdef")


def _fingerprint(der):
    import hashlib

    return hashlib.sha256(der).hexdigest()


def _format_fingerprint(hexdigest):
    return ":".join(hexdigest[i : i + 2] for i in range(0, len(hexdigest), 2)).upper()


def _parse_retry_after(value):
    if not value:
        return None
    value = value.strip()
    try:
        seconds = float(value)
        return max(0.0, seconds)
    except ValueError:
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, parsed.timestamp() - time.time())
    except (TypeError, ValueError, OverflowError):
        return None


def _classify_ssl_error(exc):
    text = str(exc)
    lower = text.lower()
    # OpenSSL reports hostname/IP mismatches as CERTIFICATE_VERIFY_FAILED, so
    # check the message first to give the operator an actionable category.
    if (
        "hostname" in lower
        or "doesn't match" in lower
        or "does not match" in lower
        or "not valid for" in lower
        or "ip address mismatch" in lower
    ):
        return "tls-hostname", False
    verify_class = getattr(ssl, "SSLCertVerificationError", None)
    if (verify_class is not None and isinstance(exc, verify_class)) or "CERTIFICATE_VERIFY_FAILED" in text:
        return "tls-verify", False
    return "tls", False


def _errno_name(exc):
    code = getattr(exc, "errno", None)
    if code is not None:
        name = errno.errorcode.get(code)
        if name:
            return "%s (%s)" % (name, exc.strerror or "")
    return str(exc)
