"""A raw TCP server for deterministic network fault injection.

Each test supplies a handler that writes arbitrary bytes (or sleeps, or resets
the connection).  The server records the raw request bytes so tests can assert
exactly how many requests were made and which headers were sent.
"""

import socket
import ssl
import struct
import threading
import time


def _read_request(conn):
    """Read one request head plus a Content-Length body (best effort)."""
    data = b""
    try:
        while b"\r\n\r\n" not in data and len(data) < 256 * 1024:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    length = 0
        while len(body) < length:
            chunk = conn.recv(65536)
            if not chunk:
                break
            body += chunk
        return head + b"\r\n\r\n" + body
    except OSError:
        return data


class RawServer:
    def __init__(self, handler, tls_context=None):
        self.handler = handler
        self.tls_context = tls_context
        self.requests = []
        self.errors = []
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name="raw-server")
        self._thread.daemon = True
        self._thread.start()

    @property
    def url(self):
        return "%s://127.0.0.1:%d" % ("https" if self.tls_context else "http", self.port)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(5)
                if self.tls_context is not None:
                    conn = self.tls_context.wrap_socket(conn, server_side=True)
                self.requests.append(_read_request(conn))
                self.handler(conn)
            except Exception as exc:  # noqa: BLE001 - recorded for assertions
                self.errors.append(exc)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(2)


# ---------------------------------------------------------------------------
# Handler factories
# ---------------------------------------------------------------------------


def respond(status=200, body=b"", headers=None, reason="OK", version="HTTP/1.1", include_length=True):
    base_headers = dict(headers or {})
    if include_length and "Content-Length" not in base_headers:
        base_headers["Content-Length"] = str(len(body))

    def handler(conn):
        lines = [version + " %d %s\r\n" % (status, reason)]
        for key, value in base_headers.items():
            lines.append("%s: %s\r\n" % (key, value))
        lines.append("\r\n")
        conn.sendall("".join(lines).encode("latin-1") + body)

    return handler


def raw(payload, delay=0.0, close=True):
    def handler(conn):
        if delay:
            time.sleep(delay)
        if isinstance(payload, str):
            conn.sendall(payload.encode("latin-1"))
        else:
            conn.sendall(payload)
        if close:
            conn.close()

    return handler


def chunks(pieces, delay=0.0, close=True):
    def handler(conn):
        for piece in pieces:
            if delay:
                time.sleep(delay)
            if isinstance(piece, str):
                piece = piece.encode("latin-1")
            conn.sendall(piece)
        if close:
            conn.close()

    return handler


def headers_then_chunks(headers, pieces, delay=0.0):
    def handler(conn):
        conn.sendall(headers.encode("latin-1") if isinstance(headers, str) else headers)
        for piece in pieces:
            if delay:
                time.sleep(delay)
            conn.sendall(piece.encode("latin-1") if isinstance(piece, str) else piece)

    return handler


def sequence(handlers):
    """Use a different handler for each successive connection."""
    state = {"index": 0}

    def handler(conn):
        index = state["index"]
        state["index"] += 1
        if index < len(handlers):
            handlers[index](conn)
        else:
            handlers[-1](conn)

    return handler


def reset(payload=b""):
    def handler(conn):
        if payload:
            conn.sendall(payload)
        # SO_LINGER with a zero timeout sends a RST instead of FIN.
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        conn.close()

    return handler


def silent(seconds=1.0):
    def handler(conn):
        time.sleep(seconds)

    return handler


def make_tls_context(cert_pem_path, key_pem_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_pem_path), str(key_pem_path))
    return context
