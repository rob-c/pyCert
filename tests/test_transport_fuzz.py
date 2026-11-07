"""Randomised transport inputs: no hangs, no unexpected exception types."""

import random
import string

import pytest
from raw_server import RawServer, raw
from test_transport import make_transport

from pycert.transport import TransportError, _validate_headers, _validate_url


def _random_response(rng):
    status = rng.choice(
        [100, 101, 200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 503]
        + [rng.randint(100, 599) for _ in range(3)]
    )
    lines = [b"HTTP/1.1 %d Reason\r\n" % status]
    choice = rng.randrange(8)
    if choice == 0:
        lines.append(b"Content-Length: %d\r\n" % rng.randint(0, 200))
    elif choice == 1:
        lines.append(b"Transfer-Encoding: chunked\r\n")
    elif choice == 2:
        lines.append(b"Content-Length: %d\r\n" % rng.randint(0, 50))
        lines.append(b"Transfer-Encoding: chunked\r\n")
    elif choice == 3:
        lines.append(b"Content-Length: abc\r\n")
    elif choice == 4:
        lines.append(b"Content-Encoding: gzip\r\n")
    elif choice == 5:
        lines.append(b"X: " + b"a" * rng.randint(0, 5000) + b"\r\n")
    lines.append(b"Connection: close\r\n")
    lines.append(b"\r\n")
    body = bytes(rng.randrange(256) for _ in range(rng.randint(0, 100)))
    return b"".join(lines) + body


@pytest.mark.parametrize("seed", range(120))
def test_random_http_response_never_hangs_or_crashes(seed):
    rng = random.Random(seed)
    payload = _random_response(rng)
    server = RawServer(raw(payload))
    try:
        transport = make_transport(read_timeout=0.1, deadline=0.3, retries=0)
        try:
            response = transport.request("GET", server.url + "/")
        except TransportError:
            return
        assert response.status >= 100
    finally:
        server.stop()


ALPHABET = string.ascii_letters + string.digits + ":/?#[]@!$&'()*+,;=% \t\r\n\x00-._~"


@pytest.mark.parametrize("seed", range(40))
def test_random_urls_only_raise_transport_error(seed):
    rng = random.Random(seed)
    url = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 80)))
    try:
        parsed = _validate_url(url, True)
    except TransportError:
        return
    assert parsed["scheme"] in ("http", "https")


HEADER_ALPHABET = string.ascii_letters + string.digits + " :\t\r\n\x00-_%"


@pytest.mark.parametrize("seed", range(40))
def test_random_headers_only_raise_value_error(seed):
    rng = random.Random(seed)
    name = "".join(rng.choice(HEADER_ALPHABET) for _ in range(rng.randint(0, 20)))
    value = "".join(rng.choice(HEADER_ALPHABET) for _ in range(rng.randint(0, 40)))
    try:
        _validate_headers({name: value})
    except ValueError:
        return
