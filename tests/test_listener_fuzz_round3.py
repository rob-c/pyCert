"""Randomised listener responses and fault scripts against the CA client."""

import random

import pytest
from raw_server import RawServer, raw
from test_transport import make_transport
from test_transport_fuzz import _random_response

from pycert.ca import CAClient
from pycert.errors import CAError, NetworkError, ProtocolError
from pycert.transport import TransportError


@pytest.mark.parametrize("seed", range(300, 420))
def test_random_raw_listener_responses(seed):
    rng = random.Random(seed)
    server = RawServer(raw(_random_response(rng)))
    try:
        transport = make_transport(read_timeout=0.1, deadline=0.3, retries=0)
        try:
            response = transport.request("GET", server.url + "/")
        except TransportError:
            return
        assert response.status >= 100
    finally:
        server.stop()


FAULT_PATHS = [
    ("/pingservice", "ping"),
    ("/CA", "info"),
    ("/CA/motd/text", "motd"),
    ("/resources/resource/publickey/pk", "lookup"),
]
FAULT_STATUSES = [200, 201, 202, 301, 302, 400, 401, 403, 404, 408, 429, 500, 502, 503, 504]


@pytest.mark.parametrize("seed", range(80))
def test_random_fault_scripts_are_handled(ctx, ca, seed):
    rng = random.Random(seed + 5000)
    path, action = rng.choice(FAULT_PATHS)
    status = rng.choice(FAULT_STATUSES)
    body = rng.choice([b"", b"<resources/>", b"<bad", b"x" * 100, b"<!DOCTYPE x><x/>"])
    truncate = rng.choice([0, 0, 5])
    reset = rng.random() < 0.1
    drop = rng.random() < 0.1
    ca.fail_next(
        path,
        method="POST" if action == "lookup" else "GET",
        status=status,
        body=body,
        truncate=truncate,
        reset=reset,
        drop=drop,
    )
    config = ctx.config
    config.ca.retries = 0
    config.ca.timeout = 0.3
    config.ca.deadline = 0.5
    client = CAClient(config)
    try:
        if action == "ping":
            client.ping()
        elif action == "info":
            client.info()
        elif action == "motd":
            client.motd()
        else:
            client.lookup_public_key("bm90LWEta2V5")
    except (CAError, NetworkError, ProtocolError, TransportError):
        return
    assert True
