"""Random CLI actions against random mock-listener faults."""

import random

import pytest

ACTIONS = [
    ("ping", ["ping"], "/pingservice", "GET"),
    ("ras", ["ras"], "/CA", "GET"),
    ("info", ["info"], "/CA", "GET"),
    (
        "request",
        ["request", "fuzz request", "--pin", "1234567890AB", "--key-algorithm", "ec"],
        "/CSR",
        "POST",
    ),
]
STATUSES = [200, 201, 202, 301, 302, 400, 401, 403, 404, 405, 408, 418, 429, 500, 502, 503, 504]


@pytest.mark.parametrize("seed", range(100))
def test_random_action_fault(e2e, seed):
    rng = random.Random(seed + 12000)
    name, args, path, method = rng.choice(ACTIONS)
    status = rng.choice(STATUSES)
    body = rng.choice([b"", b"<resources/>", b"<bad", b"x" * 200, b"<html>error</html>"])
    fault = {
        "status": status,
        "body": body,
    }
    if rng.random() < 0.15:
        fault["delay"] = 0.2
    if rng.random() < 0.15:
        fault["truncate"] = 10
    if rng.random() < 0.1:
        fault["reset"] = True
    if rng.random() < 0.1:
        fault["drop"] = True
    e2e.configure(retries=0, timeout=0.2, deadline=0.4)
    e2e.ca.fail_next(path, method=method, **fault)
    result = e2e.run(*args)
    assert result.code in (0, 1, 3, 4), (seed, name, status, result.out, result.err)
    assert "Traceback" not in result.err
