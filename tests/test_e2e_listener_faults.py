"""Drive every CA endpoint/action through injected listener faults."""

import pytest

FAULT_STATUSES = [202, 301, 302, 400, 401, 403, 404, 405, 408, 418, 429, 500, 502, 503, 504]


def prepare(e2e, kind):
    if kind == "none":
        return None
    if kind == "pending":
        return e2e.setup_pending("fault pending")
    if kind == "issued":
        return e2e.setup_issued("fault issued")
    if kind == "noinline":
        alias = e2e.setup_issued("fault noinline")
        e2e.ca.lookup_mode = "no_inline"
        return alias
    raise AssertionError(kind)


def action_args(e2e, kind, action, alias):
    if action == "ping":
        return ["ping"]
    if action == "ras":
        return ["ras"]
    if action == "info":
        return ["info"]
    if action == "request":
        return ["request", "fault request", "--pin", e2e.PIN, "--key-algorithm", "ec"]
    if action == "status":
        return ["status", alias, "--refresh"]
    if action == "download":
        return ["download", alias]
    if action == "renew":
        return ["renew", alias, "--yes", "--pin", e2e.PIN]
    if action == "revoke":
        return ["revoke", alias, "--yes"]
    raise AssertionError(action)


ENDPOINTS = [
    ("ping", "/pingservice", "ping", "none"),
    ("ras", "/CA", "ras", "none"),
    ("info", "/CA", "info", "none"),
    ("request", "/CSR", "request", "none"),
    ("status", "/resources/resource/publickey/pk", "status", "pending"),
    ("download", "/certificate/*", "download", "noinline"),
    ("renew", "/CSR", "renew", "issued"),
    ("revoke", "/revoke", "revoke", "issued"),
]


@pytest.mark.parametrize("status", FAULT_STATUSES)
@pytest.mark.parametrize("name,path,action,kind", ENDPOINTS)
def test_status_faults(e2e, status, name, path, action, kind):
    e2e.configure(retries=0)
    alias = prepare(e2e, kind)
    e2e.ca.fail_next(
        path, method="GET" if action in ("ping", "ras", "info", "download") else "POST", status=status
    )
    result = e2e.run(*action_args(e2e, kind, action, alias))
    assert result.code in (0, 1, 3, 4)
    if status == 404 and action == "status":
        assert result.code == 0  # an unknown key is a normal pending state
    elif status in (400, 401, 403, 404, 405, 408, 418, 429, 500, 502, 503, 504, 202):
        assert result.code != 0, (name, status, result.out, result.err)


BODY_FAULTS = [
    ("empty", b""),
    ("malformed", b"<not-xml"),
    ("html", b"<html><body>gateway error</body></html>"),
    ("doctype", b"<?xml version='1.0'?><!DOCTYPE r><r/>"),
    ("huge-text", b"x" * 100000),
    ("wrong-root", b"<Wrong><text>no</text></Wrong>"),
]


@pytest.mark.parametrize("label,body", BODY_FAULTS)
@pytest.mark.parametrize(
    "name,path,action,kind",
    [
        ("ras", "/CA", "ras", "none"),
        ("info", "/CA", "info", "none"),
        ("request", "/CSR", "request", "none"),
        ("status", "/resources/resource/publickey/pk", "status", "pending"),
        ("download", "/certificate/*", "download", "noinline"),
    ],
)
def test_body_faults(e2e, label, body, name, path, action, kind):
    e2e.configure(retries=0)
    alias = prepare(e2e, kind)
    # Status 200 with a bad/odd body, except request where 201/202 is relevant.
    status = 201 if action == "request" else 200
    e2e.ca.fail_next(
        path,
        method="POST" if action in ("request", "status") else "GET",
        status=status,
        body=body,
    )
    result = e2e.run(*action_args(e2e, kind, action, alias))
    assert result.code in (0, 1, 3, 4)
    assert "Traceback" not in result.err


DELAYS = [0.2, 0.5]
ENDPOINTS_FAST = [
    ("ping", "/pingservice", "ping", "none", "GET"),
    ("ras", "/CA", "ras", "none", "GET"),
    ("request", "/CSR", "request", "none", "POST"),
    ("status", "/resources/resource/publickey/pk", "status", "pending", "POST"),
]


@pytest.mark.parametrize("delay", DELAYS)
@pytest.mark.parametrize("name,path,action,kind,method", ENDPOINTS_FAST)
def test_delay_faults_hit_deadline(e2e, delay, name, path, action, kind, method):
    e2e.configure(retries=0, deadline=0.1, timeout=0.1, connect_timeout=0.1)
    alias = prepare(e2e, kind)
    e2e.ca.fail_next(path, method=method, status=200, delay=delay)
    result = e2e.run(*action_args(e2e, kind, action, alias))
    assert result.code in (1, 3)


@pytest.mark.parametrize(
    "name,path,action,kind,method",
    [
        ("request-truncated", "/CSR", "request", "none", "POST"),
        ("request-reset", "/CSR", "request", "none", "POST"),
        ("request-dropped", "/CSR", "request", "none", "POST"),
        ("ping-truncated", "/pingservice", "ping", "none", "GET"),
        ("ping-reset", "/pingservice", "ping", "none", "GET"),
        ("ping-dropped", "/pingservice", "ping", "none", "GET"),
        ("status-truncated", "/resources/resource/publickey/pk", "status", "pending", "POST"),
        ("status-reset", "/resources/resource/publickey/pk", "status", "pending", "POST"),
        ("status-dropped", "/resources/resource/publickey/pk", "status", "pending", "POST"),
        ("download-truncated", "/certificate/*", "download", "noinline", "GET"),
        ("download-reset", "/certificate/*", "download", "noinline", "GET"),
        ("download-dropped", "/certificate/*", "download", "noinline", "GET"),
    ],
)
def test_connection_level_faults(e2e, name, path, action, kind, method):
    e2e.configure(retries=0, timeout=0.3, deadline=0.5)
    alias = prepare(e2e, kind)
    if "truncated" in name:
        e2e.ca.fail_next(path, method=method, status=200, body=b"<x/>", truncate=10)
    elif "reset" in name:
        e2e.ca.fail_next(path, method=method, reset=True)
    else:
        e2e.ca.fail_next(path, method=method, drop=True)
    result = e2e.run(*action_args(e2e, kind, action, alias))
    assert result.code in (1, 3)
    assert "Traceback" not in result.err


@pytest.mark.parametrize(
    "name,path,action,kind,method",
    [
        ("ras-loop", "/CA", "ras", "none", "GET"),
        ("info-crosshost", "/CA", "info", "none", "GET"),
        ("ping-crosshost", "/pingservice", "ping", "none", "GET"),
    ],
)
def test_redirect_faults(e2e, name, path, action, kind, method):
    e2e.configure(retries=0)
    alias = prepare(e2e, kind)
    if "loop" in name:
        e2e.ca.fail_next(path, method=method, status=302, headers={"Location": path})
    else:
        e2e.ca.fail_next(
            path, method=method, status=302, headers={"Location": "http://localhost:1/elsewhere"}
        )
    result = e2e.run(*action_args(e2e, kind, action, alias))
    assert result.code in (1, 3)
