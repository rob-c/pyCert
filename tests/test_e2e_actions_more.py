"""Every CLI action, human and JSON, against the mock CA listener."""

import random

import pytest

SCENARIOS = [
    ("ping", ["ping"], "none"),
    ("ras", ["ras"], "none"),
    ("info", ["info"], "none"),
    ("doctor-offline", ["doctor", "--offline"], "none"),
    ("config-show", ["config", "show"], "none"),
    ("config-check", ["config", "check"], "none"),
    ("config-path", ["config", "path"], "none"),
    ("list", ["list"], "issued"),
    ("status", ["status", "{alias}"], "issued"),
    ("status-refresh", ["status", "{alias}", "--refresh"], "issued"),
    ("show", ["show", "{alias}"], "issued"),
    ("verify", ["verify", "{alias}"], "issued"),
    ("export", ["export", "{alias}"], "issued"),
    ("download", ["download", "{alias}"], "issued"),
    ("wait", ["wait", "{alias}", "--interval", "0.1", "--timeout", "5"], "issued"),
    ("install", ["install", "{alias}", "--dir", "{tmp}/globus"], "issued"),
    ("delete", ["delete", "{alias}", "--yes"], "issued"),
    ("renew", ["renew", "{alias}", "--yes", "--pin", "1234567890AB"], "issued"),
    ("revoke", ["revoke", "{alias}", "--yes"], "issued"),
    ("renew-due-dry", ["renew", "--due", "30", "--dry-run"], "due"),
    ("watch-once", ["watch", "--once"], "signed"),
]


def setup(e2e, kind, tmp):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    if kind == "none":
        return None
    if kind == "issued":
        return e2e.setup_issued("action issued")
    if kind == "due":
        alias = e2e.setup_issued("action due")
        e2e.set_expiry(alias, 5)
        return alias
    if kind == "signed":
        result = e2e.request_user("action signed", wait=False)
        return result.json["alias"]
    raise AssertionError(kind)


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("name,args,kind", SCENARIOS)
def test_cli_action_scenario(e2e, tmp_path, json_mode, name, args, kind):
    alias = setup(e2e, kind, tmp_path)
    argv = [part.format(alias=alias, tmp=str(tmp_path)) for part in args]
    result = e2e.run(*argv, "--json") if json_mode else e2e.run(*argv)
    assert result.code == 0, (name, result.out, result.err)
    assert "Traceback" not in result.err
    if json_mode:
        assert result.json is not None


@pytest.mark.parametrize(
    "name,args,kind",
    [
        (
            "request-user",
            ["request", "action request", "--pin", "1234567890AB", "--key-algorithm", "ec"],
            "none",
        ),
        ("secret-list", ["secret", "list"], "none"),
        ("doctor-online", ["doctor"], "none"),
    ],
)
def test_cli_action_special(e2e, name, args, kind):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    result = e2e.run(*args)
    assert result.code == 0, (name, result.out, result.err)


def test_action_failures_do_not_traceback(e2e):
    for args in (
        ["show", "missing"],
        ["status", "missing", "--refresh"],
        ["download", "missing"],
        ["export", "missing"],
        ["verify", "missing"],
        ["wait", "missing"],
        ["install", "missing"],
        ["delete", "missing", "--yes"],
        ["renew", "missing", "--yes"],
        ["revoke", "missing", "--yes"],
        ["secret", "test", "--account", "missing"],
    ):
        result = e2e.run(*args)
        assert result.code in (1, 3)
        assert "Traceback" not in result.err


@pytest.mark.parametrize("seed", range(40))
def test_random_requests_against_listener(e2e, seed):
    rng = random.Random(seed + 11000)
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    cn = "random user %d" % seed
    wait = rng.choice([False, True])
    result = e2e.request_user(cn, wait=wait)
    assert result.code == 0, result.err
    state = e2e.state(result.json["alias"])
    assert state.alias == result.json["alias"]
