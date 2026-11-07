"""End-to-end lifecycle sequences against the mock CA listener."""

import random

import pytest


def assert_no_traceback(result):
    assert "Traceback" not in result.err, result.err


def test_full_lifecycle_request_download_renew_revoke_delete(e2e):
    e2e.ca.auto_approve = False
    requested = e2e.request_user("lifecycle user", wait=False)
    assert requested.code == 0
    alias = requested.json["alias"]
    state = e2e.state(alias)
    e2e.approve(state)
    e2e.sign(state)
    downloaded = e2e.run("download", alias)
    assert downloaded.code == 0, downloaded.err
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    renewed = e2e.run(
        "renew", alias, "--yes", "--pin", e2e.PIN, "--wait", "--interval", "0.2", "--timeout", "30"
    )
    assert renewed.code == 0, renewed.err
    revoked = e2e.run("revoke", alias, "--yes")
    assert revoked.code == 0, revoked.err
    deleted = e2e.run("delete", alias, "--yes")
    assert deleted.code == 0


def test_pending_then_watch_downloads(e2e):
    e2e.ca.auto_approve = False
    alias = e2e.request_user("lifecycle watch", wait=False).json["alias"]
    e2e.sign(e2e.state(alias))
    watched = e2e.run_json("watch", "--once")
    assert watched.code == 0, watched.err
    assert watched.json["downloaded"] == 1


def test_rejected_request_lifecycle(e2e):
    e2e.ca.fail_next("/CSR", status=202, body=e2e.ca._error_xml("rejected lifecycle"))
    result = e2e.request_user("lifecycle rejected")
    assert result.code == 1
    states = e2e.ctx.store.list()
    assert len(states) == 1 and states[0].status == "FAILED"


def test_timeout_then_late_sign(e2e):
    e2e.ca.auto_approve = False
    result = e2e.request_user("lifecycle timeout", wait=True, extra=["--timeout", "0.3", "--interval", "0.1"])
    assert result.code == 3
    alias = result.json.get("alias") if result.json else "lifecycle timeout"
    # The PIN/JSON request may not return the alias on timeout; use the store.
    alias = e2e.ctx.store.list()[0].alias
    e2e.sign(e2e.state(alias))
    waited = e2e.run_json("wait", alias, "--interval", "0.2", "--timeout", "30")
    assert waited.code == 0, waited.err


def test_host_lifecycle(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    user = e2e.request_user("lifecycle host user", wait=True).json["alias"]
    host = e2e.request_host(auth=user, wait=True)
    assert host.code == 0, host.err
    host_alias = host.json["alias"]
    exported = e2e.run("export", host_alias)
    assert exported.code == 0
    revoked = e2e.run("revoke", host_alias, "--yes")
    assert revoked.code == 0


def test_due_renewal_lifecycle(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("lifecycle due", wait=True).json["alias"]
    e2e.set_expiry(alias, 3)
    preview = e2e.run_json("renew", "--due", "30", "--dry-run")
    assert preview.code == 0
    actual = e2e.run_json("renew", "--due", "30", "--yes", "--wait", "--interval", "0.2", "--timeout", "30")
    assert actual.code == 0, actual.err


def test_delete_then_recreate(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("lifecycle delete", wait=True).json["alias"]
    assert e2e.run("delete", alias, "--yes").code == 0
    recreated = e2e.request_user("lifecycle delete", wait=True)
    assert recreated.code == 0, recreated.err


def test_import_export_verify_lifecycle(e2e, tmp_path):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("lifecycle import", wait=True).json["alias"]
    source = e2e.state(alias).p12_path
    imported = e2e.run_json(
        "import",
        source,
        "--alias",
        "lifecycle imported",
        "--password",
        e2e.ctx.p12_passphrase(),
        "--allow-unverified-chain",
    )
    assert imported.code == 0, imported.err
    target = tmp_path / "roundtrip.p12"
    exported = e2e.run_json("export", "lifecycle imported", "--out", str(target))
    assert exported.code == 0
    verified = e2e.run_json("verify", "lifecycle imported", "--no-p12")
    assert verified.code in (0, 4)


LIFECYCLE_ACTIONS = [
    ["status", "{alias}"],
    ["status", "{alias}", "--refresh"],
    ["show", "{alias}"],
    ["list"],
    ["verify", "{alias}"],
    ["export", "{alias}"],
    ["download", "{alias}"],
    ["watch", "--once"],
    ["renew", "--due", "30", "--dry-run"],
]


@pytest.mark.parametrize("seed", range(40))
def test_random_lifecycle_sequences(e2e, seed):
    rng = random.Random(seed + 9000)
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    alias = e2e.request_user("random lifecycle %d" % seed, wait=True).json["alias"]
    for _ in range(rng.randint(1, 5)):
        action = rng.choice(LIFECYCLE_ACTIONS)
        args = [part.format(alias=alias) for part in action]
        result = e2e.run(*args)
        assert result.code in (0, 1, 3, 4), (seed, args, result.out, result.err)
        assert_no_traceback(result)
        assert e2e.state(alias).alias == alias
