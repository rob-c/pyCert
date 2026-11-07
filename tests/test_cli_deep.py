"""Second-round CLI tests: watch, renew --due and diagnostics exit codes."""

import json

from test_workflow_deep import _state_with_expiry, spec

from pycert.cli import main
from pycert.store import STATUS_DOWNLOADED


def run(args, capsys):
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def cli(config, *args):
    return ["--config", str(config.path), *args]


def test_watch_once_no_work(config, capsys):
    code, out, err = run(cli(config, "watch", "--once", "--json"), capsys)
    assert code == 0, err
    payload = json.loads(out)
    assert payload["cycles"] == 1
    assert payload["downloaded"] == 0
    assert payload["errors"] == []


def test_watch_max_cycles_human(config, capsys):
    code, out, err = run(cli(config, "watch", "--max-cycles", "1", "--interval", "0.01"), capsys)
    assert code == 0, err
    assert "watch finished" in out


def test_watch_downloads_signed_certificate(config, ca, ctx, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    from pycert.workflow import create_request

    state = create_request(ctx, spec(config, "cli watch"), progress=lambda _m: None)
    code, out, err = run(cli(config, "watch", "--once", "--json"), capsys)
    assert code == 0, err
    payload = json.loads(out)
    assert payload["downloaded"] == 1
    assert ctx.store.get(state.alias).status == STATUS_DOWNLOADED


def test_watch_unreachable_ca_exit_1(config, ctx, ca, capsys):
    from pycert.workflow import create_request

    ca.auto_approve = False
    create_request(ctx, spec(config, "cli watch error"), progress=lambda _m: None)
    config.ca.base_url = "http://127.0.0.1:9"
    config.ca.allow_plaintext = True
    config.ca.retries = 0
    config.ca.connect_timeout = 0.2
    config.ca.deadline = 0.4
    config.save()
    code, out, err = run(cli(config, "watch", "--once", "--json"), capsys)
    assert code == 1
    payload = json.loads(out)
    assert payload["errors"]


def test_renew_due_dry_run_json(config, ctx, capsys):
    _state_with_expiry(ctx, "due soon", 10)
    _state_with_expiry(ctx, "far away", 100)
    code, out, err = run(cli(config, "renew", "--due", "30", "--dry-run", "--json"), capsys)
    assert code == 0, err
    payload = json.loads(out)
    assert payload["dry_run"] is True
    assert [item["alias"] for item in payload["renewed"]] == ["due soon"]


def test_renew_due_dry_run_human(config, ctx, capsys):
    _state_with_expiry(ctx, "due soon", 10)
    code, out, err = run(cli(config, "renew", "--due", "30", "--dry-run"), capsys)
    assert code == 0, err
    assert "would renew" in out


def test_renew_due_no_matches(config, capsys):
    code, out, err = run(cli(config, "renew", "--due", "1", "--dry-run", "--json"), capsys)
    assert code == 0
    assert json.loads(out)["renewed"] == []


def test_renew_due_requires_confirmation(config, ctx, capsys):
    _state_with_expiry(ctx, "due soon", 10)
    code, out, err = run(cli(config, "renew", "--due", "30"), capsys)
    assert code == 1
    assert "refusing" in err


def test_renew_due_and_alias_are_mutually_exclusive(config, ctx, capsys):
    _state_with_expiry(ctx, "due soon", 10)
    code, out, err = run(cli(config, "renew", "due soon", "--due", "30", "--dry-run"), capsys)
    assert code == 1
    assert "either" in err


def test_renew_requires_alias_or_due(config, capsys):
    code, out, err = run(cli(config, "renew"), capsys)
    assert code == 1
    assert "alias" in err


def test_renew_due_actual(config, ctx, ca, issued, capsys):
    state = issued()
    state.cert.not_after = (
        __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        + __import__("datetime").timedelta(days=10)
    ).isoformat()
    ctx.store.save(state)
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = run(
        cli(
            config,
            "renew",
            "--due",
            "30",
            "--yes",
            "--wait",
            "--timeout",
            "30",
            "--interval",
            "0.2",
            "--json",
        ),
        capsys,
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["renewed"][0]["error"] is None
    assert payload["renewed"][0]["status"] == STATUS_DOWNLOADED


def test_renew_due_failure_exit_1(config, ctx, ca, issued, capsys):
    state = issued()
    state.cert.not_after = (
        __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        + __import__("datetime").timedelta(days=10)
    ).isoformat()
    ctx.store.save(state)
    ca.reject_next = [(202, ca._error_xml("no renewal"))]
    code, out, err = run(cli(config, "renew", "--due", "30", "--yes", "--json"), capsys)
    assert code == 1
    payload = json.loads(out)
    assert payload["renewed"][0]["error"]


def test_doctor_corrupt_state(config, ctx, capsys):
    state = ctx.store.new_state(alias="corrupt", type="user", cn="corrupt", email="x@y.z")
    ctx.store.file(state, "state.json").write_text("{not json")
    code, out, err = run(cli(config, "doctor", "--offline"), capsys)
    assert code == 1
    assert "stored state" in out


def test_doctor_world_writable_config(config, capsys):
    config.path.chmod(0o666)
    code, out, err = run(cli(config, "doctor", "--offline"), capsys)
    assert code == 1
    assert "world-writable" in out


def test_config_set_command_timeout(config, capsys):
    code, out, err = run(cli(config, "config", "set", "secrets.command_timeout=5"), capsys)
    assert code == 0, err
    from pycert.config import load_config

    assert load_config(config.path).secrets.command_timeout == 5.0


def test_config_set_command_timeout_invalid(config, capsys):
    code, out, err = run(cli(config, "config", "set", "secrets.command_timeout=0"), capsys)
    assert code == 1
    assert "command_timeout" in err


def test_watch_rejects_zero_cycles(config, capsys):
    code, out, err = run(cli(config, "watch", "--max-cycles", "0"), capsys)
    assert code == 1
    assert "max-cycles" in err


def test_renew_due_rejects_negative_days(config, capsys):
    code, out, err = run(cli(config, "renew", "--due", "-1", "--dry-run"), capsys)
    assert code == 1
    assert "due" in err
