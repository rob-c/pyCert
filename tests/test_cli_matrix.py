"""CLI matrix: commands, JSON output, exit codes and secrets."""

import json
from pathlib import Path

import pytest

from pycert import p12 as p12_module
from pycert.cli import main
from pycert.errors import NotFound


def run(args, capsys):
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def cli(config, *args):
    return ["--config", str(config.path), *args]


SUBCOMMANDS = [
    "init",
    "config",
    "ping",
    "ras",
    "info",
    "request",
    "wait",
    "status",
    "list",
    "show",
    "download",
    "export",
    "verify",
    "renew",
    "revoke",
    "import",
    "install",
    "delete",
    "secret",
    "gui",
]


@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_subcommand_help_exits_zero(command):
    with pytest.raises(SystemExit) as exc:
        main([command, "--help"])
    assert exc.value.code == 0


def test_version_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_ping_json(config, capsys):
    code, out, err = run(cli(config, "ping", "--json"), capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["tls"]["subject"]


def test_ping_human(config, capsys):
    code, out, err = run(cli(config, "ping"), capsys)
    assert code == 0
    assert "pong" in out


def test_ping_failure_exit_code(config, capsys):
    config.ca.base_url = "http://127.0.0.1:9"
    config.ca.allow_plaintext = True
    config.ca.retries = 0
    config.ca.connect_timeout = 0.2
    config.ca.deadline = 0.4
    config.save()
    code, out, err = run(cli(config, "ping"), capsys)
    assert code == 1
    assert "no response" in err


def test_ras_json(config, capsys):
    code, out, err = run(cli(config, "ras", "--json"), capsys)
    assert code == 0
    payload = json.loads(out)
    assert [ra["ou"] for ra in payload["ras"]] == ["CLRC", "CLRC"]
    assert payload["preferred"]["l"] == "DL"


def test_ras_human_marks_preferred(config, capsys):
    code, out, err = run(cli(config, "ras"), capsys)
    assert code == 0
    assert "*" in out


def test_info_json(config, capsys):
    code, out, err = run(cli(config, "info", "--json"), capsys)
    assert code == 0
    payload = json.loads(out)
    assert "mock CA says hello" in payload["motd"]
    assert len(payload["certificates"]) == 2


def test_config_show_json(config, capsys):
    code, out, err = run(cli(config, "config", "show", "--json"), capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["ca"]["base_url"] == config.ca.base_url
    assert payload["secret_backend"]


def test_config_show_human(config, capsys):
    code, out, err = run(cli(config, "config", "show"), capsys)
    assert code == 0
    assert "Server" in out and "CA chain" in out


def test_config_check_ok(config, capsys):
    code, out, err = run(cli(config, "config", "check"), capsys)
    assert code == 0
    assert "OK:" in out


def test_config_check_insecure_settings(config, capsys):
    config.ca.tls_verify = False
    config.save()
    code, out, err = run(cli(config, "config", "check"), capsys)
    assert code == 1
    assert "tls_verify" in err


def test_config_set_and_path(config, capsys):
    code, out, err = run(cli(config, "config", "set", "ca.timeout=5.5"), capsys)
    assert code == 0
    from pycert.config import load_config

    assert load_config(config.path).ca.timeout == 5.5
    code, out, err = run(["--config", str(config.path), "config", "path"], capsys)
    assert code == 0 and out.strip() == str(config.path)


def test_config_set_invalid_exit_code(config, capsys):
    code, out, err = run(cli(config, "config", "set", "ca.tls_trust=tofu"), capsys)
    assert code == 1
    assert "tls_trust" in err


def test_missing_config(capsys):
    code, out, err = run(["--config", "/nonexistent/pycert.toml", "list"], capsys)
    assert code == 1
    assert "not found" in err.lower()


def test_list_json(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "list", "--json"), capsys)
    assert code == 0
    states = json.loads(out)
    assert states[0]["alias"] == state.alias


def test_list_human(config, issued, capsys):
    issued()
    code, out, err = run(cli(config, "list"), capsys)
    assert code == 0
    assert "ALIAS" in out


def test_list_audit_warns(config, issued, capsys):
    state = issued()
    Path(state.p12_path).parent.chmod(0o755)
    code, out, err = run(cli(config, "list"), capsys)
    assert code == 0
    assert "mode" in err


def test_show_json(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "show", state.alias, "--json"), capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["status"] == "DOWNLOADED"
    assert payload["days_remaining"] > 0


def test_show_human(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "show", state.alias), capsys)
    assert code == 0
    assert "Common name" in out


def test_show_unknown_alias(config, capsys):
    code, out, err = run(cli(config, "show", "nope"), capsys)
    assert code == 1
    assert "no certificate request" in err


def test_status_all_json(config, issued, capsys):
    issued()
    code, out, err = run(cli(config, "status", "--json"), capsys)
    assert code == 0
    assert json.loads(out)


def test_status_refresh_single(config, ca, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "status", state.alias, "--refresh"), capsys)
    assert code == 0
    assert state.alias in out


def test_request_json(config, ca, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = run(
        cli(
            config,
            "request",
            "jane doe",
            "--pin",
            "1234567890AB",
            "--wait",
            "--interval",
            "0.2",
            "--timeout",
            "30",
            "--json",
        ),
        capsys,
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["status"] == "DOWNLOADED"
    assert payload["pin"] == "1234567890AB"
    assert Path(payload["p12"]).is_file()


def test_request_generated_pin_json(config, ca, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = run(
        cli(
            config,
            "request",
            "john smith",
            "--generate-pin",
            "--wait",
            "--interval",
            "0.2",
            "--timeout",
            "30",
            "--json",
        ),
        capsys,
    )
    assert code == 0, err
    payload = json.loads(out)
    assert len(payload["pin"]) == 14


def test_request_pin_file(config, ca, capsys, tmp_path):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    pin_file = tmp_path / "pin"
    pin_file.write_text("1234567890AB\n")
    code, out, err = run(
        cli(
            config,
            "request",
            "jane doe",
            "--pin-file",
            str(pin_file),
            "--wait",
            "--interval",
            "0.2",
            "--timeout",
            "30",
            "--json",
        ),
        capsys,
    )
    assert code == 0, err


def test_request_host_without_auth(config, capsys):
    code, out, err = run(
        cli(config, "request", "host.example.org", "--type", "host", "--pin", "1234567890AB"),
        capsys,
    )
    assert code == 1
    assert "authenticated" in err


def test_request_duplicate_alias(config, issued, capsys):
    issued()
    code, out, err = run(cli(config, "request", "jane doe", "--pin", "1234567890AB"), capsys)
    assert code == 1
    assert "already exists" in err


def test_request_rejection(config, ca, capsys):
    ca.reject_next = [(202, ca._error_xml("no thanks"))]
    code, out, err = run(cli(config, "request", "jane doe", "--pin", "1234567890AB"), capsys)
    assert code == 1
    assert "no thanks" in err


def test_request_quiet_suppresses_progress(config, ca, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = run(
        cli(
            config,
            "-q",
            "request",
            "jane doe",
            "--pin",
            "1234567890AB",
            "--wait",
            "--interval",
            "0.2",
            "--timeout",
            "30",
            "--json",
        ),
        capsys,
    )
    assert code == 0, err
    assert "Preparing request" not in err


def test_wait_timeout_exit_3(config, ca, capsys):
    ca.auto_approve = False
    code, out, err = run(
        cli(
            config,
            "request",
            "jane doe",
            "--pin",
            "1234567890AB",
            "--wait",
            "--timeout",
            "0.5",
            "--interval",
            "0.2",
        ),
        capsys,
    )
    assert code == 3
    assert "timed out" in err


def test_wait_on_downloaded_cert(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "wait", state.alias), capsys)
    assert code == 0


def test_verify_json_ok(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "verify", state.alias, "--json"), capsys)
    assert code == 0
    assert json.loads(out)["ok"] is True


def test_verify_failure_exit_4(config, issued, capsys):
    state = issued()
    Path(state.p12_path).parent.joinpath("cert.pem").write_bytes(b"junk")
    code, out, err = run(cli(config, "verify", state.alias), capsys)
    assert code == 4
    assert "FAIL" in out


def test_export_with_out(config, issued, capsys, tmp_path):
    state = issued()
    target = tmp_path / "cli-export.p12"
    code, out, err = run(cli(config, "export", state.alias, "--out", str(target)), capsys)
    assert code == 0, err
    assert out.strip() == str(target)
    assert target.is_file()


def test_export_password_file(config, issued, capsys, tmp_path):
    state = issued()
    password_file = tmp_path / "pw"
    password_file.write_text("cli-pass\n")
    target = tmp_path / "cli-export2.p12"
    code, out, err = run(
        cli(config, "export", state.alias, "--out", str(target), "--password-file", str(password_file)),
        capsys,
    )
    assert code == 0, err
    assert p12_module.read_pkcs12(target, "cli-pass")


def test_export_password_argument_warns(config, issued, capsys, tmp_path):
    state = issued()
    target = tmp_path / "cli-export3.p12"
    code, out, err = run(
        cli(config, "export", state.alias, "--out", str(target), "--password", "argv-pass"), capsys
    )
    assert code == 0
    assert "process list" in err


def test_install_json(config, issued, capsys, tmp_path):
    state = issued()
    code, out, err = run(cli(config, "install", state.alias, "--dir", str(tmp_path / "g"), "--json"), capsys)
    assert code == 0
    payload = json.loads(out)
    assert Path(payload["cert"]).is_file()


def test_delete_without_yes(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "delete", state.alias), capsys)
    assert code == 1
    assert "refusing" in err


def test_delete_with_yes(config, issued, capsys):
    state = issued()
    code, out, err = run(cli(config, "delete", state.alias, "--yes"), capsys)
    assert code == 0
    assert "Deleted" in out


def test_import_cli(config, ctx, issued, capsys, tmp_path):
    state = issued()
    target = tmp_path / "import.p12"
    p12_module.write_pkcs12(
        target,
        key=ctx.store.load_key(state, ctx.key_passphrase()),
        certificate=ctx.store.load_certificate(state),
        chain=[],
        password="import-cli",
    )
    password_file = tmp_path / "import-pw"
    password_file.write_text("import-cli\n")
    code, out, err = run(
        cli(
            config,
            "import",
            str(target),
            "--alias",
            "imported-cli",
            "--password-file",
            str(password_file),
            "--allow-unverified-chain",
            "--json",
        ),
        capsys,
    )
    assert code == 0, err
    assert json.loads(out)["alias"] == "imported-cli"


def test_secret_flow(config, capsys):
    code, out, err = run(cli(config, "secret", "set", "--generate", "--account", "cli"), capsys)
    assert code == 0
    assert "Generated secret" in out
    code, out, err = run(cli(config, "secret", "get", "--account", "cli", "--show"), capsys)
    assert code == 0 and out.strip()
    code, out, err = run(cli(config, "secret", "test", "--account", "cli"), capsys)
    assert code == 0
    code, out, err = run(cli(config, "secret", "list"), capsys)
    assert code == 0 and "cli" in out
    code, out, err = run(cli(config, "secret", "rm", "--account", "cli"), capsys)
    assert code == 0
    code, out, err = run(cli(config, "secret", "get", "--account", "cli"), capsys)
    assert code == 1


def test_secret_test_missing(config, capsys):
    code, out, err = run(cli(config, "secret", "test", "--account", "does-not-exist"), capsys)
    assert code == 1


def test_debug_flag_reraises(config, capsys):
    with pytest.raises(NotFound):
        main(cli(config, "--debug", "show", "nope"))


def test_unknown_command_exits_2():
    with pytest.raises(SystemExit) as exc:
        main(["no-such-command"])
    assert exc.value.code == 2
