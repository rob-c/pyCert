"""CLI option/exit-code matrix against the mock listener."""

import json

import pytest

SAFE_COMMANDS = [
    ["ping"],
    ["ras"],
    ["info"],
    ["list"],
    ["config", "show"],
    ["config", "check"],
    ["doctor", "--offline"],
    ["selftest"],
    ["secret", "list"],
]

FLAG_SETS = [
    [],
    ["--json"],
    ["-q"],
    ["-v"],
    ["--json", "-q"],
]


@pytest.mark.parametrize("flags", FLAG_SETS)
@pytest.mark.parametrize("command", SAFE_COMMANDS)
def test_safe_command_flag_matrix(e2e, command, flags):
    result = e2e.run(*command, *flags)
    assert result.code == 0, (command, flags, result.out, result.err)
    assert "Traceback" not in result.err


def test_config_option_before_and_after_subcommand(config, capsys):
    from pycert.cli import main

    before = main(["--config", str(config.path), "ping"])
    capsys.readouterr()
    after = main(["ping", "--config", str(config.path)])
    capsys.readouterr()
    assert before == after == 0


def test_environment_config(monkeypatch, config, capsys):
    from pycert.cli import main

    monkeypatch.setenv("PYCERT_CONFIG", str(config.path))
    assert main(["ping"]) == 0
    capsys.readouterr()


@pytest.mark.parametrize(
    "args,code",
    [
        (["show", "missing"], 1),
        (["verify", "missing"], 1),
        (["export", "missing"], 1),
        (["download", "missing"], 1),
        (["renew", "missing", "--yes"], 1),
        (["revoke", "missing", "--yes"], 1),
        (["delete", "missing", "--yes"], 1),
        (["install", "missing"], 1),
        (["wait", "missing"], 1),
        (["secret", "test", "--account", "missing"], 1),
        (["config", "set", "keys.algorithm=dsa"], 1),
        (["config", "set", "ca.tls_trust=tofu"], 1),
        (["watch", "--max-cycles", "0"], 1),
        (["renew", "--due", "-1", "--dry-run"], 1),
        (["renew"], 1),
        (["renew", "a", "--due", "30", "--dry-run"], 1),
    ],
)
def test_error_exit_codes(e2e, args, code):
    result = e2e.run(*args)
    assert result.code == code, (args, result.out, result.err)
    assert "Traceback" not in result.err


@pytest.mark.parametrize("command", ["not-a-command", "gui", "config", "secret"])
def test_usage_errors(command):
    from pycert.cli import main

    with pytest.raises(SystemExit) as exc:
        main([command, "--definitely-not-a-flag"])
    assert exc.value.code == 2


def test_json_output_is_pure(e2e):
    for command in (
        ["ping"],
        ["ras"],
        ["info"],
        ["list"],
        ["config", "show"],
        ["doctor", "--offline"],
        ["selftest"],
    ):
        result = e2e.run(*command, "--json")
        assert result.code == 0
        json.loads(result.out)
        assert result.out.strip().startswith(("{", "["))


def test_quiet_suppresses_progress(e2e):
    e2e.ca.auto_approve = True
    e2e.ca.sign_after_polls = 0
    result = e2e.run("request", "quiet user", "--pin", e2e.PIN, "-q", "--json")
    assert result.code == 0
    assert "Preparing request" not in result.err


def test_debug_reraises(e2e):
    from pycert.errors import NotFound

    with pytest.raises(NotFound):
        e2e.run("show", "missing", "--debug")
