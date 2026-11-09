"""Coverage-oriented CLI tests: argument helpers, error paths and output modes."""

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pycert import cli
from pycert.errors import PyCertError


def test_console_result_modes(capsys):
    console = cli.Console(json_mode=True)
    console.result({"x": 1})
    assert json.loads(capsys.readouterr().out) == {"x": 1}
    console = cli.Console()
    console.result({"x": 2})
    assert json.loads(capsys.readouterr().out) == {"x": 2}


def _stdin(text="", isatty=False):
    class S:
        def readline(self):
            return text

        def isatty(self):
            return isatty

    return S()


def _secret_args(**kwargs):
    base = {"password": None, "password_file": None, "password_stdin": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_read_secret_option_file_errors(tmp_path, monkeypatch):
    args = _secret_args(password="secret")
    assert cli._read_secret_option(args, what="secret", prompt_label="x") == "secret"
    args = _secret_args(password_file=str(tmp_path / "missing"))
    with pytest.raises(PyCertError):
        cli._read_secret_option(args, what="secret", prompt_label="x")
    args = _secret_args(password_stdin=True)
    monkeypatch.setattr(sys, "stdin", _stdin(""))
    with pytest.raises(PyCertError):
        cli._read_secret_option(args, what="secret", prompt_label="x")
    monkeypatch.setattr(sys, "stdin", _stdin("value\n"))
    assert cli._read_secret_option(args, what="secret", prompt_label="x") == "value"
    monkeypatch.setattr(sys, "stdin", _stdin("", False))
    with pytest.raises(PyCertError):
        cli._read_secret_option(_secret_args(), what="secret", prompt_label="x")
    monkeypatch.setattr(sys, "stdin", _stdin("", True))
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "typed")
    assert cli._read_secret_option(_secret_args(), what="secret", prompt_label="x") == "typed"


def _pin_args(**kwargs):
    base = {"pin": None, "pin_file": None, "pin_stdin": False, "generate_pin": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_read_pin_paths(tmp_path, monkeypatch):
    assert cli._read_pin(_pin_args(pin="123456")) == "123456"
    path = tmp_path / "pin"
    path.write_text("123456\n")
    assert cli._read_pin(_pin_args(pin_file=str(path))) == "123456"
    monkeypatch.setattr(sys, "stdin", _stdin(""))
    with pytest.raises(PyCertError):
        cli._read_pin(_pin_args(pin_stdin=True))
    monkeypatch.setattr(sys, "stdin", _stdin("123456\n"))
    assert cli._read_pin(_pin_args(pin_stdin=True)) == "123456"
    assert cli._read_pin(_pin_args(generate_pin=True)) == ""
    monkeypatch.setattr(sys, "stdin", _stdin("", True))
    values = iter(["", ""])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(values))
    assert cli._read_pin(_pin_args()) == ""
    values = iter(["one", "two"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(values))
    with pytest.raises(PyCertError):
        cli._read_pin(_pin_args())
    values = iter(["one", "one"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(values))
    assert cli._read_pin(_pin_args()) == "one"


def test_confirm_paths(monkeypatch):
    assert cli._confirm(argparse.Namespace(yes=True), "sure?", "yes")
    monkeypatch.setattr(sys, "stdin", _stdin("", False))
    with pytest.raises(PyCertError):
        cli._confirm(argparse.Namespace(yes=False), "sure?", "yes")
    monkeypatch.setattr(sys, "stdin", _stdin("", True))
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    with pytest.raises(PyCertError):
        cli._confirm(argparse.Namespace(yes=False), "sure?", "yes")
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert cli._confirm(argparse.Namespace(yes=False), "sure?", "yes")


def test_cmd_init_toml_path_and_text_output(tmp_path, capsys):
    target = tmp_path / "config.toml"
    args = cli.build_parser().parse_args(
        ["init", str(target), "--email", "e@example.org", "--ra", "CLRC DL", "--backend", "file"]
    )
    assert cli.cmd_init(args) == 0
    out = capsys.readouterr().out
    assert "Configuration written" in out
    assert (tmp_path / "pycert.toml").is_file()


def test_cmd_config_paths(config, capsys, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda _path: config)
    parser = cli.build_parser()
    show = parser.parse_args(["--config", str(config.path), "config", "show"])
    assert cli.cmd_config(show) == 0
    assert "Configuration:" in capsys.readouterr().out
    config.ca.tls_pin_sha256 = ["AA:BB"]
    config.warnings = ["a warning"]
    assert cli.cmd_config(show) == 0
    assert "TLS pin" in capsys.readouterr().out
    bad = parser.parse_args(["--config", str(config.path), "config", "set", "bad"])
    with pytest.raises(PyCertError):
        cli.cmd_config(bad)
    check = parser.parse_args(["--config", str(config.path), "config", "check"])
    assert cli.cmd_config(check) == 0
    capsys.readouterr()


def test_cmd_config_check_warnings_and_errors(config, capsys, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda _path: config)
    parser = cli.build_parser()
    config.chain = []
    config.ca.allow_plaintext = True
    config.csr.pin_hash = "sha256"
    check = parser.parse_args(["--config", str(config.path), "config", "check"])
    assert cli.cmd_config(check) == 1
    out = capsys.readouterr()
    assert "no trust anchors" in (out.out + out.err)
    config.load_chain = lambda: (_ for _ in ()).throw(cli.ConfigError("bad chain"))
    assert cli.cmd_config(check) == 1
    assert "bad chain" in capsys.readouterr().err


def test_cmd_config_unknown_action(config):
    args = argparse.Namespace(config=config.path, json=False, quiet=False, action="unknown")
    with pytest.raises(PyCertError):
        cli.cmd_config(args)


def test_cmd_list_show_status_wait_output(e2e, issued, capsys):
    state = issued("cli coverage")
    e2e.config.identity.email = "e@example.org"
    listed = e2e.run("list")
    assert listed.code == 0
    shown = e2e.run("show", state.alias)
    assert shown.code == 0
    status = e2e.run("status", state.alias, "--refresh")
    assert status.code == 0
    waited = e2e.run("wait", state.alias, "--interval", "0.1", "--timeout", "5")
    assert waited.code == 0
    capsys.readouterr()


def test_cmd_proxy_text_output(e2e, issued, tmp_path):
    state = issued("cli proxy text")
    result = e2e.run("proxy", state.alias, "--out", str(tmp_path / "p.pem"))
    assert result.code == 0
    assert "Proxy bundle created" in result.out


def test_cmd_delete_keep_p12(e2e, issued, tmp_path):
    state = issued("delete keep")
    external = tmp_path / "external.p12"
    external.write_bytes(Path(state.p12_path).read_bytes())
    state.p12_path = str(external)
    e2e.ctx.store.save(state)
    result = e2e.run("delete", state.alias, "--keep-p12", "--yes")
    assert result.code == 0
    assert external.is_file()


def test_cmd_secret_interactive_paths(e2e, monkeypatch, capsys):
    # interactive set (no --generate) with matching values
    monkeypatch.setattr(sys, "stdin", _stdin("", True))
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "value")
    result = e2e.run("secret", "set", "--account", "coverage-secret")
    assert result.code == 0
    # stdin set
    monkeypatch.setattr(sys, "stdin", _stdin("", False))
    monkeypatch.setattr(sys.stdin, "readline", lambda: "value\n")
    result = e2e.run("secret", "set", "--account", "coverage-stdin")
    assert result.code == 0
    # empty stdin
    monkeypatch.setattr(sys.stdin, "readline", lambda: "")
    result = e2e.run("secret", "set", "--account", "coverage-empty")
    assert result.code != 0
    capsys.readouterr()


def test_cmd_gui_import_error(config, monkeypatch):
    args = argparse.Namespace(config=config.path, json=False, quiet=False)
    monkeypatch.setattr("builtins.__import__", lambda name, *a, **k: (_ for _ in ()).throw(ImportError("no tk")))
    with pytest.raises(PyCertError):
        cli.cmd_gui(args)


def test_main_keyboard_interrupt_and_generic_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda _path: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert cli.main(["ping"]) == 130
    assert "interrupted" in capsys.readouterr().err
    monkeypatch.setattr(cli, "load_config", lambda _path: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cli.main(["ping"]) == 1
    assert "unexpected error" in capsys.readouterr().err


def test_cmd_config_check_pin_and_expiry_warnings(config, capsys, monkeypatch):
    from pycert.config import ChainEntry

    monkeypatch.setattr(cli, "load_config", lambda _path: config)
    config.chain = [ChainEntry(label="x", file=str(Path.cwd() / "src/pycert/data/ca/escience-root.pem"))]
    config._bundle = None
    config.ca.tls_verify = False
    config.csr.pin_hash = "sha1"
    parser = cli.build_parser()
    args = parser.parse_args(["--config", str(config.path), "config", "check"])
    assert cli.cmd_config(args) == 1
    assert "no SHA-256 pin" in capsys.readouterr().err


def test_cmd_info_and_motd_error_paths(config, monkeypatch, capsys):
    class Client:
        last_tls = None
        last_error = ""

        def ping(self):
            return True

        def info(self):
            return SimpleNamespace(problems=["problem"], ras=[], policy={}, certificates=[])

        def motd(self):
            raise PyCertError("no motd")

    monkeypatch.setattr(cli.AppContext, "client", lambda self: Client())
    args = cli.build_parser().parse_args(["--config", str(config.path), "info"])
    assert cli.cmd_info(args) == 0
    assert "problem" in capsys.readouterr().err


def test_cmd_status_refresh_all_and_show_notes(e2e, issued, monkeypatch, capsys):
    state = issued("coverage status")
    state.notes = ["note one"]
    e2e.ctx.store.save(state)
    shown = e2e.run("show", state.alias)
    assert shown.code == 0
    assert "Notes" in shown.out
    monkeypatch.setattr(e2e.__class__, "run", e2e.run)
    # refresh_all path through the CLI's own context
    from pycert import cli as cli_module

    monkeypatch.setattr(cli_module, "refresh_all", lambda ctx, progress: [(state, "ok")])
    result = e2e.run("status", "--refresh")
    assert result.code == 0
    capsys.readouterr()


def test_cmd_download_and_renew_output(e2e, issued, tmp_path, monkeypatch, capsys):
    state = issued("coverage download")
    result = e2e.run("download", state.alias)
    assert result.code == 0
    assert "PKCS#12" in result.out
    e2e.set_expiry(state.alias, 1)
    monkeypatch.setattr(cli, "renew", lambda *a, **k: (_ for _ in ()).throw(PyCertError("renew error")))
    due = e2e.run("renew", "--due", "30", "--dry-run")
    assert due.code in (0, 1)
    capsys.readouterr()


def test_cmd_secret_interactive_failures(e2e, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    values = iter(["one", "two"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(values))
    result = e2e.run("secret", "set", "--account", "mismatch")
    assert result.code != 0
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "")
    result = e2e.run("secret", "set", "--account", "empty")
    assert result.code != 0
    result = e2e.run("secret", "set", "--account", "json", "--generate", "--json")
    assert result.code == 0
    result = e2e.run("secret", "get", "--account", "json")
    assert result.code == 0
    result = e2e.run("secret", "list")
    assert result.code == 0
    capsys.readouterr()


def test_cmd_gui_success_and_debug_error(config, monkeypatch):
    import pycert.gui as gui_module

    monkeypatch.setattr(gui_module, "run_gui", lambda config_path=None: 0)
    args = argparse.Namespace(config=config.path, json=False, quiet=False)
    assert cli.cmd_gui(args) == 0
    monkeypatch.setattr(cli, "load_config", lambda _path: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        cli.main(["ping", "--debug"])


def test_cmd_config_expiry_warnings(config, capsys, monkeypatch):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    monkeypatch.setattr(cli, "load_config", lambda _path: config)
    fake = SimpleNamespace(subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired")]))
    monkeypatch.setattr(cli.certs, "describe_certificate", lambda _cert: SimpleNamespace(days_remaining=0))
    config._bundle = SimpleNamespace(certificates=[fake], anchors=[fake], sources=[])
    args = cli.build_parser().parse_args(["--config", str(config.path), "config", "check"])
    assert cli.cmd_config(args) == 1
    assert "expired" in capsys.readouterr().err
    monkeypatch.setattr(cli.certs, "describe_certificate", lambda _cert: SimpleNamespace(days_remaining=10))
    config._bundle = SimpleNamespace(certificates=[fake], anchors=[fake], sources=[])
    args = cli.build_parser().parse_args(["--config", str(config.path), "config", "check"])
    cli.cmd_config(args)
    assert "expires in" in capsys.readouterr().err


def test_cmd_ras_info_problems(config, monkeypatch, capsys):
    class Client:
        last_tls = None
        last_error = ""

        def info(self):
            return SimpleNamespace(ras=[], problems=["problem"], preferred_ra=None, policy={}, certificates=[])

    monkeypatch.setattr(cli.AppContext, "client", lambda self: Client())
    args = cli.build_parser().parse_args(["--config", str(config.path), "ras"])
    assert cli.cmd_ras(args) == 0
    assert "problem" in capsys.readouterr().err


def test_cmd_request_list_show_download_text(e2e, issued, ca, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    result = e2e.run("request", "text request", "--pin", e2e.PIN, "--key-algorithm", "rsa", "--wait")
    assert result.code == 0
    assert "valid until" in result.out
    state = next(item for item in e2e.ctx.store.list() if item.cn == "text request")
    e2e.set_expiry(state.alias, 5)
    listed = e2e.run("list")
    assert listed.code == 0 and "!" in listed.out
    shown = e2e.run("show", state.alias)
    assert shown.code == 0 and "expires" in shown.err
    download = e2e.run("download", state.alias)
    assert download.code == 0 and "PKCS#12" in download.out
    capsys.readouterr()


def test_cmd_verify_warnings_and_renew_due_output(e2e, issued, monkeypatch, capsys):
    state = issued("coverage verify warnings")
    report = SimpleNamespace(
        checks=[],
        warnings=["warning"],
        chain=None,
        as_dict=lambda: {},
        ok=True,
    )
    monkeypatch.setattr(cli, "verify", lambda *a, **k: report)
    result = e2e.run("verify", state.alias)
    assert result.code == 0
    assert "WARN" in result.out
    monkeypatch.setattr(cli, "renew_due", lambda *a, **k: [(state, "error")])
    due = e2e.run("renew", "--due", "30", "--yes")
    assert due.code == 1
    assert "FAILED" in due.out
    monkeypatch.setattr(cli, "renew_due", lambda *a, **k: [(state, None)])
    due = e2e.run("renew", "--due", "30", "--dry-run")
    assert due.code == 0 and "would renew" in due.out
    capsys.readouterr()


def test_cmd_watch_errors_and_secret_nonfile(e2e, monkeypatch, capsys):
    e2e.request_user("watch error", wait=True)
    report = SimpleNamespace(
        errors=[("alias", "error")],
        as_dict=lambda: {},
        cycles=1,
        polled=1,
        downloaded=0,
    )
    monkeypatch.setattr(cli, "watch", lambda *a, **k: report)
    result = e2e.run("watch")
    assert result.code == 1 and "alias: error" in result.out
    # Backend that cannot enumerate accounts.
    e2e.config.secrets.backend = "command"
    e2e.config.secrets.command = "true"
    e2e.config.save()
    result = e2e.run("secret", "list")
    assert result.code == 0 and "cannot enumerate" in result.out
    args = SimpleNamespace(config=e2e.config.path, json=False, quiet=False, action="unknown", account=None)
    with pytest.raises(PyCertError):
        cli.cmd_secret(args)
    capsys.readouterr()


def test_cmd_download_text_and_renew_due_else(e2e, issued, monkeypatch, capsys):
    state = issued("download text")
    result = e2e.run("download", state.alias)
    assert result.code == 0
    assert "Certificate stored" in result.out
    monkeypatch.setattr(cli, "renew_due", lambda *a, **k: [(state, None)])
    due = e2e.run("renew", "--due", "30", "--yes")
    assert due.code == 0
    assert "DOWNLOADED" in due.out or "SUBMITTED" in due.out
    capsys.readouterr()
