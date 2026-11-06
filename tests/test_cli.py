import json
import stat
from pathlib import Path

from pycert.cli import main
from pycert.config import load_config
from pycert.workflow import AppContext


def run(args, capsys):
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_init_json_and_config_check(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PYCERT_DATA_DIR", str(tmp_path / "data"))
    directory = tmp_path / "conf"
    code, out, err = run(
        ["init", str(directory), "--backend", "file", "--email", "ops@example.org", "--json"], capsys
    )
    assert code == 0, err
    payload = json.loads(out)
    assert Path(payload["config"]).is_file()
    assert payload["secret_stored"] is True
    assert payload["secret_backend"] == "file"
    assert (tmp_path / "data" / "secrets.json").is_file()
    assert stat.S_IMODE((tmp_path / "data" / "secrets.json").stat().st_mode) == 0o600
    # init is protected against accidental overwrite
    assert main(["init", str(directory), "--backend", "file"]) == 1
    code, out, err = run(["--config", str(directory / "pycert.toml"), "config", "check"], capsys)
    assert code == 0
    assert "OK: 4 CA certificates" in out
    code, out, _ = run(["--config", str(directory / "pycert.toml"), "config", "path"], capsys)
    assert out.strip().endswith("pycert.toml")
    code, _, _ = run(["--config", str(directory / "pycert.toml"), "config", "set", "ca.timeout=12.5"], capsys)
    assert code == 0
    assert load_config(directory / "pycert.toml").ca.timeout == 12.5


def test_init_rejects_bad_settings(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PYCERT_DATA_DIR", str(tmp_path / "data"))
    code, _, err = run(
        ["init", str(tmp_path / "conf"), "--backend", "file", "--base-url", "http://x"], capsys
    )
    assert code == 1
    assert "allow_plaintext" in err


def test_ping_and_ras_json(config, capsys):
    code, out, err = run(["--config", str(config.path), "ping", "--json"], capsys)
    assert code == 0, err
    payload = json.loads(out)
    assert payload["ok"] is True and payload["tls"]["subject"]
    code, out, _ = run(["--config", str(config.path), "ras", "--json"], capsys)
    assert code == 0
    payload = json.loads(out)
    assert [ra["ou"] for ra in payload["ras"]] == ["CLRC", "CLRC"]
    assert payload["preferred"]["l"] == "DL"


def test_request_wait_export_json(config, ctx, ca, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = run(
        [
            "--config",
            str(config.path),
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
        ],
        capsys,
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["status"] == "DOWNLOADED"
    assert payload["pin"] == "1234567890AB"
    assert Path(payload["p12"]).is_file()
    assert Path(payload["certificate"]).is_file()
    state = ctx.store.get("jane doe")
    assert state.cert.verified is True


def test_request_generates_pin_when_absent(config, ca, capsys):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = run(
        [
            "--config",
            str(config.path),
            "request",
            "john smith",
            "--generate-pin",
            "--wait",
            "--interval",
            "0.2",
            "--timeout",
            "30",
            "--json",
        ],
        capsys,
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["pin"] and len(payload["pin"]) == 14


def test_list_show_status_json(config, issued, capsys):
    state = issued()
    code, out, _ = run(["--config", str(config.path), "list", "--json"], capsys)
    assert code == 0
    states = json.loads(out)
    assert states[0]["alias"] == "jane doe"
    code, out, _ = run(["--config", str(config.path), "show", state.alias, "--json"], capsys)
    assert code == 0
    payload = json.loads(out)
    assert payload["status"] == "DOWNLOADED"
    assert payload["days_remaining"] > 0
    code, out, err = run(["--config", str(config.path), "status", state.alias, "--refresh", "--json"], capsys)
    assert code == 0, err
    assert json.loads(out)


def test_wait_timeout_exit_code_3(config, ca, capsys):
    ca.auto_approve = False
    code, out, err = run(
        [
            "--config",
            str(config.path),
            "request",
            "jane doe",
            "--pin",
            "1234567890AB",
            "--wait",
            "--timeout",
            "0.6",
            "--interval",
            "0.2",
            "--json",
        ],
        capsys,
    )
    assert code == 3
    assert "timed out" in err
    code, out, err = run(
        ["--config", str(config.path), "wait", "jane doe", "--timeout", "0.3", "--interval", "0.1"], capsys
    )
    assert code == 3


def test_verify_and_export(config, issued, capsys, tmp_path):
    state = issued()
    code, out, err = run(["--config", str(config.path), "verify", state.alias, "--json"], capsys)
    assert code == 0, err
    assert json.loads(out)["ok"] is True
    target = tmp_path / "explicit.p12"
    code, out, err = run(["--config", str(config.path), "export", state.alias, "--out", str(target)], capsys)
    assert code == 0, err
    assert out.strip() == str(target)
    assert target.is_file()
    # corrupt the certificate: verify must exit 4
    ctx = AppContext.from_config(load_config(config.path))
    ctx.store.cert_path(state).write_bytes(b"junk")
    code, out, err = run(["--config", str(config.path), "verify", state.alias], capsys)
    assert code == 4
    assert "FAIL" in out


def test_unverified_chain_exit_code_4(config, ca, capsys, monkeypatch):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    from pycert import chain as chain_module
    from pycert.workflow import AppContext

    monkeypatch.setattr(
        AppContext,
        "build_chain",
        lambda self, certificate: chain_module.ChainResult(
            [certificate], complete=False, trusted=False, problems=["test: no anchor"]
        ),
    )
    code, out, err = run(
        [
            "--config",
            str(config.path),
            "request",
            "jane doe",
            "--pin",
            "1234567890AB",
            "--wait",
            "--interval",
            "0.2",
            "--timeout",
            "30",
        ],
        capsys,
    )
    assert code == 4
    assert "did not validate" in err


def test_secret_commands(config, ctx, capsys):
    ctx.secrets.ensure()
    code, out, err = run(["--config", str(config.path), "secret", "test"], capsys)
    assert code == 0
    assert "OK" in out
    code, out, _ = run(["--config", str(config.path), "secret", "get", "--show"], capsys)
    assert code == 0
    assert out.strip() == ctx.p12_passphrase()
    code, out, err = run(["--config", str(config.path), "secret", "list"], capsys)
    assert code == 0
    assert "default" in out


def test_missing_config(capsys):
    code, out, err = run(["--config", "/nonexistent/pycert.toml", "list"], capsys)
    assert code == 1
    assert "not found" in err


def test_unknown_alias(config, capsys):
    code, out, err = run(["--config", str(config.path), "show", "nope"], capsys)
    assert code == 1
    assert "no certificate request" in err


def test_delete_requires_confirmation_and_removes_files(config, issued, capsys):
    state = issued()
    directory = Path(state.p12_path).parent
    code, out, err = run(["--config", str(config.path), "delete", state.alias], capsys)
    assert code == 1
    assert "refusing to continue without --yes" in err
    assert directory.is_dir()
    code, out, err = run(["--config", str(config.path), "delete", state.alias, "--yes"], capsys)
    assert code == 0, err
    assert "Deleted" in out
    assert not directory.exists()
