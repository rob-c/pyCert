"""Private keys are never written unprotected, and exports need a new passphrase.

* every export or install of a private key needs a passphrase chosen for it:
  never pyCertWiz's saved secret, never a default;
* one individual key file may be left without a passphrase after a typed
  confirmation; bundles never.
"""

import io
import json
import sys

import pytest

from pycert import certs, cli
from pycert.deploy import add_target, deploy_target, validate_target
from pycert.errors import CryptoError, PyCertError
from pycert.workflow import export_pem, install_pem

NEW = "a brand new passphrase"


def _run(args, capsys, stdin="", tty=False, answer=None, monkeypatch=None, typed=None):
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    if tty:
        sys.stdin.isatty = lambda: True
    try:
        if answer is not None:
            monkeypatch.setattr("builtins.input", lambda _prompt: answer)
        if typed is not None:
            answers = iter(typed)
            monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))
        code = cli.main(args)
    finally:
        sys.stdin = old
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _is_encrypted(path):
    return path.read_text().startswith("-----BEGIN ENCRYPTED PRIVATE KEY")


def _key_file(directory, alias):
    return directory / f"{alias.replace(' ', '_')}.key"


def test_unprotected_pem_needs_explicit_confirmation(ctx, issued):
    key = ctx.store.load_key(issued("jane doe"), ctx.key_passphrase())
    for value in (False, None, "yes", 1):
        with pytest.raises(CryptoError, match="explicit confirmation"):
            certs.unprotected_key_pem(key, confirmed=value)
    assert certs.unprotected_key_pem(key, confirmed=True).startswith("-----BEGIN PRIVATE KEY")


def test_export_pem_requires_a_new_passphrase(ctx, issued, tmp_path):
    state = issued("jane doe")
    with pytest.raises(PyCertError, match="needs a new passphrase"):
        export_pem(ctx, state.alias, tmp_path / "none")
    with pytest.raises(PyCertError, match="not pyCertWiz's own saved secret"):
        export_pem(ctx, state.alias, tmp_path / "saved", password=ctx.p12_passphrase())
    with pytest.raises(PyCertError, match="at least 8"):
        export_pem(ctx, state.alias, tmp_path / "short", password="short")
    with pytest.raises(PyCertError, match="not both"):
        export_pem(ctx, state.alias, tmp_path / "both", password=NEW, no_passphrase=True)
    messages = []
    paths = export_pem(ctx, state.alias, tmp_path / "own", password=NEW, progress=messages.append)
    assert _is_encrypted(paths["key"]) and certs.load_private_key(paths["key"].read_bytes(), NEW)
    assert paths["cert"].read_text().count("BEGIN CERTIFICATE") >= 2
    assert any("does not keep it" in m for m in messages)
    paths = export_pem(ctx, state.alias, tmp_path / "leaf", password=NEW, include_chain=False)
    assert paths["cert"].read_text().count("BEGIN CERTIFICATE") == 1
    paths = export_pem(ctx, state.alias, tmp_path / "plain", no_passphrase=True, progress=messages.append)
    assert not _is_encrypted(paths["key"]) and (paths["key"].stat().st_mode & 0o777) == 0o400
    assert any("NO passphrase" in m for m in messages)
    paths = install_pem(ctx, state.alias, tmp_path / "globus", no_passphrase=True)
    assert not _is_encrypted(paths["key"])


def test_cli_export_and_install_ask_for_a_new_passphrase(e2e, config, tmp_path, capsys, monkeypatch):
    alias = e2e.setup_issued("cli protection")
    base = ["--config", str(config.path)]
    # without a terminal or a passphrase option: refused, nothing written
    code, _, err = _run([*base, "export", alias, "--pem", "--out", str(tmp_path / "x")], capsys)
    assert code == 1 and "a new passphrase" in err and not (tmp_path / "x").exists()
    # on a terminal it is asked twice; a mismatch is refused
    code, _, err = _run(
        [*base, "export", alias, "--pem", "--out", str(tmp_path / "m")], capsys, tty=True, typed=[NEW, "other"], monkeypatch=monkeypatch
    )
    assert code == 1 and "do not match" in err
    code, out, err = _run(
        [*base, "export", alias, "--pem", "--out", str(tmp_path / "t")], capsys, tty=True, typed=[NEW, NEW], monkeypatch=monkeypatch
    )
    assert code == 0, err
    assert certs.load_private_key(_key_file(tmp_path / "t", alias).read_bytes(), NEW)
    # or given for one command
    code, out, err = _run([*base, "--json", "export", alias, "--pem", "--out", str(tmp_path / "s"), "--password-stdin"], capsys, NEW + "\n")
    assert code == 0 and json.loads(out)["files"]["key"].endswith(".key")
    # no passphrase: refused without a terminal, refused with the wrong word, written only after typing it
    target = tmp_path / "plain"
    code, _, err = _run([*base, "export", alias, "--pem", "--out", str(target), "--no-key-passphrase"], capsys)
    assert code == 1 and "interactive confirmation" in err and not target.exists()
    code, _, err = _run(
        [*base, "export", alias, "--pem", "--out", str(target), "--no-key-passphrase"], capsys, tty=True, answer="yes", monkeypatch=monkeypatch
    )
    assert code == 1 and "aborted" in err and not target.exists()
    code, _, err = _run(
        [*base, "export", alias, "--pem", "--out", str(target), "--no-key-passphrase"],
        capsys,
        tty=True,
        answer="unencrypted",
        monkeypatch=monkeypatch,
    )
    assert code == 0, err
    assert not _is_encrypted(_key_file(target, alias))
    code, _, err = _run(
        [*base, "export", alias, "--pem", "--no-key-passphrase", "--password-stdin"], capsys, "x\n", tty=True, answer="unencrypted", monkeypatch=monkeypatch
    )
    assert code == 1 and "cannot be combined" in err
    # bundles never: a PKCS#12 export cannot be unprotected
    code, _, err = _run([*base, "export", alias, "--no-key-passphrase"], capsys, tty=True, answer="unencrypted", monkeypatch=monkeypatch)
    assert code == 1 and "always protected" in err
    # install: the same choice for userkey.pem
    globus = tmp_path / "globus"
    code, _, err = _run([*base, "install", alias, "--dir", str(globus)], capsys)
    assert code == 1 and "a new passphrase" in err
    code, _, err = _run([*base, "install", alias, "--dir", str(globus), "--password-stdin"], capsys, NEW + "\n")
    assert code == 0 and certs.load_private_key((globus / "userkey.pem").read_bytes(), NEW)
    code, _, err = _run(
        [*base, "install", alias, "--dir", str(globus), "--no-key-passphrase"], capsys, tty=True, answer="unencrypted", monkeypatch=monkeypatch
    )
    assert code == 0 and not _is_encrypted(globus / "userkey.pem")


def test_deploy_override_is_confirmed_and_never_for_bundles(ctx, issued, tmp_path, e2e, config, capsys, monkeypatch):
    state = issued("deploy protection")
    key_file = tmp_path / "svc" / "service.key"
    with pytest.raises(PyCertError, match="explicit confirmation"):
        validate_target({"name": "x", "key": str(key_file), "unencrypted_key": True})
    with pytest.raises(PyCertError, match="bundles are always encrypted"):
        validate_target({"name": "x", "bundle": str(key_file), "unencrypted_key": True, "unencrypted_key_confirmed": "now"})
    assert "unencrypted_key" not in validate_target({"name": "x", "key": str(key_file), "unencrypted_key": False})
    target = add_target(
        ctx, state, {"name": "svc", "key": str(key_file), "unencrypted_key": True, "unencrypted_key_confirmed": "2026-11-11T00:00:00Z"}
    )
    deploy_target(ctx, state, target)
    assert not _is_encrypted(key_file)
    # CLI: the override is confirmed once, when the target is created
    base = ["--config", str(config.path)]
    alias = e2e.setup_issued("cli deploy protection")
    plain = tmp_path / "cli" / "plain.key"
    code, _, err = _run([*base, "deploy", "add", alias, "--name", "p", "--key", str(plain), "--no-key-passphrase"], capsys)
    assert code == 1 and "interactive confirmation" in err
    code, _, err = _run(
        [*base, "deploy", "add", alias, "--name", "b", "--bundle", str(plain), "--no-key-passphrase"], capsys, tty=True, answer="unencrypted", monkeypatch=monkeypatch
    )
    assert code == 1 and "bundles are always encrypted" in err
    code, out, err = _run(
        [*base, "deploy", "add", alias, "--name", "p", "--key", str(plain), "--no-key-passphrase", "--now"],
        capsys,
        tty=True,
        answer="unencrypted",
        monkeypatch=monkeypatch,
    )
    assert code == 0, err
    assert not _is_encrypted(plain)
    stored = e2e.ctx.store.get(alias).deploy[0]
    assert stored["unencrypted_key"] is True and stored["unencrypted_key_confirmed"]
