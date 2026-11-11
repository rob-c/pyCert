"""Deployment targets: validation, presets, file writing, hooks and drift."""

import os
import shutil
import stat
import subprocess
import sys

import pytest

from pycert import certs, workflow
from pycert import deploy as deploy_module
from pycert.deploy import (
    PRESETS,
    DeployResult,
    DriftItem,
    add_target,
    check_drift,
    deploy_state,
    deploy_target,
    remove_target,
    target_from_preset,
    validate_target,
)
from pycert.errors import CryptoError, PyCertError


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _hook(tmp_path, body, name="hook.py"):
    script = tmp_path / name
    script.write_text(body)
    return f"{sys.executable} {script}"


# ---------------------------------------------------------------------------
# Validation and presets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target, match",
    [
        ("not a dict", "table/dict"),
        ({"name": "x", "cert": "/a", "colour": "red"}, "unknown deployment setting"),
        ({"cert": "/a"}, "needs a name"),
        ({"name": "  ", "cert": "/a"}, "needs a name"),
        ({"name": "x"}, "writes no files"),
        ({"name": "x", "cert": "relative/cert.pem"}, "must be absolute"),
        ({"name": "x", "cert": "/a", "cert_mode": "0999"}, "invalid file mode"),
        ({"name": "x", "cert": "/a", "cert_mode": "01777"}, "invalid file mode"),
        ({"name": "x", "key": "/k", "key_mode": "0644"}, "other users read the private key"),
        ({"name": "x", "key": "/k", "key_mode": "0606"}, "other users read the private key"),
        ({"name": "x", "cert": "/a", "hook_timeout": 0}, "hook_timeout"),
        ({"name": "x", "cert": "/a", "hook_timeout": True}, "hook_timeout"),
        ({"name": "x", "cert": "/a", "hook_timeout": "10"}, "hook_timeout"),
        ({"name": "x", "cert": "/a", "hook": 'echo "unterminated'}, "cannot parse"),
        ({"name": "x", "cert": "/a", "hook": "   "}, "hook command is empty"),
    ],
)
def test_invalid_targets_are_rejected(target, match):
    with pytest.raises(PyCertError, match=match):
        validate_target(target)


def test_valid_target_is_normalised():
    target = validate_target({"name": " web ", "fullchain": "/etc/x/full.pem", "key": "/etc/x/key.pem", "key_mode": "640"})
    assert target["name"] == "web"
    assert target["cert_mode"] == "0644" and target["key_mode"] == "0640"


@pytest.mark.parametrize("preset", sorted(PRESETS))
def test_every_preset_builds_a_valid_target(preset, tmp_path):
    target = target_from_preset(preset, directory=str(tmp_path), alias="web 1/a")
    assert target["name"] == preset
    files = [target[kind] for kind in deploy_module.FILE_KINDS if target.get(kind)]
    assert files and all(path.startswith(str(tmp_path)) for path in files)
    assert all("web_1-a" in path or preset in ("grid-host", "globus-user") for path in files)


def test_preset_overrides_and_unknown_preset():
    target = target_from_preset(
        "nginx", name="frontend", directory="/srv/tls/", alias="web", hook="nginx -s reload", owner="root", group="www"
    )
    assert target["name"] == "frontend"
    assert target["fullchain"] == "/srv/tls/web.fullchain.pem"
    assert target["hook"] == "nginx -s reload" and target["owner"] == "root" and target["group"] == "www"
    assert target_from_preset("grid-host")["cert"] == "/etc/grid-security/hostcert.pem"
    with pytest.raises(PyCertError, match="unknown deployment preset"):
        target_from_preset("tomcat")


def test_result_objects_serialise():
    assert DeployResult("t", ["a"], "h", "out").as_dict() == {
        "target": "t",
        "written": ["a"],
        "hook": "h",
        "hook_output": "out",
        "ok": True,
        "error": "",
    }
    assert DriftItem("t", "/p", "missing").as_dict() == {"target": "t", "path": "/p", "problem": "missing"}


# ---------------------------------------------------------------------------
# Writing files
# ---------------------------------------------------------------------------


@pytest.fixture
def user(issued, ctx):
    return ctx.store.get(issued("deploy person").alias)


def test_deploy_writes_every_file_kind_with_modes(ctx, user, tmp_path):
    out = tmp_path / "out"
    target = {
        "name": "all",
        "cert": str(out / "cert.pem"),
        "chain": str(out / "chain.pem"),
        "fullchain": str(out / "full.pem"),
        "key": str(out / "key.pem"),
        "bundle": str(out / "bundle.pem"),
        "p12": str(out / "p12" / "copy.p12"),
        "key_mode": "0400",
    }
    messages = []
    result = deploy_target(ctx, user, target, progress=messages.append)
    assert len(result.written) == 6 and result.ok and not result.hook
    leaf = ctx.store.load_certificate(user)
    assert certs.fingerprint(certs.load_certificate((out / "cert.pem").read_bytes())) == certs.fingerprint(leaf)
    assert (out / "full.pem").read_text().count("BEGIN CERTIFICATE") == 1 + (out / "chain.pem").read_text().count(
        "BEGIN CERTIFICATE"
    )
    # Deployed keys are never unprotected: they open only with the saved secret.
    assert (out / "key.pem").read_text().startswith("-----BEGIN ENCRYPTED PRIVATE KEY")
    assert (out / "bundle.pem").read_text().startswith("-----BEGIN ENCRYPTED PRIVATE KEY")
    with pytest.raises(CryptoError):
        certs.load_private_key((out / "key.pem").read_bytes())
    deployed = certs.load_private_key((out / "key.pem").read_bytes(), ctx.p12_passphrase())
    assert certs.certificate_matches_key(leaf, deployed)
    assert _mode(out / "cert.pem") == 0o644 and _mode(out / "key.pem") == 0o400
    assert _mode(out / "bundle.pem") == 0o400 and _mode(out / "p12" / "copy.p12") == 0o400
    assert _mode(out / "p12") == 0o700
    from pycert import p12

    bundle = p12.read_pkcs12(out / "p12" / "copy.p12", ctx.p12_passphrase())
    assert certs.fingerprint(bundle.cert) == certs.fingerprint(leaf)
    assert any("wrote" in message for message in messages)


def test_existing_directories_keep_their_mode(ctx, user, tmp_path):
    shared = tmp_path / "grid-security"
    shared.mkdir(mode=0o755)
    os.chmod(shared, 0o755)
    target = target_from_preset("grid-host", directory=str(shared))
    deploy_target(ctx, user, target)
    # Writing hostkey.pem (0400) must not lock others out of the shared directory.
    assert _mode(shared) == 0o755
    assert _mode(shared / "hostkey.pem") == 0o400 and _mode(shared / "hostcert.pem") == 0o644
    fresh = tmp_path / "new" / "keys"
    deploy_target(ctx, user, {"name": "k", "key": str(fresh / "key.pem")})
    assert _mode(fresh) == 0o700


def test_encrypted_key_backup_and_symlink_refusal(ctx, user, tmp_path):
    key_path = tmp_path / "key.pem"
    key_path.write_text("old key")
    key_path.chmod(0o600)
    deploy_target(ctx, user, {"name": "enc", "key": str(key_path)})
    assert "ENCRYPTED PRIVATE KEY" in key_path.read_text()
    with pytest.raises(PyCertError, match="unknown deployment setting"):
        deploy_target(ctx, user, {"name": "plain", "key": str(key_path), "encrypt_key": False})
    backup = tmp_path / "key.pem.bak"
    assert backup.read_text() == "old key" and _mode(backup) == 0o600
    no_backup = tmp_path / "plain.pem"
    no_backup.write_text("previous")
    deploy_target(ctx, user, {"name": "nb", "cert": str(no_backup), "backup": False})
    assert not (tmp_path / "plain.pem.bak").exists()
    victim = tmp_path / "victim"
    victim.write_text("do not overwrite")
    link = tmp_path / "link.pem"
    link.symlink_to(victim)
    with pytest.raises(PyCertError, match="symbolic link"):
        deploy_target(ctx, user, {"name": "s", "cert": str(link)})
    p12_link = tmp_path / "link.p12"
    p12_link.symlink_to(victim)
    with pytest.raises(PyCertError, match="symbolic link"):
        deploy_target(ctx, user, {"name": "s2", "p12": str(p12_link)})
    assert victim.read_text() == "do not overwrite"


def test_backup_failure_is_not_fatal(ctx, user, tmp_path, monkeypatch):
    path = tmp_path / "cert.pem"
    path.write_text("old")
    monkeypatch.setattr(shutil, "copy2", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    deploy_target(ctx, user, {"name": "c", "cert": str(path)})
    assert "BEGIN CERTIFICATE" in path.read_text()


def test_owner_and_group(ctx, user, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(shutil, "chown", lambda path, user=None, group=None: calls.append((str(path), user, group)))
    deploy_target(ctx, user, {"name": "own", "cert": str(tmp_path / "c.pem"), "owner": "root", "group": "wheel"})
    assert calls == [(str(tmp_path / "c.pem"), "root", "wheel")]

    def refuse(*_a, **_k):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(shutil, "chown", refuse)
    with pytest.raises(PyCertError, match="owner/group"):
        deploy_target(ctx, user, {"name": "own", "cert": str(tmp_path / "d.pem"), "group": "wheel"})


def test_deploy_needs_a_certificate_and_matching_key(ctx, user, tmp_path, monkeypatch):
    pending = ctx.store.new_state(alias="not issued", type="user", cn="not issued", email="x@example.org")
    with pytest.raises(PyCertError, match="no certificate to deploy"):
        deploy_target(ctx, pending, {"name": "x", "cert": str(tmp_path / "c.pem")})
    monkeypatch.setattr(deploy_module.certs, "certificate_matches_key", lambda *_a: False)
    with pytest.raises(PyCertError, match="does not match"):
        deploy_target(ctx, user, {"name": "x", "cert": str(tmp_path / "c.pem")})
    assert not (tmp_path / "c.pem").exists()


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------


def test_hooks_run_after_files_and_report_failures(ctx, user, tmp_path):
    marker = tmp_path / "ran"
    ok_hook = _hook(tmp_path, f"import pathlib\npathlib.Path({str(marker)!r}).write_text('reloaded')\nprint('done')\n")
    result = deploy_target(ctx, user, {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": ok_hook})
    assert marker.read_text() == "reloaded" and result.hook_output == "done"
    skipped = deploy_target(ctx, user, {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": ok_hook}, run_hook=False)
    assert skipped.hook == ""
    bad = _hook(tmp_path, "import sys\nprint('config test failed', file=sys.stderr)\nsys.exit(2)\n", "bad.py")
    with pytest.raises(PyCertError, match=r"exit 2.*\n.*config test failed"):
        deploy_target(ctx, user, {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": bad})
    with pytest.raises(PyCertError, match="deploy hook not found"):
        deploy_target(ctx, user, {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": "/nonexistent/reload"})


def test_hook_timeout(ctx, user, tmp_path, monkeypatch):
    def slow(*_args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="reload", timeout=kwargs["timeout"])

    monkeypatch.setattr(deploy_module.subprocess, "run", slow)
    monkeypatch.setattr(deploy_module, "command_problem", lambda program: "")  # "reload" is not a real program
    with pytest.raises(PyCertError, match="timed out after 5s"):
        deploy_target(ctx, user, {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": "reload", "hook_timeout": 5})


# ---------------------------------------------------------------------------
# Targets stored with the request
# ---------------------------------------------------------------------------


def test_add_remove_and_deploy_state(ctx, user, tmp_path):
    with pytest.raises(PyCertError, match="no deployment targets"):
        deploy_state(ctx, user)
    first = add_target(ctx, user, {"name": "one", "cert": str(tmp_path / "one.pem")})
    add_target(ctx, user, {"name": "two", "cert": str(tmp_path / "two.pem")})
    assert first["cert_mode"] == "0644"
    with pytest.raises(PyCertError, match="already has a deployment target called 'one'"):
        add_target(ctx, user, {"name": "one", "cert": str(tmp_path / "x.pem")})
    with pytest.raises(PyCertError, match=r"no deployment target\(s\) three"):
        deploy_state(ctx, user, names=["three"])
    results = deploy_state(ctx, user, names=["two"])
    assert [r.target for r in results] == ["two"]
    assert (tmp_path / "two.pem").is_file() and not (tmp_path / "one.pem").exists()
    saved = ctx.store.get(user.alias)
    two = next(t for t in saved.deploy if t["name"] == "two")
    assert two["last_sha256"] == saved.cert.sha256 and two["last_deployed"]
    remove_target(ctx, saved, "one")
    assert [t["name"] for t in ctx.store.get(user.alias).deploy] == ["two"]
    with pytest.raises(PyCertError, match="no deployment target called 'one'"):
        remove_target(ctx, saved, "one")


def test_failed_target_is_recorded_and_cleared_on_success(ctx, user, tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("a file where a directory should be")
    add_target(ctx, user, {"name": "bad", "cert": str(blocked / "cert.pem")})
    add_target(ctx, user, {"name": "good", "cert": str(tmp_path / "good.pem")})
    with pytest.raises(PyCertError, match="bad: "):
        deploy_state(ctx, user)
    saved = ctx.store.get(user.alias)
    assert next(t for t in saved.deploy if t["name"] == "bad")["last_error"]
    assert "last_error" not in next(t for t in saved.deploy if t["name"] == "good")
    assert (tmp_path / "good.pem").is_file()  # other targets are still deployed
    blocked.unlink()
    deploy_state(ctx, saved, names=["bad"])
    assert "last_error" not in next(t for t in ctx.store.get(user.alias).deploy if t["name"] == "bad")


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------


def test_drift_detection(ctx, user, tmp_path, issued):
    assert check_drift(ctx, user) == []
    target = add_target(
        ctx,
        user,
        {"name": "web", "cert": str(tmp_path / "c.pem"), "fullchain": str(tmp_path / "f.pem"), "key": str(tmp_path / "k.pem"), "bundle": str(tmp_path / "b.pem")},
    )
    problems = {(item.path, item.problem) for item in check_drift(ctx, user)}
    assert {(target[kind], "missing") for kind in ("cert", "fullchain", "key", "bundle")} == problems
    deploy_state(ctx, user)
    user = ctx.store.get(user.alias)
    assert check_drift(ctx, user) == []
    other = issued("someone else")
    (tmp_path / "c.pem").write_text(certs.cert_pem(ctx.store.load_certificate(other)))
    (tmp_path / "f.pem").write_text("garbage")
    os.chmod(tmp_path / "k.pem", 0o644)
    user.deploy[0]["last_error"] = "hook failed"
    problems = {(item.path, item.problem.split(" (")[0].split(":")[0]) for item in check_drift(ctx, user)}
    assert (str(tmp_path / "c.pem"), "out of date") in problems
    assert (str(tmp_path / "f.pem"), "unreadable") in problems
    assert any(path == str(tmp_path / "k.pem") and "mode" in problem for path, problem in problems)
    assert ("", "last deployment failed") in problems


# ---------------------------------------------------------------------------
# Automatic deployment after issuance
# ---------------------------------------------------------------------------


def test_download_deploys_automatically_and_survives_failures(ctx, user, tmp_path):
    add_target(ctx, user, {"name": "auto", "cert": str(tmp_path / "auto.pem")})
    user = ctx.store.get(user.alias)
    certificate = ctx.store.load_certificate(user)
    messages = []
    state = workflow.download_and_export(ctx, user, certificate=certificate, progress=messages.append)
    assert (tmp_path / "auto.pem").is_file()
    assert not any("deployment failed" in note for note in state.notes)

    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")
    add_target(ctx, state, {"name": "broken", "cert": str(blocked / "x.pem")})
    state = ctx.store.get(state.alias)
    state = workflow.download_and_export(ctx, state, certificate=certificate, progress=messages.append)
    assert state.cert.sha256 and state.p12_path  # the certificate itself is safe
    assert any("deployment failed" in note for note in ctx.store.get(state.alias).notes)
    assert any(message.startswith("warning: deployment failed") for message in messages)
    no_deploy = workflow.download_and_export(ctx, state, certificate=certificate, deploy=False)
    assert no_deploy.cert.sha256


def test_unrunnable_hook_and_unwritable_p12(ctx, user, tmp_path):
    script = tmp_path / "reload.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o644)  # not executable
    with pytest.raises(PyCertError, match="could not be run"):
        deploy_target(ctx, user, {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": str(script)})
    blocked = tmp_path / "blocked"
    blocked.write_text("a file where a directory should be")
    with pytest.raises(PyCertError, match="cannot write"):
        deploy_target(ctx, user, {"name": "p", "p12": str(blocked / "copy.p12")})


def test_atomic_write_never_changes_an_existing_directory(tmp_path):
    from pycert.util import atomic_write

    shared = tmp_path / "webroot"
    shared.mkdir()
    os.chmod(shared, 0o755)
    atomic_write(shared / "token", "value", mode=0o644)
    assert _mode(shared) == 0o755 and _mode(shared / "token") == 0o644
    atomic_write(tmp_path / "new" / "dir" / "secret", "value")
    assert _mode(tmp_path / "new" / "dir") == 0o700 and _mode(tmp_path / "new" / "dir" / "secret") == 0o600


def test_bulk_presets_get_one_directory_per_certificate(tmp_path):
    grid = target_from_preset("grid-host", directory=str(tmp_path), alias="web1.example.org", per_certificate_dir=True)
    assert grid["cert"] == f"{tmp_path}/web1.example.org/hostcert.pem"
    assert grid["key"] == f"{tmp_path}/web1.example.org/hostkey.pem"
    # presets that already name files after the certificate keep their layout
    nginx = target_from_preset("nginx", directory=str(tmp_path), alias="web1.example.org", per_certificate_dir=True)
    assert nginx["fullchain"] == f"{tmp_path}/web1.example.org.fullchain.pem"
