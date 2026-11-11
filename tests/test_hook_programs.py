"""Hooks whose program is missing or not executable fail with a clear message.

The program is checked before it is run, because under emulation (x86_64
containers on Apple silicon) the exec error can be lost, leaving only
"exit 127". The handlers for a program that vanishes between the check and
the run stay in place.
"""

import os
import sys

import pytest

from pycert import util
from pycert.deploy import deploy_target
from pycert.errors import PyCertError


def test_command_problem(tmp_path):
    script = tmp_path / "hook.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    assert util.command_problem(str(tmp_path / "missing")) == "not found"
    script.chmod(0o644)
    assert util.command_problem(str(script)) == "not executable"
    assert util.command_problem(str(tmp_path)) == "not executable"  # a directory
    script.chmod(0o755)
    assert util.command_problem(str(script)) == ""
    assert util.command_problem(os.path.basename(sys.executable)) in ("", "not found on PATH")
    assert util.command_problem("sh") == ""
    assert util.command_problem("pycert-no-such-program") == "not found on PATH"


@pytest.fixture
def user(issued):
    return issued("hook person")


def _target(tmp_path, hook):
    return {"name": "h", "cert": str(tmp_path / "c.pem"), "hook": hook}


def test_deploy_hook_checks_the_program_first(ctx, user, tmp_path):
    with pytest.raises(PyCertError, match="deploy hook not found: pycert-no-such-program"):
        deploy_target(ctx, user, _target(tmp_path, "pycert-no-such-program --reload"))
    with pytest.raises(PyCertError, match="deploy hook not found: /nonexistent/reload"):
        deploy_target(ctx, user, _target(tmp_path, "/nonexistent/reload"))
    script = tmp_path / "reload.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o644)
    with pytest.raises(PyCertError, match=r"could not be run \(not executable\)"):
        deploy_target(ctx, user, _target(tmp_path, str(script)))


def _raise(exc):
    def run(*_args, **_kwargs):
        raise exc

    return run


def test_deploy_hook_that_vanishes_after_the_check(ctx, user, tmp_path, monkeypatch):
    import pycert.deploy as deploy_module

    # The program passes the check, then is gone (or loses its permissions) when it is run.
    monkeypatch.setattr(deploy_module, "command_problem", lambda program: "")
    monkeypatch.setattr(deploy_module.subprocess, "run", _raise(FileNotFoundError(2, "No such file", "gone")))
    with pytest.raises(PyCertError, match="deploy hook not found"):
        deploy_target(ctx, user, _target(tmp_path, str(tmp_path / "gone")))
    monkeypatch.setattr(deploy_module.subprocess, "run", _raise(PermissionError(13, "Permission denied")))
    with pytest.raises(PyCertError, match="could not be run"):
        deploy_target(ctx, user, _target(tmp_path, str(tmp_path / "locked.sh")))


def test_dns_hook_checks_the_program_first(monkeypatch):
    from types import SimpleNamespace

    import pycert.providers.acme as acme_module

    challenges = acme_module._Challenges.__new__(acme_module._Challenges)
    challenges.acme = SimpleNamespace(dns_hook="/nonexistent/pycert-dns-hook")
    with pytest.raises(PyCertError, match=r"could not be run \(not found: /nonexistent/pycert-dns-hook\)"):
        challenges._run_hook("add", "a.example.org", "_acme-challenge.a.example.org", "x")
    # ...and if it vanishes after the check, the error from running it is still clear
    monkeypatch.setattr(acme_module, "command_problem", lambda program: "")
    monkeypatch.setattr(acme_module.subprocess, "run", _raise(FileNotFoundError(2, "No such file")))
    with pytest.raises(PyCertError, match=r"could not be run \("):
        challenges._run_hook("add", "a.example.org", "_acme-challenge.a.example.org", "x")
