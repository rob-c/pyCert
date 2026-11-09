"""Coverage-oriented tests for secret backends and diagnostics error paths."""

from types import SimpleNamespace

import pytest

from pycert import secrets_store
from pycert.config import SecretConfig
from pycert.errors import SecretError


def _python(value):
    return SimpleNamespace(returncode=0, stdout=value, stderr="")


def _store(tmp_path, **kwargs):
    cfg = SecretConfig(backend="file", file=str(tmp_path / "secrets.json"))
    for key, value in kwargs.items():
        setattr(cfg, key, value)
    return secrets_store.SecretStore(cfg, tmp_path)


def test_backend_resolution_and_availability(tmp_path, monkeypatch):
    cfg = SecretConfig(backend="auto")
    monkeypatch.setattr(secrets_store.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(secrets_store.shutil, "which", lambda name: "/bin/" + name)
    assert secrets_store.SecretStore(cfg, tmp_path).backend == "keychain"
    monkeypatch.setattr(secrets_store.platform, "system", lambda: "Linux")
    assert secrets_store.SecretStore(cfg, tmp_path).backend == "secret-service"
    monkeypatch.setattr(secrets_store.shutil, "which", lambda name: None)
    assert secrets_store.SecretStore(cfg, tmp_path).backend == "file"
    for backend in ("keychain", "secret-service"):
        cfg.backend = backend
        with pytest.raises(SecretError):
            secrets_store.SecretStore(cfg, tmp_path)
    cfg.backend = "command"
    with pytest.raises(SecretError):
        secrets_store.SecretStore(cfg, tmp_path)


def test_descriptions_and_paths(tmp_path):
    for backend, text in (("file", "file "), ("command", "command "), ("env", "environment"), ("prompt", "prompt")):
        store = _store(tmp_path, backend=backend, command="cmd", env_var="ENV")
        assert text in store.description()
    store = _store(tmp_path, backend="file", file="")
    assert store.path == tmp_path / "secrets.json"
    store = _store(tmp_path, backend="file", file=str(tmp_path / "x.json"))
    assert store.path.name == "x.json"


def test_file_backend_errors_and_locking(tmp_path, monkeypatch, capsys):
    store = _store(tmp_path)
    assert store.get("missing", allow_missing=True) is None
    with pytest.raises(SecretError):
        store.get("missing")
    with pytest.raises(SecretError):
        store.set("")
    file_path = store.path
    file_path.symlink_to(tmp_path / "missing")
    with pytest.raises(SecretError):
        store.get("x")
    file_path.unlink()
    file_path.write_text("{")
    with pytest.raises(SecretError):
        store.get("x")
    file_path.unlink()
    store.set("value", "x")
    file_path.chmod(0o644)
    assert store.get("x") == "value"
    assert "warning" in capsys.readouterr().err
    # Force the lock path to fail through the imported fcntl module.
    import fcntl

    monkeypatch.setattr(fcntl, "flock", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lock")))
    with pytest.raises(RuntimeError), store._file_lock():
        pass


def test_keychain_and_secret_service_and_command_backends(tmp_path, monkeypatch):
    store = _store(tmp_path, backend="keychain")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: SimpleNamespace(returncode=44, stdout="", stderr=""))
    assert store._get("x") is None
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: _python("value\n"))
    assert store._get("x") == "value"
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="locked"))
    with pytest.raises(SecretError):
        store._get("x")
    with pytest.raises(SecretError):
        store._set("bad value", "x")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="bad"))
    with pytest.raises(SecretError):
        store._set("value", "x")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: _python(""))
    store._set("value", "x")
    assert store._delete("x") is True

    monkeypatch.setattr(secrets_store.shutil, "which", lambda name: "/bin/" + name)
    store = _store(tmp_path, backend="secret-service")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="bad"))
    assert store._get("x") is None
    with pytest.raises(SecretError):
        store._set("value", "x")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: _python("value\n"))
    assert store._get("x") == "value"
    assert store._delete("x") is True

    store = _store(tmp_path, backend="command", command="cmd")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="bad"))
    assert store._get("x") is None
    with pytest.raises(SecretError):
        store._set("value", "x")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: _python("value\n"))
    assert store._get("x") == "value"
    with pytest.raises(SecretError):
        store._delete("x")


def test_env_prompt_and_unknown_backends(tmp_path, monkeypatch):
    store = _store(tmp_path, backend="env", env_var="PYCERT_TEST_SECRET")
    monkeypatch.setenv("PYCERT_TEST_SECRET", "value")
    assert store._get("x") == "value"
    with pytest.raises(SecretError):
        store._set("value", "x")
    with pytest.raises(SecretError):
        store._delete("x")
    store = _store(tmp_path, backend="prompt")
    monkeypatch.setattr(secrets_store.getpass, "getpass", lambda _prompt: "value")
    assert store._get("x") == "value"
    with pytest.raises(SecretError):
        store.ensure("x")
    store.backend = "unknown"
    with pytest.raises(SecretError):
        store._get("x")
    with pytest.raises(SecretError):
        store._set("value", "x")
    with pytest.raises(SecretError):
        store._delete("x")


def test_secret_ensure_and_quote(tmp_path):
    store = _store(tmp_path)
    value = store.ensure("x", length=8)
    assert store.get("x") == value
    assert secrets_store._quote("safe") == '"safe"'
    with pytest.raises(SecretError):
        secrets_store._quote("bad value")


def test_secret_lock_nonfile_and_write_error(tmp_path, monkeypatch):
    store = _store(tmp_path, backend="command", command="cmd")
    with store._file_lock():
        pass
    store = _store(tmp_path)
    monkeypatch.setattr(secrets_store, "atomic_write", lambda *a, **k: (_ for _ in ()).throw(OSError("write")))
    with pytest.raises(SecretError):
        store._write_file({"x": "y"})


def test_secret_env_ensure_and_secret_service_success(tmp_path, monkeypatch):
    store = _store(tmp_path, backend="env", env_var="MISSING_SECRET")
    monkeypatch.delenv("MISSING_SECRET", raising=False)
    with pytest.raises(SecretError):
        store.ensure("x")
    monkeypatch.setattr(secrets_store.shutil, "which", lambda name: "/bin/" + name)
    store = _store(tmp_path, backend="secret-service")
    monkeypatch.setattr(store, "_subprocess", lambda *a, **k: _python(""))
    store._set("value", "x")
