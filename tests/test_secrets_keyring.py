"""The optional OS-keyring secret backend (python 'keyring' library)."""

import sys
import types

import pytest

from pycert.config import SecretConfig
from pycert.errors import SecretError
from pycert.secrets_store import BACKENDS, SecretStore


class _KeyringError(Exception):
    pass


class _PasswordDeleteError(_KeyringError):
    pass


@pytest.fixture
def fake_keyring(monkeypatch):
    errors = types.ModuleType("keyring.errors")
    errors.KeyringError = _KeyringError
    errors.PasswordDeleteError = _PasswordDeleteError
    module = types.ModuleType("keyring")
    module.errors = errors
    module.vault = {}
    module.fail = None

    def check():
        if module.fail is not None:
            raise module.fail

    def get_password(service, account):
        check()
        return module.vault.get((service, account))

    def set_password(service, account, value):
        check()
        module.vault[(service, account)] = value

    def delete_password(service, account):
        check()
        if (service, account) not in module.vault:
            raise _PasswordDeleteError("not found")
        del module.vault[(service, account)]

    module.get_password = get_password
    module.set_password = set_password
    module.delete_password = delete_password
    monkeypatch.setitem(sys.modules, "keyring", module)
    monkeypatch.setitem(sys.modules, "keyring.errors", errors)
    return module


def _store(tmp_path, profile="default"):
    return SecretStore(SecretConfig(backend="keyring"), tmp_path, profile)


def test_keyring_round_trip(fake_keyring, tmp_path):
    assert "keyring" in BACKENDS
    store = _store(tmp_path)
    assert store.backend == "keyring"
    assert store.get(allow_missing=True) is None
    generated = store.ensure()
    assert fake_keyring.vault[("pyCert:default", "default")] == generated
    assert store.ensure() == generated  # never regenerated once stored
    store.set("explicit", "acme-eab:le")
    assert store.get("acme-eab:le") == "explicit"
    assert store.delete("acme-eab:le") is True
    assert store.delete("acme-eab:le") is False
    assert not store.exists("acme-eab:le")
    assert not (tmp_path / "secrets.json").exists()  # nothing falls back to a file


def test_locked_keyring_is_an_error_not_a_missing_secret(fake_keyring, tmp_path):
    store = _store(tmp_path)
    store.set("keep me")
    fake_keyring.fail = _KeyringError("the keyring is locked")
    with pytest.raises(SecretError, match="could not read the secret from the OS keyring"):
        store.ensure()  # must not overwrite the saved secret
    with pytest.raises(SecretError, match="could not store"):
        store.set("other")
    with pytest.raises(SecretError, match="could not delete"):
        store.delete()
    fake_keyring.fail = None
    assert store.get() == "keep me"


def test_keyring_package_missing(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(SecretError, match=r"pip install 'pyCertWiz\[keyring\]'"):
        _store(tmp_path)


def test_unreadable_keychain_is_never_overwritten(monkeypatch, tmp_path):
    """Regression: ensure() used to treat a read error as 'missing' and generate a new secret."""
    from types import SimpleNamespace

    from pycert import secrets_store

    monkeypatch.setattr(secrets_store.shutil, "which", lambda _name: "/usr/bin/security")
    store = SecretStore(SecretConfig(backend="keychain"), tmp_path, "default")
    calls = []

    def fake(args, **kwargs):
        calls.append(args)
        if "find-generic-password" in args:
            return SimpleNamespace(returncode=51, stdout="", stderr="User interaction is not allowed.")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(store, "_subprocess", fake)
    with pytest.raises(SecretError, match="keychain unlocked"):
        store.ensure()
    assert all("find-generic-password" in args for args in calls)  # nothing was written
    assert store.get(allow_missing=True) is None  # explicit 'maybe missing' reads still tolerate errors
