"""Second-round secret-store tests: concurrency, symlinks, timeouts."""

import stat
import sys
import threading

import pytest

from pycert.config import SecretConfig
from pycert.errors import SecretError
from pycert.secrets_store import SecretStore, generate_secret


def file_store(tmp_path, **kwargs):
    return SecretStore(SecretConfig(backend="file", **kwargs), tmp_path, "test")


def test_ensure_is_concurrent_safe(tmp_path):
    store = file_store(tmp_path)
    values = []
    lock = threading.Lock()

    def worker():
        value = store.ensure()
        with lock:
            values.append(value)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert len(values) == 20
    assert len(set(values)) == 1
    assert store.get() == values[0]


def test_concurrent_set_and_get(tmp_path):
    store = file_store(tmp_path)
    threads = []
    for index in range(10):
        thread = threading.Thread(target=store.set, args=("value-%d" % index, "account-%d" % index))
        threads.append(thread)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    for index in range(10):
        assert store.get("account-%d" % index) == "value-%d" % index


def test_secret_file_symlink_is_refused(tmp_path):
    store = file_store(tmp_path)
    target = tmp_path / "target.json"
    target.write_text("{}")
    store.path.symlink_to(target)
    with pytest.raises(SecretError, match="symlink"):
        store.get()
    with pytest.raises(SecretError, match="symlink"):
        store.set("value")


def test_secret_lock_symlink_is_refused(tmp_path):
    store = file_store(tmp_path)
    target = tmp_path / "target"
    target.write_text("")
    lock_path = store.path.with_name(store.path.name + ".lock")
    lock_path.symlink_to(target)
    with pytest.raises(SecretError, match="lock"):
        store.set("value")


def test_command_timeout(tmp_path):
    store = SecretStore(
        SecretConfig(
            backend="command",
            command="%s -c 'import time; time.sleep(2)'" % sys.executable,
            command_timeout=0.1,
        ),
        tmp_path,
        "test",
    )
    with pytest.raises(SecretError, match="timed out"):
        store.get()


def test_command_backend_roundtrip(tmp_path):
    storage = tmp_path / "store.txt"
    script = tmp_path / "secret.py"
    script.write_text(
        "import pathlib, sys\n"
        "p = pathlib.Path(sys.argv[1])\n"
        "data = sys.stdin.read()\n"
        "p.write_text(data) if data else print(p.read_text().strip())\n"
    )
    store = SecretStore(
        SecretConfig(
            backend="command",
            command="%s %s %s" % (sys.executable, script, storage),
            command_timeout=5,
        ),
        tmp_path,
        "test",
    )
    store.set("from-command")
    assert store.get() == "from-command"


def test_env_backend_is_read_only(tmp_path, monkeypatch):
    monkeypatch.setenv("PYCERT_TEST_SECRET", "env-secret")
    store = SecretStore(SecretConfig(backend="env", env_var="PYCERT_TEST_SECRET"), tmp_path, "test")
    assert store.get() == "env-secret"
    with pytest.raises(SecretError):
        store.set("x")
    with pytest.raises(SecretError):
        store.delete()


def test_prompt_backend_is_read_only(tmp_path, monkeypatch):
    store = SecretStore(SecretConfig(backend="prompt"), tmp_path, "test")
    with pytest.raises(SecretError):
        store.set("x")
    with pytest.raises(SecretError):
        store.ensure()


def test_generated_secret_characters():
    value = generate_secret(32)
    assert len(value) >= 40
    assert all(character.isalnum() or character in "-_" for character in value)


def test_file_permissions(tmp_path):
    store = file_store(tmp_path)
    store.set("value")
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_missing_account_message(tmp_path):
    store = file_store(tmp_path)
    with pytest.raises(SecretError, match="no saved secret"):
        store.get("missing")
    assert store.get("missing", allow_missing=True) is None


def test_empty_secret_is_refused(tmp_path):
    store = file_store(tmp_path)
    with pytest.raises(SecretError):
        store.set("")


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS keychain")
def test_keychain_roundtrip(tmp_path):
    store = SecretStore(SecretConfig(backend="keychain", service="pyCertWiz-pytest-deep"), tmp_path, "test")
    value = generate_secret()
    store.set(value, "probe")
    assert store.get("probe") == value
    store.delete("probe")
