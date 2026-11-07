"""Second-round store hardening tests."""

import os
import threading

import pytest

from pycert.errors import NotFound, PyCertError
from pycert.store import MAX_STATE_BYTES, Store
from pycert.util import read_private_file


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "data")


def make(store, alias="x"):
    return store.new_state(alias=alias, type="user", cn=alias, email="x@y.z")


def test_oversize_state_is_reported(store):
    state = make(store)
    path = store.file(state, "state.json")
    with open(path, "wb") as handle:
        handle.write(b"{" + b" " * (MAX_STATE_BYTES + 1) + b"}")
    with pytest.raises(PyCertError, match="larger"):
        store.get(state.alias)
    assert store.list() == []
    assert store.corrupt_files()


def test_corrupt_files_listing(store):
    state = make(store)
    store.file(state, "state.json").write_text("{bad")
    problems = store.corrupt_files()
    assert len(problems) == 1
    assert "corrupt" in problems[0][1]


def test_key_symlink_is_refused(store, tmp_path):
    state = make(store)
    target = tmp_path / "target-key"
    target.write_bytes(b"junk")
    store.file(state, "key.pem").symlink_to(target)
    with pytest.raises(PyCertError, match="symlink"):
        store.load_key(state, "pw")


def test_lock_symlink_is_refused(store, tmp_path):
    state = make(store)
    target = tmp_path / "target-lock"
    target.write_text("")
    lock_path = store.file(state, ".lock")
    if lock_path.exists():
        lock_path.unlink()
    lock_path.symlink_to(target)
    with pytest.raises(PyCertError, match="lock"), store.lock(state):
        pass


def test_audit_reports_symlinks(store, tmp_path):
    state = make(store)
    target = tmp_path / "target"
    target.write_text("x")
    store.file(state, "extra.pem").symlink_to(target)
    problems = store.audit()
    assert any("symlink" in problem for problem in problems)


def test_read_private_file_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(PyCertError, match="symlink"):
        read_private_file(link)


def test_concurrent_locks_serialise(store, tmp_path):
    state = make(store)
    counter = tmp_path / "counter"
    counter.write_text("0")

    def worker():
        for _ in range(20):
            with store.lock(state):
                value = int(counter.read_text())
                counter.write_text(str(value + 1))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert int(counter.read_text()) == 100


def test_atomic_state_write_is_private(store):
    state = make(store)
    assert os.stat(store.file(state, "state.json")).st_mode & 0o077 == 0


def test_delete_missing_slug(store):
    with pytest.raises(NotFound):
        store.get_by_slug("missing")
