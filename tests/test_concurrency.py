"""Concurrency tests for shared components."""

import threading

from pycert.config import SecretConfig
from pycert.secrets_store import SecretStore
from pycert.store import Store


def test_store_writes_from_many_threads(tmp_path):
    store = Store(tmp_path / "data")
    errors = []

    def worker(index):
        try:
            state = store.new_state(alias="worker-%d" % index, type="user", cn="w%d" % index, email="x@y.z")
            state.set_status("SUBMITTED")
            store.save(state)
            loaded = store.get(state.alias)
            assert loaded.alias == state.alias
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert not errors
    assert len(store.list()) == 15


def test_secret_ensure_from_many_threads(tmp_path):
    store = SecretStore(SecretConfig(backend="file"), tmp_path, "test")
    values = []
    errors = []

    def worker():
        try:
            values.append(store.ensure())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(15)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert not errors
    assert len(set(values)) == 1


def test_config_bundles_load_concurrently(tmp_path):
    from pycert.config import init_config, load_config

    config = init_config(tmp_path / "conf", copy_chain=True)
    loaded = load_config(config.path)
    results = []
    errors = []

    def worker():
        try:
            results.append(len(loaded.bundle.certificates))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not errors
    assert results == [4] * 10
