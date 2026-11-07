"""Concurrency round three: CLI-equivalent workflows against the listener."""

import threading

import pytest

from pycert.workflow import RequestSpec, create_request, poll_once


def _spec(config, cn, pin="1234567890AB"):
    return RequestSpec.build(config, cn, email="test@example.org", pin=pin, key_algorithm="ec")


def test_concurrent_requests_against_listener(ctx, config, ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    results = []
    errors = []

    def worker(index):
        try:
            results.append(
                create_request(ctx, _spec(config, "concurrent user %d" % index), progress=lambda _m: None)
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert not errors
    assert len(results) == 8
    assert len(ctx.store.list()) == 8


def test_concurrent_polling_against_listener(ctx, config, ca):
    ca.auto_approve = False
    states = [
        create_request(ctx, _spec(config, "poll concurrent %d" % i), progress=lambda _m: None)
        for i in range(5)
    ]
    outputs = []
    errors = []

    def worker(state):
        try:
            outputs.append(poll_once(ctx, state))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(state,)) for state in states]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert not errors
    assert len(outputs) == 5


def test_concurrent_secret_ensure_round3(tmp_path):
    from pycert.config import SecretConfig
    from pycert.secrets_store import SecretStore

    store = SecretStore(SecretConfig(backend="file"), tmp_path, "round3")
    values = []
    errors = []

    def worker():
        try:
            values.append(store.ensure())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert not errors and len(set(values)) == 1


@pytest.mark.parametrize("seed", range(5))
def test_concurrent_store_round3(tmp_path, seed):
    from pycert.store import Store

    store = Store(tmp_path / ("store-%d" % seed))
    errors = []

    def worker(index):
        try:
            state = store.new_state(alias="c-%d-%d" % (seed, index), type="user", cn="c", email="x@y.z")
            store.save(state)
            assert store.get(state.alias).alias == state.alias
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert not errors
