"""Additional randomised state and TOML sequences."""

import random
import stat

import pytest

from pycert.store import STATUSES, Store


@pytest.mark.parametrize("seed", range(100))
def test_random_store_sequences_round3(tmp_path, seed):
    rng = random.Random(seed + 7000)
    store = Store(tmp_path / ("store-%d" % seed))
    states = {}
    for step in range(15):
        operation = rng.choice(["create", "status", "save", "get", "pending", "delete"])
        if operation == "create" or not states:
            alias = "alias-%d-%d" % (seed, step)
            state = store.new_state(alias=alias, type="user", cn=alias, email="x@y.z")
            states[alias] = state
        elif operation == "status":
            alias = rng.choice(sorted(states))
            states[alias].set_status(rng.choice(STATUSES))
            store.save(states[alias])
        elif operation == "save":
            alias = rng.choice(sorted(states))
            store.save(states[alias])
        elif operation == "get":
            alias = rng.choice(sorted(states))
            assert store.get(alias).alias == alias
        elif operation == "pending":
            assert {item.alias for item in store.pending()} <= set(states)
        else:
            alias = rng.choice(sorted(states))
            store.delete(states[alias])
            del states[alias]
    assert {item.alias for item in store.list()} == set(states)
    for item in store.list():
        assert stat.S_IMODE(store.path(item).stat().st_mode) == 0o700
        assert stat.S_IMODE(store.file(item, "state.json").stat().st_mode) == 0o600
