"""Randomised store operation sequences and state round-trips."""

import random
import stat

import pytest

from pycert.store import (
    STATUSES,
    CertInfo,
    RequestState,
    ServerInfo,
    Store,
)


@pytest.mark.parametrize("seed", range(60))
def test_random_store_operation_sequences(tmp_path, seed):
    rng = random.Random(seed)
    store = Store(tmp_path / ("data-%d" % seed))
    created = {}
    for step in range(30):
        operation = rng.choice(["create", "status", "save", "get", "pending", "archive", "adopt", "delete"])
        if operation == "create" or not created:
            alias = "alias-%d-%d" % (seed, step)
            state = store.new_state(alias=alias, type="user", cn=alias, email="x@y.z")
            created[state.alias] = state
        elif operation == "status":
            alias = rng.choice(sorted(created))
            created[alias].set_status(rng.choice(STATUSES))
            store.save(created[alias])
        elif operation == "save":
            alias = rng.choice(sorted(created))
            store.save(created[alias])
        elif operation == "get":
            alias = rng.choice(sorted(created))
            loaded = store.get(alias)
            assert loaded.alias == alias
        elif operation == "pending":
            pending = {item.alias for item in store.pending()}
            assert pending <= set(created)
        elif operation == "archive":
            alias = rng.choice(sorted(created))
            store.archive_current(created[alias])
        elif operation == "adopt":
            alias = rng.choice(sorted(created))
            store.adopt_pending(created[alias])
        elif operation == "delete":
            alias = rng.choice(sorted(created))
            store.delete(created[alias])
            del created[alias]
    assert {state.alias for state in store.list()} == set(created)
    for state in store.list():
        assert state.slug
        assert store.path(state).parent == store.requests_dir
        assert stat.S_IMODE(store.path(state).stat().st_mode) == 0o700
        assert stat.S_IMODE(store.file(state, "state.json").stat().st_mode) == 0o600
        loaded = store.get(state.alias)
        assert loaded.to_dict()["alias"] == state.alias


@pytest.mark.parametrize("seed", range(20))
def test_random_state_roundtrip(seed):
    rng = random.Random(seed)
    state = RequestState(
        alias="alias-%d" % seed,
        slug="alias-%d" % seed,
        type=rng.choice(["user", "host"]),
        cn="cn-%d" % seed,
        email="x@y.z",
        subject="CN=x",
        key_algorithm=rng.choice(["RSA 2048", "ECDSA P-256"]),
        key_bits=rng.choice([0, 2048, 256]),
        spki_b64="spki-%d" % seed,
        public_key_sha256=("%02x" % seed) * 32,
        csr_sha256=("%02x" % (seed + 1)) * 32,
        status=rng.choice(STATUSES),
        server=ServerInfo(csr_id=str(seed), cert_id=str(seed + 1), status="NEW"),
        cert=CertInfo(subject="s", issuer="i", serial="1", key="RSA 2048"),
        notes=["note-%d" % seed],
    )
    state.add_history(state.status, "detail")
    restored = RequestState.from_dict(state.to_dict())
    assert restored.to_dict() == state.to_dict()
