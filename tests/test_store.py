import stat

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pycert import certs
from pycert import csr as csr_module
from pycert.errors import CryptoError, NotFound, PyCertError
from pycert.store import Store
from pycert.util import atomic_write


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "data")


def _state(store, alias="jane doe"):
    return store.new_state(alias=alias, type="user", cn=alias, email="jane@example.org")


def test_new_state_and_slug_collision(store):
    a = _state(store, "Jane Doe")
    b = _state(store, "jane-doe")
    assert a.slug == "jane-doe"
    assert b.slug == "jane-doe-2"
    assert store.get("Jane Doe").alias == "Jane Doe"
    assert store.get("jane-doe").alias == "jane-doe"
    assert store.get("JANE DOE").alias == "Jane Doe"
    assert len(store.list()) == 2


def test_get_missing(store):
    with pytest.raises(NotFound):
        store.get("nope")


def test_state_roundtrip(store):
    state = _state(store)
    state.subject = "CN=jane doe"
    state.cert.sha256 = "ab" * 32
    state.cert.not_after = "2030-01-01T00:00:00+00:00"
    state.set_status("SUBMITTED", "test")
    store.save(state)
    loaded = store.get(state.alias)
    assert loaded.subject == "CN=jane doe"
    assert loaded.cert.sha256 == "ab" * 32
    assert loaded.days_remaining is not None
    assert loaded.history[-1]["status"] == "SUBMITTED"


def test_permissions(store):
    state = _state(store)
    key = rsa.generate_private_key(65537, 2048)
    store.save_key(state, key, "secret-passphrase")
    mode = stat.S_IMODE(store.file(state, "key.pem").stat().st_mode)
    assert mode == 0o600
    assert stat.S_IMODE(store.path(state).stat().st_mode) == 0o700
    loaded = store.load_key(state, "secret-passphrase")
    assert certs.key_description(loaded.public_key()) == "RSA 2048"
    with pytest.raises((CryptoError, ValueError)):
        store.load_key(state, "wrong")


def test_pending_flow(store):
    state = _state(store)
    key = rsa.generate_private_key(65537, 2048)
    store.save_pending_key(state, key, "pw")
    store.save_key(state, ec.generate_private_key(ec.SECP256R1()), "pw")
    state.pending_spki_b64 = "pending"
    state.renewal = True
    assert state.active_spki_b64 == "pending"
    store.adopt_pending(state)
    loaded_key = store.load_key(state, "pw")
    assert certs.public_keys_equal(loaded_key.public_key(), key.public_key())
    assert not store.file(state, "key.next.pem").exists()
    store.discard_pending(state)  # no-op when absent


def test_archive_current(store):
    state = _state(store)
    key = rsa.generate_private_key(65537, 2048)
    store.save_key(state, key, "pw")
    atomic_write(store.file(state, "cert.pem"), b"cert")
    target = store.archive_current(state)
    assert (target / "key.pem").exists()
    assert (target / "cert.pem").exists()
    assert not store.file(state, "key.pem").exists()


def test_csr_helpers(store):
    state = _state(store)
    key = rsa.generate_private_key(65537, 2048)
    subject = certs.build_subject(
        common_name="jane doe",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    request = csr_module.build_csr(key, subject, email="jane@example.org")
    store.save_csr(state, request)
    loaded = store.load_csr(state)
    assert csr_module.signature_valid(loaded)


def test_audit_reports_loose_permissions(store):
    _state(store)
    assert store.audit() == []
    path = store.file(store.list()[0], "state.json")
    path.chmod(0o644)
    assert any("state.json" in problem for problem in store.audit())


def test_delete(store):
    state = _state(store)
    store.delete(state)
    assert store.list() == []
    with pytest.raises(NotFound):
        store.get(state.alias)


def test_unknown_status_rejected(store):
    state = _state(store)
    with pytest.raises(PyCertError):
        state.set_status("BANANA")
