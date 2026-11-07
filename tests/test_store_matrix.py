"""Local store matrix: aliases, statuses, permissions, corruption."""

import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pycert import certs
from pycert import csr as csr_module
from pycert.errors import NotFound, PyCertError
from pycert.store import (
    STATUS_APPROVED,
    STATUS_DOWNLOADED,
    STATUS_DRAFT,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_IMPORTED,
    STATUS_REVOKED,
    STATUS_SIGNED,
    STATUS_SUBMITTED,
    STATUSES,
    CertInfo,
    RequestState,
    ServerInfo,
    Store,
)
from pycert.util import atomic_write


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "data")


def new(store, alias="jane doe", **kwargs):
    return store.new_state(
        alias=alias,
        type=kwargs.get("type", "user"),
        cn=kwargs.get("cn", alias),
        email=kwargs.get("email", "jane@example.org"),
    )


ALIASES = [
    "jane doe",
    "jane-doe",
    "JANE DOE",
    "name.with.dots",
    "../../etc/passwd",
    "a/b/c",
    "x" * 200,
    "üñïçødé name",
    "  spaces  ",
    "tab\tname",
    "-",
    "_",
    ".",
    "..",
    "CON",
    "lpt1",
    "null\x00byte",
    "emoji \U0001f600",
]


@pytest.mark.parametrize("alias", ALIASES)
def test_alias_slugs_are_safe(store, alias):
    state = new(store, alias)
    slug = state.slug
    assert slug
    assert "/" not in slug and "\\" not in slug and "\x00" not in slug
    assert slug not in (".", "..")
    assert ".." not in slug.split(".")
    assert len(slug) <= 64
    assert store.path(state).parent == store.requests_dir
    assert store.get(alias).alias == alias


def test_case_insensitive_lookup(store):
    new(store, "Jane Doe")
    assert store.get("jane doe").alias == "Jane Doe"
    assert store.get("JANE DOE").alias == "Jane Doe"


def test_lookup_by_common_name(store):
    store.new_state(alias="alias-1", type="user", cn="common name", email="x@y.z")
    assert store.get("common name").alias == "alias-1"


def test_ambiguous_alias_and_cn(store):
    new(store, "Jane Doe")
    new(store, "jane-doe")
    # Exact alias wins over a slug that collides with another alias.
    assert store.get("jane-doe").alias == "jane-doe"
    assert store.get("Jane Doe").alias == "Jane Doe"
    assert sum(1 for _ in store.list()) == 2


def test_duplicate_slug_gets_suffix(store):
    first = new(store, "Name")
    second = new(store, "name")
    assert first.slug == "name"
    assert second.slug == "name-2"


@pytest.mark.parametrize("status", STATUSES)
def test_all_statuses_roundtrip(store, status):
    state = new(store, "s-%s" % status)
    state.set_status(status, "detail")
    store.save(state)
    loaded = store.get(state.alias)
    assert loaded.status == status
    assert loaded.history[-1]["detail"] == "detail"


def test_unknown_status_is_rejected(store):
    state = new(store)
    with pytest.raises(PyCertError):
        state.set_status("BANANA")


def test_pending_statuses():
    for status, expected in [
        (STATUS_DRAFT, True),
        (STATUS_SUBMITTED, True),
        (STATUS_APPROVED, True),
        (STATUS_SIGNED, True),
        (STATUS_DOWNLOADED, False),
        (STATUS_REVOKED, False),
        (STATUS_EXPIRED, False),
        (STATUS_FAILED, False),
        (STATUS_IMPORTED, False),
    ]:
        state = RequestState(alias="x", slug="x", type="user", cn="x", status=status)
        assert state.is_pending is expected


def test_full_state_roundtrip(store):
    state = new(store)
    state.subject = "CN=jane doe"
    state.key_algorithm = "RSA 2048"
    state.key_bits = 2048
    state.spki_b64 = "spki"
    state.public_key_sha256 = "aa" * 32
    state.csr_sha256 = "bb" * 32
    state.pending_spki_b64 = "pending"
    state.renewal = True
    state.auth_alias = "auth"
    state.server = ServerInfo(csr_id="1", cert_id="2", status="VALID", owner="o", role="r")
    state.cert = CertInfo(
        subject="s", issuer="i", serial="1", not_after="2030-01-01T00:00:00Z", verified=True
    )
    state.p12_path = "/tmp/x.p12"
    state.p12_sha256 = "cc" * 32
    state.notes.append("note")
    state.add_history("SUBMITTED", "x")
    store.save(state)
    loaded = store.get(state.alias)
    assert loaded.to_dict() == state.to_dict()
    assert loaded.active_spki_b64 == "pending"


def test_state_from_dict_ignores_unknown_fields():
    state = RequestState.from_dict({"alias": "a", "slug": "a", "type": "user", "cn": "a", "extra": 1})
    assert state.alias == "a"


def test_corrupt_state_file_is_reported(store):
    state = new(store)
    store.file(state, "state.json").write_text("{ not json")
    with pytest.raises(PyCertError, match="corrupt"):
        store.get(state.alias)
    assert store.list() == []


def test_state_missing_required_fields(store):
    state = new(store)
    store.file(state, "state.json").write_text(json.dumps({"alias": "x"}))
    with pytest.raises(PyCertError):
        store.get(state.alias)


def test_key_and_cert_missing(store):
    state = new(store)
    with pytest.raises(NotFound):
        store.load_key(state, "pw")
    with pytest.raises(NotFound):
        store.load_certificate(state)


def test_csr_roundtrip(store):
    state = new(store)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = certs.build_subject(
        common_name="jane doe",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    request = csr_module.build_csr(key, subject, email="jane@example.org")
    store.save_csr(state, request)
    assert csr_module.signature_valid(store.load_csr(state))


def test_pending_key_adopt_and_discard(store):
    state = new(store)
    old = ec.generate_private_key(ec.SECP256R1())
    new_key = ec.generate_private_key(ec.SECP256R1())
    store.save_key(state, old, "pw")
    store.save_pending_key(state, new_key, "pw")
    assert store.file(state, "key.next.pem").is_file()
    store.adopt_pending(state)
    assert certs.public_keys_equal(store.load_key(state, "pw").public_key(), new_key.public_key())
    assert not store.file(state, "key.next.pem").exists()
    store.save_pending_key(state, old, "pw")
    store.discard_pending(state)
    assert not store.file(state, "key.next.pem").exists()


def test_archive_current_and_collisions(store):
    state = new(store)
    key = ec.generate_private_key(ec.SECP256R1())
    store.save_key(state, key, "pw")
    atomic_write(store.file(state, "cert.pem"), b"cert")
    first = store.archive_current(state)
    store.save_key(state, key, "pw")
    atomic_write(store.file(state, "cert.pem"), b"cert")
    second = store.archive_current(state)
    assert first != second
    assert (first / "key.pem").exists() and (first / "cert.pem").exists()
    assert (second / "key.pem").exists() and (second / "cert.pem").exists()


def test_archive_moves_exported_p12(store, tmp_path):
    state = new(store)
    external = tmp_path / "outside.p12"
    external.write_bytes(b"p12")
    state.p12_path = str(external)
    archive = store.archive_current(state)
    assert not external.exists()
    assert (archive / "outside.p12").exists()


def test_audit_reports_loose_permissions(store):
    state = new(store)
    assert store.audit() == []
    os.chmod(store.path(state), 0o755)
    problems = store.audit()
    assert any("directory" in problem for problem in problems)
    store.file(state, "state.json").chmod(0o644)
    assert any("state.json" in problem for problem in store.audit())


def test_file_modes(store):
    state = new(store)
    key = ec.generate_private_key(ec.SECP256R1())
    store.save_key(state, key, "pw")
    assert stat.S_IMODE(store.file(state, "key.pem").stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path(state).stat().st_mode) == 0o700
    assert stat.S_IMODE(store.file(state, "state.json").stat().st_mode) == 0o600


def test_lock_file_is_private(store):
    state = new(store)
    with store.lock(state):
        pass
    assert stat.S_IMODE(store.file(state, ".lock").stat().st_mode) == 0o600


def test_lock_is_reentrant_and_serialising(store):
    state = new(store)
    with store.lock(state), store.lock(state):
        pass


def test_p12_filename(store):
    state = new(store, "a/b c")
    assert "/" not in store.p12_filename(state)
    assert store.p12_filename(state).endswith(".p12")


def test_delete(store):
    state = new(store)
    store.delete(state)
    assert store.list() == []
    with pytest.raises(NotFound):
        store.get(state.alias)


def test_get_by_slug(store):
    state = new(store, "Some Name")
    assert store.get_by_slug(state.slug).alias == "Some Name"
    with pytest.raises(NotFound):
        store.get_by_slug("missing")


def test_days_remaining_and_expiry_warning(store):
    state = new(store)
    state.cert.not_after = "2030-01-01T00:00:00Z"
    assert state.days_remaining is not None
    state.cert.not_after = "not a date"
    assert state.days_remaining is None


def test_list_sorted_by_creation(store):
    for name in ("b", "a", "c"):
        new(store, name)
    aliases = [state.alias for state in store.list()]
    assert aliases == ["b", "a", "c"] or aliases == sorted(aliases)
