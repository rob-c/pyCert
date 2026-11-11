"""Branch coverage for Java keystores used as a live certificate store (pycert.keystore)."""

import pytest
from test_keystore import PASSWORD, _entry_parts, build_keystore, link, placeholder_certificate

from pycert import asn1, ber, certs
from pycert import keystore as ks
from pycert.pkcs12_writer import LOCAL_KEY_ID_OID, _certificate_bag
from pycert.store import STATUS_IMPORTED, STATUS_SUBMITTED
from pycert.workflow import RequestSpec, create_request


@pytest.fixture
def hosts(ctx, issued):
    user = issued("jane doe")
    return (
        user,
        issued("a.example.org", type="host", auth_alias=user.alias),
        issued("b.example.org", type="host", auth_alias=user.alias),
    )


def _short_lived_parts(ctx, ca, days):
    """Key, certificate and chain of a fresh a.example.org certificate valid for *days*."""
    ca.auto_approve = True
    ca.sign_after_polls = 0
    ca.host_valid_days = days
    spec = RequestSpec.build(
        ctx.config, "a.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", alias="tmp-short"
    )
    state = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    parts = _entry_parts(ctx, state)
    ctx.store.delete(ctx.store.get("tmp-short"))
    return parts


# ---------------------------------------------------------------------------
# Keystore editing
# ---------------------------------------------------------------------------


def test_local_key_id_skips_attributes_without_a_value(ctx, hosts):
    certificate = ctx.store.load_certificate(hosts[1])
    bag = ber.parse(_certificate_bag(certificate, "x", None, False))
    attributes = asn1.set_of(
        asn1.seq(asn1.oid(LOCAL_KEY_ID_OID), asn1.set_of()),
        asn1.seq(asn1.oid(LOCAL_KEY_ID_OID), asn1.set_of(asn1.octet_string(b"second"))),
    )
    raw = asn1.seq(bag.children[0].encoded, bag.children[1].encoded, attributes)
    assert ks._bag_local_key_id(ber.parse(raw)) == b"second"


def test_replacing_an_entry_keeps_a_certificate_another_alias_still_uses(tmp_path, ctx, hosts):
    _user, host_a, host_b = hosts
    key_a, cert_a, chain_a = _entry_parts(ctx, host_a)
    key_b, cert_b, chain_b = _entry_parts(ctx, host_b)
    keystore = ks.Keystore(tmp_path / "shared.p12", PASSWORD)
    assert keystore.put("first", key_a, cert_a, chain_a) == "added"
    assert keystore.put("second", key_a, cert_a, chain_a) == "added"
    assert keystore.put("first", key_b, cert_b, chain_b) == "replaced"
    fingerprints = [certs.fingerprint(ks._cert_bag_certificate(raw)) for raw in keystore._cert_bags]
    assert fingerprints.count(certs.fingerprint(cert_a)) == 2  # still used by 'second'
    keystore.save()
    reloaded = ks.Keystore.load(keystore.path, PASSWORD)
    assert reloaded.entry("first").fingerprint == certs.fingerprint(cert_b)
    assert reloaded.entry("second").fingerprint == certs.fingerprint(cert_a)


def test_entry_whose_certificate_bag_is_missing_can_be_replaced_and_removed(tmp_path, ctx, hosts):
    """Defensive: an entry's certificate bag may already be gone; nothing else is deleted."""
    _user, host_a, host_b = hosts
    key_a, cert_a, chain_a = _entry_parts(ctx, host_a)
    key_b, cert_b, chain_b = _entry_parts(ctx, host_b)
    keystore = ks.Keystore(tmp_path / "gap.p12", PASSWORD)
    keystore.put("entry", key_a, cert_a, chain_a)
    keystore._cert_bags.pop(keystore._cert_bag_index(certs.fingerprint(cert_a)))
    before = list(keystore._cert_bags)
    assert keystore.put("entry", key_b, cert_b, chain_b) == "replaced"
    assert keystore._cert_bags[: len(before)] == before
    leaf_b = keystore._cert_bag_index(certs.fingerprint(cert_b))
    keystore._cert_bags.pop(leaf_b)
    before = list(keystore._cert_bags)
    assert keystore.remove("entry") is True
    assert keystore._cert_bags == before and keystore.entries == []


def test_save_without_a_backup(tmp_path, ctx, hosts):
    _user, host_a, host_b = hosts
    path = build_keystore(tmp_path / "k.p12", [("a.example.org", *_entry_parts(ctx, host_a))])
    keystore = ks.Keystore.load(path, PASSWORD)
    keystore.put("b.example.org", *_entry_parts(ctx, host_b))
    keystore.save(backup=False)
    assert not path.with_name(path.name + ".bak").exists()
    assert sorted(ks.Keystore.load(path, PASSWORD).aliases) == ["a.example.org", "b.example.org"]


# ---------------------------------------------------------------------------
# Synchronisation with write-back disabled
# ---------------------------------------------------------------------------


def test_entry_removed_outside_pycert_is_not_rewritten_when_write_back_is_off(ctx, certwizard_store):
    linked = link(ctx, certwizard_store, write_back=False)
    assert sorted(ks.sync(ctx, linked).imported) == ["a.example.org", "b.example.org"]
    state = ctx.store.get("a.example.org")
    with ctx.store.lock(state):
        state.keystore["written"] = ""  # e.g. recorded by an older pyCertWiz
        ctx.store.save(state)
    with ks.open_keystore(certwizard_store, PASSWORD) as keystore:
        keystore.remove("a.example.org")
    report = ks.sync(ctx, linked)
    assert report.changes == 0 and report.unlinked == [] and report.written == []
    assert ks.Keystore.load(certwizard_store, PASSWORD).aliases == ["b.example.org"]
    assert ctx.store.get("a.example.org").keystore["name"] == linked.name


def test_older_keystore_entry_is_left_alone_when_write_back_is_off(ctx, ca, certwizard_store):
    linked = link(ctx, certwizard_store, write_back=False)
    ks.sync(ctx, linked)
    stored = ctx.store.get("a.example.org")
    older = _short_lived_parts(ctx, ca, days=30)
    with ks.open_keystore(certwizard_store, PASSWORD) as keystore:
        keystore.put("a.example.org", *older)
    report = ks.sync(ctx, linked)
    assert report.changes == 0
    assert ctx.store.get("a.example.org").cert.sha256 == stored.cert.sha256
    assert ks.Keystore.load(certwizard_store, PASSWORD).entry("a.example.org").fingerprint == certs.fingerprint(older[1])


def test_pending_import_adopts_the_certificate_collected_by_certwizard(ctx, tmp_path, hosts):
    _user, host_a, _host_b = hosts
    key, cert, chain = _entry_parts(ctx, host_a)
    ctx.store.delete(ctx.store.get(host_a.alias))
    path = build_keystore(tmp_path / "k.p12", [("a.example.org", key, placeholder_certificate(key, "a.example.org"), [])])
    linked = link(ctx, path)
    assert ks.sync(ctx, linked).pending == ["a.example.org"]
    pending = ctx.store.get("a.example.org")
    assert pending.status == STATUS_SUBMITTED and not pending.cert.sha256
    with ks.open_keystore(path, PASSWORD) as keystore:
        keystore.put("a.example.org", key, cert, chain)
    messages = []
    report = ks.sync(ctx, linked, progress=messages.append)
    assert report.updated == ["a.example.org"]
    adopted = ctx.store.get("a.example.org")
    assert adopted.status == STATUS_IMPORTED and adopted.cert.sha256 == certs.fingerprint(cert)
    assert not (ctx.store.path(adopted) / "previous").exists()  # nothing to archive
    assert any("renewed outside pyCertWiz" in message for message in messages)
