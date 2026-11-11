"""Java PKCS#12 keystores as a live certificate store (pycert.keystore)."""

import datetime as dt
import io
import json
import os
import shutil
import subprocess
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from pycert import ber, certs, cli
from pycert import keystore as ks
from pycert.config import KeystoreLink, load_config
from pycert.errors import ConfigError, CryptoError, NotFound, PyCertError, SecretError
from pycert.pkcs12_writer import _certificate_bag, _key_bag, encode_raw_pkcs12
from pycert.workflow import RequestSpec, create_request, renew, wait_for_certificate

PASSWORD = "keystore-pass"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _entry_parts(ctx, state):
    return (
        ctx.store.load_key(state, ctx.key_passphrase()),
        ctx.store.load_certificate(state),
        ctx.store.load_chain(state),
    )


def build_keystore(path, entries, *, password=PASSWORD, modern=False):
    """A CertWizard-style multi-entry keystore: one key entry per (alias, key, cert, chain)."""
    key_bags, cert_bags, seen = [], [], set()
    for index, (alias, key, cert, chain) in enumerate(entries):
        local_id = b"Time %d" % index
        key_bags.append(_key_bag(key, password, 2048, alias, local_id, legacy=not modern))
        cert_bags.append(_certificate_bag(cert, alias, local_id, True))
        for issuer in chain:
            fingerprint = certs.fingerprint(issuer)
            if fingerprint not in seen:
                seen.add(fingerprint)
                cert_bags.append(_certificate_bag(issuer, "", None, False))
    path.write_bytes(encode_raw_pkcs12(key_bags, cert_bags, password))
    os.chmod(path, 0o600)
    return path


def placeholder_certificate(key, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eScience")])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


def raw_key_bags(path, password=PASSWORD):
    from pycert import bundles

    return bundles.load_bundle(path, password).raw_key_bags


def link(ctx, path, name="hosts", **kwargs):
    linked, _keystore = ks.link_keystore(ctx, path, PASSWORD, name=name, **kwargs)
    return linked


# ---------------------------------------------------------------------------
# The keystore file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("modern", [False, True])
def test_load_every_entry_with_chain(tmp_path, ctx, two_hosts, modern):
    _user, host_a, host_b = two_hosts
    path = build_keystore(
        tmp_path / "k.p12",
        [("a.example.org", *_entry_parts(ctx, host_a)), ("b.example.org", *_entry_parts(ctx, host_b))],
        modern=modern,
    )
    keystore = ks.Keystore.load(path, PASSWORD)
    assert keystore.aliases == ["a.example.org", "b.example.org"]
    entry = keystore.entry("A.EXAMPLE.ORG")  # Java aliases are case-insensitive
    assert entry.fingerprint == host_a.cert.sha256 and entry.chain and not entry.pending
    assert keystore.entry_for(host_b.cert.sha256).alias == "b.example.org"
    assert entry.as_dict()["common_name"] == "a.example.org"
    assert not keystore.problems


def test_put_replace_remove_preserves_other_entries(tmp_path, ctx, two_hosts):
    user, host_a, host_b = two_hosts
    path = build_keystore(tmp_path / "k.p12", [("a.example.org", *_entry_parts(ctx, host_a)), ("b.example.org", *_entry_parts(ctx, host_b))])
    os.chmod(path, 0o640)
    original_b = raw_key_bags(path)[1]
    with ks.open_keystore(path, PASSWORD) as keystore:
        assert keystore.put("a.example.org", *_entry_parts(ctx, host_a)) == "unchanged"
        assert keystore.put("jane", *_entry_parts(ctx, user)) == "added"
        assert keystore.put("a.example.org", *_entry_parts(ctx, user)) == "replaced"
        assert keystore.remove("jane") is True
        assert keystore.remove("missing") is False
    assert raw_key_bags(path)[1] == original_b  # untouched entries are byte-identical
    assert (path.stat().st_mode & 0o777) == 0o640  # permissions preserved
    assert (tmp_path / "k.p12.bak").is_file()
    reloaded = ks.Keystore.load(path, PASSWORD)
    assert reloaded.aliases == ["a.example.org", "b.example.org"]  # replaced in place
    assert reloaded.entry("a.example.org").fingerprint == user.cert.sha256
    # every entry is still readable by a standard PKCS#12 parser (one entry per key)
    blob = path.read_bytes()
    key, cert, _extra = pkcs12.load_key_and_certificates(blob, PASSWORD.encode())
    assert key is not None and cert is not None


def test_put_rejects_mismatched_key_and_change_detection(tmp_path, ctx, two_hosts):
    _user, host_a, host_b = two_hosts
    path = build_keystore(tmp_path / "k.p12", [("a", *_entry_parts(ctx, host_a))])
    keystore = ks.Keystore.load(path, PASSWORD)
    key_b, cert_a = _entry_parts(ctx, host_b)[0], _entry_parts(ctx, host_a)[1]
    with pytest.raises(CryptoError, match="does not match"):
        keystore.put("x", key_b, cert_a, [])
    keystore.put("b", *_entry_parts(ctx, host_b))
    os.utime(path, ns=(1, 1))  # another program rewrote it
    with pytest.raises(ks.KeystoreChanged):
        keystore.save()


def test_wrong_password_jks_and_empty(tmp_path, ctx, two_hosts):
    _user, host_a, _host_b = two_hosts
    path = build_keystore(tmp_path / "k.p12", [("a", *_entry_parts(ctx, host_a))])
    with pytest.raises(CryptoError):
        ks.Keystore.load(path, "wrong")
    with pytest.raises(SecretError):
        ks.Keystore.load(path, "")
    pem = tmp_path / "chain.pem"
    pem.write_text(certs.cert_pem(_entry_parts(ctx, host_a)[1]))
    with pytest.raises(CryptoError, match="only PKCS#12"):
        ks.Keystore.load(pem, PASSWORD)
    empty = ks.Keystore.load(tmp_path / "new.p12", PASSWORD)
    assert empty.entries == []
    with pytest.raises(PyCertError, match="no certificates"):
        empty.save()
    empty.put("a", *_entry_parts(ctx, host_a))
    empty.save()
    assert (tmp_path / "new.p12").stat().st_mode & 0o777 == 0o600


def test_undecodable_entry_is_reported_and_preserved(tmp_path, ctx, two_hosts):
    _user, host_a, host_b = two_hosts
    key_a, cert_a, chain = _entry_parts(ctx, host_a)
    other_password_bag = _key_bag(_entry_parts(ctx, host_b)[0], "different", 2048, "b", b"2", legacy=True)
    blob = encode_raw_pkcs12(
        [_key_bag(key_a, PASSWORD, 2048, "a", b"1", legacy=True), other_password_bag],
        [_certificate_bag(cert_a, "a", b"1", True), _certificate_bag(_entry_parts(ctx, host_b)[1], "b", b"2", True)],
        PASSWORD,
    )
    path = tmp_path / "mixed.p12"
    path.write_bytes(blob)
    with ks.open_keystore(path, PASSWORD) as keystore:
        assert keystore.aliases == ["a"]
        assert any("'b'" in problem for problem in keystore.problems)
        keystore.remove("a")
        keystore.put("c", key_a, cert_a, chain)
    assert other_password_bag in raw_key_bags(path)  # kept although pyCertWiz cannot read it


def test_placeholder_detection(ctx, two_hosts):
    _user, host_a, _host_b = two_hosts
    key = _entry_parts(ctx, host_a)[0]
    assert ks.is_placeholder(placeholder_certificate(key, "x.example.org"))
    assert not ks.is_placeholder(_entry_parts(ctx, host_a)[1])


# ---------------------------------------------------------------------------
# Linking and synchronisation
# ---------------------------------------------------------------------------


def test_link_imports_every_entry_and_records_config(ctx, config, certwizard_store):
    linked = link(ctx, certwizard_store)
    assert linked.name == "hosts" and linked.ca == config.primary_profile.name
    report = ks.sync(ctx, linked)
    assert sorted(report.imported) == ["a.example.org", "b.example.org"]
    state = ctx.store.get("a.example.org")
    assert state.status == "IMPORTED" and state.cert.verified and state.type == "host"
    assert state.keystore == {"name": "hosts", "alias": "a.example.org", "written": state.cert.sha256}
    reloaded = load_config(config.path)
    assert reloaded.keystore("hosts").path == str(certwizard_store.resolve())
    # The passphrase is kept for this session only: never in the configuration or the secret store.
    assert ks.is_unlocked(ctx, "hosts")
    assert PASSWORD not in config.path.read_text()
    assert ctx.secrets.get("keystore:hosts", allow_missing=True) is None
    secrets_file = ctx.secrets.path
    assert not secrets_file.exists() or PASSWORD not in secrets_file.read_text()
    assert ks.sync(ctx, linked).changes == 0  # idempotent
    with pytest.raises(PyCertError, match="already linked"):
        link(ctx, certwizard_store, name="other")
    with pytest.raises(PyCertError, match="already linked"):
        link(ctx, certwizard_store)


def test_renewal_writes_back_and_keeps_other_entries(ctx, ca, certwizard_store):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    other_bag = raw_key_bags(certwizard_store)[1]
    ca.auto_approve = True
    ca.sign_after_polls = 0
    renewed = renew(ctx, "a.example.org", pin="1234567890AB", wait=True, timeout=30, interval=0.2)
    entry = ks.Keystore.load(certwizard_store, PASSWORD).entry("a.example.org")
    assert entry.fingerprint == renewed.cert.sha256
    assert certs.public_keys_equal(entry.key.public_key(), ctx.store.load_key(renewed, ctx.key_passphrase()).public_key())
    assert raw_key_bags(certwizard_store)[1] == other_bag
    assert ctx.store.get("a.example.org").keystore["written"] == renewed.cert.sha256
    assert (certwizard_store.parent / (certwizard_store.name + ".bak")).is_file()


def test_new_request_lands_in_the_keystore(ctx, ca, config, certwizard_store):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(
        load_config(config.path), "c.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", keystore="hosts"
    )
    state = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    keystore = ks.Keystore.load(certwizard_store, PASSWORD)
    assert keystore.entry("c.example.org").fingerprint == state.cert.sha256
    with pytest.raises(ConfigError, match="no keystore"):
        RequestSpec.build(config, "d.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", keystore="nope")


def test_pending_certwizard_request_is_collected_into_the_keystore(ctx, ca, config, tmp_path, two_hosts):
    """CertWizard keeps unsigned requests as self-signed placeholders; pyCertWiz finishes them."""
    user = two_hosts[0]
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    spec = RequestSpec.build(config, "pending.example.org", type="host", auth_alias=user.alias, pin="1234567890AB")
    submitted = create_request(ctx, spec, progress=lambda _m: None)
    key = ctx.store.load_key(submitted, ctx.key_passphrase())
    placeholder = placeholder_certificate(key, "pending.example.org")
    path = build_keystore(tmp_path / "cakeystore.pkcs12", [("pending.example.org", key, placeholder, [])])
    ctx.store.delete(ctx.store.get(submitted.alias))  # pretend CertWizard made the request
    linked = link(ctx, path)
    report = ks.sync(ctx, linked)
    assert report.pending == ["pending.example.org"]
    state = ctx.store.get("pending.example.org")
    assert state.status == "SUBMITTED" and not state.cert.sha256
    assert ks.sync(ctx, linked).changes == 0
    ca.approve_all()
    ca.sign_all()
    done = wait_for_certificate(ctx, state, timeout=30, interval=0.2)
    entry = ks.Keystore.load(path, PASSWORD).entry("pending.example.org")
    assert not entry.pending and entry.fingerprint == done.cert.sha256


def test_certificate_renewed_elsewhere_is_adopted(ctx, ca, certwizard_store, tmp_path):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    # Another tool renews b.example.org in the keystore with a longer-lived certificate.
    ca.auto_approve = True
    ca.sign_after_polls = 0
    ca.host_valid_days = 900
    spec = RequestSpec.build(ctx.config, "b.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", alias="b-elsewhere")
    elsewhere = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    parts = _entry_parts(ctx, elsewhere)
    with ks.open_keystore(certwizard_store, PASSWORD) as keystore:
        keystore.put("b.example.org", *parts)
    ctx.store.delete(ctx.store.get("b-elsewhere"))
    report = ks.sync(ctx, linked)
    assert report.updated == ["b.example.org"]
    state = ctx.store.get("b.example.org")
    assert state.cert.sha256 == certs.fingerprint(parts[1]) and state.status == "IMPORTED"
    assert any((ctx.store.path(state) / "previous").iterdir())


def test_older_keystore_entry_is_overwritten_and_removed_entries_unlink(ctx, ca, issued, certwizard_store, two_hosts):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    ca.host_valid_days = 5
    short = issued("short.example.org", type="host", auth_alias=two_hosts[0].alias)
    # Someone puts an older (shorter-lived) certificate under pyCertWiz's alias: pyCertWiz's copy wins.
    with ks.open_keystore(certwizard_store, PASSWORD) as keystore:
        keystore.put("a.example.org", *_entry_parts(ctx, short))
    report = ks.sync(ctx, linked)
    assert report.written == ["a.example.org"]
    entry = ks.Keystore.load(certwizard_store, PASSWORD).entry("a.example.org")
    assert entry.fingerprint == ctx.store.get("a.example.org").cert.sha256
    # Someone deletes b.example.org with keytool: pyCertWiz stops linking it but keeps managing it.
    with ks.open_keystore(certwizard_store, PASSWORD) as keystore:
        keystore.remove("b.example.org")
    report = ks.sync(ctx, linked)
    assert report.unlinked == ["b.example.org"]
    assert ctx.store.get("b.example.org").keystore == {}
    assert ctx.store.get("b.example.org").cert.sha256


def test_failed_write_is_retried_by_the_next_sync(ctx, ca, config, certwizard_store, monkeypatch):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    ca.auto_approve = True
    ca.sign_after_polls = 0
    real = ks.write_state
    monkeypatch.setattr(ks, "write_state", lambda *a, **k: (_ for _ in ()).throw(SecretError("keychain locked")))
    spec = RequestSpec.build(load_config(config.path), "late.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", keystore="hosts")
    state = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    assert any("keystore update failed" in note for note in ctx.store.get(state.alias).notes)
    assert ks.Keystore.load(certwizard_store, PASSWORD).entry("late.example.org") is None
    monkeypatch.setattr(ks, "write_state", real)
    report = ks.sync(ctx, load_config(config.path).keystore("hosts"))
    assert report.written == ["late.example.org"]
    assert ks.Keystore.load(certwizard_store, PASSWORD).entry("late.example.org").fingerprint == state.cert.sha256


def test_only_if_changed_skips_untouched_keystores(ctx, certwizard_store):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    assert ks.sync(ctx, linked, only_if_changed=True).skipped
    os.utime(certwizard_store, ns=(5, 5))
    assert not ks.sync(ctx, linked, only_if_changed=True).skipped


def test_existing_managed_certificate_is_linked_not_duplicated(ctx, tmp_path, two_hosts):
    _user, host_a, _host_b = two_hosts
    path = build_keystore(tmp_path / "k.p12", [("alias-in-java", *_entry_parts(ctx, host_a))])
    report = ks.sync(ctx, link(ctx, path))
    assert report.imported == [] and report.updated == [host_a.alias]
    assert ctx.store.get(host_a.alias).keystore["alias"] == "alias-in-java"


def test_no_import_leaves_entries_alone(ctx, certwizard_store):
    linked = link(ctx, certwizard_store, auto_import=False)
    assert ks.sync(ctx, linked).imported == []
    assert not ctx.store.exists("a.example.org")


def test_alias_clash_gets_a_suffix(ctx, tmp_path, two_hosts):
    user, _host_a, host_b = two_hosts
    path = build_keystore(tmp_path / "other.p12", [(user.alias, *_entry_parts(ctx, host_b))])
    ctx.store.delete(ctx.store.get(host_b.alias))
    report = ks.sync(ctx, link(ctx, path, name="other"))
    assert report.imported == [f"{user.alias} (other)"]


def test_failed_link_leaves_the_configuration_unchanged(ctx, config, certwizard_store, monkeypatch):
    import pycert.config as config_module

    monkeypatch.setattr(config_module, "write_config", lambda *a, **k: (_ for _ in ()).throw(OSError("read-only")))
    with pytest.raises(OSError):
        link(ctx, certwizard_store)
    assert ctx.config.keystores == [] and not ks.is_unlocked(ctx, "hosts")
    assert load_config(config.path).keystores == []
    monkeypatch.undo()
    assert link(ctx, certwizard_store).name == "hosts"  # a retry works


def test_unlink_and_import_without_link(ctx, certwizard_store, tmp_path):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    assert ks.unlink_keystore(ctx, "hosts") == 2
    assert ctx.store.get("a.example.org").keystore == {}
    assert not ks.is_unlocked(ctx, "hosts")
    with pytest.raises(ConfigError):
        ctx.config.keystore("hosts")
    for alias in ("a.example.org", "b.example.org"):
        ctx.store.delete(ctx.store.get(alias))
    states, problems = ks.import_keystore(ctx, certwizard_store, PASSWORD)
    assert sorted(s.alias for s in states) == ["a.example.org", "b.example.org"]
    assert all(s.keystore == {} for s in (ctx.store.get(x.alias) for x in states))
    states, problems = ks.import_keystore(ctx, certwizard_store, PASSWORD)
    assert states == [] and len(problems) == 2
    with pytest.raises(NotFound):
        ks.import_keystore(ctx, tmp_path / "missing.p12", PASSWORD)


def test_config_round_trip_and_validation(config):
    from pycert.config import validate_config, write_config

    config.keystores.append(KeystoreLink(name="hosts", path="/tmp/k.p12", ca=config.primary_profile.name, write_back=False))
    write_config(config.path, config)
    assert "never stored" in config.path.read_text()
    reloaded = load_config(config.path)
    assert vars(reloaded.keystore("hosts")) == vars(config.keystore("hosts"))
    assert reloaded.as_dict()["keystores"][0]["name"] == "hosts"
    for bad, message in (
        (KeystoreLink(name="Bad Name", path="x"), "lower-case"),
        (KeystoreLink(name="hosts", path="y"), "already linked"),
        (KeystoreLink(name="nopath", path=""), "required"),
        (KeystoreLink(name="noca", path="x", ca="missing"), "no CA profile"),
    ):
        reloaded.keystores.append(bad)
        with pytest.raises(ConfigError, match=message):
            validate_config(reloaded)
        reloaded.keystores.pop()
    text = config.path.read_text()
    config.path.write_text(text.replace("[[keystores]]", "[keystores_moved]", 1).replace("version = 2", "version = 2\nkeystores = 1", 1))
    with pytest.raises(ConfigError):
        load_config(config.path)


def test_pkcs12_pbes2_bundles_keep_every_entry(tmp_path, ctx, two_hosts):
    """Modern keytool/OpenSSL encrypt certificates with PBES2; every entry must survive."""
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    _user, host_a, _host_b = two_hosts
    key, cert, _chain = _entry_parts(ctx, host_a)
    (tmp_path / "k.pem").write_text(certs.key_pem(key, PASSWORD))
    (tmp_path / "c.pem").write_text(certs.cert_pem(cert))
    out = tmp_path / "modern.p12"
    result = subprocess.run(
        ["openssl", "pkcs12", "-export", "-inkey", str(tmp_path / "k.pem"), "-passin", f"pass:{PASSWORD}",
         "-in", str(tmp_path / "c.pem"), "-name", "modern", "-out", str(out), "-passout", f"pass:{PASSWORD}"],
        capture_output=True,
    )
    if result.returncode != 0:  # pragma: no cover - unusual openssl builds
        pytest.skip(result.stderr.decode())
    keystore = ks.Keystore.load(out, PASSWORD)
    assert keystore.aliases == ["modern"]
    with ks.open_keystore(out, PASSWORD) as editable:
        editable.put("second", *_entry_parts(ctx, two_hosts[2]))
    assert ks.Keystore.load(out, PASSWORD).aliases == ["modern", "second"]


def _run(args, capsys, stdin=""):
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        code = cli.main(args)
    finally:
        sys.stdin = old
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_import_request_and_errors(config, ctx, ca, certwizard_store, capsys):
    base = ["--config", str(config.path)]
    code, out, _ = _run([*base, "keystore", "import", str(certwizard_store)], capsys, PASSWORD + "\n")
    assert code == 0 and "Imported 'a.example.org'" in out
    code, out, err = _run([*base, "--json", "keystore", "import", str(certwizard_store)], capsys, PASSWORD + "\n")
    assert json.loads(out)["imported"] == [] and len(json.loads(out)["problems"]) == 2
    code, out, err = _run([*base, "keystore", "import", str(certwizard_store)], capsys, PASSWORD + "\n")
    assert "Nothing new to import" in out
    for action in ("link", "unlink", "import"):
        code, _, err = _run([*base, "keystore", action], capsys)
        assert code == 1 and "give" in err
    code, _, err = _run([*base, "keystore", "sync"], capsys)
    assert code == 1 and "no keystores" in err
    code, _, err = _run([*base, "keystore", "link", str(certwizard_store)], capsys, "")
    assert code == 1 and "passphrase is required" in err
    code, out, err = _run([*base, "keystore", "link", str(certwizard_store), "--name", "site", "--password-stdin"], capsys, PASSWORD + "\n")
    assert code == 0, err
    # A non-interactive request cannot ask for the passphrase: the certificate waits to be written.
    ca.auto_approve = True
    ca.sign_after_polls = 0
    code, out, err = _run(
        [*base, "--json", "request", "c.example.org", "--type", "host", "--auth", "jane doe", "--pin", "1234567890AB",
         "--keystore", "site", "--wait", "--interval", "0.2", "--timeout", "30"],
        capsys,
    )
    assert code == 0, err
    assert ks.Keystore.load(certwizard_store, PASSWORD).entry("c.example.org") is None
    code, out, err = _run([*base, "--json", "check"], capsys)
    assert json.loads(out)["level"] == "WARNING"
    code, out, err = _run([*base, "keystore", "sync", "site", "--password-stdin"], capsys, PASSWORD + "\n")
    assert code == 0 and "1 written" in out
    assert ks.Keystore.load(certwizard_store, PASSWORD).entry("c.example.org") is not None
    code, out, err = _run([*base, "report"], capsys)
    assert "c.example.org" in out
    code, out, err = _run([*base, "keystore", "link", str(certwizard_store), "--password-file", "/nonexistent"], capsys)
    assert code == 1


def test_bag_local_key_id(ctx, two_hosts):
    certificate = _entry_parts(ctx, two_hosts[1])[1]
    assert ks._bag_local_key_id(ber.parse(_certificate_bag(certificate, "x", b"id", True))) == b"id"
    assert ks._bag_local_key_id(ber.parse(_certificate_bag(certificate, "x", None, False))) == b""


def test_passphrases_live_only_in_the_session(ctx, config, certwizard_store):
    from pycert.workflow import AppContext

    linked = link(ctx, certwizard_store)
    ks.lock(ctx, "hosts")
    with pytest.raises(ks.KeystoreLocked, match="never stored"):
        ks.keystore_password(ctx, linked)
    reports = ks.sync_all(ctx)
    assert reports[0].locked and "locked" in reports[0].summary()
    assert ks.sync(ctx, linked, only_if_changed=True).locked
    # a front-end is asked; a wrong answer is rejected and nothing is remembered
    ctx.ask_keystore_password = lambda _link: "wrong"
    with pytest.raises(CryptoError):
        ks.keystore_password(ctx, linked)
    assert not ks.is_unlocked(ctx, "hosts")
    ctx.ask_keystore_password = lambda _link: None
    with pytest.raises(ks.KeystoreLocked):
        ks.keystore_password(ctx, linked)
    ctx.ask_keystore_password = lambda _link: PASSWORD
    assert ks.keystore_password(ctx, linked) == PASSWORD and ks.is_unlocked(ctx, "hosts")
    # a new session (a fresh context, e.g. after a restart) starts locked again
    fresh = AppContext.from_config(load_config(config.path))
    with pytest.raises(ks.KeystoreLocked):
        ks.keystore_password(fresh, fresh.config.keystore("hosts"))
    with pytest.raises(NotFound):
        ks.link_keystore(ctx, certwizard_store.parent / "missing.p12", PASSWORD)
    created, keystore = ks.link_keystore(ctx, certwizard_store.parent / "fresh.p12", PASSWORD, create=True)
    assert keystore.entries == [] and created.name == "fresh"


def test_locked_keystore_is_written_after_unlocking(ctx, ca, config, certwizard_store):
    from pycert import monitor

    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    ks.lock(ctx, "hosts")
    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(load_config(config.path), "late.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", keystore="hosts")
    state = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    assert any("locked" in note for note in ctx.store.get(state.alias).notes)
    report = monitor.check(ctx)
    assert any("not yet written to Java keystore 'hosts'" in f.message for f in report.findings)
    ks.unlock(ctx, linked, PASSWORD)
    assert ks.sync(ctx, linked).written == ["late.example.org"]
    assert not any("not yet written" in f.message for f in monitor.check(ctx).findings)


def test_cli_link_list_sync_unlink(config, ctx, certwizard_store, capsys):
    base = ["--config", str(config.path)]
    code, out, err = _run([*base, "keystore", "link", str(certwizard_store), "--name", "hosts"], capsys, PASSWORD + "\n")
    assert code == 0, err
    assert "2 key entries" in out and "2 imported" in out
    assert PASSWORD not in config.path.read_text()
    code, out, _ = _run([*base, "list", "--no-audit"], capsys)
    assert "a.example.org" in out and "b.example.org" in out
    code, out, _ = _run([*base, "--json", "keystore", "list"], capsys)
    assert json.loads(out)[0]["linked_certificates"] == ["a.example.org", "b.example.org"]
    code, out, _ = _run([*base, "keystore", "list"], capsys)
    assert "hosts" in out and "passphrase asked each session" in out
    # every command is a new session: without the passphrase the keystore is locked
    code, out, _ = _run([*base, "keystore", "sync"], capsys)
    assert code == 1 and "locked" in out
    code, out, _ = _run([*base, "--json", "keystore", "sync", "hosts", "--password-stdin"], capsys, PASSWORD + "\n")
    assert code == 0 and json.loads(out)[0]["keystore"] == "hosts"
    code, _, err = _run([*base, "keystore", "sync", "hosts", "--password-stdin"], capsys, "wrong\n")
    assert code == 1
    code, _, err = _run([*base, "keystore", "sync", "--password-stdin"], capsys, PASSWORD + "\n")
    assert code == 0  # one linked keystore: the passphrase is unambiguous
    code, _, err = _run(
        [*base, "keystore", "link", str(certwizard_store.parent / "second.p12"), "--name", "second", "--create", "--password-stdin"],
        capsys,
        PASSWORD + "\n",
    )
    assert code == 0, err
    code, _, err = _run([*base, "keystore", "sync", "--password-stdin"], capsys, PASSWORD + "\n")
    assert code == 1 and "give the keystore name" in err
    _run([*base, "keystore", "unlink", "second"], capsys)
    code, out, _ = _run([*base, "keystore", "unlink", "hosts"], capsys)
    assert code == 0 and "2 certificate(s) stay managed" in out
    code, out, _ = _run([*base, "keystore", "list"], capsys)
    assert "No keystores are linked" in out


def test_damaged_keystore_is_reported_not_raised(ctx, certwizard_store):
    linked = link(ctx, certwizard_store)
    certwizard_store.write_bytes(b"this is not a keystore")
    messages = []
    report = ks.sync_all(ctx, progress=messages.append)[0]
    assert report.error and not report.locked and "not synchronised" in report.summary()
    assert any(linked.name in m for m in messages)
