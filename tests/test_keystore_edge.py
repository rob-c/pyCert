"""Edge cases for keystore stores: malformed entries, collisions, PBES2 parameters, CLI paths."""

import io
import json
import sys

import pytest
from test_keystore import PASSWORD, _entry_parts, build_keystore, link, placeholder_certificate

from pycert import asn1, ber, bundles, cli
from pycert import keystore as ks
from pycert.config import load_config
from pycert.errors import ConfigError, CryptoError, PyCertError
from pycert.pkcs12_writer import _certificate_bag, _key_bag, encode_raw_pkcs12


@pytest.fixture
def hosts(ctx, issued):
    user = issued("jane doe")
    return user, issued("a.example.org", type="host", auth_alias=user.alias), issued("b.example.org", type="host", auth_alias=user.alias)


# ---------------------------------------------------------------------------
# PBES2 parameter handling
# ---------------------------------------------------------------------------


def _pbes2_params(kdf_oid="1.2.840.113549.1.5.12", prf_oid="1.2.840.113549.2.9", cipher_oid="2.16.840.1.101.3.4.1.42", iterations=2048, key_length=None):
    pbkdf2 = [asn1.octet_string(b"saltsalt"), asn1.integer(iterations)]
    if key_length is not None:
        pbkdf2.append(asn1.integer(key_length))
    if prf_oid:
        pbkdf2.append(asn1.seq(asn1.oid(prf_oid), asn1.null()))
    return ber.parse(
        asn1.seq(
            asn1.seq(asn1.oid(kdf_oid), asn1.seq(*pbkdf2)),
            asn1.seq(asn1.oid(cipher_oid), asn1.octet_string(b"\0" * 16)),
        )
    )


@pytest.mark.parametrize(
    "params, error",
    [
        ({"kdf_oid": "1.2.3.4"}, "key derivation"),
        ({"prf_oid": "1.2.3.4"}, "pseudo-random"),
        ({"cipher_oid": "1.2.3.4"}, "cipher"),
    ],
)
def test_unsupported_pbes2_parameters_fall_back(params, error):
    with pytest.raises(bundles._UnsupportedPBE, match=error):
        bundles._pbes2_decrypt(_pbes2_params(**params), b"\0" * 16, "pw")


def test_pbes2_iteration_bound_and_wrong_key():
    with pytest.raises(CryptoError, match="implausible"):
        bundles._pbes2_decrypt(_pbes2_params(iterations=0), b"\0" * 16, "pw")
    # keyLength present and default PRF (HMAC-SHA1); garbage ciphertext fails cleanly
    with pytest.raises(CryptoError, match="wrong passphrase"):
        bundles._pbes2_decrypt(_pbes2_params(prf_oid="", key_length=32), b"\1" * 16, "pw")


def test_unknown_encryption_algorithm_uses_the_fallback_parser():
    encrypted = asn1.seq(
        asn1.integer(0),
        asn1.seq(asn1.oid("1.2.840.113549.1.7.1"), asn1.seq(asn1.oid("1.2.3.4"), asn1.seq(asn1.octet_string(b"saltsalt"), asn1.integer(1))), asn1.implicit(0, b"x")),
    )
    content = ber.parse(asn1.explicit(0, encrypted))
    with pytest.raises(bundles._UnsupportedPBE, match="unsupported PKCS#12 encryption"):
        bundles._decrypt_encrypted_data(content, "pw")


# ---------------------------------------------------------------------------
# Keystore file edge cases
# ---------------------------------------------------------------------------


def test_orphan_key_and_duplicate_alias_are_reported(tmp_path, ctx, hosts):
    _user, host_a, host_b = hosts
    key_a, cert_a, _chain = _entry_parts(ctx, host_a)
    key_b = _entry_parts(ctx, host_b)[0]
    blob = encode_raw_pkcs12(
        [
            _key_bag(key_a, PASSWORD, 2048, "dup", b"1", legacy=True),
            _key_bag(key_a, PASSWORD, 2048, "dup", b"1", legacy=True),
            _key_bag(key_b, PASSWORD, 2048, "orphan", b"2", legacy=True),
        ],
        [_certificate_bag(cert_a, "dup", b"1", True)],
        PASSWORD,
    )
    path = tmp_path / "odd.p12"
    path.write_bytes(blob)
    keystore = ks.Keystore.load(path, PASSWORD)
    assert keystore.aliases == ["dup"]
    assert any("more than once" in p for p in keystore.problems)
    assert any("no certificate matches" in p for p in keystore.problems)


def test_save_creates_missing_directories(tmp_path, ctx, hosts):
    keystore = ks.Keystore.load(tmp_path / "new" / "dir" / "k.p12", PASSWORD)
    keystore.put("a", *_entry_parts(ctx, hosts[1]))
    assert keystore.save().is_file()


def test_report_summaries():
    assert ks.SyncReport("x", skipped=True).summary() == "x: unchanged"
    assert ks.SyncReport("x").summary() == "x: in sync"
    assert "1 problem" in ks.SyncReport("x", imported=["a"], problems=["p"]).summary()
    assert ks.SyncReport("x", error="boom").as_dict()["error"] == "boom"
    assert ks._file_signature(ks.Path("/definitely/missing")) is None


# ---------------------------------------------------------------------------
# Linking and synchronisation edge cases
# ---------------------------------------------------------------------------


def test_default_names_do_not_collide(ctx, tmp_path, hosts):
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    first = build_keystore(tmp_path / "one" / "cakeystore.pkcs12", [("a", *_entry_parts(ctx, hosts[1]))])
    second = build_keystore(tmp_path / "two" / "cakeystore.pkcs12", [("b", *_entry_parts(ctx, hosts[2]))])
    names = [ks.link_keystore(ctx, path, PASSWORD)[0].name for path in (first, second)]
    assert names == ["cakeystore", "cakeystore-2"]


def test_corrupt_status_file_triggers_a_full_sync(ctx, tmp_path, hosts):
    path = build_keystore(tmp_path / "k.p12", [("a", *_entry_parts(ctx, hosts[1]))])
    linked = link(ctx, path)
    ks.sync(ctx, linked)
    status = ctx.config.data_dir / "keystores" / "hosts.json"
    status.write_text("not json")
    assert not ks.sync(ctx, linked, only_if_changed=True).skipped


def test_certificate_in_two_keystores_is_managed_once(ctx, tmp_path, hosts):
    parts = _entry_parts(ctx, hosts[1])
    ctx.store.delete(ctx.store.get(hosts[1].alias))
    first = build_keystore(tmp_path / "first.p12", [("a", *parts)])
    second = build_keystore(tmp_path / "second.p12", [("a-copy", *parts)])
    assert ks.sync(ctx, link(ctx, first, name="first")).imported == ["a"]
    report = ks.sync(ctx, link(ctx, second, name="second"))
    assert report.imported == [] and report.updated == []


def test_reconcile_branches(ctx, ca, tmp_path, hosts):
    _user, host_a, host_b = hosts
    path = build_keystore(tmp_path / "k.p12", [("a.example.org", *_entry_parts(ctx, host_a)), ("b.example.org", *_entry_parts(ctx, host_b))])
    for state in (host_a, host_b):
        ctx.store.delete(ctx.store.get(state.alias))
    linked = link(ctx, path)
    ks.sync(ctx, linked)
    # 'written' lost (e.g. an older pyCertWiz): restored without writing the file
    state = ctx.store.get("a.example.org")
    with ctx.store.lock(state):
        state.keystore["written"] = ""
        ctx.store.save(state)
    before = path.read_bytes()
    ks.sync(ctx, linked)
    assert ctx.store.get("a.example.org").keystore["written"] == state.cert.sha256
    assert path.read_bytes() == before
    # revoked certificates and renewals in flight are left alone
    with ctx.store.lock(state):
        state = ctx.store.get("a.example.org")
        state.status = "REVOKED"
        ctx.store.save(state)
    with ks.open_keystore(path, PASSWORD) as keystore:
        keystore.put("a.example.org", *_entry_parts(ctx, ctx.store.get("b.example.org")))
    assert ks.sync(ctx, linked).changes == 0


def test_placeholder_still_in_keystore_after_pyCert_collected(ctx, ca, tmp_path, hosts):
    """The write-back after issuance failed: the next sync replaces the placeholder."""
    _user, host_a, _host_b = hosts
    key, cert, _chain = _entry_parts(ctx, host_a)
    path = build_keystore(tmp_path / "k.p12", [("a.example.org", key, placeholder_certificate(key, "a.example.org"), [])])
    linked = link(ctx, path)
    report = ks.sync(ctx, linked)
    assert report.updated == ["a.example.org"]  # matched by public key, linked as pending
    report = ks.sync(ctx, linked)
    assert report.written == ["a.example.org"]
    assert ks.Keystore.load(path, PASSWORD).entry("a.example.org").fingerprint == host_a.cert.sha256


def test_alias_suffix_counter_and_untrusted_chain(ctx, tmp_path, hosts):
    user, _host_a, host_b = hosts
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    # A certificate from a CA pyCertWiz does not trust: imported, with a chain note.
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Elsewhere CA")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foreign.example.org")]))
        .issuer_name(issuer)
        .public_key(leaf_key.public_key())
        .serial_number(7)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(issuer_key, hashes.SHA256())
    )
    ctx.store.new_state(alias=f"{user.alias} (other)", type="user", cn="placeholder name", email="x@y.z")
    path = build_keystore(tmp_path / "k.p12", [(user.alias, leaf_key, leaf, [])])
    report = ks.sync(ctx, link(ctx, path, name="other"))
    assert report.imported == [f"{user.alias} (other 2)"]
    imported = ctx.store.get(f"{user.alias} (other 2)")
    assert not imported.cert.verified and any(note.startswith("chain:") for note in imported.notes)


def test_adopt_redeploys(ctx, ca, tmp_path, hosts, monkeypatch):
    from pycert import deploy

    _user, host_a, _host_b = hosts
    path = build_keystore(tmp_path / "k.p12", [("a.example.org", *_entry_parts(ctx, host_a))])
    ctx.store.delete(ctx.store.get(host_a.alias))
    linked = link(ctx, path)
    ks.sync(ctx, linked)
    state = ctx.store.get("a.example.org")
    deploy.add_target(ctx, state, {"name": "web", "cert": str(tmp_path / "out" / "cert.pem")})
    ca.host_valid_days = 900
    newer = _issue_newer(ctx, ca)
    with ks.open_keystore(path, PASSWORD) as keystore:
        keystore.put("a.example.org", *newer)
    calls = []
    monkeypatch.setattr(deploy, "deploy_state", lambda *a, **k: calls.append(1) or (_ for _ in ()).throw(PyCertError("disk full")))
    messages = []
    report = ks.sync(ctx, linked, progress=messages.append)
    assert report.updated == ["a.example.org"] and calls == [1]
    assert any("deployment failed" in m for m in messages)


def _issue_newer(ctx, ca):
    from pycert.workflow import RequestSpec, create_request

    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(ctx.config, "a.example.org", type="host", auth_alias="jane doe", pin="1234567890AB", alias="tmp-newer")
    state = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    parts = _entry_parts(ctx, state)
    ctx.store.delete(ctx.store.get("tmp-newer"))
    return parts


def test_write_state_guards(ctx, tmp_path, hosts):
    _user, host_a, _host_b = hosts
    assert ks.write_state(ctx, ctx.store.get(host_a.alias)) == "not linked"
    path = build_keystore(tmp_path / "k.p12", [("x", *_entry_parts(ctx, hosts[2]))])
    linked = link(ctx, path, write_back=False)
    state = ctx.store.get(host_a.alias)
    state.keystore = {"name": linked.name, "alias": "a"}
    assert ks.write_state(ctx, state) == "write-back disabled"


def test_keystores_must_be_tables(config):
    config.path.write_text(config.path.read_text().replace("version = 2", "version = 2\nkeystores = [1]", 1))
    with pytest.raises(ConfigError, match="expected a table"):
        load_config(config.path)


# ---------------------------------------------------------------------------
# CLI paths
# ---------------------------------------------------------------------------


def _run(args, capsys, stdin="", tty=False, monkeypatch=None):
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    if tty:
        sys.stdin.isatty = lambda: True
    try:
        code = cli.main(args)
    finally:
        sys.stdin = old
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_prompt_json_link_and_warnings(config, ctx, tmp_path, hosts, capsys, monkeypatch):
    _user, host_a, host_b = hosts
    key_a, cert_a, chain = _entry_parts(ctx, host_a)
    path = tmp_path / "k.p12"
    path.write_bytes(
        encode_raw_pkcs12(
            [_key_bag(key_a, PASSWORD, 2048, "a", b"1", legacy=True), _key_bag(_entry_parts(ctx, host_b)[0], "other", 2048, "b", b"2", legacy=True)],
            [_certificate_bag(cert_a, "a", b"1", True), _certificate_bag(_entry_parts(ctx, host_b)[1], "b", b"2", True)],
            PASSWORD,
        )
    )
    base = ["--config", str(config.path)]
    prompts = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: prompts.append(prompt) or PASSWORD)
    code, out, err = _run([*base, "--json", "keystore", "link", str(path), "--name", "hosts"], capsys, tty=True)
    assert code == 0, err
    assert json.loads(out)["link"]["name"] == "hosts"
    # an interactive sync asks for the passphrase again (it was never stored)
    code, out, err = _run([*base, "keystore", "sync", "hosts"], capsys, tty=True)
    assert code == 0 and "could not be decrypted" in err
    assert any("never stored" in prompt for prompt in prompts)


def test_unsupported_scheme_in_a_full_pfx_fails_cleanly():
    from pycert.pkcs12_writer import DATA_OID, ENCRYPTED_DATA_OID, PBES2_OID, _mac_data

    params = asn1.seq(
        asn1.seq(asn1.oid("1.2.840.113549.1.5.12"), asn1.seq(asn1.octet_string(b"saltsalt"), asn1.integer(2048))),
        asn1.seq(asn1.oid("1.2.3.4"), asn1.octet_string(b"\0" * 16)),
    )
    encrypted_data = asn1.seq(
        asn1.integer(0),
        asn1.seq(asn1.oid(DATA_OID), asn1.seq(asn1.oid(PBES2_OID), params), asn1.implicit(0, b"\0" * 16)),
    )
    authenticated_safe = asn1.seq(asn1.seq(asn1.oid(ENCRYPTED_DATA_OID), asn1.explicit(0, encrypted_data)))
    auth_safe = asn1.seq(asn1.oid(DATA_OID), asn1.explicit(0, asn1.octet_string(authenticated_safe)))
    pfx = asn1.seq(asn1.integer(3), auth_safe, _mac_data(authenticated_safe, "pw", 2048, "sha256"))
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(pfx, "pw")
