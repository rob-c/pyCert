"""Renaming certificates (and their Java keystore entries); user/host from the certificate."""

import datetime as dt
import io
import json
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from test_keystore import PASSWORD, build_keystore, link, placeholder_certificate, raw_key_bags

from pycert import certs, cli
from pycert import keystore as ks
from pycert.errors import NotFound, PyCertError
from pycert.workflow import (
    RequestSpec,
    create_request,
    rename_certificate,
    validate_alias,
    wait_for_certificate,
)


def _cli(args, capsys, stdin=""):
    old = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        code = cli.main(args)
    finally:
        sys.stdin = old
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _cert(cn, dns=None, email=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
    )
    names = [x509.DNSName(d) for d in dns or []] + [x509.RFC822Name(e) for e in email or []]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(key, hashes.SHA256())


def test_certificate_kind():
    assert certs.certificate_kind(_cert("anything", dns=["a.example.org"])) == "host"
    assert certs.certificate_kind(_cert("web.example.org")) == "host"
    assert certs.certificate_kind(_cert("jane doe", email=["j@example.org"])) == "user"
    assert certs.certificate_kind(_cert("j. smith")) == "user"
    assert certs.certificate_kind(_cert("ignored"), "given.example.org") == "host"


def test_validate_alias():
    assert validate_alias("  dev4 nov2026  ") == "dev4 nov2026"
    for bad, message in (("   ", "empty"), ("x" * 201, "longer"), ("tab\there", "control")):
        with pytest.raises(PyCertError, match=message):
            validate_alias(bad)


def test_rename_follows_references(ctx, two_hosts):
    user, host_a, _host_b = two_hosts
    messages = []
    renamed = rename_certificate(ctx, user.alias, "Jane 2026", progress=messages.append)
    assert renamed.alias == "Jane 2026" and renamed.slug == user.slug
    assert ctx.store.get("Jane 2026").history[-1]["detail"] == "renamed from 'jane doe'"
    assert ctx.store.get("jane doe").alias == "Jane 2026"  # still found by its common name
    assert ctx.store.get(host_a.alias).auth_alias == "Jane 2026"
    assert any("Renamed 'jane doe' to 'Jane 2026'" in m for m in messages)
    assert rename_certificate(ctx, "Jane 2026", "Jane 2026").alias == "Jane 2026"  # unchanged
    with pytest.raises(PyCertError, match="already called"):
        rename_certificate(ctx, "Jane 2026", host_a.alias.upper())
    with pytest.raises(PyCertError, match="not linked"):
        rename_certificate(ctx, "Jane 2026", "other", keystore_entry=True)


def test_rename_the_keystore_entry_too(ctx, certwizard_store):
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    other_bag = raw_key_bags(certwizard_store)[1]
    renamed = rename_certificate(ctx, "a.example.org", "a.example.org 2026", keystore_entry=True)
    assert renamed.keystore["alias"] == "a.example.org 2026"
    keystore = ks.Keystore.load(certwizard_store, PASSWORD)
    assert sorted(keystore.aliases) == ["a.example.org 2026", "b.example.org"]
    assert other_bag in raw_key_bags(certwizard_store)  # the other entry is untouched, byte for byte
    report = ks.sync(ctx, linked)
    assert report.changes == 0 and len(ctx.store.list()) == 3  # no re-import of the renamed entry
    # read-only links are not renamed; a locked keystore asks (here: is refused)
    ctx.config.keystores[0].write_back = False
    with pytest.raises(PyCertError, match="read-only"):
        rename_certificate(ctx, "a.example.org 2026", "x", keystore_entry=True)
    ctx.config.keystores[0].write_back = True
    ks.lock(ctx, "hosts")
    with pytest.raises(ks.KeystoreLocked):
        rename_certificate(ctx, "a.example.org 2026", "x", keystore_entry=True)
    assert ctx.store.get("a.example.org 2026")  # nothing renamed


def test_keystore_rename_errors(ctx, certwizard_store):
    keystore = ks.Keystore.load(certwizard_store, PASSWORD)
    with pytest.raises(NotFound):
        keystore.rename("missing", "x")
    with pytest.raises(PyCertError, match="already has an entry"):
        keystore.rename("a.example.org", "B.EXAMPLE.ORG")
    keystore.rename("a.example.org", "a.example.org")
    assert not keystore.changed


def test_cli_rename(config, ctx, certwizard_store, capsys):
    base = ["--config", str(config.path)]
    linked = link(ctx, certwizard_store)
    ks.sync(ctx, linked)
    code, _, err = _cli([*base, "edit", "a.example.org", "--rename-keystore-entry"], capsys)
    assert code == 1 and "needs --name" in err
    code, out, err = _cli([*base, "--json", "edit", "a.example.org", "--name", "web a"], capsys)
    assert code == 0, err
    assert json.loads(out)["alias"] == "web a"
    code, out, err = _cli(
        [*base, "edit", "web a", "--name", "web a 2026", "--rename-keystore-entry", "--password-stdin"], capsys, PASSWORD + "\n"
    )
    assert code == 0, err
    assert "Updated name" in out and ks.Keystore.load(certwizard_store, PASSWORD).entry("web a 2026")
    code, _, err = _cli([*base, "edit", "jane doe", "--name", "j", "--rename-keystore-entry", "--password-stdin"], capsys, "x\n")
    assert code == 1 and "not linked" in err
    code, _, err = _cli([*base, "edit", "jane doe"], capsys)
    assert code == 1 and "--name" in err


def test_certwizard_placeholder_keeps_host_type_and_name(ctx, ca, config, tmp_path, two_hosts):
    """CertWizard names its placeholder '<CN> CSR cert'; that is not the certificate's name or kind."""
    user = two_hosts[0]
    ca.auto_approve = False
    ca.sign_after_polls = 10**6
    spec = RequestSpec.build(config, "dev4.example.org", type="host", auth_alias=user.alias, pin="1234567890AB")
    submitted = create_request(ctx, spec, progress=lambda _m: None)
    key = ctx.store.load_key(submitted, ctx.key_passphrase())
    placeholder = placeholder_certificate(key, "dev4.example.org CSR cert")
    path = build_keystore(tmp_path / "cakeystore.pkcs12", [("dev4_renew", key, placeholder, [])])
    ctx.store.delete(ctx.store.get(submitted.alias))
    ks.sync(ctx, link(ctx, path))
    state = ctx.store.get("dev4_renew")
    assert state.status == "SUBMITTED" and state.type == "host" and state.cn == "dev4.example.org"
    # even if an older import recorded it wrongly, the issued certificate corrects it
    state.type, state.cn = "user", "dev4.example.org CSR cert"
    ctx.store.save(state)
    ca.approve_all()
    ca.sign_all()
    done = wait_for_certificate(ctx, state, timeout=30, interval=0.2)
    assert done.type == "host" and done.cn == "dev4.example.org"
    assert not any("issued CN differs" in note for note in done.notes)
    entry = ks.Keystore.load(path, PASSWORD).entry("dev4_renew")
    assert not entry.pending
    assert ks.requested_cn(entry) == "dev4.example.org"
