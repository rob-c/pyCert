import hashlib
import stat
from pathlib import Path

import pytest

from pycert import certs
from pycert import chain as chain_module
from pycert import p12 as p12_module
from pycert.errors import CAError, ChainError, CryptoError, PyCertError, TimeoutWaiting
from pycert.store import STATUS_APPROVED, STATUS_DOWNLOADED, STATUS_REVOKED, STATUS_SUBMITTED
from pycert.workflow import (
    RequestSpec,
    create_request,
    download_and_export,
    export_p12,
    generate_pin,
    import_p12,
    install_pem,
    pin_hash,
    poll_once,
    refresh_all,
    renew,
    revoke,
    verify,
    wait_for_certificate,
)


def test_pin_hash_matches_java_convention():
    expected = hashlib.sha1(b"1234567890AB").hexdigest().upper()
    assert pin_hash("1234567890AB", "sha1") == expected
    assert len(expected) == 40
    assert pin_hash("1234567890AB", "sha256") == hashlib.sha256(b"1234567890AB").hexdigest().upper()


def test_generate_pin_shape():
    pin = generate_pin()
    assert len(pin) == 14
    assert pin.count("-") == 2
    assert all(ch.isalnum() or ch == "-" for ch in pin)
    assert not set(pin.upper()) & set("IO01")


@pytest.mark.parametrize(
    "kwargs,match",
    [
        ({"cn": "single", "type": "user"}, "two names"),
        ({"cn": "jane doe", "type": "host"}, "fully qualified"),
        ({"cn": "host..example.org", "type": "host"}, "not a valid DNS"),
        ({"cn": "jane doe", "type": "user", "email": "nope"}, "valid e-mail"),
        ({"cn": "jane doe", "type": "user", "pin": "short"}, "at least 10"),
        ({"cn": "host.example.org", "type": "host", "auth_alias": ""}, "must be authenticated"),
        ({"cn": "jane doe", "type": "user", "ra": "onlyone"}, "invalid RA"),
        ({"cn": "jane doe", "type": "user", "san_dns": ["bad host"]}, "fully qualified|not a valid DNS"),
        ({"cn": "jane doe", "type": "user", "san_ip": ["999.1.1.1"]}, "address"),
    ],
)
def test_request_spec_validation(config, kwargs, match):
    cn = kwargs.pop("cn")
    kwargs.setdefault("email", "test@example.org")
    with pytest.raises(PyCertError, match=match):
        RequestSpec.build(config, cn, **kwargs)


def test_request_spec_rejects_non_ascii(config):
    with pytest.raises(PyCertError, match="non-ASCII"):
        RequestSpec.build(config, "josé garcía", email="jose@example.org")


def test_request_spec_normalises(config):
    spec = RequestSpec.build(config, "  Jane   Doe ", email=" Jane@Example.ORG ")
    assert spec.cn == "jane doe"
    assert spec.email == "Jane@Example.ORG"
    assert spec.ou == "CLRC" and spec.l == "DL"


def test_full_request_produces_files_and_valid_chain(ctx, issued):
    state = issued()
    assert state.status == STATUS_DOWNLOADED
    assert state.cert.verified is True
    assert len(state.cert.chain_sha256) == 3
    directory = ctx.store.path(state)
    for name in ("key.pem", "request.csr", "cert.pem", "chain.pem", "fullchain.pem", "state.json"):
        assert (directory / name).is_file(), name
    assert state.p12_path and Path(state.p12_path).is_file()
    assert stat.S_IMODE((directory / "key.pem").stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(state.p12_path).stat().st_mode) == 0o600
    report = verify(ctx, state.alias)
    assert report.ok, report.checks


def test_poll_reports_csr_states(ctx, config, ca):
    ca.auto_approve = False
    spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
    state = create_request(ctx, spec, progress=lambda _m: None)
    assert state.status == STATUS_SUBMITTED
    outcome = poll_once(ctx, state)
    assert outcome.pending and outcome.server_status == "NEW"
    ca.approve_all()
    outcome = poll_once(ctx, state)
    assert outcome.state.status == STATUS_APPROVED
    ca.sign_all()
    outcome = poll_once(ctx, state)
    assert outcome.certificate is not None
    assert outcome.server_status == "VALID"


def test_wait_timeout_raises_timeout_waiting(ctx, config, ca):
    ca.auto_approve = False
    spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
    state = create_request(ctx, spec, progress=lambda _m: None)
    with pytest.raises(TimeoutWaiting, match="timed out"):
        wait_for_certificate(ctx, state, timeout=0.6, interval=0.2, progress=lambda _m: None)
    # the request is still stored and can be polled later
    assert ctx.store.get(state.alias).status == STATUS_SUBMITTED


def test_submission_rejection_marks_failed(ctx, config, ca):
    ca.reject_next = [(202, ca._error_xml("the RA says no"))]
    spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
    with pytest.raises(CAError, match="RA says no"):
        create_request(ctx, spec, progress=lambda _m: None)
    state = ctx.store.get("jane doe")
    assert state.status == "FAILED"
    assert Path(state.p12_path or "/nonexistent").exists() is False


def test_duplicate_alias_is_refused(ctx, config, issued):
    issued()
    spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
    with pytest.raises(PyCertError, match="already exists"):
        create_request(ctx, spec, progress=lambda _m: None)


def test_unverified_chain_stores_certificate_but_refuses_pkcs12(ctx, config, ca, monkeypatch):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    monkeypatch.setattr(
        ctx,
        "build_chain",
        lambda certificate, *_args, **_kwargs: chain_module.ChainResult(
            [certificate], complete=False, trusted=False, problems=["test: no anchor"]
        ),
    )
    spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
    with pytest.raises(ChainError):
        create_request(ctx, spec, wait=True, timeout=20, interval=0.2, progress=lambda _m: None)
    state = ctx.store.get("jane doe")
    assert state.status == "SIGNED"
    assert state.cert.verified is False
    assert ctx.store.cert_path(state).is_file()
    assert not state.p12_path
    # explicit opt-in allows the export
    state = download_and_export(ctx, state, require_verified_chain=False, progress=lambda _m: None)
    assert state.status == STATUS_DOWNLOADED
    assert Path(state.p12_path).is_file()


def test_renewal_archives_previous_and_replaces_files(ctx, config, ca, issued):
    state = issued()
    old_key = ctx.store.load_key(state, ctx.key_passphrase())
    old_cert = ctx.store.load_certificate(state)
    old_spki = state.spki_b64
    ca.auto_approve = True
    ca.sign_after_polls = 1
    state = renew(ctx, state.alias, progress=lambda _m: None, email="new@example.org")
    assert state.renewal is True
    assert ctx.store.file(state, "key.next.pem").is_file()
    assert ctx.store.cert_path(state).is_file()  # old certificate still in place
    state = wait_for_certificate(ctx, state, timeout=30, interval=0.2, progress=lambda _m: None)
    assert state.renewal is False
    assert state.status == STATUS_DOWNLOADED
    assert state.spki_b64 != old_spki
    new_key = ctx.store.load_key(state, ctx.key_passphrase())
    assert not certs.public_keys_equal(new_key.public_key(), old_key.public_key())
    new_cert = ctx.store.load_certificate(state)
    assert certs.fingerprint(new_cert) != certs.fingerprint(old_cert)
    assert certs.certificate_matches_key(new_cert, new_key)
    previous = ctx.store.path(state) / "previous"
    archives = [p for p in previous.iterdir() if p.is_dir()]
    assert archives
    assert (archives[0] / "cert.pem").is_file()
    assert (archives[0] / "key.pem").is_file()


def test_renewal_failure_keeps_current_certificate(ctx, config, ca, issued):
    state = issued()
    old_cert_bytes = ctx.store.cert_path(state).read_bytes()
    old_key_bytes = ctx.store.file(state, "key.pem").read_bytes()
    ca.fail_next("/CSR", status=202, body=ca._error_xml("no renewal for you"))
    with pytest.raises(CAError):
        renew(ctx, state.alias, progress=lambda _m: None)
    state = ctx.store.get(state.alias)
    assert state.renewal is False
    assert state.status == "FAILED"
    assert ctx.store.cert_path(state).read_bytes() == old_cert_bytes
    assert ctx.store.file(state, "key.pem").read_bytes() == old_key_bytes
    assert not ctx.store.file(state, "key.next.pem").exists()


def test_revoke_refuses_while_renewal_pending(ctx, issued, ca):
    state = issued()
    ca.auto_approve = False
    state = renew(ctx, state.alias, progress=lambda _m: None)
    with pytest.raises(PyCertError, match="renewal in flight"):
        revoke(ctx, state.alias, progress=lambda _m: None)


def test_revoke(ctx, issued, ca):
    state = issued()
    state = revoke(ctx, state.alias, reason="superseded", progress=lambda _m: None)
    assert state.status == STATUS_REVOKED
    assert ca.certificates[int(state.server.cert_id)].status == "REVOKED"
    with pytest.raises(PyCertError, match="already marked revoked"):
        revoke(ctx, state.alias, progress=lambda _m: None)


def test_host_request_flow(ctx, config, ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    user = ctx.store.get("jane doe") if ctx.store.exists("jane doe") else None
    if user is None:
        spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
        user = create_request(ctx, spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    host_spec = RequestSpec.build(
        config,
        "host.example.ac.uk",
        type="host",
        email="admin@example.org",
        pin="1234567890AB",
        auth_alias=user.alias,
    )
    host = create_request(ctx, host_spec, wait=True, timeout=30, interval=0.2, progress=lambda _m: None)
    assert host.status == STATUS_DOWNLOADED
    certificate = ctx.store.load_certificate(host)
    sans = certs.subject_alt_names(certificate)
    assert "DNS:host.example.ac.uk" in sans


def test_import_pkcs12(ctx, config, issued, tmp_path):
    state = issued()
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    chain_certs = ctx.store.load_chain(state)
    path = tmp_path / "import.p12"
    p12_module.write_pkcs12(
        path,
        key=key,
        certificate=certificate,
        chain=chain_certs,
        password="import-pass",
        friendly_name="import",
    )
    imported = import_p12(ctx, path, "import-pass", alias="imported", progress=lambda _m: None)
    assert imported.status == "IMPORTED"
    assert imported.cert.verified is True
    assert imported.subject == imported.cert.subject
    assert imported.key_bits > 0
    report = verify(ctx, "imported")
    assert report.ok
    # re-export with the saved secret
    exported = export_p12(ctx, imported, progress=lambda _m: None)
    assert exported.is_file()
    assert p12_module.read_pkcs12(exported, ctx.p12_passphrase())


def test_import_rejects_wrong_password(ctx, issued, tmp_path):
    state = issued()
    with pytest.raises(CryptoError):
        import_p12(ctx, Path(state.p12_path), "wrong", progress=lambda _m: None)


def test_export_accepts_custom_password_and_path(ctx, issued, tmp_path):
    state = issued()
    out = tmp_path / "custom.p12"
    path = export_p12(ctx, state, password="a-different-passphrase", out=out, progress=lambda _m: None)
    assert path == out
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    bundle = p12_module.read_pkcs12(out, "a-different-passphrase")
    assert certs.fingerprint(bundle.cert) == certs.fingerprint(ctx.store.load_certificate(state))
    with pytest.raises(CryptoError):
        p12_module.read_pkcs12(out, ctx.p12_passphrase())


def test_install_pem_modes(ctx, issued, tmp_path):
    state = issued()
    target = tmp_path / "globus"
    # userkey.pem needs a new passphrase: never the saved secret, never empty by default
    with pytest.raises(PyCertError, match="needs a new passphrase"):
        install_pem(ctx, state.alias, target, progress=lambda _m: None)
    with pytest.raises(PyCertError, match="not pyCertWiz's own saved secret"):
        install_pem(ctx, state.alias, target, password=ctx.p12_passphrase(), progress=lambda _m: None)
    paths = install_pem(ctx, state.alias, target, password="grid-proxy-pass", progress=lambda _m: None)
    assert stat.S_IMODE(paths["cert"].stat().st_mode) == 0o644
    assert stat.S_IMODE(paths["key"].stat().st_mode) == 0o400
    with pytest.raises(CryptoError):
        certs.load_private_key(paths["key"].read_bytes())
    key = certs.load_private_key(paths["key"].read_bytes(), "grid-proxy-pass")
    assert certs.key_description(key.public_key()) == state.key_algorithm


def test_private_keys_are_never_serialised_without_a_passphrase(ctx, issued):
    key = ctx.store.load_key(issued("no plain keys"), ctx.key_passphrase())
    for empty in (None, "", b""):
        with pytest.raises(CryptoError, match="without passphrase"):
            certs.key_pem(key, empty)


def test_refresh_all(ctx, config, ca):
    ca.auto_approve = False
    spec = RequestSpec.build(config, "jane doe", email="test@example.org", pin="1234567890AB")
    state = create_request(ctx, spec, progress=lambda _m: None)
    results = refresh_all(ctx, progress=lambda _m: None)
    assert results and results[0][0].alias == state.alias
    assert results[0][1] == "NEW"


def test_verify_warns_about_imminent_expiry(ctx, issued):
    from datetime import timedelta

    from pycert.util import parse_iso

    state = issued()
    near_expiry = parse_iso(state.cert.not_after) - timedelta(days=5)
    report = verify(ctx, state.alias, now=near_expiry)
    assert report.warnings
    assert "expires" in report.warnings[0]
    assert report.ok is True


def test_verify_detects_corrupt_certificate(ctx, issued):
    state = issued()
    ctx.store.cert_path(state).write_bytes(b"this is not a certificate")
    report = verify(ctx, state.alias)
    assert report.ok is False
    checks = {name: passed for name, passed, _ in report.checks}
    assert checks["certificate present"] is False


def test_verify_detects_replaced_certificate(ctx, issued):
    state = issued()
    other = ctx.store.load_chain(state)[0]
    ctx.store.cert_path(state).write_bytes(certs.cert_pem(other).encode())
    report = verify(ctx, state.alias)
    assert report.ok is False
    checks = {name: passed for name, passed, _ in report.checks}
    assert checks["key matches certificate"] is False


def test_custom_p12_filename_template(ctx, config, issued):
    state = issued()
    config.p12.filename_template = "{alias}-live.p12"
    path = export_p12(ctx, state, progress=lambda _m: None)
    assert path.name.endswith("-live.p12")
