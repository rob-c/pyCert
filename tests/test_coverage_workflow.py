"""Coverage-oriented tests for workflow error paths and expiry helpers."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pycert import workflow
from pycert.errors import CAError, ConfigError, CryptoError, ProtocolError, PyCertError
from pycert.workflow import RequestSpec


def _spec(config, cn="coverage user", **kwargs):
    return RequestSpec.build(config, cn, pin="1234567890AB", key_algorithm="rsa", **kwargs)


def test_common_name_and_modulus_errors(config):
    with pytest.raises(PyCertError):
        workflow.normalize_common_name("   ", "user")
    with pytest.raises(PyCertError):
        workflow.normalize_common_name("x" * 300, "host")
    with pytest.raises(PyCertError):
        workflow.RequestSpec.build(config, "a", type="bad", pin="1234567890AB")
    with pytest.raises(TypeError):
        workflow.RequestSpec.build(config, "a", pin="1234567890AB", unknown=True)
    with pytest.raises(PyCertError):
        workflow.RequestSpec.build(config, "a", type="host", pin="1234567890AB")
    with pytest.raises(PyCertError):
        workflow.RequestSpec.build(config, "a", pin="1234567890AB", auth_alias="x")
    with pytest.raises(PyCertError):
        workflow.RequestSpec.build(config, "a", pin="1234567890AB", san_ip="not-an-ip")
    with pytest.raises(PyCertError):
        workflow.RequestSpec.build(config, "a", pin="1234567890AB", san_email="bad")
    with pytest.raises(PyCertError):
        workflow.RequestSpec.build(config, "a", pin="short")
    key = ec.generate_private_key(ec.SECP256R1())
    cert = SimpleNamespace(public_key=lambda: key.public_key())
    with pytest.raises(CryptoError):
        workflow.modulus_exponent(cert)


def test_request_spec_defaults_and_format(config):
    spec = _spec(config, "format user")
    assert spec.subject().get_attributes_for_oid(workflow.NameOID.COMMON_NAME)
    with pytest.raises(ConfigError):
        workflow._format("{unknown}", SimpleNamespace(cn="x", alias="y"))
    assert workflow._format("{cn}", SimpleNamespace(cn="x y", alias="a")) == "x_y"


def test_create_request_failure_paths(ctx, config, ca, monkeypatch):
    ca.auto_approve = False
    # Host auth alias that does not exist.
    spec = RequestSpec.build(config, "host.example.org", type="host", auth_alias="missing", pin="1234567890AB")
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec)
    # Missing auth certificate after a state exists.
    state = ctx.store.new_state(alias="missing cert", type="host", cn="h", email="h@example.org")
    ctx.store.save(state)
    spec = RequestSpec.build(config, "host.example.org", type="host", auth_alias="missing cert", pin="1234567890AB")
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec)
    # Cancellation in poll.
    user = workflow.create_request(
        ctx, RequestSpec.build(config, "cancel user", pin="1234567890AB", key_algorithm="rsa"), wait=False
    )
    # Use a lightweight event and force poll_once to see it.
    import threading

    event = threading.Event()
    event.set()
    with pytest.raises(PyCertError):
        workflow.poll_once(ctx, ctx.store.get(user.alias), stop_event=event)


def test_renew_and_revoke_failure_paths(ctx, issued, monkeypatch):
    user = issued("renew errors")
    # already in flight
    user.renewal = True
    ctx.store.save(user)
    with pytest.raises(PyCertError):
        workflow.renew(ctx, user.alias)
    user.renewal = False
    ctx.store.save(user)
    # no certificate
    missing = ctx.store.new_state(alias="no cert", type="user", cn="n", email="n@example.org")
    ctx.store.save(missing)
    with pytest.raises(PyCertError):
        workflow.renew(ctx, missing.alias)
    # key mismatch
    real = ctx.store.load_key
    monkeypatch.setattr(ctx.store, "load_key", lambda *a, **k: rsa.generate_private_key(public_exponent=65537, key_size=2048))
    with pytest.raises(PyCertError):
        workflow.renew(ctx, user.alias)
    monkeypatch.setattr(ctx.store, "load_key", real)
    # expiry warning paths
    state = ctx.store.get(user.alias)
    state.cert.not_after = (workflow.datetime.now(workflow.timezone.utc) - timedelta(days=2)).isoformat()
    assert "expired" in workflow.expiry_warning(state)
    state.cert.not_after = (workflow.datetime.now(workflow.timezone.utc) + timedelta(days=2)).isoformat()
    assert "expires" in workflow.expiry_warning(state)
    state.cert.not_after = ""
    assert workflow.expiry_warning(state) is None


def test_verify_and_import_failure_paths(ctx, issued, tmp_path):
    user = issued("verify errors")
    report = workflow.verify(ctx, user.alias)
    assert report.ok
    missing = ctx.store.new_state(alias="verify missing", type="user", cn="v", email="v@example.org")
    ctx.store.save(missing)
    report = workflow.verify(ctx, missing.alias)
    assert not report.ok
    with pytest.raises(PyCertError):
        workflow.import_p12(ctx, tmp_path / "missing.p12", "password")


def test_normalize_common_name_and_request_spec_errors(config):
    with pytest.raises(PyCertError):
        workflow.normalize_common_name("x" * 65 + " y", "user")
    config.identity.ra = ""
    config.identity.ou = ""
    config.identity.l = ""
    with pytest.raises(PyCertError):
        RequestSpec.build(config, "user name", pin="1234567890AB")
    config.identity.ra = "CLRC DL"
    with pytest.raises(PyCertError):
        RequestSpec.build(config, "user name", pin="1234567890AB", auth_alias="x")
    with pytest.raises(PyCertError):
        RequestSpec.build(config, "host.example.org", type="host", pin="1234567890AB")
    with pytest.raises(PyCertError):
        RequestSpec.build(config, "user name", pin="1234567890AB", san_email="bad")


def test_create_request_crypto_failure_paths(ctx, config, ca, monkeypatch):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(config, "crypto user", pin="1234567890AB", key_algorithm="rsa")
    monkeypatch.setattr(workflow.csr_module, "signature_valid", lambda _csr: False)
    with pytest.raises(CryptoError):
        workflow.create_request(ctx, spec)


def test_wait_and_download_failure_paths(ctx, issued, monkeypatch):
    user = issued("download failure")
    state = ctx.store.get(user.alias)
    state.spki_b64 = ""
    with pytest.raises(PyCertError):
        workflow.poll_once(ctx, state)
    state = ctx.store.get(user.alias)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    real_load_key = ctx.store.load_key
    monkeypatch.setattr(ctx.store, "load_key", lambda *a, **k: other)
    with pytest.raises(CryptoError):
        workflow.download_and_export(ctx, state, certificate=ctx.store.load_certificate(state), cert_id="1", export=False)
    monkeypatch.setattr(ctx.store, "load_key", real_load_key)
    # Invalid certificate and CLI filename handling.
    state = ctx.store.get(user.alias)
    state.cn = "different name"
    ctx.store.save(state)
    workflow.download_and_export(
        ctx, state, certificate=ctx.store.load_certificate(state), cert_id="1", export=False,
        progress=lambda _msg: None,
    )


def test_export_filename_template(ctx, issued, tmp_path):
    user = issued("export template")
    state = ctx.store.get(user.alias)
    original = ctx.config.p12.filename_template
    ctx.config.p12.filename_template = "noextension"
    try:
        path = workflow.export_p12(ctx, state, out=tmp_path / "out.p12")
        assert path.suffix == ".p12"
    finally:
        ctx.config.p12.filename_template = original


def test_renew_ping_and_pin_failures(ctx, issued, monkeypatch):
    user = issued("renew failure")
    original_client = ctx.client

    class Dead:
        last_error = "dead"

        def ping(self):
            return False

    monkeypatch.setattr(ctx, "client", lambda: Dead())
    with pytest.raises(CAError):
        workflow.renew(ctx, user.alias)
    monkeypatch.setattr(ctx, "client", original_client)
    with pytest.raises(PyCertError):
        workflow.renew(ctx, user.alias, pin="x")


def test_verify_weak_key_and_missing_p12(ctx, issued):
    user = issued("verify weak")
    ctx.store.get(user.alias)
    report = workflow.verify(ctx, user.alias)
    assert report.ok
    missing = ctx.store.new_state(alias="verify missing key", type="user", cn="x", email="x@example.org")
    ctx.store.save(missing)
    report = workflow.verify(ctx, missing.alias)
    assert not report.ok


def test_refresh_and_housekeeping_errors(ctx, issued, monkeypatch):
    user = issued("refresh error")
    state = ctx.store.get(user.alias)
    state.set_status("SUBMITTED", "test")
    ctx.store.save(state)
    monkeypatch.setattr(workflow, "poll_once", lambda *a, **k: (_ for _ in ()).throw(PyCertError("poll")))
    results = workflow.refresh_all(ctx)
    assert results and "error" in results[0][1]
    assert workflow.list_ras(ctx)
    state.cert.not_after = ""
    assert workflow.expiry_warning(state) is None


def test_trust_anchors_and_common_name_user_long(ctx, config):
    ctx.config.use_system_trust = lambda: True
    anchors = ctx.anchors()
    assert anchors
    with pytest.raises(PyCertError):
        workflow.normalize_common_name("a" * 65 + " b", "user")


def test_host_auth_expired_and_key_mismatch(ctx, issued, config, monkeypatch):
    user = issued("host auth bad")
    spec = RequestSpec.build(config, "host.example.org", type="host", auth_alias=user.alias, pin="1234567890AB")
    monkeypatch.setattr(workflow.certs, "certificate_valid_at", lambda *a: False)
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec)
    monkeypatch.setattr(workflow.certs, "certificate_valid_at", lambda *a: True)
    monkeypatch.setattr(workflow.certs, "certificate_matches_key", lambda *a: False)
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec)


def test_short_pin_and_public_key_match(ctx, config, ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(config, "short pin user", pin="1234567890AB", key_algorithm="rsa")
    spec.pin = "x"
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec)
    state = SimpleNamespace(active_spki_b64="")
    assert workflow._public_key_matches(None, state, ctx) is True


def test_wait_cancel_and_terminal(ctx, issued, monkeypatch):
    user = issued("wait terminal")
    state = ctx.store.get(user.alias)
    event = __import__("threading").Event()
    event.set()
    with pytest.raises(PyCertError):
        workflow.wait_for_certificate(ctx, state, stop_event=event, timeout=1)
    monkeypatch.setattr(workflow, "poll_once", lambda *a, **k: SimpleNamespace(
        state=state, certificate=None, cert_id="", terminal=True, server_status="REVOKED", message="no"
    ))
    with pytest.raises(CAError):
        workflow.wait_for_certificate(ctx, state, timeout=1)


def test_renew_cn_note_and_san_values(ctx, issued):
    user = issued("cn note")
    state = ctx.store.get(user.alias)
    state.cn = "different name"
    ctx.store.save(state)
    renewed = workflow.renew(ctx, user.alias, pin="1234567890AB")
    assert renewed.renewal is True
    assert workflow._san_values(ctx.store.load_certificate(renewed), workflow.x509.DNSName) == []


def test_revoke_missing_id_and_failure(ctx, issued, monkeypatch):
    user = issued("revoke missing id")
    state = ctx.store.get(user.alias)
    state.server.cert_id = ""
    ctx.store.save(state)
    monkeypatch.setattr(workflow, "poll_once", lambda *a, **k: SimpleNamespace(
        state=state, cert_id="", server_status="VALID", certificate=None
    ))
    with pytest.raises(CAError):
        workflow.revoke(ctx, user.alias, "unspecified")
    state.server.cert_id = "1"
    ctx.store.save(state)
    monkeypatch.setattr(ctx, "client", lambda: SimpleNamespace(
        revoke=lambda *a, **k: SimpleNamespace(success=False, message="no", detail="detail", status=500)
    ))
    with pytest.raises(CAError):
        workflow.revoke(ctx, user.alias, "unspecified")


def test_import_duplicate_and_verify_missing_key(ctx, issued, tmp_path):
    user = issued("import duplicate")
    with pytest.raises(PyCertError):
        workflow.import_p12(ctx, tmp_path / "x.p12", "password", alias=user.alias)
    state = ctx.store.get(user.alias)
    (ctx.store.path(state) / "key.pem").unlink()
    report = workflow.verify(ctx, user.alias)
    assert not report.ok


def test_watch_sleep_and_stop(ctx):
    import threading

    event = threading.Event()
    event.set()
    assert workflow._watch_sleep(1, event, lambda _s: None) is False
    report = workflow.watch(ctx, max_cycles=1, stop_event=event)
    assert report.stopped is True


def test_export_default_filename_and_sanless_cert(ctx, issued):
    user = issued("export default")
    state = ctx.store.get(user.alias)
    original = ctx.config.p12.filename_template
    ctx.config.p12.filename_template = "noextension"
    try:
        path = workflow.export_p12(ctx, state)
        assert path.suffix == ".p12"
    finally:
        ctx.config.p12.filename_template = original


def test_san_values_without_extension(ctx, issued):
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no san")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now)
        .sign(key, hashes.SHA256())
    )
    assert workflow._san_values(cert, x509.DNSName) == []


def test_revoke_key_mismatch(ctx, issued, monkeypatch):
    user = issued("revoke key mismatch")
    state = ctx.store.get(user.alias)
    state.server.cert_id = "1"
    ctx.store.save(state)
    monkeypatch.setattr(workflow.certs, "certificate_matches_key", lambda *a: False)
    with pytest.raises(PyCertError):
        workflow.revoke(ctx, user.alias, "unspecified")


def test_verify_weak_key_and_bad_p12(ctx, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    from datetime import datetime, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + __import__("datetime").timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    state = ctx.store.new_state(alias="weak", type="user", cn="weak", email="w@example.org")
    ctx.store.save(state)
    ctx.store.save_key(state, key, ctx.key_passphrase())
    ctx.store.save_certificate(state, cert, [])
    state.p12_path = str(tmp_path / "missing.p12")
    ctx.store.save(state)
    report = workflow.verify(ctx, "weak")
    assert any("RSA key" in warning for warning in report.warnings)
    assert not report.ok


def test_user_long_name_and_short_pin_paths(ctx, config, ca):
    with pytest.raises(PyCertError):
        workflow.normalize_common_name("a" * 65 + " b", "user")
    ca.auto_approve = True
    ca.sign_after_polls = 0
    spec = RequestSpec.build(config, "short pin path", pin="1234567890AB", key_algorithm="rsa")
    spec.pin = "x"
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec)


def test_poll_no_inline_download_and_key_mismatch(ctx, issued, ca, monkeypatch):
    user = issued("poll inline")
    state = ctx.store.get(user.alias)
    ca.lookup_mode = "no_inline"
    outcome = workflow.poll_once(ctx, state)
    assert outcome.certificate is not None
    ca.lookup_mode = "wrong_pem"
    with pytest.raises(ProtocolError):
        workflow.poll_once(ctx, ctx.store.get(user.alias))
    ca.lookup_mode = "normal"


def test_export_bad_filename_and_renewal_failure(ctx, issued, config, monkeypatch):
    user = issued("export bad name")
    state = ctx.store.get(user.alias)
    original = config.p12.filename_template
    config.p12.filename_template = "../evil"
    try:
        with pytest.raises(ConfigError):
            workflow.export_p12(ctx, state)
    finally:
        config.p12.filename_template = original
    monkeypatch.setattr(ctx, "client", lambda: SimpleNamespace(
        ping=lambda: True,
        submit_authenticated=lambda **k: (_ for _ in ()).throw(PyCertError("fail")),
    ))
    with pytest.raises(PyCertError):
        workflow.renew(ctx, user.alias, pin="1234567890AB", email="new@example.org")


def test_user_renewal_adds_contact_when_missing(ctx, config, ca):
    # A user certificate with no e-mail SAN is unusual but exercises the
    # renewal contact fallback.
    state = ctx.store.new_state(alias="no email user", type="user", cn="no email", email="")
    ctx.store.save(state)
    with pytest.raises(PyCertError):
        workflow.renew(ctx, state.alias)


def test_reports_as_dict_and_p12_errors(ctx, issued):
    from pycert.workflow import VerifyReport, WatchReport

    report = VerifyReport(alias="x", ok=True)
    assert report.as_dict()["alias"] == "x"
    watch = WatchReport()
    assert watch.as_dict()["cycles"] == 0
    state = issued("p12 verify bad")
    state.p12_path = str(__import__("pathlib").Path("/missing/none.p12"))
    ctx.store.save(state)
    report = workflow.verify(ctx, state.alias)
    assert not report.ok


def test_wait_text_output(e2e, ca):
    ca.auto_approve = False
    result = e2e.request_user("wait text")
    alias = result.json["alias"]
    state = e2e.state(alias)
    e2e.sign(state)
    waited = e2e.run("wait", alias, "--interval", "0.1", "--timeout", "10")
    assert waited.code == 0
    assert "Certificate for" in waited.out


def test_name_too_long_and_invalid_issued_certificate(ctx, issued, monkeypatch):
    with pytest.raises(PyCertError):
        workflow.normalize_common_name("a" * 65 + " bb", "user")
    user = issued("invalid issued")
    state = ctx.store.get(user.alias)
    cert = ctx.store.load_certificate(state)
    monkeypatch.setattr(workflow.certs, "certificate_valid_at", lambda c: False)
    with pytest.raises(CryptoError):
        workflow.download_and_export(ctx, state, certificate=cert)


def test_duplicate_import_and_bad_p12_verify(ctx, issued, tmp_path):
    user = issued("duplicate import")
    from pycert import p12

    src = tmp_path / "dup.p12"
    key = ctx.store.load_key(user, ctx.key_passphrase())
    cert = ctx.store.load_certificate(user)
    p12.write_pkcs12(src, key=key, certificate=cert, password="x")
    with pytest.raises(PyCertError):
        workflow.import_p12(ctx, src, password="x", alias=user.alias)
    state = ctx.store.get(user.alias)
    state.p12_path = str(tmp_path / "not-a-p12")
    __import__("pathlib").Path(state.p12_path).write_text("bad")
    ctx.store.save(state)
    report = workflow.verify(ctx, state.alias)
    assert not report.ok
