"""Second-round workflow tests: watch, renew-due, weak keys and polling."""

import datetime as dt
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import certs
from pycert import p12 as p12_module
from pycert.errors import PyCertError
from pycert.store import STATUS_DOWNLOADED, STATUS_REVOKED, STATUS_SIGNED
from pycert.workflow import (
    RequestSpec,
    create_request,
    import_p12,
    poll_once,
    renew,
    renew_due,
    watch,
)


def spec(config, cn="jane doe", **kwargs):
    kwargs.setdefault("email", "test@example.org")
    kwargs.setdefault("pin", "1234567890AB")
    kwargs.setdefault("key_algorithm", "ec")
    return RequestSpec.build(config, cn, **kwargs)


def pending(ctx, config, ca, cn="pending user"):
    ca.auto_approve = False
    return create_request(ctx, spec(config, cn), progress=lambda _m: None)


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------


def test_watch_with_no_pending_requests(ctx):
    report = watch(ctx, interval=0.01, max_cycles=1)
    assert report.cycles == 1
    assert report.polled == 0 and report.downloaded == 0
    assert not report.errors and not report.stopped


def test_watch_stops_immediately_when_event_is_set(ctx):
    event = threading.Event()
    event.set()
    report = watch(ctx, interval=0.01, max_cycles=5, stop_event=event)
    assert report.stopped
    assert report.cycles == 0


def test_watch_polls_pending_state(ctx, config, ca):
    state = pending(ctx, config, ca)
    report = watch(ctx, interval=0.01, max_cycles=1, sleep=lambda _s: None)
    assert report.polled == 1
    assert report.downloaded == 0
    assert ctx.store.get(state.alias).server.status == "NEW"


def test_watch_downloads_and_exports_signed_certificate(ctx, config, ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    state = create_request(ctx, spec(config, "watch signed"), progress=lambda _m: None)
    report = watch(ctx, interval=0.01, max_cycles=1, sleep=lambda _s: None)
    assert report.downloaded == 1
    assert not report.errors
    loaded = ctx.store.get(state.alias)
    assert loaded.status == STATUS_DOWNLOADED
    assert loaded.p12_path


def test_watch_without_export_does_not_loop_forever(ctx, config, ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    state = create_request(ctx, spec(config, "watch no export"), progress=lambda _m: None)
    report = watch(ctx, interval=0.01, max_cycles=3, export=False, sleep=lambda _s: None)
    assert report.downloaded == 1
    assert report.polled == 1  # the second/third cycles skip the stored certificate
    loaded = ctx.store.get(state.alias)
    assert loaded.status == STATUS_SIGNED
    assert not loaded.p12_path


def test_watch_processes_a_pending_renewal(ctx, config, ca, issued):
    state = issued()
    ca.auto_approve = True
    ca.sign_after_polls = 0
    state = renew(ctx, state.alias, progress=lambda _m: None)
    report = watch(ctx, interval=0.01, max_cycles=1, sleep=lambda _s: None)
    assert report.downloaded == 1
    loaded = ctx.store.get(state.alias)
    assert loaded.status == STATUS_DOWNLOADED
    assert loaded.renewal is False


def test_watch_records_errors_and_continues(ctx, config, ca, monkeypatch):
    import pycert.workflow as workflow_module

    state = pending(ctx, config, ca)
    monkeypatch.setattr(
        workflow_module, "poll_once", lambda *a, **k: (_ for _ in ()).throw(PyCertError("boom"))
    )
    report = watch(ctx, interval=0.01, max_cycles=1, sleep=lambda _s: None)
    assert report.errors == [(state.alias, "boom")]
    assert report.downloaded == 0


def test_watch_terminal_certificate_status(ctx, config, ca):
    ca.auto_approve = False
    state = pending(ctx, config, ca)
    record = ca.csrs[state.spki_b64]
    with ca.lock:
        ca._sign_csr(record)
        ca.certificates[record.cert_id].status = "REVOKED"
    report = watch(ctx, interval=0.01, max_cycles=1, sleep=lambda _s: None)
    assert report.downloaded == 0
    assert not report.errors


def test_watch_multiple_pending(ctx, config, ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    create_request(ctx, spec(config, "multi one"), progress=lambda _m: None)
    create_request(ctx, spec(config, "multi two"), progress=lambda _m: None)
    report = watch(ctx, interval=0.01, max_cycles=1, sleep=lambda _s: None)
    assert report.downloaded == 2
    assert report.polled == 2


# ---------------------------------------------------------------------------
# renew_due
# ---------------------------------------------------------------------------


def _state_with_expiry(ctx, alias, days, *, status="DOWNLOADED", renewal=False, spki="x"):
    state = ctx.store.new_state(alias=alias, type="user", cn=alias, email="x@y.z")
    state.cert.not_after = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()
    state.status = status
    state.renewal = renewal
    state.spki_b64 = spki
    ctx.store.save(state)
    return state


def test_renew_due_dry_run_selection(ctx):
    _state_with_expiry(ctx, "soon", 10)
    _state_with_expiry(ctx, "expired", -2)
    far = _state_with_expiry(ctx, "far", 100)
    revoked = _state_with_expiry(ctx, "revoked", 5, status=STATUS_REVOKED)
    renewal = _state_with_expiry(ctx, "renewing", 5, renewal=True)
    no_spki = _state_with_expiry(ctx, "no-spki", 5, spki="")
    results = renew_due(ctx, 30, dry_run=True, progress=lambda _m: None)
    aliases = [state.alias for state, error in results]
    assert aliases == ["expired", "soon"]
    assert far.alias not in aliases
    assert revoked.alias not in aliases
    assert renewal.alias not in aliases
    assert no_spki.alias not in aliases
    assert all(error is None for _state, error in results)


def test_renew_due_no_matches(ctx):
    _state_with_expiry(ctx, "far", 100)
    assert renew_due(ctx, 30, dry_run=True) == []


def test_renew_due_actual(ctx, config, ca, issued):
    state = issued()
    state.cert.not_after = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).isoformat()
    ctx.store.save(state)
    ca.auto_approve = True
    ca.sign_after_polls = 0
    results = renew_due(ctx, 30, progress=lambda _m: None, wait=True, timeout=30, interval=0.2)
    assert len(results) == 1
    renewed, error = results[0]
    assert error is None
    assert renewed.status == STATUS_DOWNLOADED


def test_renew_due_records_failure(ctx, config, ca, issued):
    state = issued()
    state.cert.not_after = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)).isoformat()
    ctx.store.save(state)
    ca.reject_next = [(202, ca._error_xml("no renewal"))]
    results = renew_due(ctx, 30, progress=lambda _m: None)
    assert len(results) == 1
    assert "no renewal" in results[0][1]


# ---------------------------------------------------------------------------
# Weak keys
# ---------------------------------------------------------------------------


def _weak_p12(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak")])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "weak.p12"
    p12_module.write_pkcs12(
        path,
        key=key,
        certificate=certificate,
        chain=[],
        password="weak-password",
        iterations=1000,
        mac_iterations=100,
    )
    return path, certificate


def test_key_strength_helper():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    strong = ec.generate_private_key(ec.SECP256R1())
    assert "RSA" in certs.key_strength_warning(weak.public_key())
    assert certs.key_strength_warning(strong.public_key()) is None


def test_import_weak_key_warns(ctx, tmp_path):
    path, certificate = _weak_p12(tmp_path)
    messages = []
    state = import_p12(
        ctx,
        path,
        "weak-password",
        alias="weak",
        progress=messages.append,
        require_verified_chain=False,
    )
    assert any("RSA key is only 1024" in message for message in messages)
    assert any("1024" in note for note in state.notes)


# ---------------------------------------------------------------------------
# Polling and request-spec edge cases
# ---------------------------------------------------------------------------


def test_poll_unknown_csr_status_is_treated_as_pending(ctx, config, ca):
    ca.auto_approve = False
    state = pending(ctx, config, ca)
    ca.csrs[state.spki_b64].status = "SOMETHING_NEW"
    outcome = poll_once(ctx, state)
    assert outcome.pending is True
    assert outcome.server_status == "SOMETHING_NEW"


def test_poll_certificate_without_id_waits(ctx, config, ca):
    ca.auto_approve = False
    state = pending(ctx, config, ca)
    record = ca.csrs[state.spki_b64]
    with ca.lock:
        ca._sign_csr(record)
        ca.certificates[record.cert_id].status = "VALID"
        ca.certificates[record.cert_id].id = 0  # not used by the server response
        ca.certificates.pop(record.cert_id)
        record.cert_id = 99999
    outcome = poll_once(ctx, state)
    assert outcome.certificate is None
    assert outcome.server_status == "VALID"


@pytest.mark.parametrize(
    "cn,email,type",
    [
        ("Jane Doe", "jane@example.org", "user"),
        ("john  smith", "john@example.org", "user"),
        ("host.example.org", "admin@example.org", "host"),
    ],
)
def test_request_spec_extra_matrix(config, cn, email, type):
    kwargs = {"type": type, "email": email, "pin": "1234567890AB"}
    if type == "host":
        # Build without auth fails, so use a fake alias only for validation of CN/email.
        with pytest.raises(PyCertError, match="authenticated"):
            RequestSpec.build(config, cn, **kwargs)
    else:
        built = RequestSpec.build(config, cn, **kwargs)
        assert built.cn == cn.lower().replace("  ", " ")
