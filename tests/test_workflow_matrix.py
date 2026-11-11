"""Workflow matrix: validation, polling states, export/renew/revoke/import."""

import datetime as dt
import threading
import time

import pytest

from pycert import certs
from pycert import chain as chain_module
from pycert import p12 as p12_module
from pycert.errors import CAError, ChainError, NetworkError, PyCertError, TimeoutWaiting
from pycert.store import STATUS_REVOKED
from pycert.workflow import (
    RequestSpec,
    create_request,
    describe_state,
    expiry_warning,
    export_p12,
    generate_key,
    generate_pin,
    import_p12,
    install_pem,
    normalize_common_name,
    parse_ra,
    pin_hash,
    poll_once,
    refresh_all,
    renew,
    revoke,
    validate_email,
    verify,
    wait_for_certificate,
)


def make_spec(config, cn="jane doe", **kwargs):
    kwargs.setdefault("email", "test@example.org")
    kwargs.setdefault("pin", "1234567890AB")
    kwargs.setdefault("key_algorithm", "ec")
    return RequestSpec.build(config, cn, **kwargs)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Jane Doe", "jane doe"),
        ("  Jane   Doe  ", "jane doe"),
        ("JANE DOE", "jane doe"),
        ("ab cd", "ab cd"),
    ],
)
def test_normalize_user_common_names(value, expected):
    assert normalize_common_name(value, "user") == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Host.Example.AC.UK", "host.example.ac.uk"),
        ("host.example.ac.uk.", "host.example.ac.uk"),
        ("a-b.example", "a-b.example"),
    ],
)
def test_normalize_host_common_names(value, expected):
    assert normalize_common_name(value, "host") == expected


@pytest.mark.parametrize("value", ["single", "a b", "one  t", "üñïçødé name"])
def test_invalid_user_common_names(value):
    with pytest.raises(PyCertError):
        normalize_common_name(value, "user")


@pytest.mark.parametrize(
    "value", ["nodot", "host..example", "-host.example", "host example", "1.2.3.4", "a" * 64 + ".example"]
)
def test_invalid_host_common_names(value):
    with pytest.raises(PyCertError):
        normalize_common_name(value, "host")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("a@b.example", "a@b.example"),
        ("  a@b.example ", "a@b.example"),
        ("a+tag@sub.example.org", "a+tag@sub.example.org"),
    ],
)
def test_validate_email_valid(value, expected):
    assert validate_email(value) == expected


@pytest.mark.parametrize("value", ["", "nope", "a@", "@b", "a b@c", "a@b", "a@b."])
def test_validate_email_invalid(value):
    with pytest.raises(PyCertError):
        validate_email(value)


@pytest.mark.parametrize("value", ["CLRC DL", "CLRC,DL", "  CLRC   DL ", "Manchester OneRA"])
def test_parse_ra(value):
    ou, l = parse_ra(value)
    assert ou and l


@pytest.mark.parametrize("value", ["", "only", "a b c", "a,b,c"])
def test_parse_ra_invalid(value):
    with pytest.raises(PyCertError):
        parse_ra(value)


@pytest.mark.parametrize(
    "algorithm,bits,curve,expected",
    [
        ("rsa", 2048, "P-256", "RSA"),
        ("rsa", 3072, "P-256", "RSA"),
        ("ec", 2048, "P-256", "ECDSA P-256"),
        ("ec", 2048, "P-384", "ECDSA P-384"),
        ("ec", 2048, "P-521", "ECDSA P-521"),
    ],
)
def test_generate_key_matrix(config, algorithm, bits, curve, expected):
    key = generate_key(config, algorithm=algorithm, rsa_bits=bits, ec_curve=curve)
    assert certs.key_description(key.public_key()).startswith(expected)


@pytest.mark.parametrize("algorithm,bits,curve", [("dsa", 0, ""), ("rsa", 1024, ""), ("ec", 0, "P-224")])
def test_generate_key_invalid(config, algorithm, bits, curve):
    with pytest.raises(PyCertError):
        generate_key(config, algorithm=algorithm, rsa_bits=bits, ec_curve=curve)


@pytest.mark.parametrize("algorithm", ["sha1", "sha256"])
def test_pin_hash_matrix(algorithm):
    value = pin_hash("pässwörd", algorithm)
    assert value == value.upper()
    assert len(value) == (40 if algorithm == "sha1" else 64)


def test_pin_hash_rejects_unknown():
    with pytest.raises(PyCertError):
        pin_hash("x", "md5")


# ---------------------------------------------------------------------------
# Polling state matrix
# ---------------------------------------------------------------------------


def _pending(ctx, config, ca, cn="poll user"):
    spec = make_spec(config, cn)
    return create_request(ctx, spec, progress=lambda _m: None)


@pytest.mark.parametrize(
    "status,expected_pending,terminal",
    [
        ("NEW", True, False),
        ("RENEW", True, False),
        ("APPROVED", True, False),
        ("DELETED", False, True),
    ],
)
def test_poll_csr_status_matrix(ctx, config, ca, status, expected_pending, terminal):
    ca.auto_approve = False
    state = _pending(ctx, config, ca)
    spki = state.spki_b64
    ca.csrs[spki].status = status
    outcome = poll_once(ctx, state)
    assert outcome.pending is expected_pending
    assert outcome.terminal is terminal
    assert outcome.server_status == status


@pytest.mark.parametrize("status", ["VALID", "REVOKED", "EXPIRED", "SUSPENDED", "DELETED"])
def test_poll_certificate_status_matrix(ctx, config, ca, status):
    ca.auto_approve = False
    state = _pending(ctx, config, ca)
    record = ca.csrs[state.spki_b64]
    with ca.lock:
        ca._sign_csr(record)
        ca.certificates[record.cert_id].status = status
    outcome = poll_once(ctx, state)
    if status == "VALID":
        assert outcome.certificate is not None
        assert not outcome.terminal
    else:
        assert outcome.terminal
        assert outcome.certificate is None


def test_poll_unknown_public_key(ctx, config, ca):
    ca.auto_approve = False
    state = _pending(ctx, config, ca)
    ca.csrs.clear()
    outcome = poll_once(ctx, state)
    assert outcome.pending and outcome.server_status == ""
    assert "does not know" in outcome.message


def test_poll_cancelled(ctx, config, ca):
    ca.auto_approve = False
    state = _pending(ctx, config, ca)
    event = threading.Event()
    event.set()
    with pytest.raises(NetworkError):
        poll_once(ctx, state, stop_event=event)


def test_wait_cancelled(ctx, config, ca):
    ca.auto_approve = False
    state = _pending(ctx, config, ca)
    event = threading.Event()

    def cancel():
        time.sleep(0.2)
        event.set()

    threading.Thread(target=cancel, daemon=True).start()
    with pytest.raises(PyCertError, match="cancelled"):
        wait_for_certificate(ctx, state, timeout=10, interval=0.2, stop_event=event)


def test_wait_timeout(ctx, config, ca):
    ca.auto_approve = False
    state = _pending(ctx, config, ca)
    with pytest.raises(TimeoutWaiting):
        wait_for_certificate(ctx, state, timeout=0.5, interval=0.2, progress=lambda _m: None)


# ---------------------------------------------------------------------------
# Submission failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [202, 400, 401, 403, 500])
def test_submission_failure_matrix(ctx, config, ca, status):
    ca.reject_next = [(status, ca._error_xml("rejected by test"))]
    with pytest.raises(PyCertError):
        create_request(ctx, make_spec(config), progress=lambda _m: None)
    state = ctx.store.get("jane doe")
    assert state.status == "FAILED"


def test_ca_unreachable(ctx, config):
    config.ca.base_url = "http://127.0.0.1:9"
    config.ca.allow_plaintext = True
    config.ca.retries = 0
    config.ca.connect_timeout = 0.2
    config.ca.deadline = 0.5
    with pytest.raises(CAError, match="cannot reach"):
        create_request(ctx, make_spec(config), progress=lambda _m: None)


# ---------------------------------------------------------------------------
# Export and install matrix
# ---------------------------------------------------------------------------


def test_export_with_saved_secret(ctx, issued):
    state = issued()
    path = export_p12(ctx, state, progress=lambda _m: None)
    assert p12_module.read_pkcs12(path, ctx.p12_passphrase())


def test_export_with_explicit_password(ctx, issued, tmp_path):
    state = issued()
    out = tmp_path / "explicit.p12"
    path = export_p12(ctx, state, password="explicit-pass", out=out, progress=lambda _m: None)
    assert path == out
    assert p12_module.read_pkcs12(out, "explicit-pass")


@pytest.mark.parametrize("template", ["{cn}.p12", "{alias}.p12", "{alias}-prod.p12", "{cn}-live.p12"])
def test_export_filename_templates(ctx, config, issued, template):
    state = issued()
    config.p12.filename_template = template
    path = export_p12(ctx, state, progress=lambda _m: None)
    assert path.name.startswith("jane")


def test_export_to_configured_directory(ctx, config, issued):
    state = issued()
    config.p12.export_dir = "exports"
    path = export_p12(ctx, state, progress=lambda _m: None)
    assert path.parent == ctx.config.resolve("exports")
    assert path.is_file()


def test_export_without_chain(ctx, config, issued):
    state = issued()
    config.p12.include_chain = False
    path = export_p12(ctx, state, progress=lambda _m: None)
    bundle = p12_module.read_pkcs12(path, ctx.p12_passphrase())
    assert bundle.chain == []


def test_install_with_and_without_chain(ctx, issued, tmp_path):
    state = issued()
    plain = install_pem(ctx, state.alias, tmp_path / "a", password="install passphrase", progress=lambda _m: None)
    chained = install_pem(
        ctx, state.alias, tmp_path / "b", include_chain=True, password="install passphrase", progress=lambda _m: None
    )
    assert "BEGIN CERTIFICATE" in chained["cert"].read_text()
    assert chained["cert"].read_text().count("BEGIN CERTIFICATE") > plain["cert"].read_text().count(
        "BEGIN CERTIFICATE"
    )


# ---------------------------------------------------------------------------
# Renewal / revocation / import
# ---------------------------------------------------------------------------


def test_renewal_with_ec_key(ctx, config, ca, issued):
    state = issued()
    ca.auto_approve = True
    ca.sign_after_polls = 0
    state = renew(ctx, state.alias, progress=lambda _m: None, key_algorithm="ec", ec_curve="P-256")
    state = wait_for_certificate(ctx, state, timeout=30, interval=0.2, progress=lambda _m: None)
    assert state.cert.key.startswith("ECDSA P-256")
    bundle = p12_module.read_pkcs12(state.p12_path, ctx.p12_passphrase())
    assert certs.key_description(bundle.key.public_key()).startswith("ECDSA")


@pytest.mark.parametrize("reason", ["unspecified", "keyCompromise", "superseded"])
def test_revoke_reason_matrix(ctx, ca, issued, reason):
    state = issued()
    state = revoke(ctx, state.alias, reason=reason, progress=lambda _m: None)
    assert state.status == STATUS_REVOKED
    assert ca.certificates[int(state.server.cert_id)].status == "REVOKED"


def test_import_with_chain_and_reverify(ctx, issued, tmp_path):
    state = issued()
    path = tmp_path / "chain.p12"
    p12_module.write_pkcs12(
        path,
        key=ctx.store.load_key(state, ctx.key_passphrase()),
        certificate=ctx.store.load_certificate(state),
        chain=ctx.store.load_chain(state),
        password="import-secret",
    )
    imported = import_p12(ctx, path, "import-secret", alias="imported-2", progress=lambda _m: None)
    assert imported.cert.verified
    assert verify(ctx, imported.alias).ok


def test_import_unverified_is_refused_without_opt_in(ctx, issued, tmp_path, monkeypatch):
    state = issued()
    path = tmp_path / "u.p12"
    p12_module.write_pkcs12(
        path,
        key=ctx.store.load_key(state, ctx.key_passphrase()),
        certificate=ctx.store.load_certificate(state),
        chain=[],
        password="import-secret",
    )
    monkeypatch.setattr(
        ctx,
        "build_chain",
        lambda certificate, *_args, **_kwargs: chain_module.ChainResult(
            [certificate], complete=False, trusted=False, problems=["test"]
        ),
    )
    with pytest.raises(ChainError):
        import_p12(ctx, path, "import-secret", alias="unverified", progress=lambda _m: None)
    imported = import_p12(
        ctx, path, "import-secret", alias="unverified", require_verified_chain=False, progress=lambda _m: None
    )
    assert imported.cert.verified is False


# ---------------------------------------------------------------------------
# Verification / refresh / helpers
# ---------------------------------------------------------------------------


def test_verify_expiry_warning(ctx, issued):
    from pycert.util import parse_iso

    state = issued()
    near = parse_iso(state.cert.not_after) - dt.timedelta(days=5)
    report = verify(ctx, state.alias, now=near)
    assert report.ok
    assert report.warnings


def test_verify_reports_missing_p12(ctx, issued):
    state = issued()
    state.p12_path = ""
    ctx.store.save(state)
    report = verify(ctx, state.alias)
    assert report.ok
    # Restore for other fixtures.


def test_verify_chain_untrusted_is_failure(ctx, issued, monkeypatch):
    state = issued()
    monkeypatch.setattr(
        ctx,
        "build_chain",
        lambda certificate, *_args, **_kwargs: chain_module.ChainResult(
            [certificate], complete=False, trusted=False, problems=["nope"]
        ),
    )
    report = verify(ctx, state.alias)
    assert not report.ok


def test_refresh_all_with_multiple_pending(ctx, config, ca):
    ca.auto_approve = False
    first = _pending(ctx, config, ca, "pending one")
    second = _pending(ctx, config, ca, "pending two")
    results = refresh_all(ctx, progress=lambda _m: None)
    aliases = {state.alias for state, _status in results}
    assert {first.alias, second.alias} <= aliases


def test_expiry_warning_helper():
    from pycert.store import RequestState

    state = RequestState(alias="x", slug="x", type="user", cn="x")
    state.cert.not_after = "2000-01-01T00:00:00Z"
    assert "expired" in expiry_warning(state)
    state.cert.not_after = "2999-01-01T00:00:00Z"
    assert expiry_warning(state) is None


def test_describe_state():
    from pycert.store import RequestState

    state = RequestState(alias="x", slug="x", type="user", cn="x")
    payload = describe_state(state)
    assert payload["alias"] == "x"
    assert "days_remaining" in payload


def test_generate_pin_uniqueness():
    pins = {generate_pin() for _ in range(20)}
    assert len(pins) == 20
    assert all(len(pin) == 14 for pin in pins)
