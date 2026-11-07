"""Protocol-shape variants served by the mock CA listener, driven via the CLI."""

import pytest


def status(e2e, alias):
    return e2e.run("status", alias, "--refresh")


def issue(e2e, cn="protocol user"):
    alias = e2e.setup_issued(cn)
    state = e2e.state(alias)
    state.status = "SIGNED"  # make 'status --refresh' poll the CA again
    e2e.ctx.store.save(state)
    return alias


def pending(e2e, cn="protocol pending"):
    return e2e.setup_pending(cn)


@pytest.mark.parametrize(
    "mode,refresh_code,download_code",
    [
        ("normal", 0, 0),
        ("no_inline", 0, 0),
        ("multiple", 0, 0),
        ("bad_status", 0, 0),
        ("csr_only", 0, 1),
        ("no_id", 0, 1),
        ("empty_200", 0, 1),
        ("wrong_pem", 1, 1),
        ("malformed", 1, 1),
    ],
)
def test_lookup_modes(e2e, mode, refresh_code, download_code):
    alias = issue(e2e, "lookup %s" % mode)
    e2e.ca.lookup_mode = mode
    refreshed = status(e2e, alias)
    assert refreshed.code == refresh_code, (mode, refreshed.out, refreshed.err)
    downloaded = e2e.run("download", alias)
    assert downloaded.code == download_code, (mode, downloaded.out, downloaded.err)


@pytest.mark.parametrize(
    "mode,code",
    [
        ("csr_approved", 0),
        ("csr_deleted", 0),
        ("csr_unknown", 0),
    ],
)
def test_pending_csr_status_modes(e2e, mode, code):
    alias = pending(e2e, "pending %s" % mode)
    e2e.ca.lookup_mode = mode
    result = status(e2e, alias)
    assert result.code == code
    assert mode.replace("csr_", "").upper() in result.out.upper() or "unknown" in result.out.lower()


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("normal", 0),
        ("bare_pem", 0),
        ("bare_der", 0),
        ("xml_no_cert", 1),
        ("malformed", 1),
        ("wrong_cert", 1),
    ],
)
def test_download_modes(e2e, mode, expected):
    alias = issue(e2e, "download %s" % mode)
    e2e.ca.lookup_mode = "no_inline"
    e2e.ca.download_mode = mode
    result = e2e.run("download", alias)
    assert result.code == expected, (mode, result.out, result.err)
    if mode == "wrong_cert":
        assert "public key" in result.err.lower() or "does not match" in result.err.lower()


@pytest.mark.parametrize(
    "mode,code",
    [
        ("empty", 0),
        ("huge_ra", 0),
        ("no_preferred", 0),
        ("no_policy", 0),
        ("one_cert", 0),
        ("malformed_cert", 0),
        ("bad_xml", 1),
    ],
)
def test_ca_info_modes(e2e, mode, code):
    e2e.ca.info_mode = mode
    ras = e2e.run("ras")
    assert ras.code == code, (mode, ras.out, ras.err)
    info = e2e.run("info")
    assert info.code == code, (mode, info.out, info.err)
    if mode == "huge_ra" and ras.code == 0:
        assert "500 RAs" in ras.out
    if mode == "empty" and ras.code == 0:
        assert "0 RAs" in ras.out


@pytest.mark.parametrize(
    "mode,renew_code,revoke_code",
    [
        ("normal", 0, 0),
        ("no_challenge", 0, 0),
        ("opaque", 0, 0),
        ("bad_keyid", 1, 0),
        ("bad_response", 1, 1),
    ],
)
def test_pppk_modes(e2e, mode, renew_code, revoke_code):
    alias = issue(e2e, "pppk %s" % mode)
    e2e.ca.pppk_mode = mode
    renew = e2e.run("renew", alias, "--yes", "--pin", e2e.PIN)
    assert renew.code == renew_code, (mode, "renew", renew.out, renew.err)
    if renew.code == 0:
        # move the certificate back to a state where revoke is meaningful
        alias = issue(e2e, "pppk revoke %s" % mode)
        e2e.ca.pppk_mode = mode
    revoke = e2e.run("revoke", alias, "--yes")
    assert revoke.code == revoke_code, (mode, "revoke", revoke.out, revoke.err)


@pytest.mark.parametrize("mode", ["normal", "no_challenge", "opaque", "bad_response"])
def test_host_request_pppk_modes(e2e, mode):
    user = issue(e2e, "host pppk user %s" % mode)
    e2e.ca.pppk_mode = mode
    result = e2e.run(
        "request",
        "host-%s.example.org" % mode.replace("_", "-"),
        "--type",
        "host",
        "--auth",
        user,
        "--pin",
        e2e.PIN,
        "--key-algorithm",
        "ec",
    )
    if mode in ("normal", "no_challenge", "opaque"):
        assert result.code == 0, (mode, result.out, result.err)
    else:
        assert result.code == 1


def test_duplicate_submission_toggle(e2e, ctx):
    e2e.ca.reject_duplicate = False
    alias = pending(e2e, "duplicate toggle")
    state = e2e.state(alias)
    from pycert import csr as csr_module

    csr = e2e.ctx.store.load_csr(state)
    client = e2e.ctx.client()
    first = client.submit_csr(csr_module.csr_pem(csr), "A" * 40, state.email)
    second = client.submit_csr(csr_module.csr_pem(csr), "A" * 40, state.email)
    assert first.status == 201
    assert second.status == 201


def test_email_mismatch_rejected_by_listener(e2e, ctx):
    alias = pending(e2e, "email mismatch")
    state = e2e.state(alias)
    from pycert import csr as csr_module

    csr = e2e.ctx.store.load_csr(state)
    submission = e2e.ctx.client().submit_csr(csr_module.csr_pem(csr), "A" * 40, "other@example.org")
    assert submission.success is False
    assert "Email does not match" in submission.detail


def test_new_csr_status_modes(e2e):
    for status_value in ("APPROVED", "DELETED"):
        e2e.ca.new_csr_status = status_value
        alias = e2e.setup_pending("new status %s" % status_value)
        e2e.ca.new_csr_status = "NEW"
        result = status(e2e, alias)
        assert result.code == 0
        assert status_value in result.out.upper()
