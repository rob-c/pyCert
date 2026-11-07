"""Security-focused end-to-end tests against the mock listener."""

import pytest


def issued(e2e, cn="security user"):
    return e2e.setup_issued(cn)


def pending(e2e, cn="security pending"):
    return e2e.setup_pending(cn)


@pytest.mark.parametrize("mode", ["wrong_pem", "malformed", "no_id", "empty_200"])
@pytest.mark.parametrize(
    "action", [["status", "{alias}", "--refresh"], ["download", "{alias}"], ["verify", "{alias}"]]
)
def test_bad_lookup_responses_do_not_corrupt_state(e2e, mode, action):
    alias = issued(e2e, "bad lookup %s" % mode)
    e2e.ca.lookup_mode = mode
    result = e2e.run(*[part.format(alias=alias) for part in action])
    assert result.code in (0, 1, 4)
    assert "Traceback" not in result.err
    state = e2e.state(alias)
    assert state.alias == alias
    if state.cert.sha256:
        assert state.cert.key


@pytest.mark.parametrize("mode", ["xml_no_cert", "malformed", "wrong_cert"])
def test_bad_certificate_bodies_are_refused(e2e, mode):
    alias = issued(e2e, "bad cert %s" % mode)
    e2e.ca.lookup_mode = "no_inline"
    e2e.ca.download_mode = mode
    result = e2e.run("download", alias)
    assert result.code in (1, 4)
    assert "Traceback" not in result.err
    # local verification still works against the previously stored certificate
    assert e2e.run("verify", alias, "--no-p12").code in (0, 4)


@pytest.mark.parametrize("mode", ["bad_xml", "malformed_cert"])
@pytest.mark.parametrize("command", ["ras", "info"])
def test_malicious_ca_info(e2e, mode, command):
    e2e.ca.info_mode = mode
    result = e2e.run(command)
    assert result.code in (0, 1)
    assert "Traceback" not in result.err


@pytest.mark.parametrize("mode", ["bad_keyid", "bad_response"])
@pytest.mark.parametrize("action", ["renew", "revoke", "host"])
def test_pppk_attacks_are_refused(e2e, mode, action):
    if action == "host":
        auth = issued(e2e, "pppk host auth %s" % mode)
        e2e.ca.pppk_mode = mode
        result = e2e.run(
            "request",
            "pppk-host-%s.example.org" % mode.replace("_", "-"),
            "--type",
            "host",
            "--auth",
            auth,
            "--pin",
            e2e.PIN,
            "--key-algorithm",
            "ec",
        )
        assert result.code == 1
    else:
        alias = issued(e2e, "pppk %s %s" % (mode, action))
        e2e.ca.pppk_mode = mode
        result = e2e.run(action, alias, "--yes")
        if mode == "bad_keyid" and action == "revoke":
            assert result.code == 0  # keyid injection only affects CSR submissions
        else:
            assert result.code == 1
    assert "Traceback" not in result.err


MALICIOUS_BODIES = [
    b"<?xml version='1.0'?><!DOCTYPE r><r/>",
    b"<r><!ENTITY x 'y'></r>",
    b"x" * 100000,
    b"<resources><resource><certificates>",
    b"",
]


@pytest.mark.parametrize("body", MALICIOUS_BODIES)
@pytest.mark.parametrize(
    "path,action,kind",
    [
        ("/CA", "ras", "none"),
        ("/CSR", "request", "none"),
        ("/resources/resource/publickey/pk", "status", "pending"),
    ],
)
def test_malicious_bodies_are_rejected(e2e, body, path, action, kind):
    e2e.configure(retries=0)
    alias = pending(e2e, "malicious body") if kind == "pending" else None
    e2e.ca.fail_next(
        path,
        method="POST" if action in ("request", "status") else "GET",
        status=200,
        body=body,
    )
    if action == "ras":
        args = ["ras"]
    elif action == "request":
        args = ["request", "malicious request", "--pin", e2e.PIN, "--key-algorithm", "ec"]
    else:
        args = ["status", alias, "--refresh"]
    result = e2e.run(*args)
    assert result.code in (0, 1, 3, 4)
    assert "Traceback" not in result.err


def test_cross_host_redirect_is_refused(e2e):
    e2e.ca.fail_next("/CA", method="GET", status=302, headers={"Location": "http://localhost:1/x"})
    result = e2e.run("ras")
    assert result.code == 1


def test_tls_pin_mismatch_is_fatal(e2e):
    e2e.configure(tls_pin_sha256=["00" * 32])
    result = e2e.run("ping")
    assert result.code == 1
    assert "pin" in result.err.lower()


def test_tls_verification_can_be_disabled_but_doctor_flags_it(e2e):
    e2e.configure(tls_verify=False)
    assert e2e.run("ping").code == 0
    doctor = e2e.run("doctor", "--offline")
    assert doctor.code == 1


def test_weak_key_import_warns(e2e, tmp_path):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from pycert import p12 as p12_module

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weak-security")])
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
    result = e2e.run(
        "import",
        str(path),
        "--alias",
        "weak-security",
        "--password",
        "weak-password",
        "--allow-unverified-chain",
    )
    assert result.code == 0
    assert "1024" in result.err
    assert any("1024" in note for note in e2e.state("weak-security").notes)
