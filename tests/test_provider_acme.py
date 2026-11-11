"""End-to-end tests of the ACME provider against the sandbox RFC 8555 server.

Every test talks to a real ``sandbox_ca.acme.ACMEServer`` over TLS (its
certificate is issued by the mock CA, so the ACME profile trusts the mock CA
chain).  http-01 validation is kept hermetic by pointing the sandbox's
validator at 127.0.0.1 with the identifier in the Host header.
"""

import datetime as dt
import os
import secrets
import shlex
import socket
import stat
import sys
import threading
import time
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pycert import workflow
from pycert.config import new_acme_profile, validate_config
from pycert.errors import CAError, ProtocolError, PyCertError
from pycert.providers import acme as acme_module
from pycert.providers.acme import (
    ACMEProblem,
    ACMEProvider,
    account_jwk,
    account_summary,
    b64url,
    dns01_record,
    dns01_value,
    jwk_thumbprint,
    sign_jws,
    store_eab_key,
)
from pycert.store import STATUS_DOWNLOADED, STATUS_FAILED, STATUS_REVOKED, STATUS_SUBMITTED
from sandbox_ca import acme as sandbox_acme
from sandbox_ca.acme import ACMEServer, Challenge

PROFILE = "sandbox-acme"


def noop(_message):
    pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def acme_servers(ca):
    started = []

    def start(**kwargs):
        kwargs.setdefault("challenge_mode", "auto")
        server = ACMEServer(ca, port=0, **kwargs).start()
        started.append(server)
        return server

    yield start
    for server in started:
        server.stop()


@pytest.fixture
def acme(acme_servers):
    return acme_servers()


def add_profile(config, server, name=PROFILE, *, terms=True, **settings):
    profile = new_acme_profile(
        name,
        server.directory_url(),
        display_name="Sandbox ACME",
        contact=["ops@example.org"],
        terms_agreed=terms,
        tls_trust="chain",
    )
    profile.chain = list(config.chain)
    profile.ca.retries = 0
    profile.acme.poll_interval = 0.1
    profile.acme.validation_timeout = 20
    # Never touch port 80: a high, private standalone port unless told otherwise.
    profile.acme.http_mode = "standalone"
    profile.acme.http_bind = "127.0.0.1"
    profile.acme.http_port = free_port()
    for key, value in settings.items():
        setattr(profile.acme, key, value)
    config.add_ca(profile)
    validate_config(config)
    return profile


def spec_for(config, cn="host.example.org", **kwargs):
    kwargs.setdefault("key_algorithm", "ec")
    return workflow.RequestSpec.build(config, cn, type="host", ca=PROFILE, **kwargs)


def issue(ctx, config, cn="host.example.org", *, spec=None, **kwargs):
    spec = spec or spec_for(config, cn, **kwargs)
    return workflow.create_request(ctx, spec, wait=True, interval=0.1, timeout=30, progress=noop)


def local_http_validation(server, port):
    """Make the sandbox fetch http-01 tokens from 127.0.0.1:<port> (Host = identifier)."""

    def validate(challenge):
        domain = server.authzs[challenge.authz_id].identifier["value"]
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/.well-known/acme-challenge/{challenge.token}", headers={"Host": domain}
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as response:
                body = response.read().decode().strip()
        except OSError as exc:
            return False, "fetch failed: %s" % exc
        if body != server._key_authorization(challenge):
            return False, "token mismatch"
        return True, ""

    server._validate_http_01 = validate


def offer_dns01(server):
    """The sandbox only offers dns-01 for wildcards; offer it for every name."""
    original = server._new_order

    def new_order(body, expected_url):
        result = original(body, expected_url)
        order = server.orders[result["location"].rsplit("/", 1)[-1]]
        for authz_id in order.authorizations:
            authz = server.authzs[authz_id]
            if not any(server.challenges[cid].type == "dns-01" for cid in authz.challenges):
                challenge = Challenge(
                    id=secrets.token_urlsafe(12),
                    authz_id=authz_id,
                    type="dns-01",
                    token=secrets.token_urlsafe(32),
                )
                server.challenges[challenge.id] = challenge
                authz.challenges.append(challenge.id)
        return result

    server._new_order = new_order


def hook_script(tmp_path, *, exit_code=0):
    log = tmp_path / "hook.log"
    script = tmp_path / "hook.py"
    script.write_text(
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\nsys.exit({exit_code})\n"
    )
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))}", log


def sandbox_record(ca, state):
    for record in ca.certificates.values():
        if record.spki_b64 == state.spki_b64:
            return record
    raise AssertionError("certificate not found in the sandbox CA")


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------


def test_issue_host_certificate_end_to_end(ctx, config, acme):
    add_profile(config, acme)
    messages = []
    spec = spec_for(config)
    state = workflow.create_request(ctx, spec, wait=True, interval=0.1, timeout=30, progress=messages.append)
    assert state.status == STATUS_DOWNLOADED
    assert state.ca == PROFILE
    assert state.cert.verified
    assert state.subject == "CN=host.example.org"
    assert state.p12_path and os.path.isfile(state.p12_path)
    assert state.provider["kind"] == "acme"
    assert state.provider["order_url"].startswith(acme.base_url)
    assert state.provider["certificate_url"] == state.server.cert_id
    assert state.provider["identifiers"] == ["host.example.org"]
    assert any("registered" in message for message in messages)
    assert not any("BEGIN" in message for message in messages)
    stored = ctx.store.get(state.alias)
    assert stored.ca == PROFILE and stored.status == STATUS_DOWNLOADED
    report = workflow.verify(ctx, state.alias)
    assert report.ok, report.checks


def test_account_files_are_private_and_encrypted(ctx, config, acme):
    add_profile(config, acme)
    issue(ctx, config)
    directory = config.data_dir / "acme" / PROFILE
    key_file = directory / "account.pem"
    info_file = directory / "account.json"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(info_file.stat().st_mode) == 0o600
    assert b"ENCRYPTED" in key_file.read_bytes()
    assert ctx.store.audit() == []
    summary = account_summary(ctx, PROFILE)
    assert summary["registered"] and summary["account"].startswith(acme.base_url)
    assert summary["key"] == "ES256"


def test_account_is_reused_across_provider_instances(ctx, config, acme):
    add_profile(config, acme)
    issue(ctx, config, "one.example.org")
    kid = account_summary(ctx, PROFILE)["account"]
    issue(ctx, config, "two.example.org")
    assert len(acme.accounts) == 1
    assert account_summary(ctx, PROFILE)["account"] == kid


def test_forgotten_account_is_registered_again(ctx, config, acme):
    add_profile(config, acme)
    issue(ctx, config, "one.example.org")
    old = account_summary(ctx, PROFILE)["account"]
    acme.accounts.clear()
    acme.accounts_by_thumbprint.clear()
    messages = []
    state = workflow.create_request(
        ctx,
        spec_for(config, "two.example.org"),
        wait=True,
        interval=0.1,
        timeout=30,
        progress=messages.append,
    )
    assert state.status == STATUS_DOWNLOADED
    assert account_summary(ctx, PROFILE)["account"] != old
    assert any("no longer knows" in message for message in messages)


def test_changed_directory_registers_with_the_new_server(ctx, config, acme_servers):
    first = acme_servers()
    profile = add_profile(config, first)
    issue(ctx, config, "one.example.org")
    second = acme_servers()
    profile.ca.base_url = second.directory_url()
    state = issue(ctx, config, "two.example.org")
    assert state.status == STATUS_DOWNLOADED
    assert len(second.accounts) == 1
    assert account_summary(ctx, PROFILE)["directory"] == second.directory_url()


def test_rsa_account_key(ctx, config, acme):
    add_profile(config, acme, account_key="rsa")
    state = issue(ctx, config)
    assert state.status == STATUS_DOWNLOADED
    assert account_summary(ctx, PROFILE)["key"] == "RS256"


def test_extra_dns_names_always_include_the_common_name(ctx, config, acme):
    add_profile(config, acme)
    state = issue(ctx, config, "host.example.org", san_dns=["www.example.org"])
    assert state.status == STATUS_DOWNLOADED
    assert state.provider["identifiers"] == ["host.example.org", "www.example.org"]
    sans = " ".join(state.cert.sans)
    assert "host.example.org" in sans and "www.example.org" in sans


def test_manual_ca_approval_is_polled_until_valid(ctx, config, acme, ca):
    add_profile(config, acme)
    ca.auto_approve = False
    state = workflow.create_request(ctx, spec_for(config), wait=False, progress=noop)
    assert state.status == STATUS_SUBMITTED
    outcome = workflow.poll_once(ctx, state)
    assert outcome.pending and not outcome.terminal
    assert outcome.server_status == "processing"
    assert "issuing" in outcome.message
    ca.sign_all()
    state = workflow.wait_for_certificate(
        ctx, ctx.store.get(state.alias), interval=0.1, timeout=10, progress=noop
    )
    assert state.status == STATUS_DOWNLOADED


def test_invalid_order_is_terminal(ctx, config, acme, ca):
    add_profile(config, acme)
    ca.auto_approve = False
    state = workflow.create_request(ctx, spec_for(config), wait=False, progress=noop)
    order = acme.orders[state.provider["order_url"].rsplit("/", 1)[-1]]
    order.status = "invalid"
    order.error = {"type": "urn:ietf:params:acme:error:serverInternal", "detail": "the CA gave up"}
    outcome = workflow.poll_once(ctx, state)
    assert outcome.terminal and "the CA gave up" in outcome.message
    assert ctx.store.get(state.alias).status == STATUS_FAILED
    with pytest.raises(CAError):
        workflow.wait_for_certificate(ctx, ctx.store.get(state.alias), interval=0.1, timeout=5)


def test_ready_order_is_finalized_by_poll(ctx, config, acme, monkeypatch):
    add_profile(config, acme)
    original = ACMEProvider._finalize
    calls = []

    def crash_once(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise PyCertError("simulated crash before finalize")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ACMEProvider, "_finalize", crash_once)
    with pytest.raises(PyCertError, match="simulated crash"):
        workflow.create_request(ctx, spec_for(config), wait=False, progress=noop)
    state = ctx.store.get("host.example.org")
    assert state.status == STATUS_FAILED and state.provider["order_url"]
    state.status = STATUS_SUBMITTED
    ctx.store.save(state)
    state = workflow.wait_for_certificate(ctx, state, interval=0.1, timeout=10, progress=noop)
    assert state.status == STATUS_DOWNLOADED
    assert len(calls) == 2


def test_pending_order_is_validated_by_poll(ctx, config, acme, monkeypatch):
    add_profile(config, acme)
    original = ACMEProvider._complete_authorizations
    calls = []

    def crash_once(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise PyCertError("simulated crash before validation")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ACMEProvider, "_complete_authorizations", crash_once)
    with pytest.raises(PyCertError):
        workflow.create_request(ctx, spec_for(config), wait=False, progress=noop)
    state = ctx.store.get("host.example.org")
    state.status = STATUS_SUBMITTED
    ctx.store.save(state)
    state = workflow.wait_for_certificate(ctx, state, interval=0.1, timeout=10, progress=noop)
    assert state.status == STATUS_DOWNLOADED


# ---------------------------------------------------------------------------
# Renewal and revocation
# ---------------------------------------------------------------------------


def test_renewal(ctx, config, acme):
    add_profile(config, acme)
    original = issue(ctx, config)
    old_serial = original.cert.serial
    old_order = original.provider["order_url"]
    renewed = workflow.renew(ctx, original.alias, wait=True, interval=0.1, timeout=30, progress=noop)
    assert renewed.status == STATUS_DOWNLOADED
    assert not renewed.renewal
    assert renewed.cert.serial != old_serial
    assert renewed.provider["order_url"] != old_order
    assert renewed.provider["renewal"] is True
    assert (ctx.store.path(renewed) / "previous").is_dir()
    assert workflow.verify(ctx, renewed.alias).ok


def test_renewal_without_wait_then_wait(ctx, config, acme):
    add_profile(config, acme)
    original = issue(ctx, config)
    pending = workflow.renew(ctx, original.alias, wait=False, progress=noop)
    assert pending.renewal and pending.status == STATUS_SUBMITTED
    done = workflow.wait_for_certificate(ctx, pending, interval=0.1, timeout=10, progress=noop)
    assert done.status == STATUS_DOWNLOADED and not done.renewal


def test_revocation(ctx, config, acme, ca):
    add_profile(config, acme)
    state = issue(ctx, config)
    revoked = workflow.revoke(ctx, state.alias, "superseded", progress=noop)
    assert revoked.status == STATUS_REVOKED
    record = sandbox_record(ca, state)
    assert record.status == "REVOKED" and record.revoke_reason == "superseded"


def test_revocation_reason_must_be_supported(ctx, config, acme):
    add_profile(config, acme)
    state = issue(ctx, config)
    with pytest.raises(PyCertError, match="revocation reason"):
        workflow.revoke(ctx, state.alias, "cACompromise")


def test_revocation_refused_by_the_ca_is_reported(ctx, config, acme):
    add_profile(config, acme)
    issue(ctx, config)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stranger.example.org")])
    now = dt.datetime.now(dt.timezone.utc)
    stranger = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    provider = ctx.provider(PROFILE)
    result = provider.revoke(ctx.store.get("host.example.org"), "unspecified", certificate=stranger, key=key)
    assert not result.success
    assert "not known" in result.detail
    with pytest.raises(PyCertError):
        provider.revoke(ctx.store.get("host.example.org"), "bogus", certificate=stranger, key=key)


# ---------------------------------------------------------------------------
# Account policy: terms of service and External Account Binding
# ---------------------------------------------------------------------------


def test_terms_must_be_agreed(ctx, config, acme):
    add_profile(config, acme, terms=False)
    with pytest.raises(PyCertError, match="terms_agreed"):
        workflow.create_request(ctx, spec_for(config), progress=noop)
    assert not ctx.store.exists("host.example.org")
    assert acme.accounts == {}


def test_eab_required_and_stored_in_the_secret_store(ctx, config, acme_servers):
    hmac_key = os.urandom(32)
    server = acme_servers(eab_credentials={"kid-1": b64url(hmac_key)})
    add_profile(config, server, eab_kid="kid-1")
    store_eab_key(ctx, PROFILE, b64url(hmac_key))
    assert ctx.secrets.get("acme-eab:" + PROFILE) == b64url(hmac_key)
    state = issue(ctx, config)
    assert state.status == STATUS_DOWNLOADED
    (account,) = server.accounts.values()
    assert account.eab_kid == "kid-1"
    info = ctx.provider(PROFILE).info()
    assert info["external_account_required"] and info["eab_key_stored"]


def test_eab_key_from_environment(ctx, config, acme_servers, monkeypatch):
    hmac_key = os.urandom(32)
    server = acme_servers(eab_credentials={"kid-env": b64url(hmac_key)})
    add_profile(config, server, eab_kid="kid-env", eab_hmac_env="PYCERT_TEST_EAB_KEY")
    monkeypatch.setenv("PYCERT_TEST_EAB_KEY", b64url(hmac_key))
    assert issue(ctx, config).status == STATUS_DOWNLOADED


def test_eab_kid_without_key_is_refused(ctx, config, acme_servers):
    server = acme_servers(eab_credentials={"kid-1": b64url(os.urandom(32))})
    add_profile(config, server, eab_kid="kid-1")
    with pytest.raises(PyCertError, match="pycert ca eab"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_eab_required_but_not_configured(ctx, config, acme_servers):
    server = acme_servers(eab_credentials={"kid-1": b64url(os.urandom(32))})
    add_profile(config, server)
    with pytest.raises(PyCertError, match="requires External Account Binding"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_eab_wrong_key_is_rejected_by_the_ca(ctx, config, acme_servers):
    server = acme_servers(eab_credentials={"kid-1": b64url(os.urandom(32))})
    add_profile(config, server, eab_kid="kid-1")
    store_eab_key(ctx, PROFILE, b64url(os.urandom(32)))
    with pytest.raises(CAError, match="EAB HMAC verification failed"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_store_eab_key_validation(ctx, config, acme):
    add_profile(config, acme)
    with pytest.raises(PyCertError, match="base64url"):
        store_eab_key(ctx, PROFILE, "not base64!!")
    with pytest.raises(PyCertError, match="too short"):
        store_eab_key(ctx, PROFILE, b64url(b"short"))
    with pytest.raises(PyCertError, match="not an ACME CA"):
        store_eab_key(ctx, config.ca.name, b64url(os.urandom(32)))
    padded = b64url(os.urandom(32)) + "="
    store_eab_key(ctx, PROFILE, padded)


# ---------------------------------------------------------------------------
# Challenges
# ---------------------------------------------------------------------------


def test_http01_standalone_serves_the_token(ctx, config, acme_servers):
    port = free_port()
    server = acme_servers(challenge_mode="http", http_port=port)
    local_http_validation(server, port)
    add_profile(config, server, http_mode="standalone", http_bind="127.0.0.1", http_port=port)
    state = issue(ctx, config)
    assert state.status == STATUS_DOWNLOADED
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        pass


def test_http01_webroot(ctx, config, acme_servers, tmp_path):
    webroot = tmp_path / "www"
    webroot.mkdir()
    handler = partial(SimpleHTTPRequestHandler, directory=str(webroot))
    handler.log_message = lambda *args: None
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        server = acme_servers(challenge_mode="http", http_port=httpd.server_address[1])
        local_http_validation(server, httpd.server_address[1])
        add_profile(config, server, http_mode="webroot", webroot=str(webroot))
        state = issue(ctx, config)
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert state.status == STATUS_DOWNLOADED
    assert not (webroot / ".well-known").exists()


def test_failed_http01_validation_is_reported_and_cleaned_up(ctx, config, acme_servers, tmp_path):
    webroot = tmp_path / "www"
    webroot.mkdir()
    server = acme_servers(challenge_mode="http")
    server._validate_http_01 = lambda challenge: (False, "nobody answered")
    add_profile(config, server, http_mode="webroot", webroot=str(webroot))
    with pytest.raises(CAError, match="could not validate host.example.org: nobody answered"):
        workflow.create_request(ctx, spec_for(config), progress=noop)
    assert ctx.store.get("host.example.org").status == STATUS_FAILED
    assert not (webroot / ".well-known").exists()


def test_webroot_must_exist(ctx, config, acme, tmp_path):
    add_profile(config, acme, http_mode="webroot", webroot=str(tmp_path / "missing"))
    with pytest.raises(PyCertError, match="webroot does not exist"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_standalone_port_in_use(ctx, config, acme):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        add_profile(config, acme, http_port=busy.getsockname()[1])
        with pytest.raises(PyCertError, match="cannot listen"):
            workflow.create_request(ctx, spec_for(config), progress=noop)


def test_standalone_responder_serves_only_known_tokens():
    token = "A" * 43
    responder = acme_module._Http01Standalone("127.0.0.1", free_port(), {token: token + ".thumb"})
    responder.start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f"http://127.0.0.1:{responder.port}/.well-known/acme-challenge/"
    try:
        with opener.open(base + token, timeout=5) as response:
            assert response.read().decode() == token + ".thumb"
        for path in (base + "B" * 43, f"http://127.0.0.1:{responder.port}/etc/passwd"):
            with pytest.raises(urllib.error.HTTPError) as excinfo:
                opener.open(path, timeout=5)
            assert excinfo.value.code == 404
    finally:
        responder.stop()


def test_malformed_tokens_are_refused(ctx, config, acme):
    profile = add_profile(config, acme)
    challenges = acme_module._Challenges(ctx.provider(profile.name), noop, None)
    with pytest.raises(ProtocolError):
        challenges.add("http-01", "host.example.org", "../../../etc/passwd", "x")


def test_dns01_hook(ctx, config, acme, tmp_path):
    offer_dns01(acme)
    hook, log = hook_script(tmp_path)
    add_profile(config, acme, challenge="dns-01", dns_hook=hook)
    state = issue(ctx, config)
    assert state.status == STATUS_DOWNLOADED
    lines = log.read_text().splitlines()
    assert lines[0].startswith("add host.example.org _acme-challenge.host.example.org ")
    assert lines[-1].startswith("remove host.example.org _acme-challenge.host.example.org ")
    value = lines[0].split()[-1]
    assert len(value) == 43 and lines[-1].split()[-1] == value


def test_dns01_hook_failure(ctx, config, acme, tmp_path):
    offer_dns01(acme)
    hook, _log = hook_script(tmp_path, exit_code=3)
    add_profile(config, acme, challenge="dns-01", dns_hook=hook)
    with pytest.raises(PyCertError, match="dns-01 hook failed"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_wildcard_with_dns01(ctx, config, acme, tmp_path):
    offer_dns01(acme)
    hook, log = hook_script(tmp_path)
    add_profile(config, acme, challenge="dns-01", dns_hook=hook)
    spec = spec_for(config, "example.org")
    spec.san_dns = ["example.org", "*.example.org"]
    state = issue(ctx, config, spec=spec)
    assert state.status == STATUS_DOWNLOADED
    assert any("*.example.org" in san for san in state.cert.sans)
    adds = [line for line in log.read_text().splitlines() if line.startswith("add ")]
    assert len(adds) == 2 and all("_acme-challenge.example.org" in line for line in adds)


def test_wildcard_requires_dns01(ctx, config, acme):
    add_profile(config, acme, challenge="http-01")
    spec = spec_for(config, "example.org")
    spec.san_dns = ["example.org", "*.example.org"]
    with pytest.raises(PyCertError, match="dns-01"):
        ctx.provider(PROFILE).validate_request(spec)
    with pytest.raises(PyCertError, match="dns-01"):
        workflow.create_request(ctx, spec, progress=noop)
    assert not ctx.store.exists("example.org")


def test_dns01_manual_confirmation(ctx, config, acme):
    offer_dns01(acme)
    add_profile(config, acme, challenge="dns-01")
    prompts = []

    def confirm(title, text):
        prompts.append((title, text))
        return True

    ctx.confirm = confirm
    state = issue(ctx, config)
    assert state.status == STATUS_DOWNLOADED
    ((title, text),) = prompts
    assert "TXT" in title or "TXT" in text
    assert "_acme-challenge.host.example.org." in text


def test_dns01_manual_cancelled(ctx, config, acme):
    offer_dns01(acme)
    add_profile(config, acme, challenge="dns-01")
    ctx.confirm = lambda _title, _text: False
    with pytest.raises(PyCertError, match="cancelled"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_dns01_manual_needs_a_front_end(ctx, config, acme):
    offer_dns01(acme)
    add_profile(config, acme, challenge="dns-01")
    with pytest.raises(PyCertError, match="dns_hook"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_ca_without_the_configured_challenge(ctx, config, acme):
    add_profile(config, acme, challenge="dns-01", dns_hook="true")
    with pytest.raises(CAError, match="did not offer a dns-01 challenge"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_validation_timeout(ctx, config, acme_servers):
    server = acme_servers(challenge_mode="manual")
    add_profile(config, server, validation_timeout=1.0)
    started = time.monotonic()
    with pytest.raises(CAError, match="still 'pending'"):
        workflow.create_request(ctx, spec_for(config), progress=noop)
    assert time.monotonic() - started < 15


def test_cancellation(ctx, config, acme_servers):
    server = acme_servers(challenge_mode="manual")
    add_profile(config, server, validation_timeout=60.0)
    stop = threading.Event()
    timer = threading.Timer(0.5, stop.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(PyCertError, match="cancel"):
            workflow.create_request(ctx, spec_for(config), progress=noop, stop_event=stop)
    finally:
        timer.cancel()
    assert time.monotonic() - started < 15


# ---------------------------------------------------------------------------
# Request policy
# ---------------------------------------------------------------------------


def test_personal_certificates_are_rejected(config, acme):
    add_profile(config, acme)
    with pytest.raises(PyCertError, match="only issues host certificates"):
        workflow.RequestSpec.build(config, "Jane Doe", type="user", ca=PROFILE)


def test_ip_and_email_sans_are_rejected(ctx, config, acme):
    add_profile(config, acme)
    spec = spec_for(config, san_ip=["192.0.2.1"])
    with pytest.raises(PyCertError, match="DNS hosts"):
        workflow.create_request(ctx, spec, progress=noop)
    spec = spec_for(config, san_email=["ops@example.org"])
    with pytest.raises(PyCertError, match="DNS hosts"):
        ctx.provider(PROFILE).validate_request(spec)


def test_spec_has_no_pin_ra_or_organisation(config, acme):
    add_profile(config, acme)
    spec = spec_for(config, pin="1234567890AB")
    assert spec.pin == "" and spec.ou == "" and spec.o == ""
    assert spec.subject().rfc4514_string() == "CN=host.example.org"
    assert spec.ca == PROFILE


def test_capabilities_and_describe(ctx, config, acme):
    add_profile(config, acme)
    provider = ctx.provider(PROFILE)
    assert isinstance(provider, ACMEProvider)
    caps = provider.capabilities
    assert caps.domain_validation and caps.host_certificates and not caps.user_certificates
    assert not caps.pin and not caps.ra and not caps.revoke_needs_id
    described = provider.describe()
    assert described["kind"] == "acme" and described["url"] == acme.directory_url()


# ---------------------------------------------------------------------------
# Protocol details
# ---------------------------------------------------------------------------


def test_bad_nonce_is_retried(ctx, config, acme, monkeypatch):
    add_profile(config, acme)
    original = acme.consume_nonce
    failures = []

    def flaky(nonce):
        if not failures:
            failures.append(nonce)
            raise sandbox_acme.ACMEProblem("badNonce", "stale nonce")
        return original(nonce)

    monkeypatch.setattr(acme, "consume_nonce", flaky)
    assert issue(ctx, config).status == STATUS_DOWNLOADED
    assert len(failures) == 1


def test_bad_nonce_retries_are_bounded(ctx, config, acme, monkeypatch):
    add_profile(config, acme)
    calls = []

    def always_bad(nonce):
        calls.append(nonce)
        raise sandbox_acme.ACMEProblem("badNonce", "stale nonce")

    monkeypatch.setattr(acme, "consume_nonce", always_bad)
    with pytest.raises(ACMEProblem, match="badNonce") as excinfo:
        workflow.create_request(ctx, spec_for(config), progress=noop)
    assert excinfo.value.problem_type == "badNonce"
    assert len(calls) == acme_module.MAX_NONCE_RETRIES


def test_ping_and_info(ctx, config, acme):
    add_profile(config, acme)
    provider = ctx.provider(PROFILE)
    result = provider.ping()
    assert result.ok and result.latency_ms >= 0 and result.tls is not None
    info = provider.info()
    assert info["terms_of_service"].endswith("/acme/terms")
    assert info["account_status"] == "not registered"
    assert not info["external_account_required"]
    issue(ctx, config)
    info = ctx.provider(PROFILE).info()
    assert info["account_status"] == "valid"
    assert info["contact"] == ["mailto:ops@example.org"]


def test_ping_unreachable(ctx, config, acme):
    profile = add_profile(config, acme)
    profile.ca.base_url = "https://127.0.0.1:%d/acme/directory" % free_port()
    profile.ca.connect_timeout = 2.0
    result = ctx.provider(PROFILE).ping()
    assert not result.ok and result.detail
    with pytest.raises(CAError, match="cannot reach"):
        workflow.create_request(ctx, spec_for(config), progress=noop)


def test_not_an_acme_directory(ctx, config, acme, ca):
    profile = add_profile(config, acme)
    profile.ca.base_url = ca.url + "/CA"
    result = ctx.provider(PROFILE).ping()
    assert not result.ok


def test_poll_without_an_order(ctx, config, acme):
    add_profile(config, acme)
    state = ctx.store.new_state(alias="orphan", type="host", cn="orphan.example.org", email="x@example.org")
    state.ca = PROFILE
    with pytest.raises(PyCertError, match="no ACME order"):
        ctx.provider(PROFILE).poll(state)


def test_jws_helpers_match_the_sandbox_verifier():
    for key in (ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP384R1())):
        jwk = account_jwk(key)
        assert jwk_thumbprint(jwk) == sandbox_acme.jwk_thumbprint(jwk)
        alg = acme_module.jws_algorithm(key)
        envelope = sign_jws(key, {"alg": alg, "nonce": "n", "url": "https://x/acme"}, {"a": 1})
        _check_signature(jwk, alg, envelope)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = account_jwk(key)
    assert jwk_thumbprint(jwk) == sandbox_acme.jwk_thumbprint(jwk)
    _check_signature(jwk, "RS256", sign_jws(key, {"alg": "RS256", "nonce": "n", "url": "u"}, None))


def _check_signature(jwk, alg, envelope):
    import json

    data = json.loads(envelope)
    signing_input = (data["protected"] + "." + data["payload"]).encode("ascii")
    sandbox_acme._verify_signature(jwk, alg, sandbox_acme.b64d(data["signature"]), signing_input)


def test_dns01_values():
    assert dns01_record("*.example.org") == "_acme-challenge.example.org"
    assert dns01_record("host.example.org.") == "_acme-challenge.host.example.org"
    assert dns01_value("token.thumb") == b64url(__import__("hashlib").sha256(b"token.thumb").digest())
