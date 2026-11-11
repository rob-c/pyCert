"""Protocol edge cases of the ACME provider, driven through a scripted transport.

The end-to-end behaviour is covered against the real sandbox server in
``test_provider_acme.py``; these tests feed the provider the malformed or
unusual responses a real CA (or a man in the middle) could send, and check
that every one is refused with a clear error rather than mis-handled.
"""

import json
import sys
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from pycert import bundled, certs
from pycert.config import new_acme_profile
from pycert.errors import CAError, NetworkError, ProtocolError, PyCertError
from pycert.providers import acme as acme_module
from pycert.providers.acme import (
    PROBLEM_PREFIX,
    ACMEProblem,
    ACMEProvider,
    _Challenges,
    _identifier_values,
    _retry_after,
    account_jwk,
    account_summary,
    b64url,
    jws_algorithm,
)
from pycert.transport import Response

BASE = "https://acme.test"
DIRECTORY_URL = BASE + "/directory"
KID = BASE + "/acct/1"
DIRECTORY = {
    "newNonce": BASE + "/nonce",
    "newAccount": BASE + "/new-account",
    "newOrder": BASE + "/new-order",
    "revokeCert": BASE + "/revoke",
    "meta": {"termsOfService": BASE + "/terms"},
}


def resp(status=200, body=b"", headers=None, reason=""):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    return Response(
        status=status,
        reason=reason,
        headers={key.lower(): value for key, value in (headers or {}).items()},
        body=body,
        url="",
    )


class FakeTransport:
    """Answers (method, url) from scripted queues; the last answer repeats."""

    def __init__(self):
        self.routes: "dict[tuple[str, str], list]" = {}
        self.calls: "list[tuple[str, str]]" = []
        self.last_peer_certificate = b""

    def add(self, method, url, *responses):
        self.routes.setdefault((method, url), []).extend(responses)

    def request(self, method, url, *, body=None, headers=None, idempotent=False, stop_event=None, deadline=None):
        self.calls.append((method, url))
        queue = self.routes.get((method, url))
        if not queue:
            raise AssertionError(f"unexpected request {method} {url}")
        return queue.pop(0) if len(queue) > 1 else queue[0]


def noop(_message):
    pass


@pytest.fixture
def provider(ctx, config):
    profile = new_acme_profile(
        "unit-acme", DIRECTORY_URL, display_name="Unit ACME", contact=["ops@example.org"], terms_agreed=True
    )
    config.add_ca(profile)
    instance = ACMEProvider(ctx, profile)
    fake = FakeTransport()
    fake.add("GET", DIRECTORY_URL, resp(200, DIRECTORY))
    fake.add("HEAD", DIRECTORY["newNonce"], resp(200, headers={"Replay-Nonce": "nonce-1"}))
    instance.transport = fake
    return instance


def with_account(provider):
    provider._key = ec.generate_private_key(ec.SECP256R1())
    provider._kid = KID
    provider._account_checked = True
    return provider


def make_csr(subject_cn="host.example.org", sans=None, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)] if subject_cn else [])
    builder = x509.CertificateSigningRequestBuilder().subject_name(name)
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(key, hashes.SHA256())


def new_state(ctx, alias="unit.example.org", **provider_data):
    state = ctx.store.new_state(alias=alias, type="host", cn=alias, email="ops@example.org")
    state.ca = "unit-acme"
    state.provider.update(provider_data)
    ctx.store.save(state)
    return state


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_encoding_helpers_refuse_unsupported_account_keys():
    assert b64url("abc") == b64url(b"abc") == "YWJj"
    edwards = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(PyCertError, match="EC"):
        account_jwk(edwards)
    with pytest.raises(PyCertError, match="EC or RSA"):
        jws_algorithm(edwards)


def test_problem_documents_include_subproblems():
    problem = ACMEProblem(
        "ordering",
        {
            "type": PROBLEM_PREFIX + "rejectedIdentifier",
            "detail": "some names were refused",
            "subproblems": [{"identifier": {"value": "bad.example.org"}, "detail": "blocked by policy"}, "junk"],
        },
        400,
    )
    assert problem.problem_type == "rejectedIdentifier"
    assert "bad.example.org: blocked by policy" in str(problem)
    assert str(problem).startswith("ordering: some names were refused")


def test_identifier_values_from_csr():
    assert _identifier_values(make_csr("Host.Example.org.")) == ["host.example.org"]
    names = [x509.DNSName("a.example.org"), x509.DNSName("B.example.org"), x509.DNSName("a.example.org")]
    assert _identifier_values(make_csr("a.example.org", names)) == ["a.example.org", "b.example.org"]
    with pytest.raises(PyCertError, match="IP and e-mail"):
        _identifier_values(make_csr("a.example.org", [x509.DNSName("a.example.org"), x509.RFC822Name("x@y.org")]))
    with pytest.raises(PyCertError, match="must also be one of its DNS names"):
        _identifier_values(make_csr("a.example.org", [x509.DNSName("b.example.org")]))
    with pytest.raises(PyCertError, match="names no DNS host"):
        _identifier_values(make_csr("", [x509.UniformResourceIdentifier("https://example.org/")]))


def test_retry_after_is_bounded():
    assert _retry_after(resp(headers={"Retry-After": "5"}), 1.0) == 5.0
    assert _retry_after(resp(headers={"Retry-After": "9999"}), 1.0) == acme_module.MAX_RETRY_AFTER
    assert _retry_after(resp(headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}), 2.0) == 2.0
    assert _retry_after(resp(headers={"Retry-After": "0"}), 3.0) == 3.0


def test_account_summary_offline(ctx, provider):
    assert account_summary(ctx, "unit-acme") == {"registered": False}
    provider.account_dir.mkdir(parents=True)
    provider.account_info_path.write_text("{not json")
    provider.account_info_path.chmod(0o600)
    assert account_summary(ctx, "unit-acme") == {"registered": False, "error": "unreadable account.json"}
    assert provider._read_account_info() == {}


# ---------------------------------------------------------------------------
# Construction, directory and nonces
# ---------------------------------------------------------------------------


def test_plaintext_directory_is_refused(ctx):
    profile = new_acme_profile("plain", "http://acme.test/directory")
    with pytest.raises(NetworkError, match="plaintext"):
        ACMEProvider(ctx, profile)


@pytest.mark.parametrize(
    "response, error, match",
    [
        (resp(500, {"type": PROBLEM_PREFIX + "serverInternal", "detail": "down"}), ACMEProblem, "down"),
        (resp(503, b"<html>maintenance</html>", reason="Service Unavailable"), ACMEProblem, "HTTP 503"),
        (resp(502, b"[1, 2]"), ACMEProblem, "HTTP 502"),
        (resp(404, b""), ACMEProblem, "HTTP 404"),
        (resp(200, b"[]"), ProtocolError, "unexpected JSON"),
        (resp(200, b"not json"), ProtocolError, "invalid JSON"),
        (resp(200, {"newNonce": "x", "newAccount": "y"}), ProtocolError, "missing newOrder"),
    ],
)
def test_directory_failures_are_reported(provider, response, error, match):
    provider.transport.routes[("GET", DIRECTORY_URL)] = [response]
    with pytest.raises(error, match=match):
        provider.directory()
    result = provider.ping()
    assert not result.ok and match.split()[0].lower() in result.detail.lower()


def test_nonce_falls_back_to_get_and_requires_a_nonce(provider):
    url = DIRECTORY["newNonce"]
    provider.transport.routes[("HEAD", url)] = [resp(405)]
    provider.transport.add("GET", url, resp(204, headers={"Replay-Nonce": "via-get"}))
    assert provider._fresh_nonce(None) == "via-get"
    provider.transport.routes[("GET", url)] = [resp(204)]
    with pytest.raises(ProtocolError, match="Replay-Nonce"):
        provider._fresh_nonce(None)


def test_peer_details_ignore_garbage(provider):
    provider.transport.last_peer_certificate = b"not a certificate"
    assert provider._peer() is None
    result = provider.ping()
    assert result.ok and result.tls is None


# ---------------------------------------------------------------------------
# Signed POSTs
# ---------------------------------------------------------------------------


def test_post_retries_rate_limits_then_reports_garbage(provider, monkeypatch):
    with_account(provider)
    slept = []
    monkeypatch.setattr(acme_module, "_sleep", lambda seconds, _stop: slept.append(seconds))
    url = BASE + "/thing"
    provider.transport.add(
        "POST",
        url,
        resp(429, {"type": PROBLEM_PREFIX + "rateLimited"}, headers={"Retry-After": "7", "Replay-Nonce": "a"}),
        resp(200, {"ok": True}, headers={"Replay-Nonce": "b"}),
    )
    assert provider._post_json(url, None, context="reading") == {"ok": True}
    assert slept == [7.0]
    provider.transport.routes[("POST", url)] = [resp(400, b"\xff\xfe not json", headers={"Replay-Nonce": "c"})]
    with pytest.raises(ACMEProblem, match="HTTP 400"):
        provider._post(url, None, context="reading")


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------


def test_registration_needs_a_location_header(provider):
    provider._key = ec.generate_private_key(ec.SECP256R1())
    provider.transport.add("POST", DIRECTORY["newAccount"], resp(201, {"status": "valid"}, headers={"Replay-Nonce": "x"}))
    with pytest.raises(ProtocolError, match="account URL"):
        provider._register(noop, None)


def _saved_account(provider):
    provider.account_dir.mkdir(parents=True, exist_ok=True)
    provider._load_or_create_key(noop)
    provider.account_info_path.write_text(json.dumps({"kid": KID, "directory": DIRECTORY_URL}))
    provider.account_info_path.chmod(0o600)


def test_deactivated_account_is_reported(provider):
    _saved_account(provider)
    provider.transport.add("POST", KID, resp(200, {"status": "deactivated"}, headers={"Replay-Nonce": "x"}))
    with pytest.raises(PyCertError, match="deactivated"):
        provider.ensure_account(progress=noop)


def test_unexpected_account_errors_are_not_swallowed(provider):
    _saved_account(provider)
    provider.transport.add(
        "POST", KID, resp(500, {"type": PROBLEM_PREFIX + "serverInternal", "detail": "db down"}, headers={"Replay-Nonce": "x"})
    )
    with pytest.raises(ACMEProblem, match="db down"):
        provider.ensure_account(progress=noop)


def test_info_reports_unreadable_eab_and_account_problems(provider, monkeypatch):
    provider.profile.acme.eab_kid = "kid-1"
    provider.profile.acme.eab_hmac_env = "PYCERT_TEST_EAB"
    monkeypatch.setenv("PYCERT_TEST_EAB", "!!not base64!!")
    _saved_account(provider)
    provider.transport.add("POST", KID, resp(500, {"detail": "unavailable"}, headers={"Replay-Nonce": "x"}))
    info = provider.info()
    assert info["eab_key_stored"] is False
    assert info["account"] == KID
    assert info["account_status"].startswith("unknown (") and "unavailable" in info["account_status"]
    assert info["terms_of_service"] == DIRECTORY["meta"]["termsOfService"]


# ---------------------------------------------------------------------------
# Requests, authorizations and orders
# ---------------------------------------------------------------------------


def test_validate_request_puts_the_cn_first(provider):
    spec = SimpleNamespace(
        type="host", auth_alias="", san_ip=[], san_email=[], cn="a.example.org", san_dns=["b.example.org"]
    )
    provider.validate_request(spec)
    assert spec.san_dns == ["a.example.org", "b.example.org"]


def _authz(url, status, *, wildcard=False, challenges=None):
    body = {"identifier": {"type": "dns", "value": "a.example.org"}, "status": status, "challenges": challenges or []}
    if wildcard:
        body["wildcard"] = True
    return resp(200, body, headers={"Replay-Nonce": "n"})


def test_already_valid_authorizations_need_no_challenge(provider):
    with_account(provider)
    url = BASE + "/authz/1"
    provider.transport.add("POST", url, _authz(url, "valid"))
    provider._complete_authorizations([url], noop, None)
    assert provider.transport.calls.count(("POST", url)) == 1


def test_unusable_authorizations_are_refused(provider):
    with_account(provider)
    url = BASE + "/authz/2"
    provider.transport.add("POST", url, _authz(url, "deactivated"))
    with pytest.raises(CAError, match="is deactivated"):
        provider._complete_authorizations([url], noop, None)
    provider.transport.routes[("POST", url)] = [_authz(url, "pending", wildcard=True)]
    with pytest.raises(PyCertError, match="dns-01"):
        provider._complete_authorizations([url], noop, None)


def test_invalid_orders_and_missing_locations(ctx, provider):
    with_account(provider)
    state = new_state(ctx, order_url=BASE + "/order/1", finalize_url=BASE + "/finalize/1")
    csr = make_csr("unit.example.org")
    provider.transport.add("POST", BASE + "/order/1", resp(200, {"status": "invalid"}, headers={"Replay-Nonce": "n"}))
    with pytest.raises(CAError, match="the ACME order failed: invalid"):
        provider._finalize(state, {"status": "invalid"}, csr, noop, None)
    assert provider._order_error({"status": "expired"}) == "expired"
    provider.transport.add("POST", DIRECTORY["newOrder"], resp(201, {"status": "pending"}, headers={"Replay-Nonce": "n"}))
    with pytest.raises(ProtocolError, match="order URL"):
        provider._place_order(state, csr, renewal=False, progress=noop, stop_event=None)


def test_failed_renewal_order_keeps_the_current_certificate(ctx, provider):
    with_account(provider)
    order_url = BASE + "/order/renew"
    state = new_state(ctx, order_url=order_url)
    state.renewal = True
    state.status = "DOWNLOADED"
    ctx.store.save(state)
    provider.transport.add(
        "POST", order_url, resp(200, {"status": "invalid", "error": {"detail": "caa forbids"}}, headers={"Replay-Nonce": "n"})
    )
    outcome = provider.poll(state, progress=noop)
    assert outcome.terminal
    saved = ctx.store.get(state.alias)
    assert saved.status == "DOWNLOADED"  # the issued certificate is not marked failed
    assert any("caa forbids" in note for note in saved.notes)


def test_valid_order_without_certificate_url(ctx, provider):
    with_account(provider)
    order_url = BASE + "/order/2"
    state = new_state(ctx, order_url=order_url)
    provider.transport.add("POST", order_url, resp(200, {"status": "valid"}, headers={"Replay-Nonce": "n"}))
    with pytest.raises(ProtocolError, match="no certificate URL"):
        provider.poll(state, progress=noop)


def test_certificate_for_another_key_is_refused(ctx, provider):
    with_account(provider)
    order_url = BASE + "/order/3"
    cert_url = BASE + "/cert/3"
    state = new_state(ctx, order_url=order_url)
    state.spki_b64 = certs.spki_b64(ec.generate_private_key(ec.SECP256R1()).public_key())
    ctx.store.save(state)
    stranger = bundled.certificates()[0]
    provider.transport.add(
        "POST", order_url, resp(200, {"status": "valid", "certificate": cert_url}, headers={"Replay-Nonce": "n"})
    )
    provider.transport.add("POST", cert_url, resp(200, certs.cert_pem(stranger).encode(), headers={"Replay-Nonce": "n"}))
    with pytest.raises(ProtocolError, match="does not match"):
        provider.poll(state, progress=noop)


# ---------------------------------------------------------------------------
# Challenge responders
# ---------------------------------------------------------------------------


def test_standalone_listener_permission_error(provider, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise PermissionError("[Errno 13] Permission denied")

    monkeypatch.setattr(acme_module, "ThreadingHTTPServer", refuse)
    challenges = _Challenges(provider, noop, None)
    challenges.add("http-01", "a.example.org", "A" * 43, "A" * 43 + ".thumb")
    with pytest.raises(PyCertError, match="cannot listen on port"):
        challenges.publish()
    challenges.cleanup()


def test_dns_hook_that_cannot_run(provider):
    provider.profile.acme.dns_hook = "/nonexistent/pycert-dns-hook"
    challenges = _Challenges(provider, noop, None)
    challenges.add("dns-01", "a.example.org", "B" * 43, "B" * 43 + ".thumb")
    with pytest.raises(PyCertError, match="could not be run"):
        challenges.publish()


def test_dns_propagation_wait_and_failed_cleanup_is_only_a_warning(provider, tmp_path):
    hook = tmp_path / "hook.py"
    hook.write_text("import sys\nsys.exit(3 if sys.argv[1] == 'remove' else 0)\n")
    provider.profile.acme.dns_hook = f"{sys.executable} {hook}"
    provider.profile.acme.dns_propagation_seconds = 0.05
    messages = []
    challenges = _Challenges(provider, messages.append, None)
    challenges.add("dns-01", "*.example.org", "C" * 43, "C" * 43 + ".thumb")
    challenges.publish()
    assert any("propagation" in message for message in messages)
    challenges.cleanup()
    assert any(message.startswith("warning:") and "remove" in message for message in messages)
    assert challenges._dns_published == []

