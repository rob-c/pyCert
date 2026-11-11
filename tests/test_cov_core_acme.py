"""Branch coverage for the ACME provider, driven through the scripted transport.

The helpers come from ``test_provider_acme_unit``; the provider fixture is
rebuilt here so this module stays independent of that file's fixtures.
"""

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from test_provider_acme_unit import (
    BASE,
    DIRECTORY,
    DIRECTORY_URL,
    KID,
    FakeTransport,
    make_csr,
    new_state,
    noop,
    resp,
    with_account,
)

from pycert.config import new_acme_profile
from pycert.errors import CAError
from pycert.providers import acme as acme_module
from pycert.providers.acme import ACMEProvider

TOKEN = "T" * 43


class RecordingTransport(FakeTransport):
    """The scripted transport, also keeping each request body."""

    def __init__(self):
        super().__init__()
        self.bodies: "list[tuple[str, bytes | None]]" = []

    def request(self, method, url, *, body=None, **kwargs):
        self.bodies.append((url, body))
        return super().request(method, url, body=body, **kwargs)


@pytest.fixture
def acme_provider(ctx, config):
    profile = new_acme_profile(
        "unit-acme", DIRECTORY_URL, display_name="Unit ACME", contact=["ops@example.org"], terms_agreed=True
    )
    config.add_ca(profile)
    provider = ACMEProvider(ctx, profile)
    transport = RecordingTransport()
    transport.add("GET", DIRECTORY_URL, resp(200, DIRECTORY))
    transport.add("HEAD", DIRECTORY["newNonce"], resp(200, headers={"Replay-Nonce": "nonce-1"}))
    provider.transport = transport
    return provider


def _jws_payload(body: bytes) -> dict:
    encoded = json.loads(body)["payload"]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def _authz(status, challenges):
    return resp(
        200,
        {"identifier": {"type": "dns", "value": "a.example.org"}, "status": status, "challenges": challenges},
        headers={"Replay-Nonce": "n"},
    )


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------


def test_account_lock_without_fcntl(acme_provider, monkeypatch):
    monkeypatch.setattr(acme_module, "fcntl", None)
    with acme_provider._account_lock():
        assert acme_provider.account_dir.is_dir()
    assert not (acme_provider.account_dir / ".lock").exists()


def test_registration_without_any_contact_address(acme_provider, config):
    acme_provider.profile.acme.contact = []
    config.identity.email = ""
    assert acme_provider._contact() == []
    acme_provider.account_dir.mkdir(parents=True, exist_ok=True)
    acme_provider._key = ec.generate_private_key(ec.SECP256R1())
    acme_provider.transport.add(
        "POST", DIRECTORY["newAccount"], resp(201, {"status": "valid"}, headers={"Location": KID, "Replay-Nonce": "x"})
    )
    acme_provider._register(noop, None)
    body = next(body for url, body in acme_provider.transport.bodies if url == DIRECTORY["newAccount"])
    payload = _jws_payload(body)
    assert payload == {"termsOfServiceAgreed": True}
    assert json.loads(acme_provider.account_info_path.read_text())["contact"] == []


# ---------------------------------------------------------------------------
# Authorizations
# ---------------------------------------------------------------------------


def test_challenge_already_processing_is_not_triggered_again(acme_provider, tmp_path):
    with_account(acme_provider)
    acme_provider.profile.acme.challenge = "http-01"
    acme_provider.profile.acme.http_mode = "webroot"
    acme_provider.profile.acme.webroot = str(tmp_path)
    well_known = tmp_path / ".well-known"
    well_known.mkdir()  # the web server already serves other /.well-known content
    authz_url = BASE + "/authz/processing"
    challenge_url = BASE + "/chall/processing"
    challenge = {"type": "http-01", "url": challenge_url, "token": TOKEN, "status": "processing"}
    acme_provider.transport.add(
        "POST", authz_url, _authz("pending", [challenge]), _authz("valid", [dict(challenge, status="valid")])
    )
    messages = []
    acme_provider._complete_authorizations([authz_url], messages.append, None)
    assert ("POST", challenge_url) not in acme_provider.transport.calls
    assert "a.example.org validated" in messages
    # Only the directory pyCertWiz created is removed again; the existing .well-known stays.
    assert well_known.is_dir() and not (well_known / "acme-challenge").exists()


def test_failed_validation_reports_the_last_challenge_error(acme_provider, tmp_path):
    with_account(acme_provider)
    acme_provider.profile.acme.challenge = "http-01"
    acme_provider.profile.acme.http_mode = "webroot"
    acme_provider.profile.acme.webroot = str(tmp_path)
    authz_url = BASE + "/authz/invalid"
    challenge_url = BASE + "/chall/invalid"
    pending = {"type": "http-01", "url": challenge_url, "token": TOKEN, "status": "pending"}
    invalid = [
        "not a challenge object",
        {"type": "dns-01", "error": "not a problem document"},
        {"type": "http-01", "status": "invalid", "error": {"detail": "connection refused"}},
        {"type": "tls-alpn-01", "status": "pending"},
    ]
    acme_provider.transport.add("POST", authz_url, _authz("pending", [pending]), _authz("invalid", invalid))
    acme_provider.transport.add("POST", challenge_url, resp(200, pending, headers={"Replay-Nonce": "n"}))
    with pytest.raises(CAError, match="could not validate a.example.org: connection refused"):
        acme_provider._complete_authorizations([authz_url], noop, None)
    assert ("POST", challenge_url) in acme_provider.transport.calls
    assert not (tmp_path / ".well-known").exists()


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------


def test_processing_order_is_not_finalized_again(ctx, acme_provider):
    with_account(acme_provider)
    state = new_state(ctx, alias="processing.example.org", order_url=BASE + "/order/p")
    order = acme_provider._finalize(state, {"status": "processing"}, make_csr("processing.example.org"), noop, None)
    assert order == {"status": "processing"}
    assert state.server.status == "processing" and "certificate_url" not in state.provider
    assert acme_provider.transport.calls == []


def test_ready_order_skips_the_authorizations(ctx, acme_provider):
    with_account(acme_provider)
    state = new_state(ctx, alias="ready.example.org")
    order_url, finalize_url = BASE + "/order/ready", BASE + "/finalize/ready"
    acme_provider.transport.add(
        "POST",
        DIRECTORY["newOrder"],
        resp(
            201,
            {"status": "ready", "finalize": finalize_url, "authorizations": [BASE + "/authz/unused"]},
            headers={"Location": order_url, "Replay-Nonce": "n"},
        ),
    )
    acme_provider.transport.add(
        "POST",
        finalize_url,
        resp(200, {"status": "valid", "certificate": BASE + "/cert/ready"}, headers={"Replay-Nonce": "n"}),
    )
    result = acme_provider._place_order(
        state, make_csr("ready.example.org"), renewal=False, progress=noop, stop_event=None
    )
    assert result.success and "has been issued" in result.message
    assert ("POST", BASE + "/authz/unused") not in acme_provider.transport.calls
    assert ctx.store.get("ready.example.org").provider["certificate_url"] == BASE + "/cert/ready"
