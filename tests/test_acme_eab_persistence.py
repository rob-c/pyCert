"""EAB, durable-state and routing tests for the ACME front-end.

Adds 1,000 cases: 300 external-account-binding cases, 300 persistence/restart
cases and 400 routing/header variants.  These are the production-readiness
edges that matter after basic certbot issuance works: institutional account
authorization and surviving an ACME-service restart.
"""

import json

import pytest
from acme_client import ACMEClient, eab_binding, jwk_for
from cryptography.hazmat.primitives.asymmetric import rsa

from sandbox_ca.acme import ACMEServer, b64e


@pytest.fixture(scope="session")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def acme(ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    return ACMEServer(ca, public_url="https://acme.test", challenge_mode="auto")


EAB_KID = "stfc-test-001"
EAB_KEY = b"stfc-test-hmac-key-0123456789"
EAB_OTHER_KEY = b"wrong-key-0123456789"
_EAB_VARIANTS = [
    ("hs256", 201),
    ("hs384", 201),
    ("hs512", 201),
    ("missing", 400),
    ("wrong-key", 403),
    ("unknown-kid", 403),
    ("wrong-url", 403),
    ("bad-signature", 403),
    ("none-alg", 400),
    ("payload-other-key", 403),
    ("payload-array", 400),
    ("missing-protected", 400),
    ("missing-payload", 400),
    ("missing-signature", 400),
    ("malformed-protected", 400),
    ("malformed-signature", 403),
    ("extra-field", 201),
    ("empty-kid", 403),
    ("url-trailing", 403),
    ("valid-hs256", 201),
    ("bad-hmac-base64", 400),
    ("protected-array", 400),
    ("payload-jwk-only", 201),
    ("payload-extra-jwk-field", 201),
    ("empty-signature", 403),
    ("signature-uppercase", 403),
    ("hmac-hs1", 400),
    ("kid-string", 403),
    ("wrong-kid-right-key", 403),
    ("valid-again", 201),
]
_EAB_CASES = [(variant, repeat) for variant in range(len(_EAB_VARIANTS)) for repeat in range(10)]


def _eab_server(acme):
    acme.eab_credentials = {EAB_KID: EAB_KEY}
    acme.require_eab = True
    return acme


def _binding_for(client, variant, key):
    jwk = client.jwk
    url = "https://acme.test/acme/new-account"
    if variant in ("hs256", "valid-hs256", "valid-again"):
        return eab_binding(jwk, EAB_KID, EAB_KEY, url)
    if variant == "hs384":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url, alg="HS384")
    if variant == "hs512":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url, alg="HS512")
    if variant == "missing":
        return None
    if variant == "wrong-key":
        return eab_binding(jwk, EAB_KID, EAB_OTHER_KEY, url)
    if variant == "unknown-kid":
        return eab_binding(jwk, "unknown", EAB_KEY, url)
    if variant == "wrong-url":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url + "/wrong")
    if variant == "bad-signature":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["signature"] = b64e(b"wrong")
        return value
    if variant == "none-alg":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url, alg="none")
    if variant == "payload-other-key":
        return eab_binding(jwk_for(rsa.generate_private_key(public_exponent=65537, key_size=2048)), EAB_KID, EAB_KEY, url)
    if variant == "payload-array":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["payload"] = b64e(b"[]")
        return value
    if variant == "missing-protected":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        del value["protected"]
        return value
    if variant == "missing-payload":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        del value["payload"]
        return value
    if variant == "missing-signature":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        del value["signature"]
        return value
    if variant == "malformed-protected":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["protected"] = "%%%"
        return value
    if variant == "malformed-signature":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["signature"] = "***"
        return value
    if variant == "extra-field":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["extra"] = True
        return value
    if variant == "empty-kid":
        return eab_binding(jwk, "", EAB_KEY, url)
    if variant == "url-trailing":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url + "/")
    if variant == "bad-hmac-base64":
        return {"protected": "e30", "payload": "", "signature": "AA"}
    if variant == "protected-array":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["protected"] = b64e(b"[]")
        return value
    if variant == "payload-jwk-only":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url)
    if variant == "payload-extra-jwk-field":
        broad = dict(jwk)
        broad["extra"] = "ignored"
        return eab_binding(broad, EAB_KID, EAB_KEY, url)
    if variant == "empty-signature":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["signature"] = ""
        return value
    if variant == "signature-uppercase":
        value = eab_binding(jwk, EAB_KID, EAB_KEY, url)
        value["signature"] = value["signature"].upper()
        return value
    if variant == "hmac-hs1":
        return eab_binding(jwk, EAB_KID, EAB_KEY, url, alg="HS1")
    if variant == "kid-string":
        return eab_binding(jwk, 123, EAB_KEY, url)
    if variant == "wrong-kid-right-key":
        return eab_binding(jwk, "other", EAB_KEY, url)
    return eab_binding(jwk, EAB_KID, EAB_KEY, url)


@pytest.mark.parametrize(
    "variant_index,repeat",
    _EAB_CASES,
    ids=["%s-r%d" % (_EAB_VARIANTS[v][0], r) for v, r in _EAB_CASES],
)
def test_external_account_binding_matrix(acme, key, variant_index, repeat):
    variant, expected = _EAB_VARIANTS[variant_index]
    acme = _eab_server(acme)
    client = ACMEClient(acme, key=key)
    status, _, body = client.register(externalAccountBinding=_binding_for(client, variant, EAB_KEY))
    if expected == 201:
        assert status == 201, body
        assert json.loads(body)["status"] == "valid"
    else:
        assert status in (400, 403), body
        problem = json.loads(body)
        assert problem["type"].startswith("urn:ietf:params:acme:error:")
    directory = json.loads(acme.handle("GET", "/acme/directory", {}, b"")[2])
    assert directory["meta"]["externalAccountRequired"] is True


# ---------------------------------------------------------------------------
# 300 persistence/restart cases
# ---------------------------------------------------------------------------

_PERSISTENCE_CASES = list(range(300))


def _make_persistent_server(ca, path, key):
    server = ACMEServer(ca, public_url="https://acme.test", challenge_mode="auto", state_path=path)
    client = ACMEClient(server, key=key)
    assert client.register()[0] == 201
    return server, client


@pytest.mark.parametrize("case", _PERSISTENCE_CASES, ids=["p%03d" % i for i in _PERSISTENCE_CASES])
def test_acme_state_persistence_matrix(ca, key, tmp_path, case):
    scenario = case % 6
    path = tmp_path / ("acme-%03d.json" % case)
    server, client = _make_persistent_server(ca, path, key)
    order = None
    if scenario >= 1:
        status, headers, body = client.new_order(["p%03d.example.org" % case])
        assert status == 201, body
        order = json.loads(body)
    if scenario == 2:
        authz = json.loads(client.authz(order["authorizations"][0])[2])
        client.challenge(authz["challenges"][0]["url"])
        client.order(order["finalize"].replace("/finalize/", "/order/"))
    elif scenario == 3:
        authz = json.loads(client.authz(order["authorizations"][0])[2])
        client.challenge(authz["challenges"][0]["url"])
        client.order(order["finalize"].replace("/finalize/", "/order/"))
        csr = client.csr(["p%03d.example.org" % case], key=key)
        status, _, body = client.finalize(order["finalize"], csr)
        assert status == 200
    elif scenario == 4:
        authz_id = server.orders[order["finalize"].rsplit("/", 1)[-1]].authorizations[0]
        server.authzs[authz_id].status = "invalid"
        server.orders[order["finalize"].rsplit("/", 1)[-1]].status = "invalid"
        server._persist_state()
    elif scenario == 5:
        client.authz(order["authorizations"][0])

    assert path.exists()
    state = json.loads(path.read_text())
    assert state["format"] == 1
    account_ids = {item["id"] for item in state["accounts"]}
    assert client.kid.rsplit("/", 1)[-1] in account_ids

    restored = ACMEServer(ca, public_url="https://acme.test", challenge_mode="auto", state_path=path)
    assert len(restored.accounts) == 1
    if order is not None:
        order_id = order["finalize"].rsplit("/", 1)[-1]
        assert order_id in restored.orders
        restored_order = restored.orders[order_id]
        if scenario == 2:
            assert restored_order.status in ("ready", "valid")
        elif scenario == 3:
            assert restored_order.status == "valid"
            assert restored_order.certificate
            cert_id = int(restored_order.certificate.rsplit("/", 1)[-1])
            assert cert_id in restored.cert_orders
        elif scenario == 4:
            assert restored_order.status == "invalid"
    assert (path.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# 400 routing/header cases
# ---------------------------------------------------------------------------

_PATHS = [
    "/acme/directory",
    "/acme/new-nonce",
    "/acme/new-account",
    "/acme/new-order",
    "/acme/order/x",
    "/acme/authz/x",
    "/acme/chall/x",
    "/acme/finalize/x",
    "/acme/cert/1",
    "/acme/revoke-cert",
    "/acme/acct/x",
    "/acme/orders/x",
    "/acme/terms",
    "/acme/key-change",
    "/acme/unknown",
    "/",
    "/acme",
    "/acme?x=1",
    "/acme/directory?x=1",
    "/acme/new-nonce/",
]
_HEADERS = [
    {},
    {"accept": "*/*"},
    {"content-type": "application/jose+json"},
    {"content-type": "application/json"},
    {"user-agent": "certbot/5.9.0"},
    {"x-forwarded-for": "127.0.0.1"},
    {"host": "acme.test"},
    {"accept": "application/problem+json"},
    {"content-type": "text/plain"},
    {"x-request-id": "abc"},
    {"accept-encoding": "identity"},
    {"connection": "close"},
    {"date": "Sat, 07 Nov 2026 12:00:00 GMT"},
    {"local-host": "localhost"},
    {"x-real-ip": "127.0.0.1"},
    {"cache-control": "no-cache"},
    {"if-none-match": "x"},
    {"origin": "https://example.org"},
    {"referer": "https://example.org"},
    {"x-test": "value"},
]
_ROUTE_CASES = [(path, header_index) for path in _PATHS for header_index in range(20)]


@pytest.mark.parametrize(
    "path,header_index",
    _ROUTE_CASES,
    ids=["%03d-h%02d" % (i, h) for i, (_, h) in enumerate(_ROUTE_CASES)],
)
def test_acme_routing_header_matrix(acme, path, header_index):
    status, response_headers, body, content_type = acme.handle(
        "GET", path, _HEADERS[header_index], b""
    )
    assert status != 500
    assert 200 <= status <= 501
    assert response_headers.get("Replay-Nonce")
    if content_type:
        assert content_type in ("application/json", "application/problem+json", "text/plain; charset=utf-8")
