"""ACME v2 emulation tests for the sandbox CA front-end."""

import json
import threading

import pytest
from acme_client import ACMEClient, complete_order
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from sandbox_ca.acme import ACMEProblem, ACMEServer, b64d, b64e, jwk_thumbprint, validate_dns_identifier


@pytest.fixture(scope="session")
def account_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def csr_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def acme(ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    return ACMEServer(ca, public_url="https://acme.test", challenge_mode="auto")


@pytest.fixture
def client(acme, account_key):
    result = ACMEClient(acme, key=account_key)
    status, headers, body = result.register()
    assert status == 201, body
    return result


def _json(body):
    return json.loads(body.decode())


def test_directory_contract(acme):
    status, headers, body, content_type = acme.handle("GET", "/acme/directory", {}, b"")
    assert status == 200 and content_type == "application/json"
    assert headers["Replay-Nonce"]
    directory = _json(body)
    assert directory["newNonce"].endswith("/acme/new-nonce")
    assert directory["newAccount"].endswith("/acme/new-account")
    assert directory["newOrder"].endswith("/acme/new-order")
    assert directory["revokeCert"].endswith("/acme/revoke-cert")
    assert directory["meta"]["externalAccountRequired"] is False


def test_full_auto_order_and_certificate(acme, client, csr_key):
    status, headers, body = client.new_order(["host.example.org", "www.example.org"])
    assert status == 201
    order = _json(body)
    assert order["status"] == "pending"
    assert len(order["authorizations"]) == 2

    for authz_url in order["authorizations"]:
        status, _, body = client.authz(authz_url)
        assert status == 200
        authz = _json(body)
        assert authz["status"] == "pending"
        challenge = authz["challenges"][0]
        assert challenge["type"] == "http-01"
        status, headers, body = client.challenge(challenge["url"])
        assert status == 200
        assert b'"status": "valid"' in body
        assert "rel=\"up\"" in headers.get("Link", "")

    status, _, body = client.order(order["finalize"].replace("/finalize/", "/order/"))
    assert status == 200 and _json(body)["status"] == "ready"

    csr = client.csr(["host.example.org", "www.example.org"], key=csr_key)
    status, headers, body = client.finalize(order["finalize"], csr)
    assert status == 200
    order = _json(body)
    assert order["status"] == "valid"
    assert order["certificate"].startswith("https://acme.test/acme/cert/")

    status, headers, body = client.certificate(order["certificate"])
    assert status == 200
    assert client.last_content_type == "application/pem-certificate-chain"
    assert body.count(b"BEGIN CERTIFICATE") == 2
    leaf = x509.load_pem_x509_certificate(body.split(b"-----END CERTIFICATE-----\n", 1)[0] + b"-----END CERTIFICATE-----\n")
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(san.get_values_for_type(x509.DNSName)) == ["host.example.org", "www.example.org"]


def test_manual_ca_order_becomes_valid_after_signing(acme, client, csr_key, ca):
    ca.auto_approve = False
    status, headers, body = client.new_order(["manual.example.org"])
    assert status == 201
    order = _json(body)
    authz_url = order["authorizations"][0]
    status, _, body = client.authz(authz_url)
    challenge = _json(body)["challenges"][0]
    status, _, _ = client.challenge(challenge["url"])
    assert status == 200
    csr = client.csr(["manual.example.org"], key=csr_key)
    status, _, body = client.finalize(order["finalize"], csr)
    assert status == 200
    assert _json(body)["status"] == "processing"
    csr_id = next(iter(ca.csrs.values())).id
    ca.sign(csr_id)
    status, _, body = client.order(order["finalize"].replace("/finalize/", "/order/"))
    assert status == 200
    assert _json(body)["status"] == "valid"


def test_bad_csr_is_rejected(acme, client, csr_key):
    status, _, body = client.new_order(["expected.example.org"])
    order = _json(body)
    authz = _json(client.authz(order["authorizations"][0])[2])
    client.challenge(authz["challenges"][0]["url"])
    csr = client.csr(["other.example.org"], key=csr_key)
    status, _, body = client.finalize(order["finalize"], csr)
    assert status == 400
    assert _json(body)["type"].endswith("badCSR")


def test_finalize_before_challenge_is_order_not_ready(acme, client, csr_key):
    status, _, body = client.new_order(["pending.example.org"])
    order = _json(body)
    csr = client.csr(["pending.example.org"], key=csr_key)
    status, _, body = client.finalize(order["finalize"], csr)
    assert status == 403
    assert _json(body)["type"].endswith("orderNotReady")


def test_wildcard_uses_dns_01_and_can_be_issued(acme, client, csr_key):
    status, _, body = client.new_order(["*.wild.example.org"])
    assert status == 201
    order = _json(body)
    authz = _json(client.authz(order["authorizations"][0])[2])
    assert authz["wildcard"] is True
    assert authz["identifier"]["value"] == "wild.example.org"
    assert [item["type"] for item in authz["challenges"]] == ["dns-01"]
    client.challenge(authz["challenges"][0]["url"])
    csr = client.csr(["*.wild.example.org"], key=csr_key)
    status, _, body = client.finalize(order["finalize"], csr)
    assert status == 200 and _json(body)["status"] == "valid"


def test_revocation_marks_certificate(acme, client, csr_key, ca):
    status, _, body = complete_order(client, ["revoke.example.org"])
    assert status == 200
    cert_url = _json(body)["certificate"]
    status, _, pem = client.certificate(cert_url)
    cert = x509.load_pem_x509_certificate(pem)
    cert_der = b64e(cert.public_bytes(serialization.Encoding.DER))
    status, _, body = client.request(
        "POST",
        "/acme/revoke-cert",
        {"certificate": cert_der, "reason": 1},
    )
    assert status == 200
    assert any(item.status == "REVOKED" for item in ca.certificates.values())


def test_ec_and_ed25519_account_keys_work(acme):
    for key in (
        ec.generate_private_key(ec.SECP256R1()),
        ed25519.Ed25519PrivateKey.generate(),
    ):
        client = ACMEClient(acme, key=key)
        status, _, body = client.register()
        assert status == 201, body


def test_account_reuse_and_only_return_existing(acme, account_key):
    first = ACMEClient(acme, key=account_key)
    assert first.register()[0] == 201
    second = ACMEClient(acme, key=account_key)
    status, headers, body = second.register()
    assert status == 200
    assert headers["Location"] == first.kid
    third = ACMEClient(acme)
    status, _, body = third.register(onlyReturnExisting=True)
    assert status == 400
    assert _json(body)["type"].endswith("accountDoesNotExist")


def test_bad_nonce_and_reused_nonce_are_problem_documents(acme, client):
    status, _, body = client.request(
        "POST", "/acme/new-order", {"identifiers": [{"type": "dns", "value": "x.example.org"}]},
        nonce="not-a-nonce",
    )
    assert status == 400
    assert _json(body)["type"].endswith("badNonce")
    nonce = client.head_nonce()
    status, _, _ = client.request(
        "POST", "/acme/new-order",
        {"identifiers": [{"type": "dns", "value": "x.example.org"}]}, nonce=nonce,
    )
    assert status == 201
    status, _, body = client.request(
        "POST", "/acme/new-order",
        {"identifiers": [{"type": "dns", "value": "x.example.org"}]}, nonce=nonce,
    )
    assert status == 400
    assert _json(body)["type"].endswith("badNonce")


def test_b64url_and_thumbprint_helpers():
    payload = b"\x00\xffhello"
    assert b64d(b64e(payload)) == payload
    jwk = {"kty": "RSA", "n": "AQAB", "e": "AQAB", "extra": "ignored"}
    assert jwk_thumbprint(jwk) == jwk_thumbprint({key: jwk[key] for key in ("kty", "n", "e")})


@pytest.mark.parametrize("value", ["example.org", "*.example.org", "localhost", "a-b.example.org"])
def test_valid_dns_identifiers(value):
    assert validate_dns_identifier(value)


@pytest.mark.parametrize("value", ["", " ", "bad..example", "-bad.example", "bad-.example", "x" * 64 + ".org"])
def test_invalid_dns_identifiers(value):
    with pytest.raises(ACMEProblem):
        validate_dns_identifier(value)


def _challenge_http_server(body_getter):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            body = body_getter(self.path)
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_http_01_fetches_the_key_authorization(ca, account_key):
    holder = {}
    server = _challenge_http_server(lambda path: holder.get(path))
    try:
        acme = ACMEServer(
            ca,
            public_url="https://acme.test",
            challenge_mode="http",
            http_port=server.server_address[1],
        )
        client = ACMEClient(acme, key=account_key)
        assert client.register()[0] == 201
        status, _, body = client.new_order(["localhost"])
        order = _json(body)
        authz = _json(client.authz(order["authorizations"][0])[2])
        challenge = authz["challenges"][0]
        holder["/.well-known/acme-challenge/" + challenge["token"]] = (
            challenge["token"] + "." + jwk_thumbprint(client.jwk)
        )
        status, _, body = client.challenge(challenge["url"])
        assert status == 200
        assert _json(body)["status"] == "valid"
    finally:
        server.shutdown()
        server.server_close()


def test_http_01_wrong_body_invalidates_the_order(ca, account_key):
    server = _challenge_http_server(lambda path: "wrong-token")
    try:
        acme = ACMEServer(
            ca,
            public_url="https://acme.test",
            challenge_mode="http",
            http_port=server.server_address[1],
        )
        client = ACMEClient(acme, key=account_key)
        assert client.register()[0] == 201
        status, _, body = client.new_order(["localhost"])
        order = _json(body)
        authz = _json(client.authz(order["authorizations"][0])[2])
        status, _, body = client.challenge(authz["challenges"][0]["url"])
        assert status == 200
        assert _json(body)["status"] == "invalid"
        assert _json(client.order(order["finalize"].replace("/finalize/", "/order/"))[2])["status"] == "invalid"
    finally:
        server.shutdown()
        server.server_close()


def test_manual_challenge_stays_pending_and_blocks_finalize(ca, account_key, csr_key):
    acme = ACMEServer(ca, public_url="https://acme.test", challenge_mode="manual")
    client = ACMEClient(acme, key=account_key)
    assert client.register()[0] == 201
    status, _, body = client.new_order(["manual.example.org"])
    order = _json(body)
    authz = _json(client.authz(order["authorizations"][0])[2])
    status, _, body = client.challenge(authz["challenges"][0]["url"])
    assert status == 200
    assert _json(body)["status"] == "pending"
    csr = client.csr(["manual.example.org"], key=csr_key)
    status, _, body = client.finalize(order["finalize"], csr)
    assert status == 403
    assert _json(body)["type"].endswith("orderNotReady")
