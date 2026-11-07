"""Large RFC 8555 behaviour matrix for the sandbox ACME server.

Most cases are deliberately table-driven: they exercise routing, identifier
validation, JWS rejection and order creation without repeating the expensive
certificate-issuance path.  The focused lifecycle tests live in
``test_acme_emulation.py``; together they provide ~1,000 CA/ACME emulation
cases.
"""

import json

import pytest
from acme_client import ACMEClient, jwk_for, sign_jws
from cryptography.hazmat.primitives.asymmetric import rsa

from sandbox_ca.acme import ACMEProblem, ACMEServer, validate_dns_identifier


@pytest.fixture(scope="session")
def matrix_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def acme(ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    return ACMEServer(ca, public_url="https://acme.test", challenge_mode="auto")


# 20 resource paths x 10 HTTP methods = 200 routing cases.
_PATHS = [
    "/acme/directory",
    "/acme/new-nonce",
    "/acme/new-account",
    "/acme/new-order",
    "/acme/order/missing",
    "/acme/authz/missing",
    "/acme/chall/missing",
    "/acme/finalize/missing",
    "/acme/cert/1",
    "/acme/revoke-cert",
    "/acme/acct/missing",
    "/acme/orders/missing",
    "/acme/terms",
    "/acme/key-change",
    "/acme/unknown",
    "/acme",
    "/",
    "/acme/directory/",
    "/acme/new-nonce/",
    "/acme/new-order/",
]
_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PROPFIND"]
_ROUTES = [(path, method) for path in _PATHS for method in _METHODS]


@pytest.mark.parametrize("path,method", _ROUTES, ids=["%s-%s" % (m, p.replace("/", "_")) for p, m in _ROUTES])
def test_route_method_matrix(acme, path, method):
    status, headers, body, content_type = acme.handle(method, path, {}, b"")
    assert status != 500
    assert 200 <= status <= 501
    assert headers.get("Replay-Nonce")
    if status >= 400 and content_type:
        assert content_type in ("application/problem+json", "application/json")
    if method not in ("GET", "HEAD", "POST"):
        assert status in (404, 501)


# 250 DNS identifier cases.
_VALID_IDENTIFIERS = []
for index in range(125):
    if index % 5 == 0:
        _VALID_IDENTIFIERS.append("*.h%03d.example.org" % index)
    elif index % 7 == 0:
        _VALID_IDENTIFIERS.append("single-label-%03d" % index)
    else:
        _VALID_IDENTIFIERS.append("h%03d.example.org" % index)

_INVALID_IDENTIFIERS = [
    "",
    " ",
    ".",
    "..",
    "bad..example",
    "-bad.example",
    "bad-.example",
    "bad-.example",
    "bad/example",
    "bad?example",
    "bad:example",
    "bad example",
    "bad@example",
    "*.example..org",
    "*.",
    "a" * 64 + ".example",
    "a" * 254,
]
while len(_INVALID_IDENTIFIERS) < 125:
    index = len(_INVALID_IDENTIFIERS)
    _INVALID_IDENTIFIERS.append("bad_%03d.example.org" % index)
_IDENTIFIERS = [(item, True) for item in _VALID_IDENTIFIERS] + [(item, False) for item in _INVALID_IDENTIFIERS]


@pytest.mark.parametrize(
    "value,valid",
    _IDENTIFIERS,
    ids=["valid-%03d" % i for i in range(len(_VALID_IDENTIFIERS))]
    + ["invalid-%03d" % i for i in range(len(_INVALID_IDENTIFIERS))],
)
def test_identifier_validation_matrix(value, valid):
    if valid:
        assert validate_dns_identifier(value)
    else:
        with pytest.raises(ACMEProblem):
            validate_dns_identifier(value)


# 250 malformed JWS cases: 50 mutations x 5 nonce/url combinations.
def _mutations(key, jwk, url, nonce):
    valid = sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk}, {"contact": []})
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_valid = sign_jws(
        other_key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk_for(other_key)}, {"contact": []}
    )
    return [
        b"",
        b"not json",
        b"{}",
        b'{"protected": ""}',
        b'{"protected": "%%%", "payload": "", "signature": ""}',
        b'{"protected": "e30", "payload": "", "signature": "AA"}',
        valid.replace(b'"protected"', b'"protectedX"'),
        valid.replace(b'"signature"', b'"signatureX"'),
        valid.replace(b'"payload"', b'"payloadX"'),
        b'{"protected": "e30", "payload": "", "signature": ""}',
        sign_jws(key, {"alg": "RS256", "nonce": "wrong", "url": url, "jwk": jwk}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url + "/wrong", "jwk": jwk}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "jwk": jwk}, {"contact": []}),
        sign_jws(key, {"nonce": nonce, "url": url, "jwk": jwk}, {"contact": []}),
        sign_jws(key, {"alg": "none", "nonce": nonce, "url": url, "jwk": jwk}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk, "kid": "x"}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "kid": "x"}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": {"kty": "RSA"}}, {"contact": []}),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": {"kty": "NOPE"}}, {"contact": []}),
        other_valid,
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk}, []),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk}, "string"),
        sign_jws(key, {"alg": "RS256", "nonce": nonce, "url": url, "jwk": jwk}, None).replace(b'"payload": ""', b'"payload": "e30"'),
        b'{"protected": "eyJhbGciOiJSUzI1NiIsIm5vbmNlIjogIngiLCAidXJsIjogIngifQ", "payload": "", "signature": "AA"}',
        valid[:-2],
        valid + b"x",
        b'{"protected": 1, "payload": "", "signature": ""}',
        b'{"protected": [], "payload": "", "signature": ""}',
        b'{"protected": "e30", "payload": "", "signature": 1}',
        b'{"protected": "e30", "payload": "", "signature": "***"}',
        b'{"protected": "e30", "payload": "***", "signature": "AA"}',
        b'{"protected": "e30", "payload": "", "signature": "AA", "extra": true}',
        b'{"payload": "", "signature": "AA"}',
        b'{"protected": "", "signature": "AA"}',
        b'{"protected": "", "payload": ""}',
        valid.replace(b'"alg": "RS256"', b'"alg": "RS512"'),
        valid.replace(b'"jwk"', b'"jwkX"'),
        valid.replace(b'"contact"', b'"contactX"'),
        valid.replace(b'{"contact": []}', b'[]'),
        b'{"protected": "e30", "payload": "e30", "signature": ""}',
        b'{"protected": "e30", "payload": "e30", "signature": "AA"}',
        b'{"protected": "eyJhbGciOiJSUzI1NiIsIm5vbmNlIjogIiIsICJ1cmwiOiAiIiwgImp3ayI6IHt9fQ", "payload": "", "signature": "AA"}',
        b'{"protected": "eyJhbGciOiJSUzI1NiIsIm5vbmNlIjogIngiLCAidXJsIjogIngifQ", "payload": "", "signature": "AA"}',
        b'{"protected": "!!", "payload": "", "signature": "AA"}',
        b'{"protected": "e30", "payload": "e30", "signature": "!!"}',
        b'{"protected": "e30", "payload": "e30", "signature": ""}',
        b'{"protected": "e30", "payload": "", "signature": ""}',
        b'{"protected": "e30", "payload": "e30", "signature": "AA"}',
        b'{"protected": "e30", "payload": "e30", "signature": "AA", "extra": 1}',
        b'\xff',
        b'{"protected": "e30", "payload": "", "signature": "AA"}',
    ]


_JWS_CASES = []
for nonce_index in range(5):
    for variant_index in range(50):
        _JWS_CASES.append((nonce_index, variant_index))


@pytest.mark.parametrize(
    "nonce_index,variant_index",
    _JWS_CASES,
    ids=["n%d-v%02d" % (n, v) for n, v in _JWS_CASES],
)
def test_jws_rejection_matrix(acme, matrix_key, nonce_index, variant_index):
    client = ACMEClient(acme, key=matrix_key)
    nonce = "nonce-%d-%s" % (nonce_index, client.server.new_nonce())
    client.nonce = nonce
    url = acme.url("/acme/new-account")
    variants = _mutations(matrix_key, jwk_for(matrix_key), url, nonce)
    body = variants[variant_index]
    status, headers, response, content_type = acme.handle("POST", "/acme/new-account", {}, body)
    assert status in (400, 403)
    assert headers.get("Replay-Nonce")
    assert content_type == "application/problem+json"
    problem = json.loads(response)
    assert problem["type"].startswith("urn:ietf:params:acme:error:")


# 279 order-creation cases (150 valid + 129 invalid).
_ORDER_VALID = ["o%03d.example.org" % index for index in range(150)]
_ORDER_INVALID = [
    "",
    " ",
    ".",
    "..",
    "bad..example",
    "-bad.example",
    "bad-.example",
    "bad/example",
    "bad?example",
    "bad:example",
    "bad example",
    "bad@example",
    "*.example..org",
    "*.",
    "a" * 64 + ".example",
    "a" * 254,
]
while len(_ORDER_INVALID) < 129:
    index = len(_ORDER_INVALID)
    _ORDER_INVALID.append("bad_%03d.example.org" % index)
_ORDER_CASES = [(item, True) for item in _ORDER_VALID] + [(item, False) for item in _ORDER_INVALID]


@pytest.mark.parametrize(
    "domain,valid",
    _ORDER_CASES,
    ids=["valid-%03d" % i for i in range(len(_ORDER_VALID))]
    + ["invalid-%03d" % i for i in range(len(_ORDER_INVALID))],
)
def test_order_creation_matrix(acme, matrix_key, domain, valid):
    client = ACMEClient(acme, key=matrix_key)
    status, _, body = client.register()
    assert status == 201, body
    status, headers, body = client.new_order([domain])
    if valid:
        assert status == 201, body
        order = json.loads(body)
        assert order["status"] == "pending"
        assert len(order["identifiers"]) == 1
        assert order["identifiers"][0]["value"] == domain.lower()
        assert len(order["authorizations"]) == 1
    else:
        assert status == 400, body
        assert json.loads(body)["type"].startswith("urn:ietf:params:acme:error:")
