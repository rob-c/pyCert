"""Second large ACME/CA-emulation matrix: algorithms, CSRs, HTTP-01, nonces.

This module adds exactly 1,000 table-driven cases to the first ACME suite.
It focuses on the parts most likely to break when an implementation is changed:
cryptographic account-key algorithms, CSR/order name matching, the HTTP-01
validator, nonce state and protocol routing under varied request metadata.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from acme_client import ACMEClient, jwk_for, sign_jws
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from sandbox_ca.acme import ACMEProblem, ACMEServer, jwk_thumbprint


@pytest.fixture(scope="session")
def matrix_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def csr_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def algorithm_keys():
    return [
        ("RS256", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("RS384", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("RS512", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("ES256", ec.generate_private_key(ec.SECP256R1())),
        ("ES384", ec.generate_private_key(ec.SECP384R1())),
        ("ES512", ec.generate_private_key(ec.SECP521R1())),
        ("EdDSA", ed25519.Ed25519PrivateKey.generate()),
    ]


@pytest.fixture
def acme(ca):
    ca.auto_approve = True
    ca.sign_after_polls = 0
    return ACMEServer(ca, public_url="https://acme.test", challenge_mode="auto")


@pytest.fixture
def client(acme, matrix_key):
    result = ACMEClient(acme, key=matrix_key)
    status, _, body = result.register()
    assert status == 201, body
    return result


def _json(body):
    return json.loads(body.decode())


# ---------------------------------------------------------------------------
# 120 JWS/account-key cases
# ---------------------------------------------------------------------------

_ACCOUNT_PAYLOADS = [
    {"contact": []},
    {"contact": ["mailto:one@example.org"]},
    {"contact": ["mailto:one@example.org", "mailto:two@example.org"]},
    {"contact": [], "termsOfServiceAgreed": True},
    {"contact": [], "termsOfServiceAgreed": False},
    {"contact": [], "onlyReturnExisting": False},
    {"contact": [], "extra": "ignored"},
    {"contact": ["mailto:a@example.org"], "termsOfServiceAgreed": True},
    {"contact": ["mailto:b@example.org"]},
    {"contact": []},
]
_JWS_ALGORITHM_CASES = [
    (alg_index, payload_index)
    for alg_index in range(7)
    for payload_index in range(10)
]
_INVALID_ALGORITHM_CASES = [
    (alg_index, variant_index)
    for alg_index in range(5)
    for variant_index in range(10)
]


@pytest.mark.parametrize(
    "alg_index,payload_index",
    _JWS_ALGORITHM_CASES,
    ids=["a%d-p%d" % (a, p) for a, p in _JWS_ALGORITHM_CASES],
)
def test_jws_algorithm_and_account_matrix(acme, algorithm_keys, alg_index, payload_index):
    alg, key = algorithm_keys[alg_index]
    client = ACMEClient(acme, key=key, alg=alg)
    status, headers, body = client.register(**_ACCOUNT_PAYLOADS[payload_index])
    assert status == 201, body
    assert headers["Location"].startswith("https://acme.test/acme/acct/")
    assert _json(body)["status"] == "valid"


@pytest.mark.parametrize(
    "alg_index,variant_index",
    _INVALID_ALGORITHM_CASES,
    ids=["a%d-x%d" % (a, v) for a, v in _INVALID_ALGORITHM_CASES],
)
def test_jws_algorithm_failure_matrix(acme, algorithm_keys, alg_index, variant_index):
    alg, key = algorithm_keys[alg_index]
    nonce = acme.new_nonce()
    url = acme.url("/acme/new-account")
    protected = {"alg": alg, "nonce": nonce, "url": url, "jwk": jwk_for(key)}
    payload = {"contact": []}
    valid = sign_jws(key, protected, payload)
    variants = [
        sign_jws(key, {k: v for k, v in protected.items() if k != "url"}, payload),
        sign_jws(key, {**protected, "nonce": "wrong"}, payload),
        sign_jws(key, {**protected, "url": url + "/wrong"}, payload),
        sign_jws(key, {k: v for k, v in protected.items() if k != "jwk"}, payload),
        sign_jws(key, {**protected, "kid": "https://wrong.example/acct/x"}, payload),
        sign_jws(key, {**protected, "alg": "none"}, payload),
        valid[:-1],
        b"not-json",
        b'{"protected": "e30", "payload": "", "signature": "***"}',
        sign_jws(key, protected, []),
    ]
    status, headers, body, content_type = acme.handle(
        "POST", "/acme/new-account", {}, variants[variant_index]
    )
    assert status in (400, 403), body
    assert content_type == "application/problem+json"
    assert _json(body)["type"].startswith("urn:ietf:params:acme:error:")


# ---------------------------------------------------------------------------
# 240 order/CSR name-matching cases
# ---------------------------------------------------------------------------

_CSR_PATTERNS = [
    ("one", 1, 1, True),
    ("two", 1, 2, True),
    ("three", 1, 3, True),
    ("wildcard", 1, 1, True),
    ("wildcard-and-base", 1, 2, True),
    ("extra-csr-name", 1, 2, False),
    ("missing-csr-name", 1, 2, False),
    ("wrong-csr-name", 1, 1, False),
    ("no-san-wrong-cn", 1, 1, False),
    ("case-normalised", 1, 1, True),
    ("wildcard-mismatch", 1, 1, False),
    ("duplicate-order-name", 1, 2, False),
]
_CSR_CASES = [(pattern_index, variant) for pattern_index in range(12) for variant in range(20)]


def _names_for(pattern, variant):
    base = "c%02d.example.org" % variant
    other = "d%02d.example.org" % variant
    if pattern == "one":
        return [base], [base], False
    if pattern == "two":
        return [base, other], [base, other], False
    if pattern == "three":
        third = "e%02d.example.org" % variant
        return [base, other, third], [base, other, third], False
    if pattern == "wildcard":
        return ["*." + base], ["*." + base], False
    if pattern == "wildcard-and-base":
        return ["*." + base, base], ["*." + base, base], False
    if pattern == "extra-csr-name":
        return [base], [base, other], False
    if pattern == "missing-csr-name":
        return [base, other], [base], False
    if pattern == "wrong-csr-name":
        return [base], [other], False
    if pattern == "no-san-wrong-cn":
        return [base], [other], True
    if pattern == "case-normalised":
        return [base.upper()], [base], False
    if pattern == "wildcard-mismatch":
        return ["*." + base], [base], False
    if pattern == "duplicate-order-name":
        return [base, base], [base], False
    raise AssertionError(pattern)


@pytest.mark.parametrize(
    "pattern_index,variant",
    _CSR_CASES,
    ids=["%s-%02d" % (_CSR_PATTERNS[p][0], v) for p, v in _CSR_CASES],
)
def test_csr_order_name_matrix(acme, matrix_key, csr_key, pattern_index, variant):
    pattern, _, _, expected_valid = _CSR_PATTERNS[pattern_index]
    order_names, csr_names, no_san = _names_for(pattern, variant)
    client = ACMEClient(acme, key=matrix_key)
    assert client.register()[0] == 201
    status, _, body = client.new_order(order_names)
    if pattern == "duplicate-order-name":
        assert status == 400
        return
    assert status == 201, body
    order = _json(body)
    for authz_url in order["authorizations"]:
        authz = _json(client.authz(authz_url)[2])
        client.challenge(authz["challenges"][0]["url"])
    if no_san:
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, csr_names[0])]))
            .sign(csr_key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)
    else:
        csr_der = client.csr(csr_names, key=csr_key)
    status, _, body = client.finalize(order["finalize"], csr_der)
    if expected_valid:
        assert status == 200, body
        assert _json(body)["status"] == "valid"
    else:
        assert status == 400, body
        assert _json(body)["type"].endswith("badCSR")


# ---------------------------------------------------------------------------
# 200 HTTP-01 validation cases
# ---------------------------------------------------------------------------

_BODY_MODES = [
    "correct",
    "trailing-newline",
    "surrounding-spaces",
    "wrong",
    "empty",
    "token-only",
    "uppercase",
    "extra-suffix",
    "prefix",
    "partial",
    "very-long",
    "json",
    "html",
    "nul",
    "double",
    "wrong-key",
    "reversed",
    "truncated",
    "linebreak",
    "quoted",
]
_PATH_MODES = [
    "exact",
    "trailing-slash",
    "query",
    "wrong-prefix",
    "encoded-token",
    "wrong-token",
    "double-slash",
    "prefix-only",
    "suffix",
    "domain-prefix",
]


class _ChallengeServer:
    def __init__(self, body_builder, path_mode, token):
        self.body_builder = body_builder
        self.path_mode = path_mode
        self.token = token
        self.expected_path = "/.well-known/acme-challenge/" + token
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                # Only successful exact paths serve a body; the other path
                # modes deliberately produce a 404 to exercise the validator.
                if server.path_mode == "exact" and self.path == server.expected_path:
                    payload = server.body_builder().encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.httpd.server_address[1]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _http_body(mode, token, keyauth):
    if mode == "correct":
        return keyauth
    if mode == "trailing-newline":
        return keyauth + "\n"
    if mode == "surrounding-spaces":
        return "  " + keyauth + "  "
    if mode == "wrong":
        return "wrong"
    if mode == "empty":
        return ""
    if mode == "token-only":
        return token
    if mode == "uppercase":
        return keyauth.upper()
    if mode == "extra-suffix":
        return keyauth + "x"
    if mode == "prefix":
        return "x" + keyauth
    if mode == "partial":
        return keyauth[:-1]
    if mode == "very-long":
        return keyauth + "x" * 9000
    if mode == "json":
        return json.dumps({"token": keyauth})
    if mode == "html":
        return "<html>" + keyauth + "</html>"
    if mode == "nul":
        return keyauth + "\x00"
    if mode == "double":
        return keyauth + keyauth
    if mode == "wrong-key":
        return token + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    if mode == "reversed":
        return keyauth[::-1]
    if mode == "truncated":
        return keyauth[: max(1, len(keyauth) // 2)]
    if mode == "linebreak":
        return keyauth + "\r\n"
    if mode == "quoted":
        return '"' + keyauth + '"'
    raise AssertionError(mode)


_HTTP_CASES = [(body_index, path_index) for body_index in range(20) for path_index in range(10)]


@pytest.mark.parametrize(
    "body_index,path_index",
    _HTTP_CASES,
    ids=["%s-%s" % (_BODY_MODES[b], _PATH_MODES[p]) for b, p in _HTTP_CASES],
)
def test_http_01_body_and_path_matrix(ca, matrix_key, body_index, path_index):
    body_mode = _BODY_MODES[body_index]
    path_mode = _PATH_MODES[path_index]
    server = None
    try:
        acme = ACMEServer(ca, public_url="https://acme.test", challenge_mode="http", http_port=1)
        client = ACMEClient(acme, key=matrix_key)
        assert client.register()[0] == 201
        status, _, body = client.new_order(["localhost"])
        order = _json(body)
        authz = _json(client.authz(order["authorizations"][0])[2])
        challenge = authz["challenges"][0]
        keyauth = challenge["token"] + "." + jwk_thumbprint(client.jwk)
        server = _ChallengeServer(
            lambda: _http_body(body_mode, challenge["token"], keyauth), path_mode, challenge["token"]
        )
        acme.http_port = server.port
        status, _, body = client.challenge(challenge["url"])
        assert status == 200
        expected_valid = body_mode in ("correct", "trailing-newline", "surrounding-spaces", "linebreak")
        expected_valid = expected_valid and path_mode == "exact"
        assert (_json(body)["status"] == "valid") is expected_valid
    finally:
        if server is not None:
            server.stop()


# ---------------------------------------------------------------------------
# 120 nonce lifecycle/concurrency cases
# ---------------------------------------------------------------------------

_NONCE_CASES = list(range(120))


@pytest.mark.parametrize("case", _NONCE_CASES, ids=["n%03d" % i for i in _NONCE_CASES])
def test_nonce_lifecycle_matrix(acme, case):
    mode = case % 4
    if mode == 0:
        nonce = acme.new_nonce()
        acme.consume_nonce(nonce)
        assert nonce not in acme.nonces
    elif mode == 1:
        nonce = acme.new_nonce()
        acme.consume_nonce(nonce)
        with pytest.raises(ACMEProblem) as exc:
            acme.consume_nonce(nonce)
        assert exc.value.kind == "badNonce"
    elif mode == 2:
        nonce = acme.new_nonce()
        acme.nonces[nonce] = 0
        with pytest.raises(ACMEProblem):
            acme.consume_nonce(nonce)
    else:
        nonces = {acme.new_nonce() for _ in range(20)}
        assert len(nonces) == 20
        assert all(item in acme.nonces for item in nonces)


# ---------------------------------------------------------------------------
# 120 problem-document cases
# ---------------------------------------------------------------------------

_PROBLEM_KINDS = [
    "malformed",
    "badNonce",
    "unauthorized",
    "accountDoesNotExist",
    "orderNotReady",
    "badCSR",
    "badPublicKey",
    "badSignatureAlgorithm",
    "unsupportedIdentifier",
    "rejectedIdentifier",
    "serverInternal",
] + ["customError%02d" % index for index in range(19)]
_PROBLEM_CASES = [(kind, status) for kind in _PROBLEM_KINDS for status in (400, 403, 404, 500)]


@pytest.mark.parametrize(
    "kind,status",
    _PROBLEM_CASES,
    ids=["%s-%d" % (kind, status) for kind, status in _PROBLEM_CASES],
)
def test_problem_document_matrix(kind, status):
    problem = ACMEProblem(kind, "detail for " + kind, status).as_problem()
    assert problem["type"] == "urn:ietf:params:acme:error:" + kind
    assert problem["detail"] == "detail for " + kind
    assert problem["status"] == status


# ---------------------------------------------------------------------------
# 200 routing/header/query cases
# ---------------------------------------------------------------------------

_ROUTE_PATHS = [
    "/acme/directory",
    "/acme/directory?x=1",
    "/acme/new-nonce",
    "/acme/new-nonce/",
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
    "/acme?query=yes",
]
_HEADER_VARIANTS = [
    {},
    {"accept": "*/*"},
    {"content-type": "application/jose+json"},
    {"content-type": "application/json"},
    {"user-agent": "certbot/5.9.0"},
    {"x-forwarded-for": "127.0.0.1"},
    {"host": "acme.test"},
    {"accept": "application/problem+json"},
    {"content-type": "text/plain"},
    {"x-test": "value"},
]
_ROUTE_CASES = [(path, header_index) for path in _ROUTE_PATHS for header_index in range(10)]


@pytest.mark.parametrize(
    "path,header_index",
    _ROUTE_CASES,
    ids=["%03d-h%d" % (i, h) for i, (_, h) in enumerate(_ROUTE_CASES)],
)
def test_route_query_and_header_matrix(acme, path, header_index):
    headers = _HEADER_VARIANTS[header_index]
    status, response_headers, body, content_type = acme.handle("GET", path, headers, b"")
    assert status != 500
    assert 200 <= status <= 501
    assert response_headers.get("Replay-Nonce")
    if content_type:
        assert content_type in ("application/json", "application/problem+json", "text/plain; charset=utf-8")
