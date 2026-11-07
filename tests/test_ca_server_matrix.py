"""Large emulation matrix for the legacy UK-CA listener.

These cases exercise the server the way CertWizard and pyCert do: real TLS
sockets, XML request bodies, PPPK challenges, status lookup, download and
revocation.  The matrix focuses on protocol edges rather than repeating the
happy-path workflow tests.
"""

import http.client
import ssl
import time
import xml.etree.ElementTree as ET

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert.csr import build_csr
from sandbox_ca.mock_ca import CertRecord, _spki_b64

PIN = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
EMAIL = "wire@example.org"
_CONTEXTS = {}


@pytest.fixture(scope="session")
def material():
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_csr = build_csr(
        user_key,
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wire user")]),
        cert_type="user",
        email=EMAIL,
    )
    host_csr = build_csr(
        host_key,
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "host.example.org")]),
        cert_type="host",
        dns_names=["host.example.org"],
    )
    return {
        "user_key": user_key,
        "host_key": host_key,
        "user_csr": user_csr,
        "host_csr": host_csr,
        "user_pem": user_csr.public_bytes(serialization.Encoding.PEM).decode(),
        "host_pem": host_csr.public_bytes(serialization.Encoding.PEM).decode(),
    }


def _context(ca):
    key = str(ca.data_dir)
    context = _CONTEXTS.get(key)
    if context is None:
        context = ssl.create_default_context(cafile=str(ca.data_dir / "root.pem"))
        _CONTEXTS[key] = context
    return context


def _request(ca, method, path, body=b"", headers=None):
    connection = http.client.HTTPSConnection("localhost", ca.port, context=_context(ca), timeout=10)
    try:
        connection.request(method, path, body=body, headers=dict(headers or {}))
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, response_headers, payload
    finally:
        connection.close()


def _user_body(pem, *, pin=PIN, email=EMAIL, version="CertWizard 2.2.1", request_tag="Request"):
    return (
        "<CSR><%s>%s</%s><PIN>%s</PIN><Email>%s</Email><Version>%s</Version></CSR>"
        % (request_tag, pem, request_tag, pin, email, version)
    ).encode()


_CSR_VARIANTS = [
    ("valid", None, 201),
    ("valid-pin", {"pin": "A" * 40}, 201),
    ("valid-extra", {"extra": "<Extra>ignored</Extra>"}, 201),
    ("valid-version", {"version": "CertWizard 9.9.9"}, 201),
    ("missing-request", {"pem": ""}, 202),
    ("missing-pin", {"pin": ""}, 202),
    ("missing-email", {"email": ""}, 202),
    ("missing-version", {"version": ""}, 202),
    ("lower-pin", {"pin": PIN.lower()}, 202),
    ("short-pin", {"pin": "A" * 39}, 202),
    ("long-pin", {"pin": "A" * 41}, 202),
    ("nonhex-pin", {"pin": "Z" * 40}, 202),
    ("pin-spaces", {"pin": " " + PIN}, 201),
    ("bad-email", {"email": "not-an-email"}, 202),
    ("email-mismatch", {"email": "other@example.org"}, 202),
    ("empty-request", {"pem": " "}, 202),
    ("bad-request", {"pem": "not a pem"}, 202),
    ("wrong-request-tag", {"request_tag": "RequestX"}, 202),
    ("wrong-root", {"root": "Bulk"}, 202),
    ("empty-body", {"body": b""}, 202),
    ("malformed-xml", {"body": b"<CSR><Request>"}, 202),
    ("malformed-close", {"body": b"<CSR></CSRX>"}, 202),
    ("trailing-garbage", {"body": b"<CSR/>garbage"}, 202),
    ("doctype", {"body": b'<!DOCTYPE x [<!ENTITY e "x">]><CSR/>'}, 202),
    ("xml-comment", {"body": b"<!-- x --><CSR/>"}, 202),
    ("self-closing", {"body": b"<CSR/>"}, 202),
    ("bulk-root", {"body": b"<Bulk/>"}, 202),
    ("publickey-root", {"body": b"<PublicKey>AAAA</PublicKey>"}, 202),
    ("request-cdata", {"pem": "<![CDATA[x]]>"}, 202),
    ("pin-cdata", {"pin": "<![CDATA[" + PIN + "]]>"}, 201),
    ("email-cdata", {"email": "<![CDATA[" + EMAIL + "]]>"}, 201),
    ("version-cdata", {"version": "<![CDATA[CertWizard 2.2.1]]>"}, 201),
    ("nested-request", {"pem": "<Request>" + PIN + "</Request>"}, 202),
    ("empty-csr-name", {"body": b"<CSR></CSR>"}, 202),
    ("missing-all", {"body": b"<CSR></CSR>"}, 202),
    ("wrong-case-root", {"body": b"<csr/>"}, 202),
    ("wrong-case-pin", {"body": b"<CSR><PIN>" + PIN.encode() + b"</PIN></CSR>"}, 202),
    ("request-newline", {"pem": "\n" + PIN + "\n"}, 202),
    ("large-gear", {"body": b"<CSR>" + b"<X/>" * 100 + b"</CSR>"}, 202),
    ("email-case-mismatch", {"email": EMAIL.upper()}, 202),
]


def _variant_body(material, variant_index):
    name, overrides, expected = _CSR_VARIANTS[variant_index]
    overrides = dict(overrides or {})
    if "body" in overrides:
        return overrides["body"], expected
    root = overrides.pop("root", "CSR")
    pem = overrides.pop("pem", material["user_pem"])
    pin = overrides.pop("pin", PIN)
    email = overrides.pop("email", EMAIL)
    version = overrides.pop("version", "CertWizard 2.2.1")
    request_tag = overrides.pop("request_tag", "Request")
    extra = overrides.pop("extra", "")
    body = _user_body(pem, pin=pin, email=email, version=version, request_tag=request_tag)
    if root != "CSR":
        body = body.replace(b"<CSR>", ("<" + root + ">").encode()).replace(b"</CSR>", ("</" + root + ">").encode())
    if extra:
        body = body.replace(b"</CSR>", extra.encode() + b"</CSR>")
    return body, expected


def _csr_cases():
    return [(variant, repeat) for variant in range(len(_CSR_VARIANTS)) for repeat in range(10)]


@pytest.mark.parametrize(
    "variant,repeat",
    _csr_cases(),
    ids=["%s-r%d" % (_CSR_VARIANTS[v][0], r) for v, r in _csr_cases()],
)
def test_csr_xml_emulation_matrix(ca, material, variant, repeat):
    body, expected = _variant_body(material, variant)
    status, headers, response = _request(
        ca, "POST", "/CSR", body, {"Content-Type": "application/xml; charset=UTF-8"}
    )
    assert status == expected, (variant, response.decode("utf-8", "replace"))
    if status == 202:
        assert b"<error>" in response
        texts = [item.text for item in ET.fromstring(response).findall(".//text")]
        assert len(texts) == 2
    if status == 201:
        assert not response


# ---------------------------------------------------------------------------
# 200 PPPK authentication/challenge cases (20 scenarios x 10 repeats)
# ---------------------------------------------------------------------------

_PPPK_SCENARIOS = [
    ("host", "nonce", "valid", 201),
    ("host", "nonce", "bad-response", 403),
    ("host", "nonce", "missing", 401),
    ("host", "nonce", "old", 403),
    ("host", "nonce", "wrong-serial", 403),
    ("host", "opaque", "valid", 201),
    ("host", "opaque", "missing", 401),
    ("renew-csr", "nonce", "valid", 201),
    ("renew-legacy", "nonce", "valid", 201),
    ("renew-csr", "nonce", "bad-response", 403),
    ("renew-csr", "nonce", "old", 403),
    ("renew-csr", "opaque", "valid", 201),
    ("renew-csr", "nonce", "missing", 401),
    ("revoke", "nonce", "valid", 201),
    ("revoke", "nonce", "bad-response", 403),
    ("revoke", "nonce", "old", 403),
    ("revoke", "opaque", "valid", 201),
    ("revoke", "nonce", "missing", 401),
    ("host", "no-challenge", "valid", 201),
    ("renew-csr", "no-challenge", "valid", 201),
]
_PPPK_CASES = [(index, repeat) for index in range(20) for repeat in range(10)]


def _issue_auth(ca, material):
    certificate = ca.issue(material["user_csr"], kind="user")
    ca.certificates[5000] = CertRecord(5000, certificate, spki_b64="")
    return certificate


def _pubkey_value(key):
    numbers = key.private_numbers().public_numbers
    return "%x.%x" % (numbers.n, numbers.e)


def _pppk_response(key, nonce, when=None):
    timestamp = int((when if when is not None else time.time()) * 1000)
    text = (nonce + ":" + str(timestamp)).lower().encode("ascii")
    numbers = key.private_numbers()
    value = pow(int(text.hex(), 16), numbers.d, numbers.public_numbers.n)
    return format(value, "x")


def _bulk_body(material):
    return (
        "<Bulk><CSR><Request>%s</Request><PIN>%s</PIN><Email>%s</Email>"
        "<Version>CertWizard 2.2.1</Version></CSR></Bulk>"
        % (material["host_pem"], PIN, EMAIL)
    ).encode()


def _renewal_body(material, key):
    return (
        "<CSR><Request>%s</Request><PIN>%s</PIN><Email>%s</Email>"
        "<PublicKey>%s</PublicKey><Version>CertWizard 2.2.1</Version></CSR>"
        % (material["user_pem"], PIN, EMAIL, _pubkey_value(key))
    ).encode()


def _revoke_body():
    return b"<Revoke><id>5000</id><reason>superseded</reason></Revoke>"


@pytest.mark.parametrize(
    "scenario_index,repeat",
    _PPPK_CASES,
    ids=["%s-%s-%s-r%d" % (_PPPK_SCENARIOS[i][0], _PPPK_SCENARIOS[i][1], _PPPK_SCENARIOS[i][2], r) for i, r in _PPPK_CASES],
)
def test_pppk_challenge_emulation_matrix(ca, material, scenario_index, repeat):
    kind, challenge_mode, variant, expected = _PPPK_SCENARIOS[scenario_index]
    auth = _issue_auth(ca, material)
    ca.pppk_mode = "normal" if challenge_mode == "no-challenge" else challenge_mode
    if kind == "host":
        path = "/CSRs"
        body = _bulk_body(material)
        initial_headers = {"PPPK": "this is pppk", "serial": str(auth.serial_number)}
    elif kind == "renew-legacy":
        path = "/CSRs"
        body = _renewal_body(material, material["user_key"])
        initial_headers = {"PPPK": "this is pppk"}
    elif kind == "renew-csr":
        path = "/CSR"
        body = _renewal_body(material, material["user_key"])
        initial_headers = {"PPPK": "this is pppk"}
    else:
        path = "/revoke"
        body = _revoke_body()
        initial_headers = {"PPPK": "this is pppk"}

    if challenge_mode == "no-challenge":
        ca.pppk_mode = "no_challenge"
        status, _, _ = _request(ca, "POST", path, body, initial_headers)
        assert status == expected
        return

    status, headers, response = _request(ca, "POST", path, body, initial_headers)
    assert status == 401, (kind, status, response)
    if challenge_mode == "opaque":
        assert headers.get("opaque")
        if variant == "missing":
            return
        follow = {"PPPK": "this is pppk", "opaque": headers["opaque"]}
        if kind == "host":
            follow["serial"] = str(auth.serial_number)
        status, _, _ = _request(ca, "POST", path, body, follow)
        assert status == 201
        return

    nonce = headers["nonce"]
    keyid = headers["keyid"]
    realm = headers["realm"]
    follow = {
        "PPPK": "this is pppk",
        "keyid": keyid,
        "realm": realm,
        "response": _pppk_response(
            material["user_key"], nonce, time.time() - 600 if variant == "old" else None
        ),
    }
    if kind == "host":
        follow["serial"] = str(auth.serial_number + 1 if variant == "wrong-serial" else auth.serial_number)
    if variant == "bad-response":
        follow["response"] = "00"
    if variant == "missing":
        return
    status, _, _ = _request(ca, "POST", path, body, follow)
    assert status == expected


# ---------------------------------------------------------------------------
# 200 status/download/revocation cases
# ---------------------------------------------------------------------------

_LOOKUP_MODES = [
    "normal",
    "no_inline",
    "csr_only",
    "malformed",
    "empty_200",
    "wrong_pem",
    "multiple",
    "no_id",
    "bad_status",
    "normal",
]
_LOOKUP_STATUSES = ["VALID", "REVOKED", "EXPIRED", "SUSPENDED", "DELETED", "NEW", "APPROVED", "RENEW", "BANANA", "VALID"]
_DOWNLOAD_MODES = ["normal", "bare_pem", "bare_der", "xml_no_cert", "malformed", "wrong_cert", "normal", "bare_pem", "xml_no_cert", "malformed"]
_REVOKE_SCENARIOS = [
    ("normal", "valid", 201),
    ("normal", "missing", 401),
    ("normal", "bad-response", 403),
    ("normal", "old", 403),
    ("opaque", "valid", 201),
    ("opaque", "missing", 401),
    ("no-challenge", "valid", 201),
    ("normal", "unknown-id", 404),
    ("normal", "malformed-body", 400),
    ("normal", "valid", 201),
]


def _lookup_body(material):
    return ("<PublicKey>%s</PublicKey>" % _spki_b64(material["user_csr"].public_key())).encode()


def _status_cases():
    return list(range(200))


@pytest.mark.parametrize("case", _status_cases(), ids=["state-%03d" % i for i in range(200)])
def test_status_download_revoke_emulation_matrix(ca, material, case):
    from sandbox_ca.mock_ca import CSRRecord

    if case < 100:
        mode = _LOOKUP_MODES[case % 10]
        status_value = _LOOKUP_STATUSES[case // 10]
        cert = ca.issue(material["user_csr"], kind="user")
        ca.certificates[5000] = CertRecord(5000, cert, status=status_value, spki_b64="")
        ca.csrs[_spki_b64(material["user_csr"].public_key())] = CSRRecord(
            1000, material["user_csr"], EMAIL, status=status_value, cert_id=5000
        )
        ca.lookup_mode = mode
        status, headers, body = _request(
            ca,
            "POST",
            "/resources/resource/publickey/pk",
            _lookup_body(material),
            {"Content-Type": "application/xml"},
        )
        assert status == 200, body
        if mode in ("normal", "no_inline", "wrong_pem", "multiple", "no_id", "bad_status", "normal"):
            assert b"<resources" in body
        if mode == "empty_200":
            assert b"<resources" in body
        if mode == "csr_only":
            assert b"<CSRs>" in body
        return

    if case < 150:
        mode = _DOWNLOAD_MODES[(case - 100) // 5]
        cert = ca.issue(material["user_csr"], kind="user")
        ca.certificates[5000] = CertRecord(5000, cert, status="VALID", spki_b64="")
        ca.download_mode = mode
        status, headers, body = _request(ca, "GET", "/certificate/5000")
        assert status == 200, (mode, status, body[:100])
        assert headers.get("content-type")
        return

    # 50 revoke cases: 10 scenarios x 5 repeats.
    scenario_index = (case - 150) // 5
    scenario, variant, expected = _REVOKE_SCENARIOS[scenario_index]
    _issue_auth(ca, material)
    ca.pppk_mode = "normal" if scenario == "no-challenge" else scenario
    body = _revoke_body() if variant != "malformed-body" else b"<Revoke>"
    if variant == "unknown-id":
        body = b"<Revoke><id>9999</id><reason>superseded</reason></Revoke>"
    if scenario == "no-challenge":
        ca.pppk_mode = "no_challenge"
        status, _, _ = _request(ca, "POST", "/revoke", body, {"PPPK": "this is pppk"})
        assert status == expected
        return
    status, headers, response = _request(ca, "POST", "/revoke", body, {"PPPK": "this is pppk"})
    if variant in ("unknown-id", "malformed-body"):
        assert status == expected
        return
    assert status == 401, response
    if scenario == "opaque":
        if variant == "missing":
            return
        status, _, _ = _request(
            ca, "POST", "/revoke", body, {"PPPK": "this is pppk", "opaque": headers["opaque"]}
        )
        assert status == 201
        return
    nonce = headers["nonce"]
    follow = {
        "PPPK": "this is pppk",
        "keyid": headers["keyid"],
        "realm": headers["realm"],
        "response": _pppk_response(
            material["user_key"], nonce, time.time() - 600 if variant == "old" else None
        ),
    }
    if variant == "bad-response":
        follow["response"] = "00"
    if variant == "missing":
        return
    status, _, _ = _request(ca, "POST", "/revoke", body, follow)
    assert status == expected


# ---------------------------------------------------------------------------
# 200 CA-info/liveness/header/framing cases
# ---------------------------------------------------------------------------

_INFO_PATHS = [
    "/pingservice",
    "/CA",
    "/CA/motd/text",
    "/ca/root.pem",
    "/ca/issuer.pem",
    "/ca/issuing-ca.pem",
    "/ca/chain.pem",
]
_HEADER_VARIANTS = [
    {},
    {"Accept": "*/*"},
    {"Accept": "application/xml"},
    {"Content-Type": "application/xml"},
    {"LocalHost": "localhost"},
    {"User-Agent": "NGS-CertWizard/2.2.0"},
    {"Date": "Sat, 07 Nov 2026 12:00:00 GMT"},
    {"Connection": "Keep-Alive"},
    {"X-Test": "value"},
    {"Accept-Encoding": "identity"},
]
_INFO_CASES = [(path, header_index) for path in _INFO_PATHS for header_index in range(10)]


@pytest.mark.parametrize(
    "path,header_index",
    _INFO_CASES,
    ids=["%03d-h%d" % (i, h) for i, (_, h) in enumerate(_INFO_CASES)],
)
def test_ca_info_liveness_and_headers_matrix(ca, path, header_index):
    status, headers, body = _request(ca, "GET", path, headers=_HEADER_VARIANTS[header_index])
    assert status == 200, (path, status)
    assert headers.get("content-type")
    if path == "/pingservice":
        assert b"pingservice" in body
    if path == "/CA":
        assert b"RAlist" in body and b"certWizard" in body
    if path == "/CA/motd/text":
        assert b"<Motd>" in body
    if path.endswith(".pem"):
        assert b"BEGIN CERTIFICATE" in body


# ---------------------------------------------------------------------------
# 130 /CA response-shape cases
# ---------------------------------------------------------------------------

_CA_MODES = [
    "normal",
    "bad_xml",
    "empty",
    "malformed_cert",
    "one_cert",
    "huge_ra",
    "no_preferred",
    "no_policy",
    "no_motd",
    "no_version",
]
_CA_CASES = [(mode, repeat) for mode in _CA_MODES for repeat in range(13)]


@pytest.mark.parametrize(
    "mode,repeat",
    _CA_CASES,
    ids=["%s-r%d" % (mode, repeat) for mode, repeat in _CA_CASES],
)
def test_ca_info_response_shape_matrix(ca, mode, repeat):
    ca.info_mode = mode
    status, headers, body = _request(ca, "GET", "/CA")
    assert status == 200, (mode, status)
    assert headers.get("content-type")
    assert body
    if mode in ("normal", "one_cert", "huge_ra", "no_preferred", "no_policy", "no_motd", "no_version"):
        assert b"<CA>" in body
        assert b"RAlist" in body
    if mode == "bad_xml":
        assert not body.endswith(b"</CA>")
    if mode == "empty":
        assert b"<RAlist>" in body
