"""Compatibility tests for the standalone Java-client sandbox.

These exercise the wire details the Java client depends on rather than pyCert's
own client: OpenCA error documents with two <text> elements, chunked request
bodies, renewal on /CSR, the /CA version document, and the admin API.
"""

import hashlib
import http.client
import json
import ssl
import time
import xml.etree.ElementTree as ET
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert.compat import not_valid_after, not_valid_before
from pycert.csr import build_csr
from sandbox_ca.java_kit import _CLASS_PATH, _CONFIG_PATH, _OLD_PINS, build_jar_kit
from sandbox_ca.mock_ca import CSRRecord, MockCA, _spki_b64
from sandbox_ca.server import SandboxCA

PIN = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
EMAIL = "sandbox@example.org"


@pytest.fixture
def sandbox(tmp_path):
    ca = SandboxCA(
        data_dir=tmp_path / "ca",
        port=0,
        auto_approve=False,
        sign_after_polls=100,
        admin_token="test-token",
        motd="sandbox test motd",
    )
    try:
        yield ca
    finally:
        ca.stop()


def _request(ca, method, path, body=None, headers=None, chunked=False):
    context = ssl.create_default_context(cafile=str(ca.data_dir_path / "root.pem"))
    connection = http.client.HTTPSConnection("localhost", ca.port, context=context, timeout=10)
    all_headers = dict(headers or {})
    if chunked:
        all_headers["Transfer-Encoding"] = "chunked"
    connection.request(method, path, body=body, headers=all_headers, encode_chunked=chunked)
    response = connection.getresponse()
    data = response.read()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, data


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csr(key, *, cn="sandbox user", kind="user"):
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sandbox"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    return build_csr(key, name, cert_type=kind, email=EMAIL if kind == "user" else "")


def _user_xml(csr):
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return (
        "<CSR><Request>%s</Request><PIN>%s</PIN><Email>%s</Email>"
        "<Version>CertWizard 2.2.1</Version></CSR>" % (pem, PIN, EMAIL)
    ).encode()


def _admin(ca, method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    return _request(
        ca,
        method,
        path,
        body,
        {"Content-Type": "application/json", "X-Sandbox-Token": "test-token"},
    )


def test_error_document_has_the_java_second_text_element():
    body = MockCA._error_xml("PIN does not match")
    root = ET.fromstring(body)
    assert root.tag == "error"
    texts = [item.text for item in root.findall(".//text")]
    assert len(texts) == 2
    assert texts[1] == "PIN does not match"


def test_ca_document_has_ra_list_motd_and_latest_version(sandbox):
    status, _, body = _request(sandbox, "GET", "/CA")
    assert status == 200
    root = ET.fromstring(body)
    assert root.findtext("./RAlist/ra/ou") == "CLRC"
    assert root.findtext("./RAlist/ra/l") == "DL"
    assert root.findtext("./certWizard/latestVersion") == "2.2.1"
    assert root.findtext("./motd/text") == "sandbox test motd"


def test_ping_returns_the_real_xml_shape(sandbox):
    status, headers, body = _request(sandbox, "GET", "/pingservice")
    assert status == 200
    assert b"<pingservice>" in body
    assert headers["content-type"] == "application/xml"


def test_chunked_request_body_is_dechunked_and_captured(sandbox):
    payload = b"<PublicKey>AAAA</PublicKey>"
    status, _, _ = _request(
        sandbox,
        "POST",
        "/resources/resource/publickey/pk",
        payload,
        {"Content-Type": "application/xml"},
        chunked=True,
    )
    assert status == 404
    captured = sandbox.last_request("/resources/resource/publickey/pk")
    assert captured is not None
    assert captured.body == payload


def test_chunked_user_csr_is_accepted(sandbox):
    request = _csr(_key())
    status, _, body = _request(
        sandbox,
        "POST",
        "/CSR",
        _user_xml(request),
        {"Content-Type": "application/xml"},
        chunked=True,
    )
    assert status == 201, body
    captured = sandbox.last_request("/CSR")
    assert captured is not None
    assert b"<Request>" in captured.body


def test_error_202_body_is_parseable_by_the_java_client(sandbox):
    status, _, body = _request(
        sandbox,
        "POST",
        "/CSR",
        b"<CSR><Request>x</Request></CSR>",
        {"Content-Type": "application/xml"},
    )
    assert status == 202
    root = ET.fromstring(body)
    texts = [item.text for item in root.findall(".//text")]
    assert len(texts) == 2
    assert "required" in (texts[1] or "")


def test_pppk_renewal_is_dispatched_from_slash_csr(sandbox):
    auth_key = _key()
    auth_csr = _csr(auth_key, cn="renew auth user")
    record = CSRRecord(7001, auth_csr, EMAIL)
    sandbox.csrs[_spki_b64(auth_csr.public_key())] = record
    sandbox.sign(7001)
    auth_numbers = auth_key.private_numbers().public_numbers

    new_key = _key()
    renewal = _csr(new_key, cn="renew auth user")
    pem = renewal.public_bytes(serialization.Encoding.PEM).decode()
    body = (
        "<CSR><Request>%s</Request><PIN>%s</PIN><Email>%s</Email>"
        "<PublicKey>%x.%x</PublicKey><Version>CertWizard 2.2.1</Version></CSR>"
        % (pem, PIN, EMAIL, auth_numbers.n, auth_numbers.e)
    ).encode()

    status, headers, _ = _request(
        sandbox, "POST", "/CSR", body, {"PPPK": "this is pppk", "Content-Type": "application/xml"}
    )
    assert status == 401
    assert headers.get("nonce") and headers.get("keyid") and headers.get("realm")

    challenge = headers["nonce"] + ":" + str(int(time.time() * 1000))
    encoded = challenge.lower().encode("ascii").hex()
    private = auth_key.private_numbers()
    response = format(pow(int(encoded, 16), private.d, auth_numbers.n), "x")
    status, _, payload = _request(
        sandbox,
        "POST",
        "/CSR",
        body,
        {
            "PPPK": "this is pppk",
            "Content-Type": "application/xml",
            "keyid": headers["keyid"],
            "realm": headers["realm"],
            "response": response,
        },
    )
    assert status == 201, payload
    assert any(item.kind == "renew" for item in sandbox.csrs.values())


def test_admin_can_approve_and_sign(sandbox):
    request = _csr(_key(), cn="admin flow user")
    status, _, _ = _request(
        sandbox, "POST", "/CSR", _user_xml(request), {"Content-Type": "application/xml"}
    )
    assert status == 201
    csr_id = next(iter(sandbox.csrs.values())).id

    status, _, body = _admin(sandbox, "GET", "/__sandbox__/status")
    assert status == 200
    assert json.loads(body)["csrs"][0]["status"] == "NEW"

    status, _, body = _admin(sandbox, "POST", "/__sandbox__/approve", {"id": csr_id})
    assert status == 200
    assert json.loads(body)["changed"] == [csr_id]
    status, _, body = _admin(sandbox, "POST", "/__sandbox__/sign", {"id": csr_id})
    assert status == 200
    assert json.loads(body)["changed"] == [csr_id]

    status, _, body = _admin(sandbox, "GET", "/__sandbox__/status")
    payload = json.loads(body)
    assert payload["certificates"][0]["status"] == "VALID"
    assert payload["csrs"][0]["cert_id"] == payload["certificates"][0]["id"]


def test_admin_rejects_a_bad_token(sandbox):
    status, _, body = _request(
        sandbox, "GET", "/__sandbox__/status", headers={"X-Sandbox-Token": "wrong"}
    )
    assert status == 403
    assert "token" in json.loads(body)["error"]


def test_persisted_hierarchy_survives_a_restart(tmp_path):
    data_dir = tmp_path / "persistent"
    first = SandboxCA(data_dir=data_dir, port=0, auto_approve=False)
    first_pins = (first.info()["root_sha256"], first.info()["issuing_sha256"])
    first.stop()

    second = SandboxCA(data_dir=data_dir, port=0, auto_approve=False)
    try:
        assert (second.info()["root_sha256"], second.info()["issuing_sha256"]) == first_pins
        assert second.info()["issuer_dn"].startswith("CN=pyCert Test Issuing CA")
        # The TLS leaf is allowed to rotate; the trust anchors must not.
        assert hashlib.sha256(second.server_cert.public_bytes(serialization.Encoding.DER)).digest()
    finally:
        second.stop()


def _fake_java_jar(path):
    class_bytes = b"fake-class" + b"".join(pin.encode() for pin in _OLD_PINS.values())
    config = (
        "ngsca.issuer.dn=CN=old,O=old,C=UK\n"
        "ngsca.cert.o=eScience\n"
        "ngsca.cert.c=UK\n"
        "uk.ngs.ca.request.csr.url=https://cwiz-live.ca.ngs.ac.uk:443/CSR\n"
        "uk.ngs.ca.request.certificate.url=https://cwiz-live.ca.ngs.ac.uk:443/certificate\n"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as jar:
        jar.writestr(_CLASS_PATH, class_bytes)
        jar.writestr(_CONFIG_PATH, config)
        for name in _OLD_PINS:
            jar.writestr(name, b"old-resource")
        jar.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        jar.writestr("META-INF/CERT.SF", b"signature")
        jar.writestr("META-INF/CERT.RSA", b"signature")


def test_java_kit_patches_pins_resources_config_and_drops_signatures(tmp_path, sandbox):
    source = tmp_path / "CertWizard.jar"
    output = tmp_path / "CertWizard-sandbox.jar"
    _fake_java_jar(source)
    build_jar_kit(source, output, sandbox.info())

    with zipfile.ZipFile(output) as jar:
        assert "META-INF/CERT.SF" not in jar.namelist()
        assert "META-INF/CERT.RSA" not in jar.namelist()
        class_bytes = jar.read(_CLASS_PATH)
        assert all(pin.encode() not in class_bytes for pin in _OLD_PINS.values())
        assert sandbox.info()["root_sha256"].encode() in class_bytes
        config = jar.read(_CONFIG_PATH).decode()
        assert sandbox.info()["url"] + "/CSR" in config
        assert sandbox.info()["issuer_dn"] in config
        assert jar.read("escience-root.pem") == (sandbox.data_dir_path / "root.pem").read_bytes()


def test_java_kit_refuses_a_jar_with_unknown_pins(tmp_path, sandbox):
    source = tmp_path / "unknown.jar"
    with zipfile.ZipFile(source, "w") as jar:
        jar.writestr(_CLASS_PATH, b"no known pins here")
        jar.writestr(_CONFIG_PATH, "ngsca.cert.o=old\n")
    with pytest.raises(SystemExit, match="different bundled CA pins"):
        build_jar_kit(source, tmp_path / "out.jar", sandbox.info())


def test_state_survives_restart_and_can_be_looked_up(tmp_path):
    data_dir = tmp_path / "persistent-state"
    first = SandboxCA(data_dir=data_dir, port=0, auto_approve=False, admin_token="test-token")
    try:
        key = _key()
        request = _csr(key, cn="persistent user")
        status, _, _ = _request(first, "POST", "/CSR", _user_xml(request), {"Content-Type": "application/xml"})
        assert status == 201
        csr_id = next(iter(first.csrs.values())).id
        status, _, _ = _admin(first, "POST", "/__sandbox__/sign", {"id": csr_id})
        assert status == 200
        cert_id = first.certificates[next(iter(first.certificates))].id
        assert (data_dir / "state.json").exists()
    finally:
        first.stop()

    second = SandboxCA(data_dir=data_dir, port=0, auto_approve=False, admin_token="test-token")
    try:
        assert len(second.csrs) == 1
        assert len(second.certificates) == 1
        lookup = b"<PublicKey>" + _spki_b64(key.public_key()).encode() + b"</PublicKey>"
        status, _, body = _request(
            second, "POST", "/resources/resource/publickey/pk", lookup, {"Content-Type": "application/xml"}
        )
        assert status == 200
        assert ("<id>%d</id>" % cert_id).encode() in body
        status, _, body = _admin(second, "GET", "/__sandbox__/status")
        assert status == 200
        payload = json.loads(body)
        assert payload["certificates"][0]["id"] == cert_id
    finally:
        second.stop()


def test_reject_is_reported_and_persisted(sandbox):
    request = _csr(_key(), cn="reject me")
    status, _, _ = _request(sandbox, "POST", "/CSR", _user_xml(request), {"Content-Type": "application/xml"})
    assert status == 201
    csr_id = next(iter(sandbox.csrs.values())).id
    status, _, body = _admin(
        sandbox, "POST", "/__sandbox__/reject", {"id": csr_id, "reason": "not this time"}
    )
    assert status == 200
    assert json.loads(body)["changed"] == [csr_id]
    # A rejected request must never be auto-issued by a later status lookup.
    sandbox.auto_approve = True
    sandbox.sign_after_polls = 0
    key = next(iter(sandbox.csrs.values())).csr.public_key()
    lookup = b"<PublicKey>" + _spki_b64(key).encode() + b"</PublicKey>"
    status, _, body = _request(
        sandbox, "POST", "/resources/resource/publickey/pk", lookup, {"Content-Type": "application/xml"}
    )
    assert status == 200
    assert b"<status>REJECTED</status>" in body
    assert b"<reason>not this time</reason>" in body
    assert not sandbox.certificates


def test_admin_ui_requires_the_token_and_renders_the_dashboard(sandbox):
    status, _, body = _request(sandbox, "GET", "/__sandbox__/ui")
    assert status == 200
    assert b"Admin token" in body
    status, _, body = _request(sandbox, "GET", "/__sandbox__/ui?token=test-token")
    assert status == 200
    assert b"pyCert sandbox CA" in body
    assert b"Certificate requests" in body


def test_validity_setting_is_applied_to_issued_certificates(sandbox):
    status, _, _ = _admin(sandbox, "POST", "/__sandbox__/settings", {"valid_days": 30})
    assert status == 200
    request = _csr(_key(), cn="short lived user")
    status, _, _ = _request(sandbox, "POST", "/CSR", _user_xml(request), {"Content-Type": "application/xml"})
    assert status == 201
    csr_id = next(iter(sandbox.csrs.values())).id
    sandbox.sign(csr_id)
    cert = next(iter(sandbox.certificates.values())).cert
    lifetime = (not_valid_after(cert) - not_valid_before(cert)).days
    assert 28 <= lifetime <= 30
