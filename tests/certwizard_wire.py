"""Canonical application-level comparison of CertWizard and pyCertWiz requests.

The Java project's golden fixtures are byte-level recordings from the original
Restlet implementation.  pyCertWiz intentionally uses a different hardened HTTP
transport, so comparing raw bytes would only produce noise (connection framing,
User-Agent, compression negotiation).  This module strips those transport
details and keeps exactly the parts the CA listener and the Java application
agree on:

* method and resource path;
* application headers: Content-Type, PPPK, serial, keyid/realm/response/opaque,
  LocalHost, Date and Accept;
* XML request shape and field types/values, with request-specific random values
  (CSR PEM, PIN hash, public key, certificate id and revocation reason)
  canonicalised.

The fixtures live in ``tests/fixtures/certwizard_golden/requests`` and are
copied from the CertWizard repository; see the README there.
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "certwizard_golden" / "requests"

# Headers which only describe identity or message framing.  Java's Restlet
# recording used chunked bodies and Keep-Alive; java.net.http and pyCertWiz use
# Content-Length/close.  None of these change the CA protocol.
_IGNORED_HEADERS = {
    "host",
    "connection",
    "transfer-encoding",
    "content-length",
    "accept-encoding",
    "user-agent",
}
_KEYID_RE = re.compile(r"^[0-9a-fA-F]+\.[0-9a-fA-F]+$")
_PIN_RE = re.compile(r"^[0-9A-F]{40}$")
_RESPONSE_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class WireRequest:
    method: str
    path: str
    headers: dict
    body: bytes


def parse_fixture(text: str) -> WireRequest:
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    method, path, version = lines[0].split(" ", 2)
    if version != "HTTP/1.1":
        raise AssertionError("unexpected fixture HTTP version: %s" % version)
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return WireRequest(method.upper(), path, headers, body.encode("utf-8"))


def load_fixtures(scenario: str) -> "list[WireRequest]":
    paths = sorted(
        FIXTURES.glob(scenario + ".*.http"),
        key=lambda path: int(path.name.rsplit(".", 2)[-2]),
    )
    if not paths:
        raise AssertionError("no golden fixtures for %s in %s" % (scenario, FIXTURES))
    return [parse_fixture(path.read_text()) for path in paths]


def canonical_path(path: str) -> str:
    path = path.split("?", 1)[0]
    if path.startswith("/certificate/"):
        return "/certificate/<id>"
    return path


def _canonical_content_type(value: str) -> str:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    media = parts[0].lower() if parts else ""
    for part in parts[1:]:
        if "=" in part:
            key, val = part.split("=", 1)
            if key.strip().lower() == "charset":
                return "%s; charset=%s" % (media, val.strip().strip('"').lower())
    return media


def _canonical_headers(headers: dict, method: str) -> dict:
    lower = {str(name).lower(): str(value) for name, value in headers.items()}
    result = {}
    if "content-type" in lower:
        result["content-type"] = _canonical_content_type(lower["content-type"])
    # CAInfo adds PPPK to its GET /CA request, while CAMotd's version request
    # does not.  The server treats it as optional on read-only GETs; only
    # authenticated POSTs are required to carry it.
    if method != "GET" and "pppk" in lower:
        result["pppk"] = lower["pppk"]
    if "serial" in lower:
        if not lower["serial"].isdigit():
            raise AssertionError("serial header is not a decimal number: %r" % lower["serial"])
        result["serial"] = "<serial>"
    if "keyid" in lower:
        if not _KEYID_RE.match(lower["keyid"]):
            raise AssertionError("keyid is not modulus.exponent: %r" % lower["keyid"])
        result["keyid"] = "<keyid>"
    if "realm" in lower:
        result["realm"] = "<realm>"
    if "response" in lower:
        if lower["response"] != "${PPPK_RESPONSE}" and not _RESPONSE_RE.match(lower["response"]):
            raise AssertionError("PPPK response is not hex: %r" % lower["response"])
        result["response"] = "<response>"
    if "opaque" in lower:
        result["opaque"] = "<opaque>"
    if "localhost" in lower:
        result["localhost"] = "<localhost>"
    if "date" in lower:
        result["date"] = "<date>"
    if "accept" in lower:
        result["accept"] = lower["accept"].strip()
    for name, value in lower.items():
        if name in _IGNORED_HEADERS or name in result or name in {
            "content-type",
            "pppk",
            "serial",
            "keyid",
            "realm",
            "response",
            "opaque",
            "localhost",
            "date",
            "accept",
        }:
            continue
        result[name] = value
    return result


def _text(element) -> str:
    return (element.text or "").strip()


def _canonical_element(element, *, root: bool = False):
    tag = element.tag.split("}")[-1]
    if tag == "Request":
        text = _text(element)
        if "BEGIN CERTIFICATE REQUEST" not in text or "END CERTIFICATE REQUEST" not in text:
            raise AssertionError("Request is not a PEM PKCS#10 request")
        return ("Request", "csr-pem")
    if tag == "PIN":
        if not (_PIN_RE.match(_text(element)) or _text(element) == "${RANDOM_PIN_HASH}"):
            raise AssertionError("PIN is not a 40-character upper-case hash: %r" % _text(element))
        return ("PIN", "sha1-pin-hash")
    if tag == "PublicKey":
        text = _text(element)
        if root:
            # Status lookup: base64 DER SubjectPublicKeyInfo.
            if not text or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for ch in text):
                raise AssertionError("lookup PublicKey is not base64")
            return ("PublicKey", "spki-base64")
        if not _KEYID_RE.match(text) and text != "${PUBLIC_KEY}":
            raise AssertionError("renewal PublicKey is not modulus.exponent: %r" % text)
        return ("PublicKey", "pppk-public-key")
    if tag in ("CSR", "Bulk"):
        return (tag, tuple(_canonical_element(child) for child in list(element)))
    if tag == "Revoke":
        return ("Revoke", tuple(_canonical_element(child) for child in list(element)))
    if tag == "id":
        return ("id", "certificate-id")
    if tag == "reason":
        if not _text(element):
            raise AssertionError("empty revocation reason")
        return ("reason", "revocation-reason")
    if tag == "Version":
        return ("Version", _text(element))
    if tag == "Email":
        return ("Email", _text(element))
    return (tag, _text(element))


def canonical_body(body: bytes):
    if not body:
        return None
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise AssertionError("request body is not XML: %s" % exc)
    return _canonical_element(root, root=True)


def canonical_request(request: WireRequest):
    return (
        request.method,
        canonical_path(request.path),
        _canonical_headers(request.headers, request.method),
        canonical_body(request.body),
    )


def assert_request_matches(actual, expected: WireRequest, *, label: str = "") -> None:
    """Compare a ``sandbox_ca.Captured`` with a golden ``WireRequest``."""
    actual_wire = WireRequest(actual.method, actual.path, actual.headers, actual.body)
    a = canonical_request(actual_wire)
    e = canonical_request(expected)
    if a != e:
        raise AssertionError(
            "request does not match CertWizard golden fixture%s\n"
            "expected: %r\nactual:   %r\n"
            "actual headers: %r\nactual body: %s"
            % (
                (" " + label) if label else "",
                e,
                a,
                actual.headers,
                actual.body.decode("utf-8", "replace"),
            )
        )
