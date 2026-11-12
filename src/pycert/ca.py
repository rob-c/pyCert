"""Client for the UK e-Science CA (OpenCA / "cwiz") REST interface.

The protocol is the one CertWizard uses; it is reproduced here deliberately and
documented, because there is no public specification:

======================  =====================================================
Endpoint                Purpose
======================  =====================================================
``GET  /pingservice``   liveness probe (200 OK)
``GET  /CA``            CA certificates, RA list, policy
``POST /CSR``           new user CSR: XML ``<CSR>`` with PEM, PIN hash, e-mail
``POST /CSRs``          host CSR: XML ``<Bulk>``, PPPK-authenticated
``POST /CSR``           renewal: XML ``<CSR>`` with ``<PublicKey>``, PPPK-authenticated
``POST /resources/resource/publickey/pk``
                        status lookup by base64 SubjectPublicKeyInfo
``GET  /certificate/<id>``
                        issued certificate
``POST /revoke``        revocation, PPPK-authenticated
======================  =====================================================

Security properties pyCertWiz adds on top of the Java client:

* TLS is verified against the configured CA chain by default, with optional
  key pinning.  CertWizard shipped a Java truststore whose password was the
  literal string ``passwd``.
* Responses are size-limited and XML with a DOCTYPE/ENTITY declaration is
  rejected (XXE / entity-expansion defence).
* Nothing is retried automatically after a submission may have reached the
  server; the caller is told to check the status instead of risking duplicates.
* Error messages never include private key material, passphrases or PINs.
"""

import base64
import functools
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from . import certs
from .certs import not_valid_after
from .errors import CAError, CryptoError, NetworkError, ProtocolError
from .transport import Response, Transport, TransportConfig
from .util import clamp_text, format_fingerprint

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_XML_BYTES = 4 * 1024 * 1024
MAX_XML_DEPTH = 100
MAX_XML_ELEMENTS = 100000
USER_AGENT_FALLBACK = "pyCertWiz/1.0"

REVOCATION_REASONS = (
    "unspecified",
    "keyCompromise",
    "cACompromise",
    "affiliationChanged",
    "superseded",
    "cessationOfOperation",
    "certificateHold",
)


# ---------------------------------------------------------------------------
# Small value objects
# ---------------------------------------------------------------------------


@dataclass
class TLSPeer:
    subject: str
    issuer: str
    fingerprint: str
    not_after: datetime

    def as_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "sha256_fingerprint": self.fingerprint,
            "not_after": self.not_after.astimezone(timezone.utc).isoformat(),
        }


@dataclass
class Submission:
    success: bool
    status: int
    message: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "success": self.success,
            "status": self.status,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass
class ServerCertificate:
    id: str = ""
    status: str = ""
    owner: str = ""
    role: str = ""
    email: str = ""
    start_date: str = ""
    end_date: str = ""
    life_days: str = ""
    renew: str = ""
    pem: str = ""

    def certificate(self) -> "x509.Certificate | None":
        if not self.pem:
            return None
        try:
            return certs.load_certificate(self.pem.encode())
        except Exception:  # noqa: BLE001 - a bad server response should not crash polling
            return None


@dataclass
class ServerCSR:
    id: str = ""
    status: str = ""
    owner: str = ""
    role: str = ""
    email: str = ""


@dataclass
class Lookup:
    certificates: "list[ServerCertificate]" = field(default_factory=list)
    csrs: "list[ServerCSR]" = field(default_factory=list)
    raw: str = ""

    @property
    def latest_certificate(self) -> "ServerCertificate | None":
        return self.certificates[-1] if self.certificates else None

    @property
    def latest_csr(self) -> "ServerCSR | None":
        return self.csrs[-1] if self.csrs else None


@dataclass
class RA:
    ou: str
    l: str

    @property
    def label(self) -> str:
        return f"{self.ou} {self.l}"


@dataclass
class CAInfo:
    certificates: "list[x509.Certificate]"
    ras: "list[RA]"
    preferred_ra: "RA | None"
    policy: "dict[str, str]"
    problems: "list[str]" = field(default_factory=list)


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------


class CAClient:
    """Client for one CA, using the hardened transport in :mod:`pycert.transport`."""

    def __init__(self, config):
        self.config = config
        self.ca = config.ca
        self.base = urlsplit(self.ca.base_url)
        if self.base.scheme not in ("https", "http"):
            raise NetworkError("unsupported URL scheme: %s" % self.base.scheme)
        if self.base.scheme == "http" and not self.ca.allow_plaintext:
            raise NetworkError("refusing to use plaintext HTTP (set ca.allow_plaintext to override)")
        self.last_tls = None
        self.last_url = ""
        self.last_error = ""
        transport_config = TransportConfig(
            connect_timeout=self.ca.connect_timeout,
            read_timeout=self.ca.timeout,
            deadline=self.ca.deadline,
            dns_timeout=self.ca.dns_timeout,
            retries=self.ca.retries,
            max_redirects=self.ca.max_redirects,
            max_body_bytes=self.ca.max_body_bytes,
            max_header_bytes=self.ca.max_header_bytes,
            backoff_base=self.ca.backoff_base,
            backoff_cap=self.ca.backoff_cap,
            user_agent=self.ca.user_agent,
            allow_plaintext=self.ca.allow_plaintext,
            tls_verify=self.ca.tls_verify,
            tls_pem=self.config.tls_trust_pem(),
            use_system_trust=self.config.use_system_trust(),
            tls_pins=list(self.ca.tls_pin_sha256),
        )
        self.transport = Transport(transport_config)

    def _peer_info(self, der):
        cert = x509.load_der_x509_certificate(der)
        return TLSPeer(
            subject=certs.name_to_string(cert.subject),
            issuer=certs.name_to_string(cert.issuer),
            fingerprint=format_fingerprint(cert.fingerprint(certs.hash_algorithm("sha256"))),
            not_after=not_valid_after(cert),
        )

    def request(
        self,
        method,
        url,
        *,
        body=None,
        headers=None,
        idempotent=False,
        stop_event=None,
        deadline=None,
    ):
        self.last_error = ""
        try:
            response = self.transport.request(
                method,
                url,
                body=body,
                headers=headers,
                idempotent=idempotent,
                stop_event=stop_event,
                deadline=deadline,
            )
        except NetworkError as exc:
            self.last_error = str(exc)
            raise
        finally:
            der = self.transport.last_peer_certificate
            if der:
                try:
                    self.last_tls = self._peer_info(der)
                except Exception:  # noqa: BLE001 - a display detail, not a protocol error
                    self.last_tls = None
        self.last_url = url
        return response

    # -- helpers -----------------------------------------------------------
    @staticmethod
    @functools.lru_cache(maxsize=1)
    def local_host_header() -> str:
        """This computer's name, sent as CertWizard's LocalHost header.

        Looked up once per process: getfqdn() does a reverse DNS lookup, which
        takes seconds where reverse DNS is slow (GitHub's macOS runners, many
        laptops on hotel networks), and the name does not change mid-run.
        """
        try:
            return socket.getfqdn()
        except OSError:  # pragma: no cover
            return socket.gethostname()

    def _base_headers(self) -> "dict[str, str]":
        return {"LocalHost": self.local_host_header()}

    def _parse_xml(self, response: Response) -> ET.Element:
        return _safe_xml(response.body)

    @staticmethod
    def server_message(body: bytes) -> str:
        """Extract the human-readable part of an OpenCA error document."""
        try:
            root = _safe_xml(body)
        except (ProtocolError, ET.ParseError):
            text = body.decode("utf-8", "replace")
            return clamp_text(text, 400)
        texts = [elem.text.strip() for elem in root.iter() if elem.tag.split("}")[-1] == "text" and elem.text]
        texts = [t for t in texts if t]
        if texts:
            # OpenCA nests a generic message and a more specific one; keep both.
            return " / ".join(dict.fromkeys(texts))
        return clamp_text(" ".join(root.itertext()), 400)

    def _error(self, response: Response, context: str) -> CAError:
        if response.status == 404:
            message = (
                f"{context}: endpoint not found (404). Check ca.base_url and ca.endpoints "
                "in the configuration."
            )
        elif response.status == 403:
            message = f"{context}: authentication failed (403)."
        elif response.status == 401:
            message = f"{context}: authentication required (401)."
        elif response.status == 405:
            message = f"{context}: server does not accept this method (405)."
        else:
            message = f"{context}: server returned HTTP {response.status} {response.reason}."
        detail = self.server_message(response.body) if response.body else ""
        return CAError(message, status=response.status, detail=detail)

    # -- endpoints ---------------------------------------------------------
    def ping(self) -> bool:
        url = self.ca.url("ping")
        self.last_error = ""
        try:
            response = self.request("GET", url, headers=self._base_headers(), idempotent=True)
        except NetworkError as exc:
            self.last_error = str(exc)
            return False
        if response.status not in (200, 204):
            self.last_error = f"HTTP {response.status} {response.reason}"
        return response.status in (200, 204)

    def info(self) -> CAInfo:
        url = self.ca.url("info")
        response = self.request("GET", url, headers=self._base_headers(), idempotent=True)
        if response.status != 200:
            raise self._error(response, "reading CA information")
        root = self._parse_xml(response)
        certificates: "list[x509.Certificate]" = []
        problems: "list[str]" = []
        for element in _iter_tags(root, "certificate"):
            text = (element.text or "").strip()
            if "BEGIN CERTIFICATE" not in text:
                continue
            try:
                certificates.append(certs.load_certificate(text.encode()))
            except Exception as exc:  # noqa: BLE001
                problems.append(f"could not parse a /CA certificate: {exc}")
        ras: "list[RA]" = []
        ra_list = _first_tag(root, "RAlist")
        # Only <ra> elements inside <RAlist>; <PreferredRA> has one too and must
        # not appear twice in the list.
        for ra_element in _iter_tags(ra_list, "ra") if ra_list is not None else ():
            ou = _child_text(ra_element, "ou")
            l = _child_text(ra_element, "l")
            if ou and l:
                ras.append(RA(ou, l))
        preferred = None
        preferred_section = _first_tag(root, "PreferredRA")
        if preferred_section is not None:
            ra_element = _first_tag(preferred_section, "ra")
            if ra_element is not None:
                ou = _child_text(ra_element, "ou")
                l = _child_text(ra_element, "l")
                if ou and l:
                    preferred = RA(ou, l)
        policy = {}
        policy_section = _first_tag(root, "Policy")
        if policy_section is not None:
            for child in policy_section:
                tag = child.tag.split("}")[-1]
                policy[tag] = (child.text or "").strip()
        return CAInfo(certificates, ras, preferred, policy, problems)

    def motd(self) -> str:
        url = self.ca.url("motd")
        response = self.request("GET", url, headers=self._base_headers(), idempotent=True)
        if response.status != 200:
            raise self._error(response, "reading message of the day")
        text = response.text().strip()
        # The live server returns an XML wrapper even for the "/text" resource.
        if text.startswith("<"):
            try:
                root = self._parse_xml(response)
                parts = [
                    (element.text or "").strip()
                    for element in _iter_tags(root, "text")
                    if (element.text or "").strip()
                ]
                if parts:
                    return clamp_text(" / ".join(parts), 2000)
            except ProtocolError:
                pass
        return clamp_text(text, 2000)

    # -- CSR submission ----------------------------------------------------
    @staticmethod
    def _csr_xml(pem: str, pin_hash: str, email: str, version: str, public_key: "str | None") -> bytes:
        root = ET.Element("CSR")
        ET.SubElement(root, "Request").text = pem
        ET.SubElement(root, "PIN").text = pin_hash
        ET.SubElement(root, "Email").text = email
        if public_key:
            ET.SubElement(root, "PublicKey").text = public_key
        ET.SubElement(root, "Version").text = version
        return ET.tostring(root, encoding="utf-8")

    @staticmethod
    def _bulk_xml(pem: str, pin_hash: str, email: str, version: str) -> bytes:
        root = ET.Element("Bulk")
        csr = ET.SubElement(root, "CSR")
        ET.SubElement(csr, "Request").text = pem
        ET.SubElement(csr, "PIN").text = pin_hash
        ET.SubElement(csr, "Email").text = email
        ET.SubElement(csr, "Version").text = version
        return ET.tostring(root, encoding="utf-8")

    def submit_csr(self, csr_pem: str, pin_hash: str, email: str) -> Submission:
        """Submit a new *user* certificate request (no client authentication)."""
        url = self.ca.url("csr")
        body = self._csr_xml(csr_pem, pin_hash, email, self.ca.version_string, None)
        headers = self._base_headers()
        response = self.request("POST", url, body=body, headers=headers)
        if response.status == 201:
            return Submission(True, 201, "CSR submitted; awaiting RA approval and CA signing")
        if response.status == 202:
            detail = self.server_message(response.body)
            return Submission(False, 202, "the CA rejected the CSR", detail)
        raise self._error(response, "submitting CSR")

    def submit_authenticated(
        self,
        *,
        csr_pem: str,
        pin_hash: str,
        email: str,
        auth_cert: x509.Certificate,
        auth_key,
        host_request: bool = False,
        public_key: "str | None" = None,
    ) -> Submission:
        """Submit a host CSR or a renewal using PPPK client authentication.

        CertWizard uses ``/CSRs`` for a host (bulk) request but the same
        ``/CSR`` resource as a user request for renewal; the renewal is
        distinguished by ``<PublicKey>`` and the ``PPPK`` header.  Follow that
        exactly, while the listener also accepts the legacy ``/CSRs`` renewal
        path.
        """
        url = self.ca.url("bulk") if host_request else self.ca.url("csr")
        if host_request:
            body = self._bulk_xml(csr_pem, pin_hash, email, self.ca.version_string)
        else:
            body = self._csr_xml(csr_pem, pin_hash, email, self.ca.version_string, public_key)
        base_headers = self._base_headers()
        base_headers["PPPK"] = "this is pppk"
        if host_request:
            base_headers["serial"] = str(auth_cert.serial_number)

        challenge = self.request("POST", url, body=body, headers=base_headers)
        if challenge.status == 201:
            # Some server versions accept the request without a challenge.
            return Submission(True, 201, "CSR submitted")
        if challenge.status == 202:
            return Submission(False, 202, "the CA rejected the CSR", self.server_message(challenge.body))
        if challenge.status != 401:
            raise self._error(challenge, "submitting authenticated CSR")

        realm = challenge.headers.get("realm")
        nonce = challenge.headers.get("nonce")
        keyid = challenge.headers.get("keyid")
        opaque = challenge.headers.get("opaque")
        if opaque:
            retry_headers = dict(base_headers)
            retry_headers["opaque"] = opaque
            response = self.request("POST", url, body=body, headers=retry_headers)
        else:
            if not (realm and nonce and keyid):
                raise ProtocolError(
                    "PPPK challenge is missing realm/nonce/keyid headers; the server may not "
                    "support client-certificate authentication for this resource"
                )
            response_value = pppk_response(
                auth_key, realm, nonce, keyid, timestamp_ms=self.transport.now_ms()
            )
            retry_headers = dict(base_headers)
            retry_headers.update({"keyid": keyid, "realm": realm, "response": response_value})
            response = self.request("POST", url, body=body, headers=retry_headers)
        if response.status == 201:
            return Submission(True, 201, "CSR submitted")
        if response.status == 202:
            return Submission(False, 202, "the CA rejected the CSR", self.server_message(response.body))
        raise self._error(response, "submitting authenticated CSR")

    # -- status / certificates --------------------------------------------
    def lookup_public_key(self, spki_base64: str, *, stop_event=None) -> Lookup:
        url = self.ca.url("lookup")
        root = ET.Element("PublicKey")
        root.text = spki_base64
        body = ET.tostring(root, encoding="utf-8")
        # A lookup is safe to retry: it has no side effects.
        response = self.request(
            "POST", url, body=body, headers=self._base_headers(), idempotent=True, stop_event=stop_event
        )
        if response.status == 404:
            return Lookup(raw=response.text())
        if response.status != 200:
            raise self._error(response, "looking up certificate status")
        root_element = self._parse_xml(response)
        lookup = Lookup(raw=response.text())
        for element in _iter_tags(root_element, "certificate"):
            certificate = ServerCertificate(
                id=_child_text(element, "id"),
                status=_child_text(element, "status"),
                owner=_child_text(element, "owner"),
                role=_child_text(element, "role"),
                email=_child_text(element, "useremail"),
                start_date=_child_text(element, "startdate"),
                end_date=_child_text(element, "enddate"),
                life_days=_child_text(element, "lifedays"),
                renew=_child_text(element, "renew"),
                pem=_child_text(element, "X509Certificate"),
            )
            if certificate.id or certificate.status:
                lookup.certificates.append(certificate)
        for element in _iter_tags(root_element, "CSR"):
            csr = ServerCSR(
                id=_child_text(element, "id"),
                status=_child_text(element, "status"),
                owner=_child_text(element, "owner"),
                role=_child_text(element, "role"),
                email=_child_text(element, "useremail"),
            )
            if csr.id or csr.status:
                lookup.csrs.append(csr)
        return lookup

    def download_certificate(self, cert_id: str, *, stop_event=None) -> x509.Certificate:
        if not cert_id or not all(ch.isdigit() or ch.isalpha() or ch in "-_." for ch in cert_id):
            raise ProtocolError(f"refusing to use suspicious certificate id: {cert_id!r}")
        url = self.ca.url("certificate").rstrip("/") + "/" + cert_id
        response = self.request("GET", url, headers=self._base_headers(), idempotent=True)
        if response.status != 200:
            raise self._error(response, f"downloading certificate {cert_id}")
        try:
            root = self._parse_xml(response)
            text = ""
            for element in _iter_tags(root, "X509Certificate"):
                text = (element.text or "").strip()
                if text:
                    break
            if not text and "BEGIN CERTIFICATE" in response.text():
                text = response.text()
            if not text:
                raise ProtocolError("certificate response did not contain an X509Certificate element")
            return certs.load_certificate(text.encode())
        except ProtocolError:
            # Last resort: a plain PEM/DER body is also acceptable.
            return certs.load_certificate(response.body)

    # -- revocation --------------------------------------------------------
    def revoke(self, cert_id: str, reason: str, auth_cert: x509.Certificate, auth_key) -> Submission:
        if reason not in REVOCATION_REASONS:
            raise CAError(
                f"unknown revocation reason: {reason!r} (choose from {', '.join(REVOCATION_REASONS)})"
            )
        url = self.ca.url("revoke")
        root = ET.Element("Revoke")
        ET.SubElement(root, "id").text = cert_id
        ET.SubElement(root, "reason").text = reason
        body = ET.tostring(root, encoding="utf-8")
        headers = self._base_headers()
        headers["PPPK"] = "this is pppk"
        challenge = self.request("POST", url, body=body, headers=headers)
        if challenge.status == 201:
            return Submission(True, 201, "certificate revoked")
        if challenge.status != 401:
            raise self._error(challenge, "revoking certificate")
        realm = challenge.headers.get("realm")
        nonce = challenge.headers.get("nonce")
        keyid = challenge.headers.get("keyid")
        opaque = challenge.headers.get("opaque")
        if opaque:
            retry_headers = dict(headers)
            retry_headers["opaque"] = opaque
            response = self.request("POST", url, body=body, headers=retry_headers)
        else:
            if not (realm and nonce and keyid):
                raise ProtocolError("PPPK challenge for revocation is missing realm/nonce/keyid")
            retry_headers = dict(headers)
            retry_headers.update(
                {
                    "keyid": keyid,
                    "realm": realm,
                    "response": pppk_response(
                        auth_key, realm, nonce, keyid, timestamp_ms=self.transport.now_ms()
                    ),
                }
            )
            response = self.request("POST", url, body=body, headers=retry_headers)
        if response.status == 201:
            return Submission(True, 201, "certificate revoked")
        if response.status == 202:
            return Submission(
                False, 202, "the CA rejected the revocation", self.server_message(response.body)
            )
        raise self._error(response, "revoking certificate")


# ---------------------------------------------------------------------------
# PPPK (public-key challenge/response, as used by the CA)
# ---------------------------------------------------------------------------


def pppk_response(private_key, realm: str, nonce: str, keyid: str, timestamp_ms: "int | None" = None) -> str:
    """Compute the PPPK challenge response.

    The server sends ``keyid`` = ``<modulus hex>.<public exponent hex>`` and a
    ``nonce``.  The client forms ``nonce:<unix millis>`` in lower case, treats the
    ASCII characters of that string as hex digits, raises it to the private
    exponent modulo the server's modulus, and returns the result in lower-case
    hex.  The server checks the result with the certificate's public key.

    This is what CertWizard implements; pyCertWiz reproduces it exactly so the CA
    keeps working, but the exponentiation is done with Python's big integers
    from the key material supplied by ``cryptography``.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise CryptoError("PPPK authentication requires an RSA private key")
    if "." not in keyid:
        raise ProtocolError(f"malformed PPPK keyid: {keyid!r}")
    modulus_hex, _exponent_hex = keyid.split(".", 1)
    timestamp_ms = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    lowered = f"{nonce}:{timestamp_ms}".lower()
    c_hex = "".join(format(ord(ch), "x") for ch in lowered).upper()
    try:
        challenge = int(c_hex, 16)
        modulus = int(modulus_hex, 16)
    except ValueError as exc:
        raise ProtocolError("malformed PPPK challenge") from exc
    numbers = private_key.private_numbers()
    if modulus != numbers.public_numbers.n:
        raise CryptoError(
            "the CA challenged a different key than the one supplied; check that the "
            "certificate belongs to the private key"
        )
    response = pow(challenge, numbers.d, modulus)
    return format(response, "x")


# ---------------------------------------------------------------------------
# XML helpers that ignore namespaces
# ---------------------------------------------------------------------------


def _safe_xml(data: bytes) -> ET.Element:
    """Parse untrusted XML with entity-expansion and size defences."""
    if len(data) > MAX_XML_BYTES:
        raise ProtocolError("XML response too large")
    # Scan the whole document, not just the prolog: a comment padded past the
    # first few kilobytes must not smuggle a DOCTYPE in.
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ProtocolError("server returned XML with a DOCTYPE/ENTITY declaration; refusing it")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ProtocolError(f"could not parse server XML: {exc}") from exc
    count = 0
    stack = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        count += 1
        if depth > MAX_XML_DEPTH:
            raise ProtocolError("server XML is nested too deeply")
        if count > MAX_XML_ELEMENTS:
            raise ProtocolError("server XML contains too many elements")
        for child in element:
            stack.append((child, depth + 1))
    return root


def _local(tag: str) -> str:
    return tag.split("}")[-1]


def _iter_tags(root: ET.Element, name: str):
    for element in root.iter():
        if _local(element.tag) == name:
            yield element


def _first_tag(root: ET.Element, name: str) -> "ET.Element | None":
    for element in _iter_tags(root, name):
        return element
    return None


def _child_text(element: ET.Element, name: str) -> str:
    for child in element:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def b64_spki(certificate_or_key) -> str:
    return base64.b64encode(certs.spki_der(certificate_or_key)).decode("ascii")
