"""A mock UK e-Science CA server for the test suite.

It implements just enough of the OpenCA / CertWizard protocol to exercise pyCert
end to end over real TLS:

* ``GET /pingservice``, ``GET /CA``, ``GET /CA/motd/text``
* ``POST /CSR`` (new user request)
* ``POST /CSRs`` (host request and renewal, PPPK authenticated)
* ``POST /resources/resource/publickey/pk`` (status by public key)
* ``GET /certificate/<id>``
* ``POST /revoke`` (PPPK authenticated)
* ``GET /ca/issuer.pem`` for AIA fetching (plain HTTP)

The CA hierarchy is deliberately mixed: an RSA root signing an ECDSA
intermediate, which signs the endpoints' certificates.  That exercises both
signature families in pyCert's chain builder.

Nothing here is meant to be secure; it is a test double.
"""

import base64
import datetime as dt
import ipaddress
import ssl
import threading
import xml.etree.ElementTree as ET

from pycert import certs
from pycert.compat import csr_signature_valid, dataclass, not_valid_after, not_valid_before

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:  # Python 3.6
    import socketserver
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True


from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID


def _pem(obj) -> str:
    if isinstance(obj, x509.Certificate):
        return obj.public_bytes(serialization.Encoding.PEM).decode()
    return obj.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _der_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _spki_b64(cert_or_key) -> str:
    key = cert_or_key.public_key() if isinstance(cert_or_key, x509.Certificate) else cert_or_key
    return base64.b64encode(
        key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode()


@dataclass
class CSRRecord:
    id: int
    csr: x509.CertificateSigningRequest
    email: str
    status: str = "NEW"
    polls: int = 0
    cert_id: "int | None" = None
    pin_hash: str = ""
    kind: str = "user"


@dataclass
class CertRecord:
    id: int
    cert: x509.Certificate
    status: str = "VALID"
    spki_b64: str = ""
    revoke_reason: str = ""


@dataclass
class Captured:
    method: str
    path: str
    headers: dict
    body: bytes

    @property
    def xml(self):
        try:
            return ET.fromstring(self.body)
        except ET.ParseError:
            return None


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):  # noqa: D401 - silence aborted TLS
        pass


class MockCA:
    """A threaded HTTPS server implementing the CA protocol."""

    def __init__(self, *, auto_approve: bool = True, sign_after_polls: int = 1):
        self.auto_approve = auto_approve
        self.sign_after_polls = sign_after_polls
        self.lock = threading.Lock()
        self.csrs: "dict[str, CSRRecord]" = {}
        self.certificates: "dict[int, CertRecord]" = {}
        self.captured: "list[Captured]" = []
        self.next_csr_id = 1000
        self.next_cert_id = 5000
        self.reject_next: "list[tuple[int, bytes]]" = []
        self.delay = 0.0
        self._build_hierarchy()
        self._build_server_certificate()

        self.httpd = _QuietServer(("127.0.0.1", 0), self._handler_class())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.server_chain_path, self.server_key_path)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]

        self.aia_httpd = _QuietServer(("127.0.0.1", 0), self._handler_class())
        self.aia_port = self.aia_httpd.server_address[1]

        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        self._aia_thread = threading.Thread(target=self.aia_httpd.serve_forever, daemon=True)
        self._aia_thread.start()

    # -- lifecycle ---------------------------------------------------------
    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}"

    @property
    def plain_url(self) -> str:
        return f"http://127.0.0.1:{self.aia_port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.aia_httpd.shutdown()
        self.aia_httpd.server_close()

    def reset(self) -> None:
        with self.lock:
            self.csrs.clear()
            self.certificates.clear()
            self.captured.clear()
            self.reject_next.clear()
            self.auto_approve = True
            self.sign_after_polls = 1
            self.delay = 0.0

    # -- hierarchy ---------------------------------------------------------
    def _build_hierarchy(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pyCert Test Root"),
                x509.NameAttribute(NameOID.COMMON_NAME, "pyCert Test Root CA"),
            ]
        )
        self.root = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.root_key.public_key()), critical=False
            )
            .sign(self.root_key, hashes.SHA256())
        )

        self.intermediate_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pyCert Test CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "pyCert Test Issuing CA"),
            ]
        )
        self.intermediate = (
            x509.CertificateBuilder()
            .subject_name(intermediate_name)
            .issuer_name(self.root.subject)
            .public_key(self.intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.intermediate_key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()), critical=False
            )
            .sign(self.root_key, hashes.SHA256())
        )

    def _build_server_certificate(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        self.server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.server_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pyCert Test"),
                    ]
                )
            )
            .issuer_name(self.intermediate.subject)
            .public_key(self.server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key()),
                critical=False,
            )
            .sign(self.intermediate_key, hashes.SHA256())
        )
        self._tmp = Path(self._tempdir())
        self.server_chain_path = self._tmp / "server-chain.pem"
        self.server_chain_path.write_text(_pem(self.server_cert) + _pem(self.intermediate))
        self.server_key_path = self._tmp / "server-key.pem"
        self.server_key_path.write_text(_pem(self.server_key))

    @staticmethod
    def _tempdir() -> str:
        import tempfile

        return tempfile.mkdtemp(prefix="pycert-mockca-")

    # -- certificate authority --------------------------------------------
    def chain_files(self, directory: Path) -> "dict[str, str]":
        """Write the CA chain to *directory* and return name -> SHA-256."""
        from hashlib import sha256

        directory.mkdir(parents=True, exist_ok=True)
        result = {}
        for name, cert in (
            ("pycert-test-root.pem", self.root),
            ("pycert-test-intermediate.pem", self.intermediate),
        ):
            path = directory / name
            path.write_text(_pem(cert))
            result[name] = sha256(_der_cert(cert)).hexdigest()
        return result

    def issue(
        self, csr: x509.CertificateSigningRequest, *, kind: str = "user", days: int = 365
    ) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.intermediate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=isinstance(csr.public_key(), rsa.RSAPublicKey),
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(f"{self.plain_url}/ca/issuer.pem"),
                        )
                    ]
                ),
                critical=False,
            )
        )
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            builder = builder.add_extension(san, critical=False)
            host = bool(san.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            host = kind == "host"
        usages = (
            [ExtendedKeyUsageOID.SERVER_AUTH]
            if host
            else [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]
        )
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        return builder.sign(self.intermediate_key, hashes.SHA256())

    def _sign_csr(self, record: CSRRecord) -> None:
        certificate = self.issue(record.csr, kind=record.kind)
        cert_id = self.next_cert_id
        self.next_cert_id += 1
        self.certificates[cert_id] = CertRecord(cert_id, certificate, spki_b64=_spki_b64(certificate))
        record.cert_id = cert_id
        record.status = "VALID"

    def sign_all(self) -> None:
        with self.lock:
            for record in self.csrs.values():
                if record.cert_id is None:
                    self._sign_csr(record)

    def approve_all(self) -> None:
        with self.lock:
            for record in self.csrs.values():
                if record.status in ("NEW", "RENEW"):
                    record.status = "APPROVED"

    # -- PPPK verification -------------------------------------------------
    def _find_auth_cert(
        self, serial: "str | None", public_key: "str | None", csr_id: "str | None"
    ) -> "x509.Certificate | None":
        if serial:
            try:
                wanted = int(serial)
            except ValueError:
                return None
            for record in self.certificates.values():
                if record.cert.serial_number == wanted:
                    return record.cert
        if public_key:
            modulus_hex = public_key.split(".", 1)[0]
            for record in self.certificates.values():
                key = record.cert.public_key()
                if isinstance(key, rsa.RSAPublicKey) and format(key.public_numbers().n, "x") == modulus_hex:
                    return record.cert
        if csr_id:
            for record in self.certificates.values():
                if str(record.id) == str(csr_id):
                    return record.cert
        return None

    def _verify_pppk(self, cert: x509.Certificate, headers: dict, nonce: str) -> "tuple[bool, str]":
        key = cert.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            return False, "PPPK requires an RSA certificate"
        response = headers.get("response")
        if not response:
            return False, "missing response header"
        try:
            value = pow(int(response, 16), key.public_numbers().e, key.public_numbers().n)
        except ValueError:
            return False, "malformed response"
        hexdigits = format(value, "x")
        if len(hexdigits) % 2:
            hexdigits = "0" + hexdigits
        try:
            text = bytes.fromhex(hexdigits).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return False, "bad challenge encoding"
        expected = nonce.lower()
        if not text.startswith(expected):
            return False, "nonce mismatch"
        suffix = text[len(expected) :]
        if not suffix.startswith(":"):
            return False, "missing timestamp"
        try:
            stamp = int(suffix[1:])
        except ValueError:
            return False, "bad timestamp"
        now_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
        if abs(now_ms - stamp) > 300_000:
            return False, "timestamp outside the window"
        return True, ""

    @staticmethod
    def _error_xml(message: str) -> bytes:
        root = ET.Element("Response")
        minor = ET.SubElement(root, "minor")
        ET.SubElement(minor, "text").text = message
        return ET.tostring(root, encoding="utf-8")

    @staticmethod
    def _child_text(root, name: str) -> str:
        element = root.find(name)
        return (element.text or "").strip() if element is not None else ""

    # -- request handling --------------------------------------------------
    def _handler_class(self):
        ca = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence the test output
                pass

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length > 8 * 1024 * 1024:
                    self.send_error(413)
                    return b""
                return self.rfile.read(length) if length else b""

            def _send(self, status: int, body: bytes = b"", content_type: str = "application/xml") -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if body:
                    self.wfile.write(body)
                self.close_connection = True

            def _record(self, method: str, path: str, body: bytes) -> None:
                ca.captured.append(
                    Captured(method, path, {k.lower(): v for k, v in self.headers.items()}, body)
                )

            def do_GET(self):
                path = urlsplit(self.path).path
                self._record("GET", path, b"")
                if ca.delay:
                    import time

                    time.sleep(ca.delay)
                if path == "/pingservice":
                    return self._send(200, b"pong", "text/plain")
                if path == "/CA":
                    return self._send(200, ca._ca_xml())
                if path == "/CA/motd/text":
                    return self._send(
                        200,
                        b'<?xml version="1.0"?><CA><Motd><text>mock CA says hello</text></Motd></CA>',
                    )
                if path == "/ca/issuer.pem":
                    return self._send(200, _pem(ca.intermediate).encode(), "application/x-pem-file")
                if path.startswith("/certificate/"):
                    return self._certificate(path.rsplit("/", 1)[-1])
                return self._send(404, b"not found", "text/plain")

            def do_POST(self):
                path = urlsplit(self.path).path
                body = self._read_body()
                self._record("POST", path, body)
                if ca.delay:
                    import time

                    time.sleep(ca.delay)
                if ca.reject_next:
                    status, payload = ca.reject_next.pop(0)
                    return self._send(status, payload)
                try:
                    if path == "/CSR":
                        return self._submit_csr(body)
                    if path == "/CSRs":
                        return self._submit_bulk(body)
                    if path == "/resources/resource/publickey/pk":
                        return self._lookup(body)
                    if path == "/revoke":
                        return self._revoke(body)
                except Exception as exc:  # noqa: BLE001 - test double: surface the error
                    return self._send(500, ca._error_xml(f"mock CA error: {exc}"))
                return self._send(404, b"not found", "text/plain")

            # -- handlers --------------------------------------------------
            def _submit_csr(self, body: bytes):
                root = ET.fromstring(body)
                if root.tag != "CSR":
                    return self._send(202, ca._error_xml("expected a CSR document"))
                pem = ca._child_text(root, "Request")
                pin = ca._child_text(root, "PIN")
                email = ca._child_text(root, "Email")
                version = ca._child_text(root, "Version")
                if not pem or not pin or not email or not version:
                    return self._send(202, ca._error_xml("Request, PIN, Email and Version are required"))
                if len(pin) != 40 or not all(c in "0123456789ABCDEF" for c in pin):
                    return self._send(202, ca._error_xml("PIN must be an upper-case SHA-1 hash"))
                try:
                    request = x509.load_pem_x509_csr(pem.encode())
                except ValueError:
                    return self._send(202, ca._error_xml("could not parse the CSR"))
                if not csr_signature_valid(request):
                    return self._send(202, ca._error_xml("CSR signature is invalid"))
                if "@" not in email:
                    return self._send(202, ca._error_xml("Email is not valid"))
                spki = _spki_b64(request.public_key())
                with ca.lock:
                    if spki in ca.csrs:
                        return self._send(202, ca._error_xml("this public key has already been submitted"))
                    ca.next_csr_id += 1
                    record = CSRRecord(ca.next_csr_id, request, email, pin_hash=pin)
                    ca.csrs[spki] = record
                    if ca.auto_approve and ca.sign_after_polls <= 0:
                        ca._sign_csr(record)
                return self._send(201, b"")

            def _submit_bulk(self, body: bytes):
                root = ET.fromstring(body)
                if root.tag == "Bulk":
                    csr_element = root.find("CSR")
                    if csr_element is None:
                        return self._send(202, ca._error_xml("Bulk request without CSR"))
                    kind = "host"
                elif root.tag == "CSR":
                    csr_element = root
                    kind = "renew"
                else:
                    return self._send(202, ca._error_xml("expected Bulk or CSR document"))
                pem = ca._child_text(csr_element, "Request")
                pin = ca._child_text(csr_element, "PIN")
                email = ca._child_text(csr_element, "Email")
                public_key = ca._child_text(csr_element, "PublicKey")
                if not pem or not pin or not email:
                    return self._send(202, ca._error_xml("Request, PIN and Email are required"))
                try:
                    request = x509.load_pem_x509_csr(pem.encode())
                except ValueError:
                    return self._send(202, ca._error_xml("could not parse the CSR"))
                if not csr_signature_valid(request):
                    return self._send(202, ca._error_xml("CSR signature is invalid"))

                auth_cert = ca._find_auth_cert(
                    self.headers.get("serial"), public_key or None, self.headers.get("id")
                )
                if auth_cert is None:
                    return self._send(403, ca._error_xml("no matching client certificate"))
                key = auth_cert.public_key()
                if not isinstance(key, rsa.RSAPublicKey):
                    return self._send(403, ca._error_xml("client certificate must be RSA"))
                realm = "mock-realm"
                if not self.headers.get("response"):
                    body_out = ca._error_xml("authentication required")
                    self.send_response(401)
                    self.send_header("Content-Type", "application/xml")
                    self.send_header("realm", realm)
                    self.send_header("nonce", "Tm9uY2UtMTIzNDU2Nzg5MA==")
                    self.send_header("keyid", f"{key.public_numbers().n:x}.{key.public_numbers().e:x}")
                    self.send_header("Content-Length", str(len(body_out)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body_out)
                    self.close_connection = True
                    return None
                ok, problem = ca._verify_pppk(
                    auth_cert, {k.lower(): v for k, v in self.headers.items()}, "Tm9uY2UtMTIzNDU2Nzg5MA=="
                )
                if not ok:
                    return self._send(403, ca._error_xml(f"PPPK verification failed: {problem}"))
                spki = _spki_b64(request.public_key())
                with ca.lock:
                    if spki in ca.csrs:
                        return self._send(202, ca._error_xml("this public key has already been submitted"))
                    ca.next_csr_id += 1
                    record = CSRRecord(ca.next_csr_id, request, email, pin_hash=pin, kind=kind)
                    record.status = "RENEW" if kind == "renew" else "NEW"
                    ca.csrs[spki] = record
                    if ca.auto_approve and ca.sign_after_polls <= 0:
                        ca._sign_csr(record)
                return self._send(201, b"")

            def _lookup(self, body: bytes):
                root = ET.fromstring(body)
                if root.tag != "PublicKey":
                    return self._send(400, ca._error_xml("expected PublicKey"))
                spki = (root.text or "").strip()
                with ca.lock:
                    record = ca.csrs.get(spki)
                    if record is None:
                        return self._send(404, b"")
                    record.polls += 1
                    if record.cert_id is None and ca.auto_approve and record.polls >= ca.sign_after_polls:
                        if record.status in ("NEW", "RENEW"):
                            record.status = "APPROVED"
                        ca._sign_csr(record)
                    cert_record = ca.certificates.get(record.cert_id) if record.cert_id else None
                    parts = ["<resources><resource>"]
                    parts.append(f"<publickey>{spki}</publickey>")
                    if cert_record is not None:
                        certificate_pem = _pem(cert_record.cert)
                        parts.append("<certificates><certificate>")
                        parts.append(f"<id>{cert_record.id}</id>")
                        parts.append(f"<status>{cert_record.status}</status>")
                        parts.append("<owner>" + certs.name_to_string(cert_record.cert.subject) + "</owner>")
                        parts.append("<role>RA Operator</role>")
                        parts.append(f"<useremail>{record.email}</useremail>")
                        parts.append(
                            "<startdate>"
                            + not_valid_before(cert_record.cert).strftime("%d/%m/%Y")
                            + "</startdate>"
                        )
                        parts.append(
                            "<enddate>"
                            + not_valid_after(cert_record.cert).strftime("%d/%m/%Y")
                            + "</enddate>"
                        )
                        parts.append("<lifedays>365</lifedays>")
                        parts.append(
                            "<renew>" + not_valid_after(cert_record.cert).strftime("%d/%m/%Y") + "</renew>"
                        )
                        parts.append("<X509Certificate>" + certificate_pem + "</X509Certificate>")
                        parts.append("</certificate></certificates>")
                    else:
                        parts.append("<CSRs><CSR>")
                        parts.append(f"<id>{record.id}</id>")
                        parts.append(f"<status>{record.status}</status>")
                        parts.append("<owner>" + certs.name_to_string(record.csr.subject) + "</owner>")
                        parts.append("<role>RA Operator</role>")
                        parts.append(f"<useremail>{record.email}</useremail>")
                        parts.append("</CSR></CSRs>")
                    parts.append("</resource></resources>")
                return self._send(200, "".join(parts).encode())

            def _certificate(self, cert_id: str):
                try:
                    record = ca.certificates[int(cert_id)]
                except (ValueError, KeyError):
                    return self._send(404, b"")
                body = (
                    "<certificate><X509Certificate>" + _pem(record.cert) + "</X509Certificate></certificate>"
                ).encode()
                return self._send(200, body)

            def _revoke(self, body: bytes):
                root = ET.fromstring(body)
                if root.tag != "Revoke":
                    return self._send(400, ca._error_xml("expected Revoke"))
                cert_id = ca._child_text(root, "id")
                reason = ca._child_text(root, "reason") or "unspecified"
                try:
                    record = ca.certificates[int(cert_id)]
                except (ValueError, KeyError):
                    return self._send(404, ca._error_xml("unknown certificate id"))
                if not self.headers.get("response"):
                    key = record.cert.public_key()
                    if not isinstance(key, rsa.RSAPublicKey):
                        return self._send(403, ca._error_xml("certificate must be RSA for PPPK"))
                    out = ca._error_xml("authentication required")
                    self.send_response(401)
                    self.send_header("Content-Type", "application/xml")
                    self.send_header("realm", "mock-realm")
                    self.send_header("nonce", "UmV2b2tlLU5vbmNl")
                    self.send_header("keyid", f"{key.public_numbers().n:x}.{key.public_numbers().e:x}")
                    self.send_header("Content-Length", str(len(out)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(out)
                    self.close_connection = True
                    return None
                ok, problem = ca._verify_pppk(
                    record.cert, {k.lower(): v for k, v in self.headers.items()}, "UmV2b2tlLU5vbmNl"
                )
                if not ok:
                    return self._send(403, ca._error_xml(f"PPPK verification failed: {problem}"))
                with ca.lock:
                    record.status = "REVOKED"
                    record.revoke_reason = reason
                return self._send(201, b"")

        return Handler

    def _ca_xml(self) -> bytes:
        parts = [
            "<CA><certificates>",
            "<certificate>" + _pem(self.root) + "</certificate>",
            "<certificate>" + _pem(self.intermediate) + "</certificate>",
            "</certificates><RAlist>",
            "<ra><ou>CLRC</ou><l>DL</l><operator><id>1</id></operator></ra>",
            "<ra><ou>CLRC</ou><l>RAL</l><operator><id>2</id></operator></ra>",
            "</RAlist><PreferredRA><ra><ou>CLRC</ou><l>DL</l></ra></PreferredRA>",
            "<Policy><MaxExpiredRekey>30</MaxExpiredRekey><MaxPrivateKeyLifeTime>365</MaxPrivateKeyLifeTime></Policy>",
            "</CA>",
        ]
        return "".join(parts).encode()
