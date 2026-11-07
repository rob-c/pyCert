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
import socketserver
import ssl
import struct
import threading
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from pycert import certs
from pycert.compat import csr_signature_valid, dataclass, field, not_valid_after, not_valid_before


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """A threaded HTTPServer that also works on Python 3.6."""

    daemon_threads = True


def _pem(obj) -> str:
    if isinstance(obj, x509.Certificate):
        return obj.public_bytes(serialization.Encoding.PEM).decode()
    return obj.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _der_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _xml_escape(value: str) -> str:
    """Escape text for the tiny XML documents this test double builds."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


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
class Fault:
    status: int = 500
    body: bytes = b"<Response><minor><text>injected fault</text></minor></Response>"
    headers: "dict[str, str]" = field(default_factory=dict)
    content_type: str = "application/xml"
    delay: float = 0.0
    truncate: int = 0
    reset: bool = False
    drop: bool = False


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
    """A threaded HTTPS server implementing the CA protocol.

    The constructor is deliberately test-friendly: by default it binds an
    ephemeral loopback port and creates a fresh, throw-away CA hierarchy.  The
    standalone sandbox passes ``data_dir`` so the issuing CA (and therefore the
    Java client's patched truststore) survives a restart:

    ``host``/``port`` choose the listener address, ``public_hosts`` are added
    to the server certificate's subjectAltName (use this when the client runs
    on another machine), and ``data_dir`` persists the CA certificates and
    private keys.
    """

    def __init__(
        self,
        *,
        auto_approve: bool = True,
        sign_after_polls: int = 1,
        host: str = "127.0.0.1",
        port: int = 0,
        data_dir: "str | Path | None" = None,
        public_hosts: "list[str] | tuple[str, ...] | None" = None,
        motd: str = "mock CA says hello",
    ):
        self.auto_approve = auto_approve
        self.sign_after_polls = sign_after_polls
        self.lock = threading.Lock()
        self.csrs: "dict[str, CSRRecord]" = {}
        self.certificates: "dict[int, CertRecord]" = {}
        self.captured: "list[Captured]" = []
        self.next_csr_id = 1000
        self.next_cert_id = 5000
        self.reject_next: "list[tuple[int, bytes]]" = []
        self.faults: "dict[tuple[str | None, str], list[Fault]]" = {}
        self.delay = 0.0
        self.pppk_mode = "normal"
        self.lookup_mode = "normal"
        self.download_mode = "normal"
        self.info_mode = "normal"
        self.require_email_match = True
        self.reject_duplicate = True
        self.new_csr_status = "NEW"
        self.fault_delay = 0.0
        self.host = host
        self.motd = motd
        self.public_hosts = [item for item in (public_hosts or []) if item]
        self.data_dir = Path(data_dir) if data_dir is not None else Path(self._tempdir())
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._build_hierarchy()
        self._build_server_certificate()

        self.httpd = _QuietServer((host, port), self._handler_class())
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
    def hostname(self) -> str:
        """The name Java should use in its configuration URLs."""
        if self.public_hosts:
            return self.public_hosts[0]
        if self.host in ("", "0.0.0.0", "::", "127.0.0.1", "::1"):
            return "localhost"
        return self.host

    @property
    def url(self) -> str:
        return f"https://{self.hostname}:{self.port}"

    @property
    def plain_url(self) -> str:
        return f"http://127.0.0.1:{self.aia_port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.aia_httpd.shutdown()
        self.aia_httpd.server_close()

    def fail_next(
        self,
        path: str,
        *,
        method: "str | None" = "POST",
        status: int = 500,
        body: "bytes | None" = None,
        headers: "dict | None" = None,
        delay: float = 0.0,
        truncate: int = 0,
        reset: bool = False,
        drop: bool = False,
    ) -> Fault:
        fault = Fault(
            status=status,
            body=body
            if body is not None
            else b"<Response><minor><text>injected fault</text></minor></Response>",
            headers=dict(headers or {}),
            delay=delay,
            truncate=truncate,
            reset=reset,
            drop=drop,
        )
        with self.lock:
            self.faults.setdefault((method, path), []).append(fault)
        return fault

    def take_fault(self, method: str, path: str) -> "Fault | None":
        with self.lock:
            for key in ((method, path), (None, path), (method, path + "*"), (None, path + "*")):
                queue = self.faults.get(key)
                if queue:
                    return queue.pop(0)
            for key, queue in list(self.faults.items()):
                if (
                    queue
                    and key[1].endswith("*")
                    and path.startswith(key[1][:-1])
                    and (key[0] is None or key[0] == method)
                ):
                    return queue.pop(0)
        return None

    def requests_for(self, path: str, method: "str | None" = None):
        return [
            item for item in self.captured if item.path == path and (method is None or item.method == method)
        ]

    def last_request(self, path: str, method: "str | None" = None):
        items = self.requests_for(path, method)
        return items[-1] if items else None

    def status_snapshot(self) -> dict:
        """JSON-friendly snapshot for the sandbox admin API."""
        with self.lock:
            csrs = []
            for record in sorted(self.csrs.values(), key=lambda item: item.id):
                csrs.append(
                    {
                        "id": record.id,
                        "kind": record.kind,
                        "status": record.status,
                        "email": record.email,
                        "subject": certs.name_to_string(record.csr.subject),
                        "polls": record.polls,
                        "cert_id": record.cert_id,
                    }
                )
            certificates = []
            for record in sorted(self.certificates.values(), key=lambda item: item.id):
                certificates.append(
                    {
                        "id": record.id,
                        "status": record.status,
                        "serial": str(record.cert.serial_number),
                        "subject": certs.name_to_string(record.cert.subject),
                        "revoke_reason": record.revoke_reason,
                    }
                )
        return {
            "url": self.url,
            "hostname": self.hostname,
            "port": self.port,
            "auto_approve": self.auto_approve,
            "sign_after_polls": self.sign_after_polls,
            "pppk_mode": self.pppk_mode,
            "lookup_mode": self.lookup_mode,
            "download_mode": self.download_mode,
            "csrs": csrs,
            "certificates": certificates,
        }

    def reset(self) -> None:
        with self.lock:
            self.csrs.clear()
            self.certificates.clear()
            self.captured.clear()
            self.reject_next.clear()
            self.faults.clear()
            self.auto_approve = True
            self.sign_after_polls = 1
            self.delay = 0.0
            self.pppk_mode = "normal"
            self.lookup_mode = "normal"
            self.download_mode = "normal"
            self.info_mode = "normal"
            self.require_email_match = True
            self.reject_duplicate = True
            self.new_csr_status = "NEW"
            self.fault_delay = 0.0

    # -- hierarchy ---------------------------------------------------------
    def _build_hierarchy(self) -> None:
        """Load the CA hierarchy from ``data_dir`` or create it once.

        Persisting the hierarchy is what makes the Java-client sandbox usable:
        the client's truststore and the patched certificate pins are tied to
        these exact CA certificates, so a restart must not silently replace
        them.
        """
        root_cert_path = self.data_dir / "root.pem"
        root_key_path = self.data_dir / "root-key.pem"
        issuing_cert_path = self.data_dir / "issuing-ca.pem"
        issuing_key_path = self.data_dir / "issuing-ca-key.pem"
        if all(path.exists() for path in (root_cert_path, root_key_path, issuing_cert_path, issuing_key_path)):
            self.root = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
            self.root_key = serialization.load_pem_private_key(root_key_path.read_bytes(), password=None)
            self.intermediate = x509.load_pem_x509_certificate(issuing_cert_path.read_bytes())
            self.intermediate_key = serialization.load_pem_private_key(
                issuing_key_path.read_bytes(), password=None
            )
            self._check_hierarchy()
            return
        self._create_hierarchy()
        # Write atomically enough for a development tool: the files are small,
        # and a partially written hierarchy is detected by _check_hierarchy on
        # the next start rather than trusted silently.
        self._write_private_key(root_key_path, self.root_key)
        self._write_private_key(issuing_key_path, self.intermediate_key)
        self._write_cert(root_cert_path, self.root)
        self._write_cert(issuing_cert_path, self.intermediate)

    def _check_hierarchy(self) -> None:
        root_public = self.root.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        root_key_public = self.root_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        issuing_public = self.intermediate.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        issuing_key_public = self.intermediate_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if root_public != root_key_public or issuing_public != issuing_key_public:
            raise RuntimeError(
                "the persisted CA hierarchy in %s is inconsistent (a key does not match its certificate); "
                "remove the directory to generate a new sandbox CA" % self.data_dir
            )
        if self.intermediate.issuer != self.root.subject:
            raise RuntimeError("the persisted issuing CA was not issued by the persisted root")

    @staticmethod
    def _write_private_key(path: Path, key) -> None:
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _write_cert(path: Path, cert: x509.Certificate) -> None:
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _create_hierarchy(self) -> None:
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

    def _server_names(self) -> "list[x509.GeneralName]":
        """DNS/IP subjectAltNames for the TLS listener."""
        names = ["localhost", "127.0.0.1", "::1"]
        if self.host not in ("", "0.0.0.0", "::", "127.0.0.1", "::1"):
            names.append(self.host)
        names.extend(self.public_hosts)
        result = []
        seen = set()
        for value in names:
            if not value or value in seen:
                continue
            seen.add(value)
            try:
                result.append(x509.IPAddress(ipaddress.ip_address(value)))
            except ValueError:
                result.append(x509.DNSName(value))
        return result

    def _build_server_certificate(self) -> None:
        # The server certificate is deliberately regenerated on every start.
        # Only the CA hierarchy must remain stable (Java pins the CA files);
        # the TLS leaf is trusted through that hierarchy, so rotating it is
        # harmless and lets a sandbox be moved between loopback ports/hosts.
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
            .add_extension(x509.SubjectAlternativeName(self._server_names()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.intermediate_key.public_key()),
                critical=False,
            )
            .sign(self.intermediate_key, hashes.SHA256())
        )
        self._tmp = self.data_dir
        self.server_chain_path = self._tmp / "server-chain.pem"
        self.server_chain_path.write_text(_pem(self.server_cert) + _pem(self.intermediate))
        self.server_key_path = self._tmp / "server-key.pem"
        self._write_private_key(self.server_key_path, self.server_key)

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

    # -- administration (also used by the standalone sandbox API) ---------
    def _find_csr(self, csr_id: int) -> "CSRRecord | None":
        for record in self.csrs.values():
            if record.id == csr_id:
                return record
        return None

    def _selected_csrs(self, csr_id: "int | None", all_records: bool) -> "list[CSRRecord]":
        if all_records:
            return list(self.csrs.values())
        if csr_id is None:
            return []
        try:
            wanted = int(csr_id)
        except (TypeError, ValueError):
            return []
        record = self._find_csr(wanted)
        return [record] if record is not None else []

    def approve(self, csr_id: "int | None" = None, *, all_records: bool = False) -> "list[int]":
        """Approve one CSR (or all); returns the IDs changed."""
        changed = []
        with self.lock:
            for record in self._selected_csrs(csr_id, all_records):
                if record.cert_id is None and record.status in ("NEW", "RENEW", "APPROVED"):
                    record.status = "APPROVED"
                    changed.append(record.id)
        return changed

    def sign(self, csr_id: "int | None" = None, *, all_records: bool = False) -> "list[int]":
        """Issue certificates for one CSR (or all); returns CSR IDs changed."""
        changed = []
        with self.lock:
            for record in self._selected_csrs(csr_id, all_records):
                if record.cert_id is None:
                    self._sign_csr(record)
                    changed.append(record.id)
        return changed

    def revoke_certificate(self, cert_id: int, reason: str = "unspecified") -> bool:
        with self.lock:
            record = self.certificates.get(int(cert_id))
            if record is None:
                return False
            record.status = "REVOKED"
            record.revoke_reason = reason
            return True

    def clear_state(self) -> None:
        """Forget requests/certificates, but keep listener settings and the CA."""
        with self.lock:
            self.csrs.clear()
            self.certificates.clear()
            self.captured.clear()
            self.reject_next.clear()
            self.faults.clear()
            self.next_csr_id = 1000
            self.next_cert_id = 5000

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
    def _error_xml(message: str, *, method: str = "POST", location: str = "/") -> bytes:
        """An OpenCA-style error document.

        The Java client's ``OnlineCertUtil.getServerErrorMessage`` is famously
        literal: for HTTP 202 it returns the *second* ``<text>`` element in the
        document.  A document with only ``<minor><text>`` therefore shows an
        empty message.  This shape (major text first, minor text second)
        matches the CA's real error responses and the golden fixture.
        """
        root = ET.Element("error")
        request = ET.SubElement(root, "request")
        ET.SubElement(request, "method").text = method
        ET.SubElement(request, "location").text = location
        ET.SubElement(request, "time").text = dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        status = ET.SubElement(root, "status")
        major = ET.SubElement(status, "major")
        ET.SubElement(major, "code").text = "3"
        ET.SubElement(major, "text").text = "Certificate error"
        minor = ET.SubElement(status, "minor")
        ET.SubElement(minor, "code").text = "3.2"
        ET.SubElement(minor, "text").text = message
        return ET.tostring(root, encoding="utf-8")

    @staticmethod
    def _child_text(root, name: str) -> str:
        element = root.find(name)
        return (element.text or "").strip() if element is not None else ""

    @staticmethod
    def email_in_csr(request, email: str) -> bool:
        try:
            san = request.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return False
        return email in san.get_values_for_type(x509.RFC822Name)

    # -- request handling --------------------------------------------------
    def _handler_class(self):
        ca = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence the test output
                pass

            def _read_body(self) -> bytes:
                """Read Content-Length or chunked bodies.

                ``java.net.http`` sends a known byte[] with Content-Length, but
                older CertWizard/Restlet builds and proxies use
                ``Transfer-Encoding: chunked`` (the golden wire fixtures are
                chunked).  Accept both; a proxy or future client change must
                not turn every request into an empty body.
                """
                transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
                if "chunked" in transfer_encoding:
                    return self._read_chunked_body()
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except ValueError:
                    self.send_error(400, "invalid Content-Length")
                    return b""
                if length < 0 or length > 8 * 1024 * 1024:
                    self.send_error(413)
                    return b""
                return self.rfile.read(length) if length else b""

            def _read_chunked_body(self) -> bytes:
                chunks = []
                total = 0
                while True:
                    line = self.rfile.readline(65536)
                    if not line:
                        return b""
                    size_text = line.split(b";", 1)[0].strip()
                    try:
                        size = int(size_text, 16)
                    except ValueError:
                        self.send_error(400, "invalid chunk size")
                        return b""
                    if size < 0 or size > 8 * 1024 * 1024 - total:
                        self.send_error(413)
                        return b""
                    if size == 0:
                        # Consume optional trailer headers up to the blank line.
                        while True:
                            trailer = self.rfile.readline(65536)
                            if trailer in (b"\r\n", b"\n", b""):
                                break
                        return b"".join(chunks)
                    chunk = self.rfile.read(size)
                    if len(chunk) != size:
                        return b""
                    chunks.append(chunk)
                    total += size
                    # Every chunk is followed by CRLF (tolerate a bare LF).
                    # Read one byte first: reading two blindly would consume
                    # the first byte of the next chunk-size line after a bare
                    # LF, which some proxies emit.
                    ending = self.rfile.read(1)
                    if ending == b"\r":
                        if self.rfile.read(1) != b"\n":
                            return b""
                    elif ending != b"\n":
                        return b""

            def _send(
                self,
                status: int,
                body: bytes = b"",
                content_type: str = "application/xml",
                headers: "dict | None" = None,
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if body:
                    self.wfile.write(body)
                self.close_connection = True

            def _apply_fault(self, fault: Fault) -> None:
                if fault.delay:
                    time.sleep(fault.delay)
                if fault.reset:
                    try:
                        self.connection.setsockopt(
                            __import__("socket").SOL_SOCKET,
                            __import__("socket").SO_LINGER,
                            struct.pack("ii", 1, 0),
                        )
                    except OSError:
                        pass
                    self.close_connection = True
                    return
                if fault.drop:
                    self.close_connection = True
                    return
                if fault.truncate:
                    self.send_response(fault.status)
                    self.send_header("Content-Type", fault.content_type)
                    for key, value in fault.headers.items():
                        self.send_header(key, value)
                    self.send_header("Content-Length", str(len(fault.body) + fault.truncate))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(fault.body)
                    self.close_connection = True
                    return
                self._send(fault.status, fault.body, fault.content_type, fault.headers)

            def _record(self, method: str, path: str, body: bytes) -> None:
                ca.captured.append(
                    Captured(method, path, {k.lower(): v for k, v in self.headers.items()}, body)
                )

            def do_GET(self):
                path = urlsplit(self.path).path
                self._record("GET", path, b"")
                fault = ca.take_fault("GET", path)
                if fault is not None:
                    return self._apply_fault(fault)
                if ca.delay:
                    time.sleep(ca.delay)
                if path == "/pingservice":
                    # The live service returns XML; the client only checks for
                    # HTTP 200, but returning the real shape avoids surprising
                    # anyone reading the traffic.
                    return self._send(
                        200,
                        b"<?xml version=\"1.0\"?><pingservice><host>sandbox-ca</host></pingservice>",
                    )
                if path == "/CA":
                    return self._send(200, ca._ca_xml())
                if path == "/CA/motd/text":
                    return self._send(
                        200,
                        (
                            '<?xml version="1.0"?><CA><Motd><text>'
                            + _xml_escape(ca.motd)
                            + "</text></Motd></CA>"
                        ).encode(),
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
                fault = ca.take_fault("POST", path)
                if fault is not None:
                    return self._apply_fault(fault)
                if ca.delay:
                    time.sleep(ca.delay)
                if ca.reject_next:
                    status, payload = ca.reject_next.pop(0)
                    return self._send(status, payload)
                try:
                    if path == "/CSR":
                        # User CSRs are unauthenticated; CertificateRenew uses
                        # the same /CSR resource with the PPPK header and a
                        # <PublicKey> element.  Java's renewal endpoint is
                        # /CSR (not /CSRs), so dispatch on the header.
                        if self.headers.get("PPPK"):
                            return self._submit_bulk(body)
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
                if ca.require_email_match and not ca.email_in_csr(request, email):
                    return self._send(202, ca._error_xml("Email does not match the CSR SAN"))
                spki = _spki_b64(request.public_key())
                with ca.lock:
                    if spki in ca.csrs and ca.reject_duplicate:
                        return self._send(202, ca._error_xml("this public key has already been submitted"))
                    ca.next_csr_id += 1
                    record = CSRRecord(ca.next_csr_id, request, email, pin_hash=pin)
                    record.status = ca.new_csr_status
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
                if kind == "renew" and ca.require_email_match and not ca.email_in_csr(request, email):
                    return self._send(202, ca._error_xml("Email does not match the CSR SAN"))

                auth_cert = ca._find_auth_cert(
                    self.headers.get("serial"), public_key or None, self.headers.get("id")
                )
                if auth_cert is None:
                    return self._send(403, ca._error_xml("no matching client certificate"))
                key = auth_cert.public_key()
                if not isinstance(key, rsa.RSAPublicKey):
                    return self._send(403, ca._error_xml("client certificate must be RSA"))

                mode = ca.pppk_mode
                realm = "mock-realm"
                nonce = "Tm9uY2UtMTIzNDU2Nzg5MA=="
                if mode == "no_challenge":
                    return self._accept_csr(request, pin, email, kind)
                if mode == "opaque":
                    if not self.headers.get("opaque"):
                        body_out = ca._error_xml("authentication required")
                        self.send_response(401)
                        self.send_header("Content-Type", "application/xml")
                        self.send_header("opaque", "mock-opaque-cookie")
                        self.send_header("Content-Length", str(len(body_out)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(body_out)
                        self.close_connection = True
                        return None
                    return self._accept_csr(request, pin, email, kind)
                if mode == "bad_keyid":
                    other = ca.server_key.public_key()
                    keyid = f"{other.public_numbers().n:x}.{other.public_numbers().e:x}"
                else:
                    keyid = f"{key.public_numbers().n:x}.{key.public_numbers().e:x}"
                if not self.headers.get("response"):
                    body_out = ca._error_xml("authentication required")
                    self.send_response(401)
                    self.send_header("Content-Type", "application/xml")
                    self.send_header("realm", realm)
                    self.send_header("nonce", nonce)
                    self.send_header("keyid", keyid)
                    self.send_header("Content-Length", str(len(body_out)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body_out)
                    self.close_connection = True
                    return None
                if mode == "bad_response":
                    return self._send(403, ca._error_xml("PPPK verification failed: injected"))
                ok, problem = ca._verify_pppk(
                    auth_cert, {k.lower(): v for k, v in self.headers.items()}, nonce
                )
                if not ok:
                    return self._send(403, ca._error_xml(f"PPPK verification failed: {problem}"))
                return self._accept_csr(request, pin, email, kind)

            def _accept_csr(self, request, pin, email, kind):
                spki = _spki_b64(request.public_key())
                with ca.lock:
                    if spki in ca.csrs and ca.reject_duplicate:
                        return self._send(202, ca._error_xml("this public key has already been submitted"))
                    ca.next_csr_id += 1
                    record = CSRRecord(ca.next_csr_id, request, email, pin_hash=pin, kind=kind)
                    record.status = "RENEW" if kind == "renew" else ca.new_csr_status
                    ca.csrs[spki] = record
                    if ca.auto_approve and ca.sign_after_polls <= 0:
                        ca._sign_csr(record)
                return self._send(201, b"")

            def _lookup(self, body: bytes):
                root = ET.fromstring(body)
                if root.tag != "PublicKey":
                    return self._send(400, ca._error_xml("expected PublicKey"))
                spki = (root.text or "").strip()
                mode = ca.lookup_mode
                if mode == "malformed":
                    return self._send(200, b"<resources><resource><certificates>")
                if mode == "empty_200":
                    return self._send(200, b"<resources/>")
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
                    if mode == "csr_only":
                        cert_record = None
                    parts = ["<resources><resource>"]
                    parts.append(f"<publickey>{spki}</publickey>")
                    if cert_record is not None:
                        include_inline = mode not in ("no_inline", "no_id")
                        include_id = mode != "no_id"
                        certificate_pem = _pem(cert_record.cert)
                        if mode == "wrong_pem":
                            certificate_pem = _pem(ca.server_cert)
                        status = "BANANA" if mode == "bad_status" else cert_record.status
                        block = ["<certificate>"]
                        if include_id:
                            block.append(f"<id>{cert_record.id}</id>")
                        block.append(f"<status>{status}</status>")
                        block.append("<owner>" + certs.name_to_string(cert_record.cert.subject) + "</owner>")
                        block.append("<role>RA Operator</role>")
                        block.append(f"<useremail>{record.email}</useremail>")
                        block.append(
                            "<startdate>"
                            + not_valid_before(cert_record.cert).strftime("%d/%m/%Y")
                            + "</startdate>"
                        )
                        block.append(
                            "<enddate>"
                            + not_valid_after(cert_record.cert).strftime("%d/%m/%Y")
                            + "</enddate>"
                        )
                        block.append("<lifedays>365</lifedays>")
                        block.append(
                            "<renew>" + not_valid_after(cert_record.cert).strftime("%d/%m/%Y") + "</renew>"
                        )
                        if include_inline:
                            block.append("<X509Certificate>" + certificate_pem + "</X509Certificate>")
                        block.append("</certificate>")
                        parts.append("<certificates>")
                        if mode == "multiple":
                            parts.append(
                                "<certificate><id>1</id><status>VALID</status><X509Certificate>"
                                + _pem(ca.root)
                                + "</X509Certificate></certificate>"
                            )
                        parts.append("".join(block))
                        parts.append("</certificates>")
                    else:
                        status = record.status
                        if mode == "csr_approved":
                            status = "APPROVED"
                        elif mode == "csr_deleted":
                            status = "DELETED"
                        elif mode == "csr_unknown":
                            status = "SOMETHING_NEW"
                        parts.append("<CSRs><CSR>")
                        parts.append(f"<id>{record.id}</id>")
                        parts.append(f"<status>{status}</status>")
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
                mode = ca.download_mode
                if mode == "bare_pem":
                    return self._send(200, _pem(record.cert).encode(), "application/x-pem-file")
                if mode == "bare_der":
                    return self._send(200, _der_cert(record.cert), "application/pkix-cert")
                if mode == "xml_no_cert":
                    return self._send(200, b"<certificate><id>%d</id></certificate>" % record.id)
                if mode == "malformed":
                    return self._send(200, b"<certificate><X509Certificate>not a cert")
                if mode == "wrong_cert":
                    return self._send(
                        200,
                        b"<certificate><X509Certificate>"
                        + _pem(ca.server_cert).encode()
                        + b"</X509Certificate></certificate>",
                    )
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
                mode = ca.pppk_mode
                if mode == "no_challenge":
                    with ca.lock:
                        record.status = "REVOKED"
                        record.revoke_reason = reason
                    return self._send(201, b"")
                if mode == "opaque":
                    if not self.headers.get("opaque"):
                        out = ca._error_xml("authentication required")
                        self.send_response(401)
                        self.send_header("Content-Type", "application/xml")
                        self.send_header("opaque", "mock-opaque-cookie")
                        self.send_header("Content-Length", str(len(out)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(out)
                        self.close_connection = True
                        return None
                    with ca.lock:
                        record.status = "REVOKED"
                        record.revoke_reason = reason
                    return self._send(201, b"")
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
                if mode == "bad_response":
                    return self._send(403, ca._error_xml("PPPK verification failed: injected"))
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
        mode = self.info_mode
        if mode == "bad_xml":
            return b"<CA><RAlist>"
        if mode == "empty":
            return b"<CA><certificates></certificates><RAlist></RAlist></CA>"
        cert_text = _pem(self.root)
        if mode == "malformed_cert":
            cert_text = "not a certificate"
        parts = ["<CA><certificates>", "<certificate>" + cert_text + "</certificate>"]
        if mode != "one_cert":
            parts.append("<certificate>" + _pem(self.intermediate) + "</certificate>")
        parts.append("</certificates><RAlist>")
        if mode == "huge_ra":
            for index in range(500):
                parts.append("<ra><ou>CLRC</ou><l>RA%d</l><operator><id>1</id></operator></ra>" % index)
            preferred = "RA0"
        else:
            parts.append("<ra><ou>CLRC</ou><l>DL</l><operator><id>1</id></operator></ra>")
            parts.append("<ra><ou>CLRC</ou><l>RAL</l><operator><id>2</id></operator></ra>")
            preferred = "DL"
        parts.append("</RAlist>")
        if mode != "no_preferred":
            parts.append("<PreferredRA><ra><ou>CLRC</ou><l>%s</l></ra></PreferredRA>" % preferred)
        if mode != "no_policy":
            parts.append(
                "<Policy><MaxExpiredRekey>30</MaxExpiredRekey><MaxPrivateKeyLifeTime>365</MaxPrivateKeyLifeTime></Policy>"
            )
        if mode != "no_motd":
            parts.append("<motd><text>" + _xml_escape(self.motd) + "</text></motd>")
        if mode != "no_version":
            # CAMotd.getLatestVersion() looks for this exact element.  Keep it
            # equal to the configured client version so the GUI does not warn
            # about an update in the sandbox.
            parts.append("<certWizard><latestVersion>2.2.1</latestVersion></certWizard>")
        parts.append("</CA>")
        return "".join(parts).encode()
