"""Diagnostics: ``pycert doctor`` and ``pycert selftest``.

``doctor`` checks a real installation: configuration pins, chain expiry, file
permissions, the secret backend, DNS, TLS, the CA's clock and the network policy.
It never changes anything.

``selftest`` runs offline cryptographic and parser self-checks.  It is useful on
a new machine, after an upgrade, and in CI.
"""

import os
import stat
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, bundled, certs, chain
from . import csr as csr_module
from . import p12 as p12_module
from .compat import dataclass

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""

    @property
    def failed(self):
        return self.status == FAIL

    def as_dict(self):
        return {"check": self.name, "status": self.status, "detail": self.detail}


def _result(name, status, detail=""):
    return Check(name, status, detail)


def run_doctor(ctx, *, offline=False):
    """Return a list of :class:`Check` results for the configured installation."""
    results = []
    config = ctx.config
    results.append(_result("pyCert version", OK, __version__))
    results.append(_result("Python", OK, "%d.%d.%d" % tuple(sys.version_info[:3])))
    try:
        import cryptography

        results.append(_result("cryptography", OK, cryptography.__version__))
        if sys.version_info[:2] == (3, 6):
            results.append(
                _result(
                    "Python 3.6 support",
                    WARN,
                    "3.6 is end-of-life and caps cryptography at 3.3.x; prefer a newer Python",
                )
            )
    except Exception as exc:  # noqa: BLE001
        results.append(_result("cryptography", FAIL, str(exc)))

    # Configuration and chain -------------------------------------------------
    try:
        bundle = config.bundle
        results.append(
            _result(
                "CA chain",
                OK,
                "%d certificates, %d trust anchors, pins verified"
                % (len(bundle.certificates), len(bundle.anchors)),
            )
        )
        if not bundle.anchors:
            results.append(_result("trust anchors", FAIL, "no anchor certificates configured"))
        expired = [
            certs.name_to_string(c.subject) for c in bundle.certificates if not certs.certificate_valid_at(c)
        ]
        if expired:
            results.append(_result("CA certificate validity", FAIL, "; ".join(expired)))
        else:
            results.append(_result("CA certificate validity", OK, "all certificates are in date"))
        if not all(entry.sha256 for entry in config.chain):
            results.append(_result("chain pins", WARN, "some chain entries are not pinned"))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("CA chain", FAIL, str(exc)))

    for warning in config.warnings:
        results.append(_result("configuration warning", WARN, warning))
    if not config.ca.tls_verify:
        results.append(_result("TLS verification", FAIL, "ca.tls_verify is disabled"))
    if config.ca.allow_plaintext:
        results.append(_result("plaintext HTTP", FAIL, "ca.allow_plaintext is enabled"))
    if config.csr.pin_hash != "sha1":
        results.append(_result("PIN hash", WARN, "the current CA expects SHA-1 PIN hashes"))

    # Files and secrets -------------------------------------------------------
    try:
        mode = stat.S_IMODE(config.data_dir.stat().st_mode)
        if mode & 0o077:
            results.append(_result("data directory", FAIL, "mode %s (expected 0700)" % oct(mode)))
        else:
            results.append(_result("data directory", OK, "%s (0700)" % config.data_dir))
    except OSError as exc:
        results.append(_result("data directory", FAIL, str(exc)))
    audit = ctx.store.audit()
    if audit:
        results.append(_result("file permissions", FAIL, "; ".join(audit[:5])))
    else:
        results.append(_result("file permissions", OK, "no world/group-readable files"))

    try:
        if ctx.secrets.exists(config.secrets.account):
            results.append(_result("saved secret", OK, str(ctx.secrets)))
        else:
            results.append(
                _result(
                    "saved secret",
                    WARN,
                    "no secret stored in %s (run 'pycert secret set')" % ctx.secrets,
                )
            )
    except Exception as exc:  # noqa: BLE001
        results.append(_result("saved secret", FAIL, str(exc)))

    for variable in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(variable):
            results.append(
                _result("proxy environment", WARN, "%s is set but pyCert does not use proxies" % variable)
            )
            break

    if offline:
        results.append(_result("network", WARN, "skipped (--offline)"))
        return results

    # Network ----------------------------------------------------------------
    client = ctx.client()
    started = time.time()
    if not client.ping():
        results.append(_result("CA connectivity", FAIL, client.last_error or "no response"))
        return results
    results.append(_result("CA connectivity", OK, "%.0f ms" % ((time.time() - started) * 1000)))
    try:
        info = client.info()
        results.append(_result("CA info", OK, "%d RAs" % len(info.ras)))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("CA info", FAIL, str(exc)))

    if client.last_tls is not None:
        results.append(
            _result(
                "TLS peer",
                OK,
                "%s (expires %s)" % (client.last_tls.subject, client.last_tls.not_after.date()),
            )
        )
        der = client.transport.last_peer_certificate
        if der:
            try:
                from cryptography import x509

                leaf = x509.load_der_x509_certificate(der)
                outcome = ctx.build_chain(leaf)
                if outcome.trusted:
                    results.append(_result("TLS chain", OK, "%d certificates" % len(outcome.chain)))
                else:
                    results.append(_result("TLS chain", FAIL, "; ".join(outcome.problems) or "not trusted"))
            except Exception as exc:  # noqa: BLE001
                results.append(_result("TLS chain", FAIL, str(exc)))
    offset = client.transport.clock_offset
    if abs(offset) > 120:
        results.append(
            _result(
                "clock skew",
                WARN,
                "the CA server clock differs from this host by %.0f seconds; PPPK may fail" % offset,
            )
        )
    else:
        results.append(_result("clock skew", OK, "%.0f seconds" % offset))

    parts = urlsplit(config.ca.base_url)
    try:
        addresses = client.transport._default_resolve(
            parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), 5.0
        )
        results.append(_result("DNS", OK, "%d address(es) for %s" % (len(addresses), parts.hostname)))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("DNS", FAIL, str(exc)))
    return results


def run_selftest():
    """Offline checks of the cryptographic and parsing paths."""
    from cryptography.hazmat.primitives.asymmetric import ec

    results = []

    # TOML parser ------------------------------------------------------------
    try:
        from .toml import loads

        doc = 'a = 1\n[t]\nb = ["x", true]\n'
        assert loads(doc) == {"a": 1, "t": {"b": ["x", True]}}
        results.append(_result("TOML parser", OK, "round-trip"))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("TOML parser", FAIL, str(exc)))

    # CSR signing and verification ------------------------------------------
    try:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = certs.build_subject(
            common_name="selftest",
            organization="eScience",
            organizational_unit="CLRC",
            locality="DL",
            country="UK",
        )
        request = csr_module.build_csr(key, subject, email="selftest@example.org")
        assert csr_module.signature_valid(request)
        results.append(_result("key generation and CSR", OK, "ECDSA P-256"))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("key generation and CSR", FAIL, str(exc)))

    # PKCS#12 ----------------------------------------------------------------
    try:
        import datetime as _dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        now = _dt.datetime.now(_dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selftest")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selftest.p12"
            p12_module.write_pkcs12(path, key=key, certificate=cert, chain=[], password="selftest-password")
            bundle = p12_module.read_pkcs12(path, "selftest-password")
            assert certs.fingerprint(bundle.cert) == certs.fingerprint(cert)
        results.append(_result("PKCS#12", OK, "write/read"))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("PKCS#12", FAIL, str(exc)))

    # Bundled chain ----------------------------------------------------------
    try:
        certs_list = bundled.certificates()
        anchor = certs_list[1] if len(certs_list) > 1 else certs_list[0]
        outcome = chain.build_chain(anchor, anchors=certs_list, extra=certs_list)
        if not outcome.trusted:
            raise RuntimeError("; ".join(outcome.problems) or "not trusted")
        results.append(_result("bundled CA chain", OK, "%d certificates" % len(certs_list)))
    except Exception as exc:  # noqa: BLE001
        results.append(_result("bundled CA chain", FAIL, str(exc)))
    return results
