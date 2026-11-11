"""Branch coverage for CA response parsing, revocation, diagnostics and the transport.

The mock CA serves the unusual documents through ``fail_next(..., status=200)``,
so every response still travels over the real TLS connection.
"""

import errno
import socket
import time
from types import SimpleNamespace

import pytest

from pycert import certs, diagnostics, workflow
from pycert.errors import NetworkError
from pycert.store import STATUS_REVOKED
from pycert.transport import Transport, TransportConfig, TransportError, _Deadline, _errno_name

LOOKUP_PATH = "/resources/resource/publickey/pk"


def _names(results):
    return {result.name: result.status for result in results}


# ---------------------------------------------------------------------------
# ca.py
# ---------------------------------------------------------------------------


def test_info_skips_incomplete_ras_and_empty_preferred_sections(ctx, ca):
    ca.fail_next(
        "/CA",
        method="GET",
        status=200,
        body=(
            b"<CA><RAlist>"
            b"<ra><ou>CLRC</ou><l>DL</l></ra>"
            b"<ra><ou>NoLocality</ou></ra>"
            b"<ra><l>NoOU</l></ra>"
            b"</RAlist><PreferredRA></PreferredRA></CA>"
        ),
    )
    info = ctx.client().info()
    assert [(ra.ou, ra.l) for ra in info.ras] == [("CLRC", "DL")]
    assert info.preferred_ra is None
    ca.fail_next(
        "/CA", method="GET", status=200, body=b"<CA><RAlist/><PreferredRA><ra><ou>CLRC</ou></ra></PreferredRA></CA>"
    )
    info = ctx.client().info()
    assert info.ras == [] and info.preferred_ra is None


def test_motd_xml_without_text_falls_back_to_the_raw_body(ctx, ca):
    body = b"<CA><Motd><text/><text></text></Motd></CA>"
    ca.fail_next("/CA/motd/text", method="GET", status=200, body=body)
    assert ctx.client().motd() == body.decode()


def test_lookup_ignores_entries_without_id_or_status(ctx, ca):
    ca.fail_next(
        LOOKUP_PATH,
        method="POST",
        status=200,
        body=(
            b"<resources>"
            b"<certificate><owner>nobody</owner></certificate>"
            b"<certificate><id>5001</id><status>VALID</status></certificate>"
            b"<CSR><owner>nobody</owner></CSR>"
            b"<CSR><id>1001</id><status>NEW</status></CSR>"
            b"</resources>"
        ),
    )
    lookup = ctx.client().lookup_public_key("AAAA")
    assert [c.id for c in lookup.certificates] == ["5001"]
    assert [c.id for c in lookup.csrs] == ["1001"]


def test_download_skips_empty_certificate_elements(ctx, ca):
    pem = certs.cert_pem(ca.intermediate).encode()
    ca.fail_next(
        "/certificate/5000",
        method="GET",
        status=200,
        body=b"<certificate><X509Certificate>  </X509Certificate><X509Certificate>" + pem + b"</X509Certificate></certificate>",
    )
    assert ctx.client().download_certificate("5000") == ca.intermediate


# ---------------------------------------------------------------------------
# workflow.revoke: the certificate id is looked up first when it is missing
# ---------------------------------------------------------------------------


def test_revoke_looks_up_a_missing_certificate_id(ctx, ca, issued):
    user = issued("revoke lookup person")
    cert_id = user.server.cert_id
    assert cert_id
    with ctx.store.lock(user):
        state = ctx.store.get(user.alias)
        state.server.cert_id = ""
        ctx.store.save(state)
    messages = []
    revoked = workflow.revoke(ctx, user.alias, "unspecified", progress=messages.append)
    assert revoked.status == STATUS_REVOKED
    assert revoked.server.cert_id == cert_id
    assert "Looking up the certificate id..." in messages
    assert ca.certificates[int(cert_id)].status == "REVOKED"


# ---------------------------------------------------------------------------
# diagnostics
# ---------------------------------------------------------------------------


def test_doctor_with_a_non_file_secret_backend(ctx, monkeypatch):
    monkeypatch.setattr(ctx.secrets, "backend", "env")
    monkeypatch.setattr(ctx.secrets, "exists", lambda _account: True)
    results = _names(diagnostics.run_doctor(ctx, offline=True))
    assert "secret file" not in results
    assert results["saved secret"] == diagnostics.OK


def test_doctor_tls_peer_without_a_recorded_certificate(ctx, monkeypatch):
    client = SimpleNamespace(
        last_error="",
        ping=lambda: True,
        info=lambda: SimpleNamespace(ras=[]),
        last_tls=SimpleNamespace(not_after=SimpleNamespace(date=lambda: "2030-01-01"), subject="CN=peer"),
        transport=SimpleNamespace(clock_offset=0, last_peer_certificate=b"", _default_resolve=lambda *a: []),
    )
    monkeypatch.setattr(ctx, "client", lambda: client)
    results = _names(diagnostics.run_doctor(ctx, offline=False))
    assert results["TLS peer"] == diagnostics.OK
    assert "TLS chain" not in results


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


def test_socket_creation_failure_tries_every_address():
    transport = Transport(TransportConfig(allow_plaintext=True, retries=0, connect_timeout=2, deadline=5))
    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 1, 0, 0)),
    ]
    transport._resolver = lambda *a: addresses
    attempts = []

    def no_sockets(family, socktype, proto):
        attempts.append(family)
        raise OSError(errno.EMFILE, "Too many open files")

    transport._socket_factory = no_sockets
    with pytest.raises(TransportError, match="EMFILE") as caught:
        transport._open_socket("example.org", 1, _Deadline(5, time.monotonic), None)
    assert attempts == [socket.AF_INET, socket.AF_INET6]
    assert isinstance(caught.value, NetworkError)


def test_errno_name_with_an_unknown_code():
    assert _errno_name(OSError(987654, "platform specific")) == "[Errno 987654] platform specific"
    assert _errno_name(OSError("no errno")) == "no errno"
