"""Coverage-oriented tests for CA response parsing and PPPK helpers."""

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pycert import ca as ca_module
from pycert import csr as csr_module
from pycert.ca import ServerCertificate, Submission, b64_spki, pppk_response
from pycert.config import CAConfig
from pycert.errors import CryptoError, NetworkError, ProtocolError


def test_submission_and_server_certificate():
    assert Submission(True, 201, "ok").as_dict()["success"] is True
    assert ServerCertificate().certificate() is None
    assert ServerCertificate(pem="bad").certificate() is None


def test_ca_client_rejects_bad_scheme():
    with pytest.raises(NetworkError):
        ca_module.CAClient(SimpleNamespace(ca=CAConfig(base_url="ftp://example.org")))


def test_pppk_errors_and_helpers():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(CryptoError):
        pppk_response(ec.generate_private_key(ec.SECP256R1()), "r", "n", "1.1")
    with pytest.raises(ProtocolError):
        pppk_response(key, "r", "n", "no-dot")
    with pytest.raises(ProtocolError):
        pppk_response(key, "r", "n", "zz.1")
    with pytest.raises(CryptoError):
        pppk_response(key, "r", "n", "1.1")
    assert b64_spki(key.public_key())


def test_client_authenticated_rejection_and_download_fallback(ctx, ca, issued):
    state = issued("ca fallback")
    cert = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    ca.download_mode = "bare_pem"
    downloaded = ctx.client().download_certificate(str(state.server.cert_id))
    assert downloaded == cert
    ca.pppk_mode = "no_challenge"
    ca.reject_next = [(202, ca._error_xml("rejected by test"))]
    submission = ctx.client().submit_authenticated(
        csr_pem=csr_module.csr_pem(ctx.store.load_csr(state)),
        pin_hash="A" * 40,
        email="x@example.org",
        auth_cert=cert,
        auth_key=key,
        host_request=False,
        public_key="1.1",
    )
    assert submission.success is False and submission.status == 202


def test_info_accepts_a_good_ca_document(ctx, ca):
    ca.info_mode = "normal"
    info = ctx.client().info()
    assert info.certificates


def test_peer_info_exception_is_ignored(ctx, ca, monkeypatch):
    client = ctx.client()
    monkeypatch.setattr(client, "_peer_info", lambda der: (_ for _ in ()).throw(RuntimeError("bad")))
    monkeypatch.setattr(client.transport, "last_peer_certificate", b"der")
    assert client.last_tls is None
