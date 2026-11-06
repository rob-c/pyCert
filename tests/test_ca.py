import datetime as dt

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pycert import ca as ca_module
from pycert import certs
from pycert import csr as csr_module
from pycert.ca import CAClient, pppk_response
from pycert.errors import CAError, CryptoError, NetworkError, ProtocolError


def test_ping_and_headers(ctx, ca):
    client = ctx.client()
    assert client.ping() is True
    captured = ca.captured[-1]
    assert captured.path == "/pingservice"
    assert captured.headers.get("localhost")
    assert captured.headers.get("user-agent", "").startswith("pyCert")
    assert client.last_tls is not None
    assert "localhost" in client.last_tls.subject
    assert client.last_tls.fingerprint.count(":") == 31


def test_ca_info(ctx):
    info = ctx.client().info()
    assert [ra.label for ra in info.ras] == ["CLRC DL", "CLRC RAL"]
    assert info.preferred_ra.label == "CLRC DL"
    assert info.policy["MaxPrivateKeyLifeTime"] == "365"
    assert len(info.certificates) == 2
    assert info.certificates[0].subject == info.certificates[0].issuer


def test_motd_extracts_text(ctx):
    assert ctx.client().motd() == "mock CA says hello"


def test_submit_csr_success(ctx, config, ca):
    ca.auto_approve = False
    key = rsa.generate_private_key(65537, 2048)
    subject = certs.build_subject(
        common_name="jane doe",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    request = csr_module.build_csr(key, subject, email="jane@example.org")
    submission = ctx.client().submit_csr(csr_module.csr_pem(request), "A" * 40, "jane@example.org")
    assert submission.success and submission.status == 201
    lookup = ctx.client().lookup_public_key(certs.spki_b64(key.public_key()))
    assert lookup.csrs and lookup.csrs[-1].status == "NEW"


def test_submit_invalid_pin_is_rejected_with_server_message(ctx):
    key = rsa.generate_private_key(65537, 2048)
    subject = certs.build_subject(
        common_name="jane doe",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    request = csr_module.build_csr(key, subject, email="jane@example.org")
    submission = ctx.client().submit_csr(csr_module.csr_pem(request), "not-a-hash", "jane@example.org")
    assert submission.success is False
    assert submission.status == 202
    assert "SHA-1" in submission.detail


def test_submit_duplicate_is_rejected(ctx):
    key = rsa.generate_private_key(65537, 2048)
    subject = certs.build_subject(
        common_name="jane doe",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    request = csr_module.build_csr(key, subject, email="jane@example.org")
    client = ctx.client()
    assert client.submit_csr(csr_module.csr_pem(request), "A" * 40, "jane@example.org").success
    second = client.submit_csr(csr_module.csr_pem(request), "A" * 40, "jane@example.org")
    assert not second.success
    assert "already been submitted" in second.detail


def test_lookup_by_unknown_key_returns_empty(ctx):
    lookup = ctx.client().lookup_public_key("bm90IGEga2V5")
    assert lookup.certificates == [] and lookup.csrs == []


def test_status_transitions_and_download(ctx, ca):
    ca.auto_approve = False
    key = rsa.generate_private_key(65537, 2048)
    subject = certs.build_subject(
        common_name="jane doe",
        organization="eScience",
        organizational_unit="CLRC",
        locality="DL",
        country="UK",
    )
    request = csr_module.build_csr(key, subject, email="jane@example.org")
    client = ctx.client()
    client.submit_csr(csr_module.csr_pem(request), "A" * 40, "jane@example.org")
    spki = certs.spki_b64(key.public_key())
    assert client.lookup_public_key(spki).latest_csr.status == "NEW"
    ca.approve_all()
    assert client.lookup_public_key(spki).latest_csr.status == "APPROVED"
    ca.sign_all()
    lookup = client.lookup_public_key(spki)
    entry = lookup.latest_certificate
    assert entry.status == "VALID" and entry.id
    inline = entry.certificate()
    assert inline is not None
    downloaded = client.download_certificate(entry.id)
    assert certs.fingerprint(downloaded) == certs.fingerprint(inline)
    assert downloaded.public_key().public_numbers() == key.public_key().public_numbers()


def test_download_rejects_suspicious_id(ctx):
    with pytest.raises(ProtocolError):
        ctx.client().download_certificate("../../etc/passwd")


def test_missing_certificate_raises(ctx):
    with pytest.raises(CAError) as exc:
        ctx.client().download_certificate("424242")
    assert exc.value.status == 404
    assert "not found" in str(exc.value).lower()


def test_pppk_response_verifies_with_public_key():
    key = rsa.generate_private_key(65537, 2048)
    numbers = key.public_key().public_numbers()
    keyid = f"{numbers.n:x}.{numbers.e:x}"
    nonce = "Tm9uY2UtMTIzNDU2Nzg5MA=="
    stamp = int(dt.datetime.now(dt.UTC).timestamp() * 1000)
    response = pppk_response(key, "realm", nonce, keyid, timestamp_ms=stamp)
    recovered = pow(int(response, 16), numbers.e, numbers.n)
    hexdigits = format(recovered, "x")
    if len(hexdigits) % 2:
        hexdigits = "0" + hexdigits
    assert bytes.fromhex(hexdigits).decode() == f"{nonce.lower()}:{stamp}"


def test_pppk_rejects_mismatched_key():
    key = rsa.generate_private_key(65537, 2048)
    other = rsa.generate_private_key(65537, 2048)
    keyid = f"{other.public_key().public_numbers().n:x}.{other.public_key().public_numbers().e:x}"
    with pytest.raises(CryptoError, match="different key"):
        pppk_response(key, "realm", "nonce", keyid)


def test_pppk_requires_rsa():
    from cryptography.hazmat.primitives.asymmetric import ec

    with pytest.raises(CryptoError):
        pppk_response(ec.generate_private_key(ec.SECP256R1()), "r", "n", "a.b")


def test_authenticated_submission_and_revocation(ctx, issued, ca):
    state = issued()
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    # renewal-style request authenticated by the current certificate
    new_key = rsa.generate_private_key(65537, 2048)
    subject = certificate.subject
    request = csr_module.build_csr(new_key, subject, email=state.email)
    submission = ctx.client().submit_authenticated(
        csr_pem=csr_module.csr_pem(request),
        pin_hash="B" * 40,
        email=state.email,
        auth_cert=certificate,
        auth_key=key,
        public_key=f"{certificate.public_key().public_numbers().n:x}.{certificate.public_key().public_numbers().e:x}",
    )
    assert submission.success, submission
    revoke = ctx.client().revoke(state.server.cert_id, "superseded", certificate, key)
    assert revoke.success
    assert ca.certificates[int(state.server.cert_id)].status == "REVOKED"


def test_authenticated_submission_with_wrong_key_is_rejected(ctx, issued):
    state = issued()
    certificate = ctx.store.load_certificate(state)
    wrong_key = rsa.generate_private_key(65537, 2048)
    new_key = rsa.generate_private_key(65537, 2048)
    request = csr_module.build_csr(new_key, certificate.subject, email=state.email)
    with pytest.raises(CAError) as exc:
        ctx.client().submit_authenticated(
            csr_pem=csr_module.csr_pem(request),
            pin_hash="B" * 40,
            email=state.email,
            auth_cert=certificate,
            auth_key=wrong_key,
            public_key=f"{wrong_key.public_key().public_numbers().n:x}.{wrong_key.public_key().public_numbers().e:x}",
        )
    assert exc.value.status == 403


def test_revoke_rejects_unknown_reason(ctx, issued):
    state = issued()
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    with pytest.raises(CAError, match="unknown revocation reason"):
        ctx.client().revoke(state.server.cert_id, "because", certificate, key)


def test_tls_pinning(ctx, config, ca):
    from pycert.errors import NetworkError

    client = ctx.client()
    assert client.ping()
    real_fingerprint = client.last_tls.fingerprint
    assert real_fingerprint == certs.formatted_fingerprint(ca.server_cert)
    config.ca.tls_pin_sha256 = [real_fingerprint]
    assert ctx.client().ping() is True
    config.ca.tls_pin_sha256 = ["00" * 32]
    with pytest.raises(NetworkError, match="pin mismatch"):
        ctx.client().request("GET", config.ca.url("ping"))
    unreachable = ctx.client()
    assert unreachable.ping() is False
    assert "pin mismatch" in unreachable.last_error


def test_plaintext_http_is_refused(config):
    config.ca.base_url = "http://127.0.0.1:9"
    config.ca.allow_plaintext = False
    with pytest.raises(NetworkError, match="plaintext"):
        CAClient(config)


def test_plaintext_http_opt_in_works(config, ca):
    config.ca.base_url = ca.plain_url
    config.ca.allow_plaintext = True
    client = CAClient(config)
    assert client.ping() is True


def test_doctype_is_rejected(ctx, ca):
    ca.reject_next = [(200, b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "b">]><resources>&a;</resources>')]
    with pytest.raises(ProtocolError, match="DOCTYPE"):
        ctx.client().lookup_public_key("x")


def test_doctype_after_a_long_comment_is_rejected(ctx, ca):
    padding = b"<!-- " + b"x" * 8000 + b" -->"
    ca.reject_next = [
        (200, b'<?xml version="1.0"?>' + padding + b'<!DOCTYPE r [<!ENTITY a "b">]><resources/>')
    ]
    with pytest.raises(ProtocolError, match="DOCTYPE"):
        ctx.client().lookup_public_key("x")


def test_oversized_response_is_refused(ctx, ca, monkeypatch):
    monkeypatch.setattr(ca_module, "MAX_RESPONSE_BYTES", 100)
    ca.reject_next = [(200, b"x" * 500)]
    with pytest.raises(ProtocolError, match="exceeds"):
        ctx.client().lookup_public_key("x")


def test_http_500_maps_to_ca_error(ctx, ca):
    ca.reject_next = [(500, b"<Response><minor><text>boom</text></minor></Response>")]
    with pytest.raises(CAError) as exc:
        ctx.client().lookup_public_key("x")
    assert exc.value.status == 500
    assert "boom" in exc.value.detail


def test_unknown_endpoint_is_reported(ctx, config):
    config.ca.endpoints.ping = "/nope"
    client = CAClient(config)
    assert client.ping() is False
    config.ca.endpoints.info = "/nope"
    with pytest.raises(CAError) as exc:
        CAClient(config).info()
    assert "endpoint not found" in str(exc.value)
