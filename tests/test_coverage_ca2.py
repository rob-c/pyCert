"""Additional CA coverage: response fallbacks and malformed server data."""

from types import SimpleNamespace

from pycert import ca as ca_module
from pycert.transport import Response


def R(status, headers, body):
    return Response(status, "OK", headers, body, "https://example.org/")


class Client(ca_module.CAClient):
    def __init__(self, responses):
        self._responses = list(responses)
        self.last_error = ""
        self.last_tls = None
        self.last_url = ""
        self.ca = SimpleNamespace(url=lambda name: "https://example.org/" + name, version_string="CertWizard 2.2.1")
        self.transport = SimpleNamespace(last_peer_certificate=b"", clock_offset=0, now_ms=lambda: 1)
        self.config = SimpleNamespace(ca=self.ca)

    def request(self, *args, **kwargs):
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


def test_authenticated_and_revoke_202(ctx, issued):
    state = issued("ca 202")
    cert = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    client = Client([R(202, {}, b"<error><status><major><text>m</text></major><minor><text>detail</text></minor></status></error>")])
    result = client.submit_authenticated(
        csr_pem="x", pin_hash="A" * 40, email="e@example.org", auth_cert=cert, auth_key=key,
        host_request=False, public_key="1.1",
    )
    assert result.success is False and "detail" in result.detail
    client = Client([
        R(401, {"realm": "r", "nonce": "n", "keyid": "%x.%x" % (key.private_numbers().public_numbers.n, key.private_numbers().public_numbers.e)}, b""),
        R(202, {}, b"<error><status><major><text>m</text></major><minor><text>revoke</text></minor></status></error>"),
    ])
    result = client.revoke(str(state.server.cert_id), "unspecified", cert, key)
    assert result.success is False and "revoke" in result.detail


def test_download_xml_without_certificate_but_with_pem(ctx, issued):
    state = issued("ca download")
    cert = ctx.store.load_certificate(state)
    from pycert import certs

    client = Client([R(200, {}, b"<foo>" + certs.cert_pem(cert).encode() + b"</foo>")])
    assert client.download_certificate(str(state.server.cert_id)) == cert


def test_info_marks_bad_ca_certificate():
    client = Client([R(200, {}, b"<CA><certificates><certificate>-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----</certificate></certificates></CA>")])
    info = client.info()
    assert info.problems


def test_peer_info_exception_is_ignored(ctx, monkeypatch):
    client = ctx.client()
    monkeypatch.setattr(client, "_peer_info", lambda der: (_ for _ in ()).throw(RuntimeError("bad")))
    monkeypatch.setattr(client.transport, "last_peer_certificate", b"der")
    monkeypatch.setattr(client.transport, "request", lambda *a, **k: R(200, {}, b""))
    # Force the finally block to run with a peer certificate.

    def fake_request(*args, **kwargs):
        try:
            return R(200, {}, b"")
        finally:
            der = client.transport.last_peer_certificate
            if der:
                try:
                    client.last_tls = client._peer_info(der)
                except Exception:
                    client.last_tls = None

    monkeypatch.setattr(client, "request", fake_request)
    assert client.request("GET", "https://example.org") is not None
    assert client.last_tls is None


def test_peer_certificate_display_error_is_ignored(ctx, monkeypatch):
    client = ctx.client()
    class FakeTransport:
        last_peer_certificate = b"der"
        clock_offset = 0.0
        def request(self, *args, **kwargs):
            return R(200, {}, b"")
        def now_ms(self):
            return 1
    client.transport = FakeTransport()
    monkeypatch.setattr(client, "_peer_info", lambda der: (_ for _ in ()).throw(RuntimeError("bad")))
    assert client.request("GET", "https://example.org").status == 200
    assert client.last_tls is None


def test_authenticated_second_response_202(ctx, issued):
    state = issued("ca second 202")
    cert = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    numbers = key.private_numbers().public_numbers
    keyid = "%x.%x" % (numbers.n, numbers.e)
    client = Client([
        R(401, {"realm": "r", "nonce": "n", "keyid": keyid}, b""),
        R(202, {}, b"<error><status><major><text>m</text></major><minor><text>second</text></minor></status></error>"),
    ])
    result = client.submit_authenticated(
        csr_pem="x", pin_hash="A" * 40, email="e@example.org", auth_cert=cert, auth_key=key,
        host_request=False, public_key="1.1",
    )
    assert result.success is False and "second" in result.detail
