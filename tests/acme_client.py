"""Minimal ACME v2 client used by the emulation tests.

It signs JWS requests with an in-memory account key and speaks to
``sandbox_ca.acme.ACMEServer.handle`` directly, so a full order can be tested
without a socket or a browser.
"""

import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from pycert.csr import build_csr
from sandbox_ca.acme import ACMEServer, b64e


def _path(url: str) -> str:
    return "/" + url.split("/", 3)[3]


def _int_b64(value: int) -> str:
    return b64e(value.to_bytes((value.bit_length() + 7) // 8 or 1, "big"))


def jwk_for(key) -> dict:
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = key.public_key().public_numbers()
        return {"kty": "RSA", "n": _int_b64(numbers.n), "e": _int_b64(numbers.e)}
    if isinstance(key, ec.EllipticCurvePrivateKey):
        numbers = key.public_key().public_numbers()
        curve = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }.get(numbers.curve.name, "P-256")
        return {"kty": "EC", "crv": curve, "x": _int_b64(numbers.x), "y": _int_b64(numbers.y)}
    if isinstance(key, ed25519.Ed25519PrivateKey):
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64e(raw)}
    raise TypeError("unsupported account key")


def sign_jws(key, protected: dict, payload) -> bytes:
    protected_b64 = b64e(json.dumps(protected, separators=(",", ":")).encode())
    payload_b64 = "" if payload is None else b64e(json.dumps(payload, separators=(",", ":")).encode())
    signed = (protected_b64 + "." + payload_b64).encode("ascii")
    alg = protected.get("alg", "RS256")
    if isinstance(key, rsa.RSAPrivateKey):
        hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}.get(alg)
        if hash_alg is None:
            hash_alg = hashes.SHA256()
        signature = key.sign(signed, padding.PKCS1v15(), hash_alg)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        hash_alg = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}.get(alg)
        if hash_alg is None:
            hash_alg = {"secp256r1": hashes.SHA256, "secp384r1": hashes.SHA384, "secp521r1": hashes.SHA512}[
                key.public_key().curve.name
            ]()
        der = key.sign(signed, ec.ECDSA(hash_alg))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(der)
        size = (key.public_key().curve.key_size + 7) // 8
        signature = r.to_bytes(size, "big") + s.to_bytes(size, "big")
    elif isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(signed)
    else:
        raise TypeError("unsupported account key")
    return json.dumps(
        {"protected": protected_b64, "payload": payload_b64, "signature": b64e(signature)},
        separators=(",", ":"),
    ).encode()


class ACMEClient:
    def __init__(self, server: ACMEServer, key=None, alg=None):
        self.server = server
        self.key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = jwk_for(self.key)
        self.kid = ""
        self.nonce = ""
        if alg:
            self.alg = alg
            self.kid = ""
            self.nonce = ""
        elif isinstance(self.key, rsa.RSAPrivateKey):
            self.alg = "RS256"
        elif isinstance(self.key, ec.EllipticCurvePrivateKey):
            self.alg = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}[
                self.key.public_key().curve.name
            ]
        elif isinstance(self.key, ed25519.Ed25519PrivateKey):
            self.alg = "EdDSA"
        else:
            raise TypeError("unsupported account key")
        self.last_status = 0
        self.last_headers = {}
        self.last_body = b""
        self.last_content_type = ""

    def request(self, method, path, payload=None, *, jwk=False, nonce=None, url=None, body=None):
        target = self.server.url(path)
        nonce = nonce if nonce is not None else self.nonce
        protected = {"alg": self.alg, "nonce": nonce, "url": url or target}
        if jwk:
            protected["jwk"] = self.jwk
        else:
            protected["kid"] = self.kid
        if body is None:
            body = sign_jws(self.key, protected, payload)
        status, headers, response, content_type = self.server.handle(method, path, {}, body)
        self.last_status = status
        self.last_headers = headers
        self.last_body = response
        self.last_content_type = content_type
        self.nonce = headers.get("Replay-Nonce", "")
        return status, headers, response

    def json(self):
        return json.loads(self.last_body.decode())

    def head_nonce(self):
        self.server.handle("HEAD", "/acme/new-nonce", {}, b"")
        # The helper does not expose that response through self.request; call
        # handle directly to obtain the fresh nonce.
        status, headers, _, _ = self.server.handle("HEAD", "/acme/new-nonce", {}, b"")
        self.nonce = headers["Replay-Nonce"]
        return self.nonce

    def register(self, contact=None, **payload):
        self.head_nonce()
        body = {"contact": contact or ["mailto:acme@example.org"], "termsOfServiceAgreed": True}
        body.update(payload)
        status, headers, response = self.request("POST", "/acme/new-account", body, jwk=True)
        if headers.get("Location"):
            self.kid = headers["Location"]
        return status, headers, response

    def new_order(self, domains, **extra):
        identifiers = [{"type": "dns", "value": domain} for domain in domains]
        payload = {"identifiers": identifiers}
        payload.update(extra)
        status, headers, response = self.request("POST", "/acme/new-order", payload)
        return status, headers, response

    def order(self, order_url, payload=None):
        return self.request("POST", _path(order_url), payload, url=order_url)

    def authz(self, authz_url):
        return self.request("POST", _path(authz_url), None, url=authz_url)

    def challenge(self, challenge_url):
        return self.request("POST", _path(challenge_url), {}, url=challenge_url)

    def finalize(self, finalize_url, csr_der: bytes):
        return self.request("POST", _path(finalize_url), {"csr": b64e(csr_der)}, url=finalize_url)

    def certificate(self, cert_url):
        return self.request("POST", _path(cert_url), None, url=cert_url)

    def csr(self, domains, key=None, *, wildcard=False):
        key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        names = [domain[2:] if domain.startswith("*.") else domain for domain in domains]
        cn = names[0]
        request = build_csr(
            key,
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]),
            cert_type="host",
            dns_names=list(domains),
        )
        return request.public_bytes(serialization.Encoding.DER)


def complete_order(client: ACMEClient, domains, *, challenge_type=None):
    status, headers, body = client.new_order(domains)
    assert status == 201, body
    order = json.loads(body)
    for authz_url in order["authorizations"]:
        status, _, body = client.authz(authz_url)
        assert status == 200, body
        authz = json.loads(body)
        challenge = next(
            item for item in authz["challenges"]
            if challenge_type is None or item["type"] == challenge_type
        )
        status, _, body = client.challenge(challenge["url"])
        assert status == 200, body
    csr_der = client.csr(domains)
    status, headers, body = client.finalize(order["finalize"], csr_der)
    return status, headers, body
