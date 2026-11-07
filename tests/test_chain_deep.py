"""Second-round chain tests, focused on AIA retrieval."""

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from raw_server import RawServer, respond, silent

from pycert import certs, chain
from pycert.errors import ChainError, CryptoError


def key():
    return ec.generate_private_key(ec.SECP256R1())


def issue(cn, *, public_key, issuer=None, issuer_key=None, ca=False, aia=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer is not None else name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(aia),
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key or public_key, hashes.SHA256())


def pki(aia_url):
    root_key = key()
    root = issue("aia root", public_key=root_key.public_key(), issuer_key=root_key, ca=True)
    intermediate_key = key()
    intermediate = issue(
        "aia intermediate",
        public_key=intermediate_key.public_key(),
        issuer=root,
        issuer_key=root_key,
        ca=True,
    )
    leaf_key = key()
    leaf = issue(
        "aia leaf",
        public_key=leaf_key.public_key(),
        issuer=intermediate,
        issuer_key=intermediate_key,
        aia=aia_url,
    )
    return root, intermediate, leaf


@pytest.mark.parametrize("encoding", ["pem", "der"])
def test_aia_fetch_and_build(encoding):
    holder = {"payload": b""}
    server = RawServer(lambda conn: respond(200, holder["payload"])(conn))
    root, intermediate, leaf = pki("http://127.0.0.1:%d/issuer.%s" % (server.port, encoding))
    holder["payload"] = (
        certs.cert_pem(intermediate).encode() if encoding == "pem" else certs.cert_der(intermediate)
    )
    try:
        result = chain.build_chain(leaf, anchors=[root], extra=[], fetcher=chain.aia_fetch)
        assert result.trusted
        assert len(result.chain) == 3
        assert result.fetched
    finally:
        server.stop()


def test_aia_fetch_404_raises():
    server = RawServer(respond(404))
    root, intermediate, leaf = pki("http://127.0.0.1:%d/issuer.pem" % server.port)
    try:
        with pytest.raises(ChainError):
            chain.aia_fetch(leaf, timeout=1)
        result = chain.build_chain(leaf, anchors=[root], extra=[], fetcher=chain.aia_fetch)
        assert not result.trusted
    finally:
        server.stop()


def test_aia_fetch_malformed_raises():
    server = RawServer(respond(200, b"not a certificate"))
    root, intermediate, leaf = pki("http://127.0.0.1:%d/issuer.pem" % server.port)
    try:
        with pytest.raises((ChainError, CryptoError)):
            chain.aia_fetch(leaf, timeout=1)
    finally:
        server.stop()


def test_aia_fetch_oversize_is_refused():
    server = RawServer(respond(200, b"x" * (chain.MAX_AIA_BYTES + 1)))
    root, intermediate, leaf = pki("http://127.0.0.1:%d/issuer.pem" % server.port)
    try:
        with pytest.raises(ChainError, match="too large"):
            chain.aia_fetch(leaf, timeout=1)
    finally:
        server.stop()


def test_aia_fetch_timeout():
    server = RawServer(silent(1))
    root, intermediate, leaf = pki("http://127.0.0.1:%d/issuer.pem" % server.port)
    try:
        with pytest.raises(ChainError):
            chain.aia_fetch(leaf, timeout=0.1)
    finally:
        server.stop()


def test_aia_fetch_unsupported_scheme():
    root, intermediate, leaf = pki("ftp://127.0.0.1/issuer.pem")
    with pytest.raises(ChainError):
        chain.aia_fetch(leaf, timeout=1)


def test_aia_fetch_without_extension_returns_empty():
    private_key = key()
    leaf = issue("no aia", public_key=private_key.public_key(), issuer_key=private_key)
    assert chain.aia_fetch(leaf) == []


def test_aia_fetched_certificate_must_verify():
    # Serve an unrelated CA certificate: it must not become the issuer.
    other_key = key()
    other = issue("unrelated", public_key=other_key.public_key(), issuer_key=other_key, ca=True)
    server = RawServer(respond(200, certs.cert_pem(other).encode()))
    root, intermediate, leaf = pki("http://127.0.0.1:%d/issuer.pem" % server.port)
    try:
        result = chain.build_chain(leaf, anchors=[root], extra=[], fetcher=chain.aia_fetch)
        assert not result.trusted
        assert any("no issuer" in problem for problem in result.problems)
    finally:
        server.stop()
