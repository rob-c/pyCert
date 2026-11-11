"""Branch coverage for the binary formats and certificate helpers (no network).

Each test builds the unusual-but-legal input that the earlier suites never fed
the parsers: BER fragments of other types, PKCS#12 bags pyCertWiz does not use,
distribution points without a URI, name constraints of other kinds, and so on.
"""

import datetime as dt
import ipaddress
import runpy

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from pycert import asn1, ber, bundles, certs, exporter, p12, proxy
from pycert.errors import CryptoError, PyCertError
from pycert.pkcs12_writer import (
    CERT_BAG_OID,
    DATA_OID,
    FRIENDLY_NAME_OID,
    X509_CERTIFICATE_OID,
    encode_pkcs12,
    encode_raw_pkcs12,
)

SECRET_BAG_OID = "1.2.840.113549.1.12.10.1.5"
ENVELOPED_DATA_OID = "1.2.840.113549.1.7.3"


def _certificate(cn="cov.example.org", *, key=None, issuer_key=None, issuer_name=None, extensions=(), ca=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    for extension in extensions:
        builder = builder.add_extension(extension, critical=False)
    return key, builder.sign(issuer_key or key, hashes.SHA256())


# ---------------------------------------------------------------------------
# __main__ / ber
# ---------------------------------------------------------------------------


def test_main_module_does_nothing_when_imported():
    """``pycert.__main__`` only runs the CLI as a script, never on a plain import."""
    namespace = runpy.run_module("pycert.__main__", run_name="pycert_main_import_probe")
    assert callable(namespace["main"])


def test_octets_skip_non_octet_primitive_fragments():
    # A constructed OCTET STRING (BER) whose fragments are an OCTET STRING and a NULL:
    # only the OCTET STRING content contributes.
    node = ber.parse(bytes([0x24, 0x07, 0x04, 0x03]) + b"abc" + bytes([0x05, 0x00]))
    assert ber.octets(node) == b"abc"
    assert ber.octets(ber.parse(bytes([0x24, 0x02, 0x05, 0x00]))) == b""


# ---------------------------------------------------------------------------
# bundles: PKCS#12 content pyCertWiz does not use is skipped, not misread
# ---------------------------------------------------------------------------


def _cert_bag(certificate, attributes=b""):
    der = certs.cert_der(certificate)
    value = asn1.seq(asn1.oid(X509_CERTIFICATE_OID), asn1.explicit(0, asn1.octet_string(der)))
    return asn1.seq(asn1.oid(CERT_BAG_OID), asn1.explicit(0, value), attributes)


def _attribute(oid, *values):
    return asn1.seq(asn1.oid(oid), asn1.set_of(*values))


def test_pkcs12_unused_bags_content_types_and_odd_friendly_names_are_skipped():
    _key, first = _certificate("first.example.org")
    _key2, second = _certificate("second.example.org")
    utf8_name = asn1.tlv(asn1.UNIVERSAL, False, 12, b"not-bmp")
    bags = [
        # friendlyName with an empty value set, then one that is a UTF8String: no alias
        _cert_bag(first, asn1.set_of(_attribute(FRIENDLY_NAME_OID), _attribute(FRIENDLY_NAME_OID, utf8_name))),
        # a secretBag: neither a certificate nor a key
        asn1.seq(asn1.oid(SECRET_BAG_OID), asn1.explicit(0, asn1.seq(asn1.oid("1.2.3.4"), asn1.explicit(0, asn1.octet_string(b"s"))))),
        _cert_bag(second, asn1.set_of(_attribute(FRIENDLY_NAME_OID, asn1.bmp_string("second")))),
    ]
    data_info = asn1.seq(asn1.oid(DATA_OID), asn1.explicit(0, asn1.octet_string(asn1.seq(*bags))))
    # envelopedData (public-key encrypted) content is not something pyCertWiz can open: skipped.
    enveloped_info = asn1.seq(asn1.oid(ENVELOPED_DATA_OID), asn1.explicit(0, asn1.seq(asn1.integer(0))))
    authenticated = asn1.seq(data_info, enveloped_info)
    pfx = asn1.seq(
        asn1.integer(3), asn1.seq(asn1.oid(DATA_OID), asn1.explicit(0, asn1.octet_string(authenticated)))
    )
    bundle = bundles.load_bundle_bytes(pfx)
    assert bundle.format == "pkcs12"
    assert [entry.alias for entry in bundle.certificates] == ["", "second"]
    assert [entry.certificate for entry in bundle.certificates] == [first, second]
    assert len(bundle.raw_cert_bags) == 2 and not bundle.raw_key_bags and not bundle.has_private_key


# ---------------------------------------------------------------------------
# certs
# ---------------------------------------------------------------------------


def test_crl_urls_ignore_points_without_a_full_name():
    relative = x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "crl")])
    points = x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(full_name=None, relative_name=relative, reasons=None, crl_issuer=None),
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier("http://crl.example.org/ca.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            ),
        ]
    )
    _key, certificate = _certificate(extensions=[points])
    assert certs.describe_certificate(certificate).crl_urls == ["http://crl.example.org/ca.crl"]


def test_name_constraints_ignore_non_dns_subtrees():
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    constraints = x509.NameConstraints(
        permitted_subtrees=[
            x509.IPAddress(ipaddress.ip_network("10.0.0.0/8")),
            x509.RFC822Name("example.org"),
            x509.DNSName("example.org"),
        ],
        excluded_subtrees=None,
    )
    _ik, issuer = _certificate("Constrained CA", key=issuer_key, extensions=[constraints], ca=True)
    sans = x509.SubjectAlternativeName([x509.DNSName("www.example.org"), x509.DNSName("www.example.com")])
    _lk, leaf = _certificate(
        "www.example.org", issuer_key=issuer_key, issuer_name=issuer.subject, extensions=[sans]
    )
    assert certs.has_name_constraints_violation(leaf, issuer) == [
        "DNS name www.example.com is outside permitted subtree .example.org"
    ]


# ---------------------------------------------------------------------------
# p12 / pkcs12_writer
# ---------------------------------------------------------------------------


def test_write_pkcs12_and_certificate_bundle_without_read_back(tmp_path):
    key, certificate = _certificate("unverified.example.org")
    path = p12.write_pkcs12(
        tmp_path / "leaf.p12", key=key, certificate=certificate, password="correct horse", verify=False
    )
    loaded_key, loaded_cert, _extra = pkcs12.load_key_and_certificates(path.read_bytes(), b"correct horse")
    assert loaded_cert == certificate and certs.public_keys_equal(loaded_cert, loaded_key.public_key())
    bundle = p12.write_certificate_bundle(
        tmp_path / "certs.p12", certificates=[certificate], password="correct horse", verify=False
    )
    loaded_key, first, extra = pkcs12.load_key_and_certificates(bundle.read_bytes(), b"correct horse")
    assert loaded_key is None and ([first] if first else []) + list(extra) == [certificate]


def test_single_iteration_mac_omits_the_iteration_count():
    """RFC 7292: macData.iterations DEFAULTs to 1 and is then left out of the DER."""
    key, certificate = _certificate("mac.example.org")
    blob = encode_pkcs12(key, certificate, [], "pass phrase", "mac", mac_iterations=1)
    mac_data = ber.parse(blob).children[2]
    assert len(mac_data.children) == 2  # digest and salt only
    loaded_key, loaded_cert, _extra = pkcs12.load_key_and_certificates(blob, b"pass phrase")
    assert loaded_cert == certificate and loaded_key is not None
    raw = encode_raw_pkcs12([], [_cert_bag(certificate)], "pass phrase", mac_iterations=1)
    assert len(ber.parse(raw).children[2].children) == 2
    # pyCertWiz's own MAC check accepts the implicit single iteration (and still catches a wrong passphrase).
    assert bundles.load_bundle_bytes(raw, "pass phrase").certificates[0].certificate == certificate
    with pytest.raises(CryptoError):
        bundles.load_bundle_bytes(raw, "wrong phrase")


# ---------------------------------------------------------------------------
# proxy / exporter
# ---------------------------------------------------------------------------


def test_proxy_bundle_lists_the_issuer_once():
    key, leaf = _certificate("proxy.example.org")
    _ik, issuer = _certificate("Issuer")
    _rk, root = _certificate("Root")
    pem = proxy.proxy_bundle_pem(key, leaf, issuer, [issuer, root, root], password=b"proxy pass")
    assert pem.count("BEGIN CERTIFICATE") == 3
    assert "ENCRYPTED PRIVATE KEY" in pem


def test_export_write_failure_is_reported_cleanly(ctx, tmp_path):
    _key, certificate = _certificate("export.example.org")
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("a regular file where a folder is expected")
    with pytest.raises(PyCertError, match="cannot write the export"):
        exporter.export_material(
            alias="export",
            certificate=certificate,
            chain=[],
            load_key=None,
            fmt="cert",
            destination=blocker / "export.pem",
            ctx=ctx,
        )
