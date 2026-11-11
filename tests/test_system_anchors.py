"""System trust anchors when OpenSSL lists no CA file (current Fedora uses a hashed directory)."""

import ssl

import pytest

from pycert import certs, chain


class _EmptyContext:
    def get_ca_certs(self, binary_form=False):
        return []


@pytest.fixture
def no_default_list(monkeypatch):
    monkeypatch.setattr(chain, "_system_anchors_cache", None)
    monkeypatch.setattr(chain.ssl, "create_default_context", lambda: _EmptyContext())
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.setattr(chain.ssl, "get_default_verify_paths", lambda: ssl.DefaultVerifyPaths(None, None, "", "", "", ""))


def test_falls_back_to_the_distribution_bundle(no_default_list, monkeypatch, tmp_path, mock_ca):
    bundle = tmp_path / "tls-ca-bundle.pem"
    bundle.write_text(certs.cert_pem(mock_ca.root) + certs.cert_pem(mock_ca.intermediate))
    broken = tmp_path / "broken.pem"
    broken.write_text("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(chain, "CA_BUNDLES", (str(tmp_path / "missing.pem"), str(broken), str(bundle)))
    anchors = chain.system_anchors()
    assert [certs.fingerprint(c) for c in anchors] == [certs.fingerprint(mock_ca.root), certs.fingerprint(mock_ca.intermediate)]
    assert chain.system_anchors() is anchors  # cached


def test_ssl_cert_file_wins(no_default_list, monkeypatch, tmp_path, mock_ca):
    chosen = tmp_path / "chosen.pem"
    chosen.write_text(certs.cert_pem(mock_ca.root))
    monkeypatch.setenv("SSL_CERT_FILE", str(chosen))
    monkeypatch.setattr(chain, "CA_BUNDLES", ())
    assert [certs.fingerprint(c) for c in chain.system_anchors()] == [certs.fingerprint(mock_ca.root)]


def test_no_bundle_anywhere(no_default_list, monkeypatch, tmp_path):
    empty = tmp_path / "empty.pem"
    empty.write_text("")
    monkeypatch.setattr(chain, "CA_BUNDLES", (str(empty),))
    assert chain.system_anchors() == []
