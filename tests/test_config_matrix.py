"""Broad configuration matrix: every field, boundary and round-trip."""

import pytest

from pycert import bundled, certs
from pycert.config import (
    ChainEntry,
    ConfigError,
    init_config,
    load_config,
    validate_config,
    write_config,
)


def make(tmp_path, copy_chain=False):
    return init_config(tmp_path / "conf", copy_chain=copy_chain)


def roundtrip(config):
    write_config(config.path, config)
    return load_config(config.path)


VALID = [
    ("ca.base_url", "https://ca.example.org:8443"),
    ("ca.version_string", "CertWizard 2.2.1"),
    ("ca.user_agent", "pyCert/test"),
    ("ca.timeout", 12.5),
    ("ca.connect_timeout", 4.5),
    ("ca.deadline", 120.0),
    ("ca.dns_timeout", 3.0),
    ("ca.retries", 4),
    ("ca.max_redirects", 1),
    ("ca.max_body_bytes", 1048576),
    ("ca.max_header_bytes", 65536),
    ("ca.backoff_base", 0.25),
    ("ca.backoff_cap", 2.0),
    ("ca.tls_verify", False),
    ("ca.tls_trust", "both"),
    ("ca.tls_pin_sha256", ["aa" * 32]),
    ("ca.allow_plaintext", True),
    ("ca.allow_sha1", True),
    ("ca.endpoints.csr", "/newcsr"),
    ("ca.endpoints.bulk", "/newbulk"),
    ("ca.endpoints.lookup", "/lookup"),
    ("ca.endpoints.certificate", "/cert"),
    ("ca.endpoints.revoke", "/revoke2"),
    ("ca.endpoints.ping", "/ping2"),
    ("ca.endpoints.info", "/info2"),
    ("ca.endpoints.motd", "/motd2"),
    ("identity.c", "DE"),
    ("identity.o", "Example Org"),
    ("identity.ou", "Example Unit"),
    ("identity.l", "Example City"),
    ("identity.st", "Example State"),
    ("identity.email", "ops@example.org"),
    ("identity.ra", "Example Unit Example City"),
    ("keys.algorithm", "ec"),
    ("keys.rsa_bits", 4096),
    ("keys.ec_curve", "P-384"),
    ("csr.hash", "sha384"),
    ("csr.extensions", ["san", "key_usage"]),
    ("csr.pin_hash", "sha256"),
    ("p12.filename_template", "{alias}.p12"),
    ("p12.friendly_name", "{alias} friendly"),
    ("p12.export_dir", "exports"),
    ("p12.include_chain", False),
    ("paths.data_dir", "data"),
    ("secrets.backend", "file"),
    ("secrets.service", "svc"),
    ("secrets.account", "acct"),
    ("secrets.key_account", "key-acct"),
    ("secrets.file", "secrets.json"),
    ("secrets.command", "pass show x"),
    ("secrets.env_var", "X_PASS"),
]


@pytest.mark.parametrize("field,value", VALID)
def test_valid_field_roundtrip(tmp_path, field, value):
    config = make(tmp_path)
    config.set(field, value)
    if field == "ca.base_url":
        config.ca.allow_plaintext = False  # https, no opt-in needed
    if field == "ca.tls_pin_sha256":
        pass
    if field == "keys.rsa_bits" and config.keys.algorithm == "rsa":
        pass
    validate_config(config)
    loaded = roundtrip(config)
    target = loaded
    for part in field.split("."):
        target = getattr(target, part)
    if field == "ca.tls_pin_sha256" or field == "ca.base_url":
        assert target == value
    else:
        assert target == value


INVALID = [
    ("ca.base_url", "not a url", "valid URL"),
    ("ca.base_url", "http://insecure", "allow_plaintext"),
    ("ca.timeout", 0, "between 0 and 300"),
    ("ca.timeout", 301, "between 0 and 300"),
    ("ca.timeout", -1, "between 0 and 300"),
    ("ca.connect_timeout", 0, "between 0 and 300"),
    ("ca.connect_timeout", 301, "between 0 and 300"),
    ("ca.deadline", 0, "between 0 and 3600"),
    ("ca.deadline", 4000, "between 0 and 3600"),
    ("ca.dns_timeout", 0, "between 0 and 120"),
    ("ca.dns_timeout", 500, "between 0 and 120"),
    ("ca.retries", -1, "between 0 and 10"),
    ("ca.retries", 11, "between 0 and 10"),
    ("ca.max_redirects", -1, "between 0 and 10"),
    ("ca.max_redirects", 11, "between 0 and 10"),
    ("ca.max_body_bytes", 10, "64 MiB"),
    ("ca.max_body_bytes", 100 * 1024 * 1024, "64 MiB"),
    ("ca.max_header_bytes", 10, "1 MiB"),
    ("ca.max_header_bytes", 2 * 1024 * 1024, "1 MiB"),
    ("ca.backoff_base", -1, "between 0 and 10"),
    ("ca.backoff_base", 11, "between 0 and 10"),
    ("ca.backoff_cap", 0, "between 0 and 60"),
    ("ca.backoff_cap", 61, "between 0 and 60"),
    ("ca.tls_trust", "tofu", "tls_trust"),
    ("ca.tls_pin_sha256", ["short"], "SHA-256"),
    ("identity.c", "UKA", "two-letter"),
    ("keys.algorithm", "dsa", "rsa"),
    ("keys.rsa_bits", 1024, "2048"),
    ("keys.ec_curve", "P-224", "P-256"),
    ("csr.hash", "md5", "sha256"),
    ("csr.pin_hash", "md5", "sha1"),
    ("csr.extensions", ["san", "bogus"], "unknown"),
    ("p12.filename_template", "fixed.p12", "{cn}"),
    ("secrets.backend", "carrier-pigeon", "auto"),
    ("secrets.command", "", "command"),
]


@pytest.mark.parametrize("field,value,match", INVALID)
def test_invalid_field_is_rejected(tmp_path, field, value, match):
    config = make(tmp_path)
    if field == "secrets.command":
        config.secrets.backend = "command"

    def apply():
        config.set(field, value)
        validate_config(config)

    with pytest.raises((ConfigError, TypeError, ValueError)):
        apply()


@pytest.mark.parametrize("field", ["ca.timeout", "ca.connect_timeout", "ca.deadline", "ca.dns_timeout"])
def test_nan_and_infinity_are_rejected(tmp_path, field):
    config = make(tmp_path)
    for value in (float("nan"), float("inf"), float("-inf")):
        setattr(config.ca, field.split(".")[-1], value)
        with pytest.raises(ConfigError):
            validate_config(config)


def test_warning_for_disabled_tls(tmp_path):
    config = make(tmp_path)
    config.ca.tls_verify = False
    validate_config(config)
    assert any("NOT be verified" in warning for warning in config.warnings)


def test_warning_for_plaintext(tmp_path):
    config = make(tmp_path)
    config.ca.base_url = "http://localhost"
    config.ca.allow_plaintext = True
    validate_config(config)
    assert any("allow_plaintext" in warning for warning in config.warnings)


def test_warning_for_sha256_pin_hash(tmp_path):
    config = make(tmp_path)
    config.csr.pin_hash = "sha256"
    validate_config(config)
    assert any("SHA-1" in warning for warning in config.warnings)


def test_warning_for_deadline_smaller_than_timeout(tmp_path):
    config = make(tmp_path)
    config.ca.timeout = 60
    config.ca.deadline = 30
    validate_config(config)
    assert any("deadline" in warning for warning in config.warnings)


def test_warning_when_chain_is_empty(tmp_path):
    config = make(tmp_path, copy_chain=False)
    config.invalidate_chain_cache()
    bundle = config.load_chain()
    assert bundle.certificates == []
    assert any("no CA chain" in warning for warning in config.warnings)


@pytest.mark.parametrize("mode", ["chain", "system", "both"])
def test_tls_trust_modes(tmp_path, mode):
    config = make(tmp_path, copy_chain=True)
    config.ca.tls_trust = mode
    validate_config(config)
    assert bool(config.tls_trust_pem()) is (mode in ("chain", "both"))
    assert config.use_system_trust() is (mode in ("system", "both"))


def test_chain_pins_and_anchor_flags(tmp_path):
    config = make(tmp_path, copy_chain=True)
    assert len(config.bundle.certificates) == 4
    config.chain[0].anchor = False
    config.invalidate_chain_cache()
    assert len(config.bundle.anchors) == 3


def test_chain_entry_file_and_pem_is_rejected(tmp_path):
    config = make(tmp_path, copy_chain=True)
    config.chain.append(ChainEntry(file="chain/escience-root.pem", pem="x"))
    with pytest.raises(ConfigError):
        config.load_chain()


def test_chain_entry_missing_file(tmp_path):
    config = make(tmp_path, copy_chain=True)
    config.chain.append(ChainEntry(file="chain/nope.pem"))
    with pytest.raises(ConfigError, match="not found"):
        config.load_chain()


def test_chain_entry_pin_mismatch(tmp_path):
    config = make(tmp_path, copy_chain=True)
    config.chain[1].sha256 = "00" * 32
    with pytest.raises(ConfigError, match="mismatch"):
        config.load_chain()


def test_chain_inline_pem_roundtrip(tmp_path):
    config = make(tmp_path, copy_chain=False)
    pem = certs.cert_pem(bundled.certificates()[0])
    config.chain = [ChainEntry(label="root", pem=pem, sha256=certs.fingerprint(bundled.certificates()[0]))]
    write_config(config.path, config)
    text = config.path.read_text()
    assert "pem = '''" in text
    loaded = load_config(config.path)
    assert len(loaded.bundle.certificates) == 1


def test_chain_entry_with_multiple_certificates_pins_all(tmp_path):
    config = make(tmp_path, copy_chain=False)
    path = tmp_path / "conf" / "bundle.pem"
    path.write_text("".join(certs.cert_pem(c) for c in bundled.certificates()[:2]))
    config.chain = [ChainEntry(file="bundle.pem", sha256=certs.fingerprint(bundled.certificates()[0]))]
    with pytest.raises(ConfigError, match="mismatch"):
        config.load_chain()


def test_chain_deduplicates(tmp_path):
    config = make(tmp_path, copy_chain=True)
    config.chain.extend([ChainEntry(file=e.file, sha256=e.sha256) for e in list(config.chain)])
    config.invalidate_chain_cache()
    assert len(config.bundle.certificates) == 4


@pytest.mark.parametrize(
    "field,value,expected_type",
    [
        ("ca.retries", "3", int),
        ("ca.timeout", "4.5", float),
        ("ca.tls_verify", "false", bool),
        ("ca.tls_pin_sha256", '["aa", "bb"]', list),
        ("csr.extensions", "san, key_usage", list),
        ("keys.rsa_bits", "2048", int),
        ("identity.o", "X", str),
    ],
)
def test_set_casts_values(tmp_path, field, value, expected_type):
    config = make(tmp_path)
    config.set(field, value)
    target = config
    for part in field.split("."):
        target = getattr(target, part)
    assert isinstance(target, expected_type)


def test_set_unknown_field(tmp_path):
    config = make(tmp_path)
    with pytest.raises(ConfigError):
        config.set("ca.unknown", 1)
    with pytest.raises(ConfigError):
        config.set("nope.nope", 1)


def test_set_bad_list_json(tmp_path):
    config = make(tmp_path)
    with pytest.raises(ConfigError, match="JSON"):
        config.set("ca.tls_pin_sha256", "[not json")


def test_set_wrong_scalar_type(tmp_path):
    config = make(tmp_path)
    with pytest.raises(ConfigError):
        config.set("ca.retries", "many")


def test_roundtrip_of_many_fields(tmp_path):
    config = make(tmp_path, copy_chain=True)
    config.profile = "prod"
    config.ca.user_agent = "agent"
    config.identity.email = "a@b.c"
    config.keys.algorithm = "ec"
    config.keys.ec_curve = "P-521"
    config.csr.extensions = ["san"]
    config.p12.filename_template = "{cn}-x.p12"
    config.secrets.backend = "file"
    loaded = roundtrip(config)
    assert loaded.profile == "prod"
    assert loaded.ca.user_agent == "agent"
    assert loaded.identity.email == "a@b.c"
    assert loaded.keys.ec_curve == "P-521"
    assert loaded.p12.filename_template == "{cn}-x.p12"
    assert loaded.secrets.backend == "file"


def test_as_dict_contains_network_hardening(tmp_path):
    data = make(tmp_path).as_dict()
    for key in (
        "connect_timeout",
        "deadline",
        "dns_timeout",
        "max_redirects",
        "max_body_bytes",
        "max_header_bytes",
        "backoff_base",
        "backoff_cap",
    ):
        assert key in data["ca"]


def test_render_contains_hardening_comments(tmp_path):
    config = make(tmp_path)
    text = config.path.read_text()
    assert "Networking hardening" in text
    assert "connect_timeout" in text
    assert "max_redirects" in text


def test_endpoint_urls(tmp_path):
    config = make(tmp_path)
    assert config.ca.url("csr") == "https://cwiz-live.ca.ngs.ac.uk:443/CSR"
    config.ca.base_url = "https://example.org/base/"
    assert config.ca.url("lookup").startswith("https://example.org/base/resources")


def test_config_with_unknown_extra_sections_is_ignored(tmp_path):
    config = make(tmp_path)
    text = config.path.read_text() + "\n[unknown]\nvalue = 1\n"
    config.path.write_text(text)
    loaded = load_config(config.path)
    assert loaded.ca.base_url
