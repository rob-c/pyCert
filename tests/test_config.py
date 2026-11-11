import stat
from pathlib import Path

import pytest
import tomllib

from pycert.config import (
    ChainEntry,
    ConfigError,
    default_config_paths,
    find_config,
    init_config,
    load_config,
    validate_config,
    write_config,
)


def test_init_creates_pinned_chain(tmp_path):
    config = init_config(tmp_path / "conf")
    assert config.path.is_file()
    assert len(config.chain) == 4
    assert all(entry.sha256 for entry in config.chain)
    assert (tmp_path / "conf" / "chain" / "escience-root.pem").is_file()
    loaded = load_config(config.path)
    assert len(loaded.bundle.certificates) == 4
    assert len(loaded.bundle.anchors) == 4
    assert loaded.tls_trust_pem().count("BEGIN CERTIFICATE") == 4
    assert stat.S_IMODE((tmp_path / "conf").stat().st_mode) in (0o700, 0o755)


def test_init_is_idempotent_and_does_not_clobber_chain(tmp_path):
    init_config(tmp_path / "conf")
    path = tmp_path / "conf" / "chain" / "escience-root.pem"
    before = path.read_bytes()
    init_config(tmp_path / "conf")
    assert path.read_bytes() == before


def test_pin_mismatch_is_fatal(tmp_path):
    config = init_config(tmp_path / "conf")
    config.chain[0].sha256 = "00" * 32
    with pytest.raises(ConfigError) as exc:
        config.load_chain()
    assert "fingerprint mismatch" in str(exc.value)


def test_missing_chain_file_is_fatal(tmp_path):
    config = init_config(tmp_path / "conf")
    config.chain[0].file = "chain/does-not-exist.pem"
    with pytest.raises(ConfigError):
        config.load_chain()


def test_relative_paths_resolve_against_config_dir(tmp_path):
    config = init_config(tmp_path / "conf")
    assert config.resolve("chain/escience-root.pem").is_file()


def test_inline_pem_chain_entry(tmp_path):
    source = init_config(tmp_path / "a")
    pem = (tmp_path / "a" / "chain" / "escience-root.pem").read_text()
    config = init_config(tmp_path / "b")
    config.chain = [ChainEntry(label="inline", pem=pem, sha256=source.chain[0].sha256)]
    write_config(config.path, config)
    text = config.path.read_text()
    assert "pem = '''" in text
    loaded = load_config(config.path)
    assert len(loaded.bundle.certificates) == 1


def test_roundtrip_preserves_values(tmp_path):
    config = init_config(tmp_path / "conf")
    config.ca.base_url = "https://ca.example.org:8443"
    config.identity.email = "x@example.org"
    config.identity.ra = "Manchester OneRA"
    config.keys.algorithm = "ec"
    config.keys.ec_curve = "P-384"
    config.csr.extensions = ["san", "key_usage"]
    config.p12.filename_template = "{alias}-prod.p12"
    config.secrets.backend = "file"
    write_config(config.path, config)
    loaded = load_config(config.path)
    assert loaded.ca.base_url == "https://ca.example.org:8443"
    assert loaded.identity.email == "x@example.org"
    assert loaded.keys.algorithm == "ec"
    assert loaded.p12.filename_template == "{alias}-prod.p12"


@pytest.mark.parametrize(
    "assignment",
    [
        ("ca.base_url", "https://host"),
        ("identity.o", "eScience"),
        ("keys.rsa_bits", "4096"),
        ("ca.tls_verify", "false"),
        ("ca.tls_pin_sha256", ["aa" * 32]),
    ],
)
def test_set_values(tmp_path, assignment):
    key, value = assignment
    config = init_config(tmp_path / "conf")
    config.set(key, value)
    validate_config(config)
    write_config(config.path, config)
    loaded = load_config(config.path)
    target = loaded
    for part in key.split("."):
        target = getattr(target, part)
    expected = value
    if key == "keys.rsa_bits":
        expected = int(value)
    elif key == "ca.tls_verify":
        expected = value == "true"
    assert target == expected


def test_unknown_setting_is_rejected(tmp_path):
    config = init_config(tmp_path / "conf")
    with pytest.raises(ConfigError):
        config.set("ca.not_a_setting", "x")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: setattr(c.keys, "algorithm", "dsa"),
        lambda c: setattr(c.keys, "rsa_bits", 1024),
        lambda c: setattr(c.identity, "c", "UKA"),
        lambda c: setattr(c.ca, "tls_trust", "tofu"),
        lambda c: setattr(c.ca, "base_url", "http://insecure"),
        lambda c: setattr(c.secrets, "backend", "carrier-pigeon"),
        lambda c: setattr(c.p12, "filename_template", "fixed.p12"),
        lambda c: setattr(c.csr, "hash", "md5"),
        lambda c: setattr(c.csr, "extensions", ["san", "bogus"]),
    ],
)
def test_validation_rejects_bad_values(tmp_path, mutate):
    config = init_config(tmp_path / "conf")
    mutate(config)
    with pytest.raises(ConfigError):
        validate_config(config)


def test_http_requires_explicit_opt_in(tmp_path):
    config = init_config(tmp_path / "conf")
    config.ca.base_url = "http://localhost:8080"
    with pytest.raises(ConfigError):
        validate_config(config)
    config.ca.allow_plaintext = True
    validate_config(config)


def test_invalid_toml(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("this is not = = toml")
    with pytest.raises(ConfigError):
        load_config(path)


def test_default_config_paths_do_not_include_cwd(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("PYCERT_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)  # set on GitHub's Linux runners
    paths = default_config_paths()
    assert Path.cwd() / "pycert.toml" not in paths
    assert paths[0] == tmp_path / ".config" / "pycert" / "pycert.toml"


def test_find_config_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("PYCERT_CONFIG", raising=False)
    with pytest.raises(ConfigError, match="no configuration file found"):
        find_config()


def test_toml_is_parseable(tmp_path):
    config = init_config(tmp_path / "conf")
    tomllib.loads(config.path.read_text())


def test_warns_when_no_chain(tmp_path):
    config = init_config(tmp_path / "conf")
    config.chain = []
    config.invalidate_chain_cache()
    bundle = config.load_chain()
    assert bundle.certificates == []
    assert any("no CA chain" in warning for warning in config.warnings)


def test_sha256_pin_hash_warns(tmp_path):
    config = init_config(tmp_path / "conf")
    config.csr.pin_hash = "sha256"
    validate_config(config)
    assert any("SHA-1" in warning for warning in config.warnings)


def test_set_list_values(tmp_path):
    config = init_config(tmp_path / "conf")
    config.set("ca.tls_pin_sha256", '["aa:bb", "cc:dd"]')
    assert config.ca.tls_pin_sha256 == ["aa:bb", "cc:dd"]
    config.set("ca.tls_pin_sha256", "aa,bb")
    assert config.ca.tls_pin_sha256 == ["aa", "bb"]
    config.set("csr.extensions", "san, key_usage")
    assert config.csr.extensions == ["san", "key_usage"]


def test_default_data_dir_order(monkeypatch, tmp_path):
    from pycert.config import default_data_dir

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("PYCERT_DATA_DIR", raising=False)
    assert default_data_dir() == str(tmp_path / ".local" / "share" / "pycert")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_data_dir() == str(tmp_path / "xdg" / "pycert")
    monkeypatch.setenv("PYCERT_DATA_DIR", str(tmp_path / "chosen"))
    assert default_data_dir() == str(tmp_path / "chosen")
