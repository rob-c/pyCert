"""Coverage-oriented tests for configuration parsing and validation."""

from pathlib import Path

import pytest

from pycert import config as config_module
from pycert.config import (
    CAConfig,
    ChainBundle,
    ChainEntry,
    Config,
    _expect_bool,
    _expect_list,
    _get_float,
    _get_int,
    _get_str,
    _parse_list_value,
    _section,
    default_data_dir,
    find_config,
    load_config,
    render_config,
    validate_config,
    write_config,
)
from pycert.errors import ConfigError


def test_config_primitive_validators():
    assert _expect_bool({"x": True}, "x", False, "where") is True
    with pytest.raises(ConfigError):
        _expect_bool({"x": "yes"}, "x", False, "where")
    assert _expect_list({"x": ["a"]}, "x", [], "where") == ["a"]
    with pytest.raises(ConfigError):
        _expect_list({"x": [1]}, "x", [], "where")
    assert _section({"t": {}}, "t", "where") == {}
    with pytest.raises(ConfigError):
        _section({"t": []}, "t", "where")
    assert _parse_list_value("x", ["a"]) == ["a"]
    assert _parse_list_value("x", '["a", "b"]') == ["a", "b"]
    assert _parse_list_value("x", "a, b") == ["a", "b"]
    with pytest.raises(ConfigError):
        _parse_list_value("x", "[")
    with pytest.raises(ConfigError):
        _parse_list_value("x", 1)
    assert _get_float({"x": 1}, "x", 0, "where") == 1.0
    with pytest.raises(ConfigError):
        _get_float({"x": True}, "x", 0, "where")
    assert _get_int({"x": 1}, "x", 0, "where") == 1
    with pytest.raises(ConfigError):
        _get_int({"x": 1.0}, "x", 0, "where")
    assert _get_str({"x": "a"}, "x", "", "where") == "a"
    with pytest.raises(ConfigError):
        _get_str({"x": 1}, "x", "", "where")


def test_config_paths_and_chain_helpers(tmp_path, monkeypatch):
    entry = ChainEntry(file="relative.pem")
    assert entry.resolved_path(tmp_path) == tmp_path / "relative.pem"
    assert ChainEntry().resolved_path(tmp_path) is None
    bundle = ChainBundle(certificates=[], anchors=[], sources=[])
    assert bundle.pem() == ""
    monkeypatch.setenv("PYCERT_DATA_DIR", str(tmp_path / "data"))
    assert default_data_dir() == str(tmp_path / "data")
    monkeypatch.delenv("PYCERT_DATA_DIR")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_data_dir() == str(tmp_path / "xdg" / "pycert")
    monkeypatch.delenv("XDG_DATA_HOME")


def test_load_config_errors_and_warnings(config, tmp_path, monkeypatch):
    text = config.path.read_text()
    bad = tmp_path / "bad.toml"
    bad.write_text("not = [")
    with pytest.raises(ConfigError):
        load_config(bad)
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.toml")
    version = tmp_path / "version.toml"
    version.write_text(text.replace("version = 1", "version = 99"))
    loaded = load_config(version)
    assert any("not the supported version" in warning for warning in loaded.warnings)
    chain_bad = tmp_path / "chain.toml"
    chain_bad.write_text(text.replace("[[chain.certificates]]", "chain.certificates = 1\n#"))
    with pytest.raises(ConfigError):
        load_config(chain_bad)
    chain_entry = tmp_path / "chain-entry.toml"
    chain_entry.write_text(text.replace("[[chain.certificates]]", "[[chain.certificates]]\nfile = 1\n#"))
    with pytest.raises(ConfigError):
        load_config(chain_entry)


def test_validate_config_backoff_and_write_paths(tmp_path):
    config = Config(path=tmp_path / "pycert.toml", profile="default", ca=CAConfig(), identity=config_module.IdentityConfig(), keys=config_module.KeyConfig(), csr=config_module.CSRConfig(), p12=config_module.P12Config(), paths=config_module.PathsConfig(data_dir=str(tmp_path / "data")), secrets=config_module.SecretConfig(), chain=[])
    config.ca.backoff_base = 20
    with pytest.raises(ConfigError):
        validate_config(config)
    config.ca.backoff_base = 0
    config.ca.backoff_cap = 100
    with pytest.raises(ConfigError):
        validate_config(config)
    config.ca.backoff_cap = 8
    config.chain = [ChainEntry(label="x", pem="not a cert", anchor=False)]
    rendered = render_config(config)
    assert "anchor = false" in rendered
    out = write_config(tmp_path / "out", config)
    assert out.name == "pycert.toml"
    assert find_config(out) == out


def test_config_load_chain_missing_file_and_oserror(config, tmp_path, monkeypatch):
    config.chain = [ChainEntry()]
    with pytest.raises(ConfigError):
        config.load_chain()
    good = tmp_path / "good.toml"
    good.write_text(config.path.read_text())
    real_read_text = Path.read_text
    def broken(self, *a, **k):
        if self == good:
            raise OSError("unreadable")
        return real_read_text(self, *a, **k)
    monkeypatch.setattr(Path, "read_text", broken)
    with pytest.raises(ConfigError):
        load_config(good)


def test_config_chain_invalid_shapes(config, tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("version = 1\n[chain]\ncertificates = 1\n")
    with pytest.raises(ConfigError):
        load_config(path)
    path = tmp_path / "both.toml"
    path.write_text('version = 1\n[chain]\n[[chain.certificates]]\nfile = "x"\npem = "y"\n')
    with pytest.raises(ConfigError):
        load_config(path)
    path = tmp_path / "neither.toml"
    path.write_text("version = 1\n[chain]\n[[chain.certificates]]\nlabel = 'x'\n")
    with pytest.raises(ConfigError):
        load_config(path)


def test_config_chain_non_dict_entry(tmp_path):
    path = tmp_path / "non-dict.toml"
    path.write_text("version = 1\n[chain]\ncertificates = [1]\n")
    with pytest.raises(ConfigError):
        load_config(path)
