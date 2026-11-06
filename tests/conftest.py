"""Shared fixtures: a mock CA, a temporary configuration, an app context."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from mock_ca import MockCA  # noqa: E402

from pycert.config import ChainEntry, init_config, load_config, write_config  # noqa: E402
from pycert.workflow import AppContext  # noqa: E402


@pytest.fixture(scope="session")
def mock_ca():
    ca = MockCA()
    try:
        yield ca
    finally:
        ca.stop()


@pytest.fixture
def ca(mock_ca):
    mock_ca.reset()
    return mock_ca


@pytest.fixture
def config(tmp_path, ca):
    confdir = tmp_path / "conf"
    confdir.mkdir()
    config = init_config(confdir, copy_chain=False)
    pins = ca.chain_files(confdir / "chain")
    config.chain = [ChainEntry(label=name, file=f"chain/{name}", sha256=pin) for name, pin in pins.items()]
    config.ca.base_url = ca.url
    config.ca.retries = 0
    config.ca.timeout = 10.0
    config.identity.email = "test@example.org"
    config.identity.ra = "CLRC DL"
    config.paths.data_dir = str(tmp_path / "data")
    config.secrets.backend = "file"
    config.keys.rsa_bits = 2048
    write_config(config.path, config)
    return load_config(config.path)


@pytest.fixture
def ctx(config):
    return AppContext.from_config(config)


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Keep the real ~/.local/share/pycert and keychain out of the tests."""
    monkeypatch.setenv("PYCERT_DATA_DIR", str(tmp_path / "home-data"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def issued(ctx, config, ca):
    """Create a fully issued certificate and return its state."""
    from pycert.workflow import RequestSpec, create_request

    def _make(cn: str = "jane doe", *, type: str = "user", **kwargs):
        ca.auto_approve = True
        ca.sign_after_polls = 0
        spec = RequestSpec.build(config, cn, type=type, pin="1234567890AB", **kwargs)
        return create_request(
            ctx,
            spec,
            wait=True,
            timeout=30,
            interval=0.2,
            progress=lambda _m: None,
        )

    return _make
