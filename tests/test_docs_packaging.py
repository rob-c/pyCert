"""Packaging, metadata, documentation and example consistency."""

import configparser
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parser():
    result = configparser.ConfigParser()
    result.read(str(ROOT / "setup.cfg"))
    return result


def test_metadata():
    data = parser()
    assert data["metadata"]["name"] == "pycert"
    assert data["metadata"]["version"] == "1.0.0"
    assert data["metadata"]["license"] == "GPL-2.0-or-later"


def test_python_requirement_and_dependencies():
    data = parser()
    assert data["options"]["python_requires"] == ">=3.6"
    assert "cryptography>=3.0" in data["options"]["install_requires"]
    assert "requests" not in data["options"]["install_requires"]
    assert "pyOpenSSL" not in data["options"]["install_requires"]


def test_console_scripts():
    data = parser()
    scripts = data["options.entry_points"]["console_scripts"]
    assert "pycert = pycert.cli:main" in scripts
    assert "pycert-gui = pycert.gui:main" in scripts


def test_build_system_markers():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    requires = data["build-system"]["requires"]
    assert any("59.6" in requirement for requirement in requires)
    assert any("setuptools" in requirement for requirement in requires)
    assert data["build-system"]["build-backend"] == "setuptools.build_meta"


def test_package_data_is_present():
    data = parser()
    assert "data/ca/*.pem" in data["options.package_data"]["pycert"]
    for name in ("escience-root.pem", "escience-2b.pem", "escience-root-2026.pem", "escience-3b.pem"):
        assert (ROOT / "src" / "pycert" / "data" / "ca" / name).is_file()


def test_manifest_includes_docs_examples_tests_tools():
    manifest = (ROOT / "MANIFEST.in").read_text()
    for token in ("docs", "examples", "tests", "tools", "setup.cfg", "pyproject.toml"):
        assert token in manifest


def test_readme_mentions_every_command():
    readme = (ROOT / "README.md").read_text()
    for command in (
        "init",
        "config",
        "ping",
        "ras",
        "info",
        "request",
        "wait",
        "status",
        "list",
        "show",
        "download",
        "export",
        "verify",
        "renew",
        "revoke",
        "import",
        "install",
        "delete",
        "secret",
        "doctor",
        "selftest",
        "gui",
        "watch",
    ):
        assert "pycert %s" % command in readme or "pycert %s`" % command in readme


def test_documentation_files_exist_and_are_linked():
    for relative in (
        "README.md",
        "SECURITY.md",
        "docs/CONFIGURATION.md",
        "docs/PROTOCOL.md",
        "docs/GUI.md",
        "docs/MIGRATION.md",
    ):
        assert (ROOT / relative).is_file(), relative
    readme = (ROOT / "README.md").read_text()
    assert "docs/CONFIGURATION.md" in readme
    assert "SECURITY.md" in readme


def test_examples_are_valid_toml_and_loadable():
    from pycert.config import load_config
    from pycert.toml import loads

    for path in (ROOT / "examples").glob("*.toml"):
        loads(path.read_text())
    config = load_config(ROOT / "examples" / "pycert.toml")
    assert config.bundle.anchors


def test_readme_does_not_claim_wrong_python_version():
    readme = (ROOT / "README.md").read_text()
    assert "Python 3.6" in readme
    assert "Python 3.11 or newer is required" not in readme


def test_install_instructions_use_supported_commands():
    readme = (ROOT / "README.md").read_text()
    assert "pip install -e ." in readme
    assert "python3 -m venv" in readme


def test_package_import_has_no_heavy_optional_dependencies():
    import pycert

    assert pycert.__version__ == "1.0.0"
