"""Packaging, metadata, documentation and example consistency."""

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def pyproject():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())


def test_metadata():
    project = pyproject()["project"]
    from pycert import __version__

    assert project["name"] == "pyCertWiz"
    assert project["version"] == __version__
    assert project["license"] == "GPL-2.0-or-later"


def test_python_requirement_and_dependencies():
    project = pyproject()["project"]
    assert project["requires-python"] == ">=3.10"
    dependencies = project["dependencies"]
    assert any(item.startswith("cryptography>=") for item in dependencies)
    # The core stays light: no HTTP or TLS wrapper libraries, and the GUI is optional.
    joined = " ".join(dependencies).lower()
    for heavy in ("requests", "pyopenssl", "pyside", "pyqt"):
        assert heavy not in joined
    assert any("pyside6" in item.lower() for item in project["optional-dependencies"]["gui"])


def test_console_scripts():
    project = pyproject()["project"]
    # `pycertwiz` is the new name; `pycert` stays for existing scripts and habits.
    for command in ("pycert", "pycertwiz"):
        assert project["scripts"][command] == "pycert.cli:main"
        assert project["gui-scripts"][f"{command}-gui"] == "pycert.gui:main"


def test_build_system():
    data = pyproject()
    assert any("setuptools" in requirement for requirement in data["build-system"]["requires"])
    assert data["build-system"]["build-backend"] == "setuptools.build_meta"


def test_package_data_is_present():
    data = pyproject()
    assert "data/ca/*.pem" in data["tool"]["setuptools"]["package-data"]["pycert"]
    for name in ("escience-root.pem", "escience-2b.pem", "escience-root-2026.pem", "escience-3b.pem"):
        assert (ROOT / "src" / "pycert" / "data" / "ca" / name).is_file()


def test_manifest_includes_docs_examples_tests():
    manifest = (ROOT / "MANIFEST.in").read_text()
    for token in ("docs", "examples", "tests", "pyproject.toml"):
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
    for path in (ROOT / "examples").glob("*.toml"):
        tomllib.loads(path.read_text())
    config = load_config(ROOT / "examples" / "pycert.toml")
    assert config.bundle.anchors


def test_readme_states_the_supported_python_version():
    readme = (ROOT / "README.md").read_text()
    assert "Python 3.10" in readme
    assert "Python 3.6" not in readme


def test_install_instructions_use_supported_commands():
    readme = (ROOT / "README.md").read_text()
    assert "pip install -e '.[gui]'" in readme or "pip install -e ." in readme
    assert "python3 -m venv" in readme
    # every extra mentioned in the README exists
    project = pyproject()["project"]
    for extra in ("gui", "keyring", "dev"):
        assert extra in project["optional-dependencies"]


def test_package_import_has_no_heavy_optional_dependencies():
    import subprocess
    import sys

    code = (
        "import sys, pycert, pycert.cli, pycert.workflow, pycert.providers;"
        "bad = [m for m in ('PySide6', 'keyring', 'requests') if m in sys.modules];"
        "print(','.join(bad))"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == ""


def test_help_uses_the_name_it_was_run_as(monkeypatch):
    from pycert import cli

    monkeypatch.setattr("sys.argv", ["/usr/local/bin/pycertwiz"])
    assert cli.build_parser().prog == "pycertwiz"
    monkeypatch.setattr("sys.argv", ["/opt/pycertwiz/pyCertWiz"])  # the bundled executable
    assert cli.build_parser().prog == "pycertwiz"
    monkeypatch.setattr("sys.argv", ["/usr/local/bin/pycert"])
    assert cli.build_parser().prog == "pycert"
