"""Static Python 3.6 checks for the third-round code."""

import ast
import configparser
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import check_py36  # noqa: E402


def test_repository_is_still_py36_clean():
    assert check_py36.check_repository(ROOT) == []


def test_new_modules_parse_as_py36():
    for name in ("transport.py", "toml.py", "compat.py", "diagnostics.py", "pkcs12_writer.py", "asn1.py"):
        path = ROOT / "src" / "pycert" / name
        ast.parse(path.read_text(), filename=str(path), feature_version=(3, 6))


def test_watch_and_renew_due_annotations_are_quoted():
    source = (ROOT / "src" / "pycert" / "workflow.py").read_text()
    assert 'max_cycles: "int | None"' in source
    assert "WatchReport" in source


def test_no_dataclasses_or_tomllib_imports_in_package():
    for path in (ROOT / "src" / "pycert").glob("*.py"):
        if path.name in ("compat.py", "_dataclasses.py", "toml.py"):
            continue
        source = path.read_text()
        assert "from dataclasses import" not in source
        assert "import tomllib" not in source


def test_packaging_requires_36_and_cryptography_3():
    parser = configparser.ConfigParser()
    parser.read(str(ROOT / "setup.cfg"))
    assert parser["options"]["python_requires"] == ">=3.6"
    assert "cryptography>=3.0" in parser["options"]["install_requires"]


def test_build_markers_support_old_setuptools():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert any("59.6" in item for item in data["build-system"]["requires"])


def test_compat_fallback_dataclass_is_importable():
    from pycert._dataclasses import dataclass

    @dataclass
    class Item:
        value: int = 1

    assert Item().value == 1


def test_asn1_encoder_is_py36_clean():
    from pycert import asn1

    assert asn1.integer(1) == b"\x02\x01\x01"


def test_pkcs12_kdf_known_vector_still_matches():
    from pycert.pkcs12_writer import pkcs12_kdf

    assert (
        pkcs12_kdf(b"\x00\x00", bytes.fromhex("f37e05b518324b4b"), 1, 2048, 24, "sha1").hex()
        == "00f759ff47d14dd03665d5943cb3c4a39a2555c02aed66e1"
    )


def test_transport_is_importable_without_modern_typing():
    from pycert.transport import TransportConfig

    assert TransportConfig().retries >= 0


def test_cli_entrypoints_declared():
    parser = configparser.ConfigParser()
    parser.read(str(ROOT / "setup.cfg"))
    scripts = parser["options.entry_points"]["console_scripts"]
    assert "pycert = pycert.cli:main" in scripts
    assert "pycert-gui = pycert.gui:main" in scripts


def test_version_consistency():
    import pycert

    parser = configparser.ConfigParser()
    parser.read(str(ROOT / "setup.cfg"))
    assert parser["metadata"]["version"] == pycert.__version__


def test_docs_mention_watch_and_due():
    readme = (ROOT / "README.md").read_text()
    assert "pycert watch" in readme
    assert "pycert renew --due" in readme
