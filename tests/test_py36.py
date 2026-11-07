"""Checks that keep the package runnable on Python 3.6."""

import ast
import sys
import textwrap
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import check_py36  # noqa: E402


def test_all_package_files_are_python36_compatible():
    problems = check_py36.check_repository(ROOT)
    assert problems == [], "\n".join("%s:%s: %s" % p for p in problems)


def test_every_file_parses_with_the_36_grammar():
    for path in sorted((ROOT / "src" / "pycert").rglob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 6))


@pytest.mark.parametrize(
    "source,message",
    [
        ("from __future__ import annotations\n", "__future__"),
        ("def f(x: list[int]): pass\n", "PEP 585"),
        ("def f(x: dict[str, int]): pass\n", "PEP 585"),
        ("def f(x: int | None): pass\n", "PEP 604"),
        ("def f(x: Later): pass\nclass Later: pass\n", "forward reference"),
        ("def f(x: Missing): pass\n", "undefined name"),
        ("from dataclasses import dataclass\n", "dataclasses"),
        ("import tomllib\n", "tomllib"),
        ("from collections.abc import Sequence\ndef f(x: Sequence[int]): pass\n", "collections.abc"),
        ("from datetime import UTC\n", "datetime.UTC"),
        ("import subprocess\nsubprocess.run(['x'], capture_output=True)\n", "subprocess.run"),
        ("import subprocess\nsubprocess.run(['x'], text=True)\n", "subprocess.run"),
        ("from datetime import datetime\ndatetime.fromisoformat('x')\n", "fromisoformat"),
        ("import importlib.resources\nimportlib.resources.files('x')\n", "importlib.resources"),
        ("zip([1], [2], strict=True)\n", "zip(strict"),
        ("'x'.removeprefix('x')\n", "removeprefix"),
        ("def f(x, /): pass\n", "positional-only"),
        ("if (x := 1): pass\n", "assignment expressions"),
    ],
)
def test_checker_detects_incompatibility(tmp_path, source, message):
    path = tmp_path / "sample.py"
    path.write_text(textwrap.dedent(source))
    problems = check_py36.check_source(path, path.read_text())
    assert problems, "checker did not flag: %s" % source
    assert any(message.lower() in problem[2].lower() for problem in problems)


@pytest.mark.parametrize(
    "source",
    [
        "def f(x: 'list[int]'): pass\n",
        "from typing import List\ndef f(x: List[int]): pass\n",
        "from __future__ import division\n",
        "class A: pass\ndef f(x: 'A'): pass\n",
        "def f(*args, **kwargs): pass\n",
        "x: int = 1\n",
    ],
)
def test_checker_accepts_36_valid_code(tmp_path, source):
    path = tmp_path / "ok.py"
    path.write_text(source)
    assert check_py36.check_source(path, source) == []


def test_packaging_declares_python_36():
    import configparser

    parser = configparser.ConfigParser()
    parser.read(str(ROOT / "setup.cfg"))
    assert parser["options"]["python_requires"] == ">=3.6"
    assert "cryptography>=3.0" in parser["options"]["install_requires"]
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert any("59.6" in requirement for requirement in pyproject["build-system"]["requires"])


def test_no_future_annotations_anywhere():
    for path in (ROOT / "src" / "pycert").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                assert all(alias.name != "annotations" for alias in node.names)


def test_compat_exports_the_fallback_implementation():
    from pycert import compat

    assert callable(compat.dataclass)
    assert callable(compat.field)
    assert callable(compat.fallback_dataclass)
    assert callable(compat.fallback_field)


def test_toml_module_is_used_by_config():
    config_source = (ROOT / "src" / "pycert" / "config.py").read_text(encoding="utf-8")
    assert "from .toml import" in config_source
    assert "import tomllib" not in config_source


def test_version_matches_packaging():
    import configparser

    import pycert

    parser = configparser.ConfigParser()
    parser.read(str(ROOT / "setup.cfg"))
    assert parser["metadata"]["version"] == pycert.__version__
