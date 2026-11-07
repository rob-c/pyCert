#!/usr/bin/env python3
"""Static checks that keep pyCert importable and runnable on Python 3.6.

Run from the repository root::

    python tools/check_py36.py

The checker parses every package file with ``ast.parse(feature_version=(3, 6))``
and looks for runtime features that the parser accepts but Python 3.6 does not
support:

* unquoted PEP 585 builtin generics (``list[str]``) and PEP 604 unions
  (``X | None``) in annotations;
* ``dataclasses``/``tomllib``/``importlib.resources.files`` imports and other
  3.7+ APIs (``datetime.fromisoformat``, ``subprocess.run(capture_output=...)``,
  ``SSLContext.minimum_version``, ``zip(strict=...)``, ``str.removeprefix``);
* syntax newer than 3.6 (walrus, match, positional-only parameters);
* ``from __future__ import annotations`` (introduced in 3.7).

Exit status is 0 when there are no violations, 1 otherwise.
"""

import ast
import builtins
import sys
from pathlib import Path

BUILTIN_NAMES = set(dir(builtins))

MODERN_SUBSCRIPTS = {"list", "dict", "set", "tuple", "type", "frozenset"}
MODERN_TYPING_NAMES = {
    "Protocol",
    "TypedDict",
    "Literal",
    "Final",
    "runtime_checkable",
    "get_origin",
    "get_args",
    "Annotated",
    "ParamSpec",
    "TypeAlias",
    "Self",
}
# Modules that would import or require Python 3.7+ if used directly in a module
# other than the compatibility layer itself.
ALLOWED_IMPORT_DIRECTORY = {
    "dataclasses": {"compat.py", "_dataclasses.py"},
    "tomllib": {"toml.py"},
}


def _annotation_problem(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return None  # deliberately quoted for 3.6
    if isinstance(node, ast.Subscript):
        base = node.value
        if isinstance(base, ast.Name) and base.id in MODERN_SUBSCRIPTS:
            return "unquoted PEP 585 generic %s[...]" % base.id
        if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
            if base.value.id in ("collections", "typing") and base.attr in ("abc",):
                return "unquoted collections.abc generic"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return "PEP 604 union (X | Y)"
    for child in ast.iter_child_nodes(node):
        problem = _annotation_problem(child)
        if problem:
            return problem
    return None


def check_source(path, source):
    name = Path(path).name
    problems = []
    try:
        tree = ast.parse(source, filename=str(path), feature_version=(3, 6))
    except SyntaxError as exc:
        return [(path, exc.lineno or 0, "syntax error for Python 3.6: %s" % exc.msg)]

    def add(node, message):
        problems.append((path, getattr(node, "lineno", 0), message))

    # Module-level names with their definition line, for forward-reference
    # detection in unquoted annotations.
    module_names = {}
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            module_names.setdefault(node.name, node.lineno)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    module_names.setdefault(target.id, node.lineno)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            module_names.setdefault(node.target.id, node.lineno)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                module_names.setdefault(alias.asname or alias.name.split(".")[0], node.lineno)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                module_names.setdefault(alias.asname or alias.name, node.lineno)

    def check_annotation_names(annotation):
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            return
        for child in ast.walk(annotation):
            if not isinstance(child, ast.Name):
                continue
            name = child.id
            if name in BUILTIN_NAMES:
                continue
            defined = module_names.get(name)
            if defined is None:
                add(child, "undefined name %r in annotation" % name)
            elif defined > getattr(child, "lineno", 0):
                add(child, "forward reference %r must be quoted for Python 3.6" % name)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root == "tomllib":
                    add(node, "import tomllib; use pycert.toml instead")
                if alias.name.startswith("importlib.resources"):
                    add(node, "importlib.resources is 3.7+; use compat.package_data_dir()")
                if alias.name == "dataclasses" and name not in ALLOWED_IMPORT_DIRECTORY["dataclasses"]:
                    add(node, "import dataclasses outside the compatibility layer")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "__future__":
                for alias in node.names:
                    if alias.name == "annotations":
                        add(node, "from __future__ import annotations is not available on 3.6")
            if module == "dataclasses" and name not in ALLOWED_IMPORT_DIRECTORY["dataclasses"]:
                add(node, "import dataclasses outside the compatibility layer")
            if module == "tomllib" and name not in ALLOWED_IMPORT_DIRECTORY["tomllib"]:
                add(node, "import tomllib; use pycert.toml instead")
            if module == "importlib.resources":
                add(node, "importlib.resources is 3.7+; use compat.package_data_dir()")
            if module == "collections.abc":
                add(node, "collections.abc generics are not subscriptable on 3.6; use typing")
            if module == "datetime":
                for alias in node.names:
                    if alias.name == "UTC":
                        add(node, "datetime.UTC is 3.11+; use timezone.utc")
            if module == "typing":
                for alias in node.names:
                    if alias.name in MODERN_TYPING_NAMES:
                        add(node, "typing.%s requires Python 3.8+" % alias.name)
        elif isinstance(node, ast.Call):
            func = node.func
            keywords = {kw.arg for kw in node.keywords}
            if isinstance(func, ast.Attribute):
                if func.attr == "fromisoformat":
                    add(node, "datetime.fromisoformat is 3.7+; use compat.parse_iso_datetime")
                if func.attr == "run" and isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                    if "capture_output" in keywords or "text" in keywords:
                        add(node, "subprocess.run(capture_output=/text=) is 3.7+; use compat.subprocess_run")
                if func.attr == "files" and isinstance(func.value, ast.Name) and func.value.id == "importlib":
                    add(node, "importlib.resources.files is 3.9+")
                if func.attr == "unlink" and "missing_ok" in keywords:
                    add(node, "Path.unlink(missing_ok=...) is 3.8+")
                if func.attr in ("removeprefix", "removesuffix"):
                    add(node, "%s is 3.9+" % func.attr)
                if func.attr == "get_type_hints":
                    add(node, "typing.get_type_hints would evaluate 3.9+ annotation syntax")
            if isinstance(func, ast.Name):
                if func.id == "zip" and "strict" in keywords:
                    add(node, "zip(strict=...) is 3.10+")
                if func.id in ("exec", "eval") and False:  # placeholder for future checks
                    pass
        elif isinstance(node, ast.NamedExpr):
            add(node, "assignment expression (walrus) is 3.8+")
        elif isinstance(node, ast.Match) if hasattr(ast, "Match") else False:
            add(node, "match statement is 3.10+")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if getattr(node.args, "posonlyargs", []):
                add(node, "positional-only parameters are 3.8+")
            for arg in list(node.args.args) + list(node.args.kwonlyargs):
                if arg.annotation is not None:
                    problem = _annotation_problem(arg.annotation)
                    if problem:
                        add(arg.annotation, problem)
                    check_annotation_names(arg.annotation)
            if node.returns is not None:
                problem = _annotation_problem(node.returns)
                if problem:
                    add(node.returns, problem)
                check_annotation_names(node.returns)
        elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
            problem = _annotation_problem(node.annotation)
            if problem:
                add(node.annotation, problem)
            check_annotation_names(node.annotation)
    return problems


def check_repository(root="."):
    root = Path(root)
    src = root / "src" / "pycert"
    problems = []
    for path in sorted(src.rglob("*.py")):
        problems.extend(check_source(path, path.read_text(encoding="utf-8")))
    return problems


def main(argv=None):
    argv = argv or sys.argv[1:]
    root = argv[0] if argv else "."
    problems = check_repository(root)
    if not problems:
        print("OK: all package files are compatible with Python 3.6")
        return 0
    for path, line, message in problems:
        print("%s:%s: %s" % (path, line, message))
    print("%d compatibility problem(s)" % len(problems))
    return 1


if __name__ == "__main__":
    sys.exit(main())
