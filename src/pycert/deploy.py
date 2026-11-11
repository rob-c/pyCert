"""Deploy issued certificates to the places services read them from.

A certificate can have any number of *deployment targets*, stored with the
request (``state.deploy``).  Each target names the files to write and an
optional hook to run afterwards::

    {
      "name": "grid",
      "cert": "/etc/grid-security/hostcert.pem",
      "key": "/etc/grid-security/hostkey.pem",
      "cert_mode": "0644", "key_mode": "0400",
      "owner": "root", "group": "root",
      "hook": "systemctl reload xrootd"
    }

Supported file kinds: ``cert`` (leaf), ``key`` (private key, PEM), ``chain``
(issuers), ``fullchain`` (leaf + issuers), ``bundle`` (key + leaf + issuers in
one PEM) and ``p12`` (a PKCS#12 copy).  **Private keys are always encrypted**
with the saved secret (``pycert secret get --show``): pyCertWiz never writes an
unprotected key, so the service must be given the passphrase (nginx
``ssl_password_file``, Apache ``SSLPassPhraseDialog``...).

Targets are deployed automatically after a certificate is downloaded or
renewed, and on demand with ``pycert deploy run``.  Every file is written
atomically with an explicit mode (keys never wider than 0640), the previous
file can be kept as ``<name>.bak``, and the hook runs only after every file of
the target has been written.  Hooks are split with :func:`shlex.split` and run
without a shell, with a timeout.

Presets cover the common layouts (``grid-host``, ``globus-user``, ``nginx``,
``apache``); see :data:`PRESETS`.
"""

import os
import shlex
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import certs
from .errors import CryptoError, NotFound, PyCertError
from .util import atomic_write, command_problem, ensure_dir, iso

Progress = Callable[[str], None]

FILE_KINDS = ("cert", "key", "chain", "fullchain", "bundle", "p12")
_KEY_KINDS = ("key", "bundle", "p12")
_DEFAULT_MODES = {"cert": "0644", "chain": "0644", "fullchain": "0644", "key": "0600", "bundle": "0600", "p12": "0600"}
_ALLOWED_KEYS = set(FILE_KINDS) | {
    "name",
    "cert_mode",
    "key_mode",
    "owner",
    "group",
    "hook",
    "hook_timeout",
    "backup",
    "unencrypted_key",
    "unencrypted_key_confirmed",
    "last_deployed",
    "last_sha256",
    "last_error",
}

#: Ready-made layouts.  ``{dir}`` is replaced by the chosen directory.
PRESETS: "dict[str, dict[str, Any]]" = {
    "grid-host": {
        "description": "IGTF grid host layout: /etc/grid-security/hostcert.pem + hostkey.pem",
        "dir": "/etc/grid-security",
        "cert": "{dir}/hostcert.pem",
        "key": "{dir}/hostkey.pem",
        "cert_mode": "0644",
        "key_mode": "0400",
    },
    "globus-user": {
        "description": "Globus/GSI user layout: ~/.globus/usercert.pem + userkey.pem",
        "dir": "~/.globus",
        "cert": "{dir}/usercert.pem",
        "key": "{dir}/userkey.pem",
        "cert_mode": "0644",
        "key_mode": "0400",
    },
    "nginx": {
        "description": "nginx: fullchain.pem + privkey.pem (reload nginx afterwards)",
        "dir": "/etc/nginx/ssl",
        "fullchain": "{dir}/{name}.fullchain.pem",
        "key": "{dir}/{name}.key",
        "key_mode": "0600",
        "hook": "systemctl reload nginx",
    },
    "apache": {
        "description": "Apache httpd: cert, chain and key files (reload httpd afterwards)",
        "dir": "/etc/pki/tls",
        "cert": "{dir}/certs/{name}.crt",
        "chain": "{dir}/certs/{name}.chain.crt",
        "key": "{dir}/private/{name}.key",
        "key_mode": "0600",
        "hook": "systemctl reload httpd",
    },
}


@dataclass
class DeployResult:
    target: str
    written: "list[str]" = field(default_factory=list)
    hook: str = ""
    hook_output: str = ""
    ok: bool = True
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "written": list(self.written),
            "hook": self.hook,
            "hook_output": self.hook_output,
            "ok": self.ok,
            "error": self.error,
        }


def _noop(_message: str) -> None:
    pass


def _mode(value: Any, default: str) -> int:
    text = str(value or default)
    try:
        mode = int(text, 8)
    except ValueError as exc:
        raise PyCertError(f"invalid file mode {text!r} (use octal, e.g. 0644)") from exc
    if not 0 <= mode <= 0o777:
        raise PyCertError(f"invalid file mode {text!r}")
    return mode


def _path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value)))


def validate_target(target: dict) -> dict:
    """Check a target definition and return a normalised copy."""
    if not isinstance(target, dict):
        raise PyCertError("a deployment target must be a table/dict")
    unknown = set(target) - _ALLOWED_KEYS
    if unknown:
        raise PyCertError(f"unknown deployment setting(s): {', '.join(sorted(unknown))}")
    name = str(target.get("name") or "").strip()
    if not name:
        raise PyCertError("a deployment target needs a name")
    if not any(target.get(kind) for kind in FILE_KINDS):
        raise PyCertError(f"deployment target '{name}' writes no files (set cert, key, fullchain, ...)")
    normal = dict(target)
    normal["name"] = name
    for kind in FILE_KINDS:
        value = normal.get(kind)
        if value:
            path = _path(str(value))
            if not path.is_absolute():
                raise PyCertError(f"deployment target '{name}': {kind} path must be absolute: {value}")
            normal[kind] = str(value)
    cert_mode = _mode(normal.get("cert_mode"), "0644")
    key_mode = _mode(normal.get("key_mode"), "0600")
    if key_mode & 0o037:
        raise PyCertError(
            f"deployment target '{name}': key_mode {oct(key_mode)} would let other users read the private key "
            "(use 0600, 0400 or 0640 at most)"
        )
    if normal.get("unencrypted_key") is not None:
        if normal["unencrypted_key"] is not True:
            normal.pop("unencrypted_key")
            normal.pop("unencrypted_key_confirmed", None)
        elif not normal.get("key") or normal.get("bundle"):
            raise PyCertError(
                f"deployment target '{name}': only a single 'key' file can be written without a passphrase; "
                "bundles are always encrypted"
            )
        elif not normal.get("unencrypted_key_confirmed"):
            raise PyCertError(
                f"deployment target '{name}': writing the key without a passphrase needs an explicit confirmation"
            )
    normal["cert_mode"] = f"0{cert_mode:o}"
    normal["key_mode"] = f"0{key_mode:o}"
    timeout = normal.get("hook_timeout", 120)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= float(timeout) <= 3600:
        raise PyCertError(f"deployment target '{name}': hook_timeout must be between 1 and 3600 seconds")
    if normal.get("hook"):
        try:
            argv = shlex.split(str(normal["hook"]))
        except ValueError as exc:
            raise PyCertError(f"deployment target '{name}': cannot parse the hook command: {exc}") from exc
        if not argv:
            raise PyCertError(f"deployment target '{name}': the hook command is empty")
    return normal


def target_from_preset(
    preset: str,
    *,
    name: str = "",
    directory: str = "",
    alias: str = "",
    hook: "str | None" = None,
    owner: str = "",
    group: str = "",
    per_certificate_dir: bool = False,
) -> dict:
    """Build a target from one of :data:`PRESETS`.

    Presets with fixed file names (``grid-host``, ``globus-user``) would make
    several certificates overwrite each other; with *per_certificate_dir*
    (used for bulk requests) each certificate gets its own sub-directory.
    """
    if preset not in PRESETS:
        raise PyCertError(f"unknown deployment preset {preset!r} (choose from {', '.join(PRESETS)})")
    template = dict(PRESETS[preset])
    template.pop("description", None)
    base = directory or template.pop("dir")
    template.pop("dir", None)
    slug = (alias or name or preset).replace(" ", "_").replace("/", "-")
    fixed_names = not any("{name}" in str(value) for key, value in template.items() if key in FILE_KINDS)
    if per_certificate_dir and fixed_names:
        base = f"{str(base).rstrip('/')}/{slug}"
    target: "dict[str, Any]" = {"name": name or preset}
    for key, value in template.items():
        if isinstance(value, str) and key in FILE_KINDS:
            target[key] = value.format(dir=str(base).rstrip("/"), name=slug)
        else:
            target[key] = value
    if hook is not None:
        target["hook"] = hook
    if owner:
        target["owner"] = owner
    if group:
        target["group"] = group
    return validate_target(target)


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------


def _ensure_parent(directory: Path, mode: int) -> None:
    """Create a missing target directory with *mode*.

    An existing directory (``/etc/grid-security``, ``/etc/nginx/ssl``...) keeps
    its mode: tightening it would lock other services out of files they need,
    such as the CA certificates next to a host certificate.
    """
    if not directory.exists():
        ensure_dir(directory, mode)


def _write(path: Path, data: "str | bytes", mode: int, target: dict, written: "list[str]") -> None:
    if path.is_symlink():
        raise PyCertError(f"refusing to replace {path}: it is a symbolic link")
    try:
        _ensure_parent(path.parent, 0o755 if mode & 0o044 else 0o700)
        if target.get("backup", True) and path.is_file():
            backup = path.with_name(path.name + ".bak")
            try:
                shutil.copy2(path, backup)
                os.chmod(backup, os.stat(path).st_mode & 0o777)
            except OSError:
                pass
        atomic_write(path, data, mode=mode)
    except OSError as exc:
        raise PyCertError(f"cannot write {path}: {exc}") from exc
    owner, group = target.get("owner") or None, target.get("group") or None
    if owner or group:
        try:
            shutil.chown(path, user=owner, group=group)
        except (PermissionError, LookupError, OSError) as exc:
            raise PyCertError(f"cannot set the owner/group of {path} to {owner or '-'}:{group or '-'}: {exc}") from exc
    written.append(str(path))


def _run_hook(command: str, timeout: float, progress: Progress) -> str:
    argv = shlex.split(command)
    problem = command_problem(argv[0])  # validate_target() guarantees a program name
    if problem.startswith("not found"):
        raise PyCertError(f"deploy hook not found: {argv[0]}")
    if problem:
        raise PyCertError(f"deploy hook could not be run ({problem}): {command}")
    progress(f"Running deploy hook: {command}")
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise PyCertError(f"deploy hook not found: {argv[0]}") from exc
    except OSError as exc:
        raise PyCertError(f"deploy hook could not be run ({exc}): {command}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PyCertError(f"deploy hook timed out after {timeout:.0f}s: {command}") from exc
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise PyCertError(f"deploy hook failed (exit {result.returncode}): {command}\n{output[-2000:]}")
    return output[-2000:]


def deploy_target(ctx: Any, state: Any, target: dict, *, progress: Progress = _noop, run_hook: bool = True) -> DeployResult:
    """Write the files of one target and run its hook."""
    target = validate_target(target)
    result = DeployResult(target=target["name"])
    try:
        certificate = ctx.store.load_certificate(state)
    except NotFound as exc:
        raise PyCertError(f"'{state.alias}' has no certificate to deploy yet") from exc
    chain_certs = ctx.store.load_chain(state)
    # During a renewal the current (still valid) key and certificate are deployed;
    # the new pair replaces them only once it has been issued and verified.
    key = ctx.store.load_key(state, ctx.key_passphrase())
    if not certs.certificate_matches_key(certificate, key):
        raise CryptoError(f"the stored key for '{state.alias}' does not match its certificate; not deploying")
    cert_mode = _mode(target.get("cert_mode"), "0644")
    key_mode = _mode(target.get("key_mode"), "0600")
    # Keys are never written unprotected: the saved secret encrypts them.
    key_password = ctx.p12_passphrase()
    leaf = certs.cert_pem(certificate)
    issuers = certs.certs_pem(chain_certs)
    progress(f"Deploying '{state.alias}' to target '{target['name']}'...")
    if target.get("cert"):
        _write(_path(target["cert"]), leaf, cert_mode, target, result.written)
    if target.get("chain"):
        _write(_path(target["chain"]), issuers, cert_mode, target, result.written)
    if target.get("fullchain"):
        _write(_path(target["fullchain"]), leaf + issuers, cert_mode, target, result.written)
    if target.get("key"):
        if target.get("unencrypted_key") is True and target.get("unencrypted_key_confirmed"):
            key_text = certs.unprotected_key_pem(key, confirmed=True)  # the user's confirmed choice
        else:
            key_text = certs.key_pem(key, key_password)
        _write(_path(target["key"]), key_text, key_mode, target, result.written)
    if target.get("bundle"):
        _write(_path(target["bundle"]), certs.key_pem(key, key_password) + leaf + issuers, key_mode, target, result.written)
    if target.get("p12"):
        from . import p12 as p12_module

        out = _path(target["p12"])
        if out.is_symlink():
            raise PyCertError(f"refusing to replace {out}: it is a symbolic link")
        try:
            _ensure_parent(out.parent, 0o700)
            p12_module.write_pkcs12(
                out,
                key=key,
                certificate=certificate,
                chain=chain_certs,
                password=ctx.p12_passphrase(),
                friendly_name=state.cn,
            )
            os.chmod(out, key_mode)
        except OSError as exc:
            raise PyCertError(f"cannot write {out}: {exc}") from exc
        result.written.append(str(out))
    for path in result.written:
        progress(f"  wrote {path}")
    if run_hook and target.get("hook"):
        result.hook = str(target["hook"])
        result.hook_output = _run_hook(result.hook, float(target.get("hook_timeout", 120)), progress)
    return result


def deploy_state(
    ctx: Any,
    state: Any,
    *,
    names: "list[str] | None" = None,
    progress: Progress = _noop,
    run_hooks: bool = True,
) -> "list[DeployResult]":
    """Deploy *state* to all (or the named) targets and record the outcome.

    Raises :class:`PyCertError` if any target failed, after attempting all of
    them; the per-target results are recorded in ``state.deploy``.
    """
    targets = state.deploy
    if names:
        missing = set(names) - {t.get("name") for t in targets}
        if missing:
            raise PyCertError(f"'{state.alias}' has no deployment target(s) {', '.join(sorted(missing))}")
        targets = [t for t in targets if t.get("name") in names]
    if not targets:
        raise PyCertError(f"'{state.alias}' has no deployment targets (see 'pycert deploy add')")
    results: "list[DeployResult]" = []
    fingerprint = state.cert.sha256
    for target in targets:
        try:
            result = deploy_target(ctx, state, target, progress=progress, run_hook=run_hooks)
            target["last_deployed"] = iso()
            target["last_sha256"] = fingerprint
            target.pop("last_error", None)
        except PyCertError as exc:
            result = DeployResult(target=str(target.get("name")), ok=False, error=str(exc))
            target["last_error"] = str(exc)[:500]
            progress(f"deployment to '{target.get('name')}' failed: {exc}")
        results.append(result)
    state.touch()
    ctx.store.save(state)
    failed = [r for r in results if not r.ok]
    if failed:
        raise PyCertError("; ".join(f"{r.target}: {r.error}" for r in failed))
    return results


def add_target(ctx: Any, state: Any, target: dict) -> dict:
    target = validate_target(target)
    if any(existing.get("name") == target["name"] for existing in state.deploy):
        raise PyCertError(f"'{state.alias}' already has a deployment target called '{target['name']}'")
    state.deploy.append(target)
    ctx.store.save(state)
    return target


def remove_target(ctx: Any, state: Any, name: str) -> None:
    before = len(state.deploy)
    state.deploy = [t for t in state.deploy if t.get("name") != name]
    if len(state.deploy) == before:
        raise PyCertError(f"'{state.alias}' has no deployment target called '{name}'")
    ctx.store.save(state)


# ---------------------------------------------------------------------------
# Drift detection (used by 'pycert check' and the GUI)
# ---------------------------------------------------------------------------


@dataclass
class DriftItem:
    target: str
    path: str
    problem: str

    def as_dict(self) -> dict:
        return {"target": self.target, "path": self.path, "problem": self.problem}


def check_drift(ctx: Any, state: Any) -> "list[DriftItem]":
    """Compare deployed certificate files with the stored certificate.

    Only public files (cert / fullchain) are compared; key files are checked
    for existence and permissions, never read.
    """
    problems: "list[DriftItem]" = []
    if not state.deploy or not state.cert.sha256:
        return problems
    for target in state.deploy:
        name = str(target.get("name"))
        for kind in ("cert", "fullchain"):
            value = target.get(kind)
            if not value:
                continue
            path = _path(value)
            if not path.is_file():
                problems.append(DriftItem(name, str(path), "missing"))
                continue
            try:
                deployed = certs.load_certificates(path.read_bytes())[0]
            except (OSError, CryptoError) as exc:
                problems.append(DriftItem(name, str(path), f"unreadable: {exc}"))
                continue
            if certs.fingerprint(deployed) != state.cert.sha256:
                problems.append(DriftItem(name, str(path), "out of date (differs from the stored certificate)"))
        for kind in ("key", "bundle"):
            value = target.get(kind)
            if not value:
                continue
            path = _path(value)
            if not path.is_file():
                problems.append(DriftItem(name, str(path), "missing"))
                continue
            mode = path.stat().st_mode & 0o777
            if mode & 0o037:
                problems.append(DriftItem(name, str(path), f"private key file has mode {oct(mode)}"))
        if target.get("last_error"):
            problems.append(DriftItem(name, "", f"last deployment failed: {target['last_error']}"))
    return problems
