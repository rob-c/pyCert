"""Storage and retrieval of the saved PKCS#12/key passphrase.

pyCertWiz must be able to produce a ``.p12`` unattended, so the passphrase has to
be stored somewhere.  Five backends are supported, in decreasing order of
preference:

``keychain``
    macOS login keychain, via ``/usr/bin/security -i``.  The secret is passed on
    stdin, so it never appears in the process list.
``secret-service``
    Freedesktop Secret Service (GNOME Keyring, KWallet) via ``secret-tool``.
``keyring``
    The cross-platform :mod:`keyring` library (``pip install 'pyCertWiz[keyring]'``):
    macOS Keychain, Freedesktop Secret Service, KWallet or the Windows
    Credential Locker, whichever keyring the platform provides.  It is never
    chosen by ``auto``, so an existing installation keeps finding its secret.
``command``
    Any external password manager (``op read``, ``pass show``, ``gopass``, ...).
    pyCertWiz runs the command and reads the secret from stdout (or writes it to
    stdin when storing).  The command comes from the configuration, so only use
    a configuration file you trust.
``file``
    A JSON file with mode 0600 in the data directory.  This is *not*
    encryption; it only prevents other users on the machine from reading the
    secret.  pyCertWiz warns when it creates one.
``env`` / ``prompt``
    Read-only backends for CI and interactive use.

``auto`` picks keychain, then secret-service, then file.  The choice is recorded
in the configuration so behaviour is reproducible.
"""

import contextlib
import getpass
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from .config import SecretConfig
from .errors import PyCertError, SecretError
from .util import atomic_write, check_private_permissions, ensure_dir, read_private_file

__all__ = ["SecretStore", "generate_secret", "BACKENDS"]

BACKENDS = ("auto", "keychain", "secret-service", "keyring", "file", "command", "env", "prompt")


def auto_backend() -> str:
    """The backend that ``auto`` chooses on this system."""
    if platform.system() == "Darwin" and shutil.which("security"):
        return "keychain"
    if shutil.which("secret-tool"):
        return "secret-service"
    return "file"



def _keychain_password(output: str) -> str:
    """Parse the ``password:`` line of ``security find-generic-password -g``.

    security(1) prints a printable-ASCII secret quoted (``password: "s3cr*t"``)
    and anything else as hex (``password: 0x77C3B6...  "w\303\266..."``), so
    every byte sequence round-trips unambiguously.  (``-w`` prints the latter
    as bare hex, which cannot be told apart from a secret made of hex digits.)
    """
    for line in output.splitlines():
        if not line.startswith("password:"):
            continue
        value = line[len("password:") :].lstrip(" ")
        if not value:
            return ""
        if value.startswith("0x"):
            try:
                return bytes.fromhex(value[2:].split()[0]).decode("utf-8")
            except (ValueError, IndexError, UnicodeDecodeError) as exc:
                raise SecretError(f"could not decode the secret returned by the keychain: {exc}") from exc
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        break
    raise SecretError("unexpected output from 'security find-generic-password'")


def generate_secret(length: int = 32) -> str:
    """A URL-safe, high-entropy passphrase (no quotes or backslashes)."""
    return secrets.token_urlsafe(length)


class SecretStore:
    def __init__(self, config: SecretConfig, data_dir: Path, profile: str = "default"):
        self.config = config
        self.data_dir = Path(data_dir)
        self.profile = profile
        self.service = f"{config.service}:{profile}"
        self.backend = self._resolve_backend()
        self._ensure_lock = threading.RLock()
        self._file_lock_handle = None
        self._file_lock_depth = 0

    # -- subprocess and file locking --------------------------------------
    def _subprocess(self, args, **kwargs):
        kwargs.setdefault("timeout", self.config.command_timeout)
        try:
            return subprocess.run(args, **kwargs)
        except subprocess.TimeoutExpired as exc:
            raise SecretError("secret command timed out after %.1fs" % self.config.command_timeout) from exc

    @contextlib.contextmanager
    def _file_lock(self):
        if self.backend != "file":
            yield
            return
        with self._ensure_lock:
            if self._file_lock_depth == 0:
                try:
                    import fcntl
                except ImportError:  # pragma: no cover - Windows
                    fcntl = None
                if fcntl is not None:
                    path = self.path
                    lock_path = path.with_name(path.name + ".lock")
                    ensure_dir(lock_path.parent)
                    flags = os.O_RDWR | os.O_CREAT
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    try:
                        fd = os.open(str(lock_path), flags, 0o600)
                    except OSError as exc:
                        raise SecretError("cannot lock secret file %s: %s" % (lock_path, exc))
                    self._file_lock_handle = os.fdopen(fd, "a+")
                    try:
                        fcntl.flock(self._file_lock_handle.fileno(), fcntl.LOCK_EX)
                    except BaseException:
                        self._file_lock_handle.close()
                        self._file_lock_handle = None
                        raise
                    self._file_lock_depth = 1
                else:  # pragma: no cover - Windows without fcntl
                    self._file_lock_depth = 1
            else:
                self._file_lock_depth += 1
            try:
                yield
            finally:
                self._file_lock_depth -= 1
                if self._file_lock_depth == 0 and self._file_lock_handle is not None:
                    import fcntl

                    try:
                        fcntl.flock(self._file_lock_handle.fileno(), fcntl.LOCK_UN)
                    finally:
                        self._file_lock_handle.close()
                        self._file_lock_handle = None

    # -- backends ----------------------------------------------------------
    def _resolve_backend(self) -> str:
        requested = self.config.backend
        if requested != "auto":
            self._require_available(requested)
            return requested
        return auto_backend()

    def _require_available(self, backend: str) -> None:
        if backend == "keychain" and not shutil.which("security"):
            raise SecretError("the 'security' command is required for the keychain backend")
        if backend == "secret-service" and not shutil.which("secret-tool"):
            raise SecretError("'secret-tool' is required for the secret-service backend")
        if backend == "command" and not self.config.command:
            raise SecretError("secrets.command is empty")
        if backend == "keyring":
            self._keyring()

    @staticmethod
    def _keyring():
        try:
            import keyring
            import keyring.errors
        except ImportError as exc:
            raise SecretError(
                "the keyring backend needs the 'keyring' package: pip install 'pyCertWiz[keyring]'"
            ) from exc
        return keyring

    def __str__(self) -> str:
        return f"{self.backend} ({self.service}/{self.config.account})"

    # -- public API --------------------------------------------------------
    def get(self, account: "str | None" = None, *, allow_missing: bool = False) -> "str | None":
        account = account or self.config.account
        try:
            value = self._get(account)
        except SecretError:
            if allow_missing:
                return None
            raise
        if not value:
            if allow_missing:
                return None
            raise SecretError(
                f"no saved secret for '{account}' in the {self.backend} backend.\n"
                "Run 'pycert secret set' (or use --password/--password-file)."
            )
        return value

    def set(self, value: str, account: "str | None" = None) -> None:
        if not value:
            raise SecretError("refusing to store an empty secret")
        account = account or self.config.account
        self._set(account, value)

    def delete(self, account: "str | None" = None) -> bool:
        account = account or self.config.account
        return self._delete(account)

    def exists(self, account: "str | None" = None) -> bool:
        return bool(self.get(account, allow_missing=True))

    def ensure(self, account: "str | None" = None, *, length: int = 32) -> str:
        """Return the saved secret, generating and storing one if absent."""
        account = account or self.config.account
        with self._ensure_lock, self._file_lock():
            if self.backend == "prompt":
                raise SecretError(
                    "the prompt backend cannot generate a saved secret; "
                    "run 'pycert secret set' with a persistent backend"
                )
            # Read through _get so a locked or failing backend raises instead of
            # looking "missing": generating here would overwrite the saved secret
            # and make every key encrypted with it unreadable.
            existing = self._get(account)
            if existing:
                return existing
            if self.backend == "env":
                raise SecretError(
                    "the env backend cannot generate a secret; set %s in the environment"
                    % self.config.env_var
                )
            value = generate_secret(length)
            self.set(value, account)
            return value

    def description(self) -> str:
        if self.backend == "file":
            return f"file {self.path}"
        if self.backend == "command":
            return f"command {self.config.command!r}"
        if self.backend == "env":
            return f"environment variable {self.config.env_var}"
        return self.backend

    # -- implementations ---------------------------------------------------
    @property
    def path(self) -> Path:
        if self.config.file:
            return Path(os.path.expandvars(os.path.expanduser(self.config.file)))
        return self.data_dir / "secrets.json"

    def _read_file(self) -> dict:
        path = self.path
        if path.is_symlink():
            raise SecretError("refusing to read a symlinked secret file: %s" % path)
        if not path.is_file():
            return {}
        for warning in check_private_permissions(path):
            print(f"warning: {warning}", file=sys.stderr)
        try:
            return json.loads(read_private_file(path).decode("utf-8"))
        except (OSError, ValueError, PyCertError) as exc:
            raise SecretError(f"cannot read secret file {path}: {exc}") from exc

    def _write_file(self, data: dict) -> None:
        ensure_dir(self.path.parent)
        try:
            atomic_write(self.path, json.dumps(data, indent=2, sort_keys=True) + "\n", mode=0o600)
        except OSError as exc:
            raise SecretError(f"cannot write secret file {self.path}: {exc}") from exc

    def _get(self, account: str) -> "str | None":
        key = f"{self.service}/{account}"
        if self.backend == "file":
            return self._read_file().get(key)
        if self.backend == "keyring":
            keyring = self._keyring()
            try:
                return keyring.get_password(self.service, account)
            except keyring.errors.KeyringError as exc:
                # A locked or unavailable keyring must not look like "missing":
                # ensure() would otherwise overwrite the saved secret.
                raise SecretError(f"could not read the secret from the OS keyring: {exc}") from exc
        if self.backend == "keychain":
            result = self._subprocess(
                ["security", "find-generic-password", "-a", account, "-s", self.service, "-g"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 44:  # errSecItemNotFound
                return None
            if result.returncode != 0:
                # A locked or unavailable keychain must NOT be treated as
                # "missing": ensure() would then overwrite the saved secret.
                raise SecretError(
                    "could not read the secret from the macOS keychain "
                    f"({result.stderr.strip() or 'unknown error'}); is the login keychain unlocked?"
                )
            return _keychain_password(result.stderr)
        if self.backend == "secret-service":
            result = self._subprocess(
                ["secret-tool", "lookup", "service", self.service, "account", account],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return result.stdout.rstrip("\n")
        if self.backend == "command":
            result = self._subprocess(self.config.command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                # A locked or unreachable password manager must not look like
                # "no secret saved": ensure() would then generate a new one and
                # keys would be encrypted with a passphrase nobody has.
                detail = (result.stderr or "").strip()[:200] or f"exit status {result.returncode}"
                raise SecretError(
                    f"the secret command failed ({detail}); store the passphrase in your password "
                    "manager first, or check that it is unlocked"
                )
            value = result.stdout.strip()
            return value or None
        if self.backend == "env":
            return os.environ.get(self.config.env_var)
        if self.backend == "prompt":
            return getpass.getpass(f"Passphrase for {self.service}/{account}: ")
        raise SecretError(f"unknown backend: {self.backend}")

    def _set(self, account: str, value: str) -> None:
        key = f"{self.service}/{account}"
        if self.backend == "keyring":
            keyring = self._keyring()
            try:
                keyring.set_password(self.service, account, value)
            except keyring.errors.KeyringError as exc:
                raise SecretError(f"could not store the secret in the OS keyring: {exc}") from exc
            return
        if self.backend == "file":
            with self._file_lock():
                data = self._read_file()
                if key not in data:
                    print(
                        "warning: storing the passphrase in a 0600 file (plaintext at rest).\n"
                        "         For stronger protection set secrets.backend to 'keychain', "
                        "'secret-service' or 'command'.",
                        file=sys.stderr,
                    )
                data[key] = value
                self._write_file(data)
            return
        if self.backend == "keychain":
            # -X takes the secret as hex, so any character (including quotes,
            # backslashes and non-ASCII) is stored exactly; the command goes to
            # 'security -i' on stdin, so the secret never appears in argv.
            command = (
                f"add-generic-password -U -a {_quote(account)} -s {_quote(self.service)} "
                f"-X {value.encode('utf-8').hex()}\n"
            )
            result = self._subprocess(["security", "-i"], input=command, capture_output=True, text=True)
            if result.returncode != 0:
                raise SecretError(
                    "could not store the secret in the keychain "
                    f"({result.stderr.strip() or result.stdout.strip()}); is the login keychain unlocked?"
                )
            return
        if self.backend == "secret-service":
            result = self._subprocess(
                [
                    "secret-tool",
                    "store",
                    f"--label=pyCertWiz {self.service} {account}",
                    "service",
                    self.service,
                    "account",
                    account,
                ],
                input=value,
                text=True,
                capture_output=True,
            )
            if result.returncode != 0:
                raise SecretError(f"secret-tool failed: {result.stderr.strip()}")
            return
        if self.backend == "command":
            result = self._subprocess(
                self.config.command, shell=True, input=value, text=True, capture_output=True
            )
            if result.returncode != 0:
                raise SecretError(f"secret command failed: {result.stderr.strip()}")
            return
        if self.backend == "env":
            raise SecretError(f"the env backend is read-only; export {self.config.env_var} instead")
        if self.backend == "prompt":
            raise SecretError("the prompt backend is read-only")
        raise SecretError(f"unknown backend: {self.backend}")

    def _delete(self, account: str) -> bool:
        key = f"{self.service}/{account}"
        if self.backend == "keyring":
            keyring = self._keyring()
            try:
                keyring.delete_password(self.service, account)
            except keyring.errors.PasswordDeleteError:
                return False
            except keyring.errors.KeyringError as exc:
                raise SecretError(f"could not delete the secret from the OS keyring: {exc}") from exc
            return True
        if self.backend == "file":
            with self._file_lock():
                data = self._read_file()
                if key not in data:
                    return False
                del data[key]
                self._write_file(data)
                return True
        if self.backend == "keychain":
            result = self._subprocess(
                ["security", "delete-generic-password", "-a", account, "-s", self.service],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        if self.backend == "secret-service":
            result = self._subprocess(
                ["secret-tool", "clear", "service", self.service, "account", account],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        if self.backend in ("command", "env", "prompt"):
            raise SecretError(f"the {self.backend} backend does not support deleting secrets")
        raise SecretError(f"unknown backend: {self.backend}")


def _quote(value: str) -> str:
    """Quote an argument for the security(1) command interpreter."""
    if not value or any(ch in value for ch in ' "\n\\'):
        raise SecretError(f"unsupported character in keychain identifier: {value!r}")
    return f'"{value}"'
