"""Storage and retrieval of the saved PKCS#12/key passphrase.

pyCert must be able to produce a ``.p12`` unattended, so the passphrase has to
be stored somewhere.  Five backends are supported, in decreasing order of
preference:

``keychain``
    macOS login keychain, via ``/usr/bin/security -i``.  The secret is passed on
    stdin, so it never appears in the process list.
``secret-service``
    Freedesktop Secret Service (GNOME Keyring, KWallet) via ``secret-tool``.
``command``
    Any external password manager (``op read``, ``pass show``, ``gopass``, ...).
    pyCert runs the command and reads the secret from stdout (or writes it to
    stdin when storing).  The command comes from the configuration, so only use
    a configuration file you trust.
``file``
    A JSON file with mode 0600 in the data directory.  This is *not*
    encryption; it only prevents other users on the machine from reading the
    secret.  pyCert warns when it creates one.
``env`` / ``prompt``
    Read-only backends for CI and interactive use.

``auto`` picks keychain, then secret-service, then file.  The choice is recorded
in the configuration so behaviour is reproducible.
"""

import getpass
import json
import os
import platform
import secrets
import shutil
import sys
from pathlib import Path

from .compat import subprocess_run
from .config import SecretConfig
from .errors import SecretError
from .util import atomic_write, check_private_permissions, ensure_dir, read_private_file

__all__ = ["SecretStore", "generate_secret", "BACKENDS"]

BACKENDS = ("auto", "keychain", "secret-service", "file", "command", "env", "prompt")

# Characters allowed in a secret stored via the macOS security(1) command
# interpreter.  Quoting rules there are minimal, so refuse anything that could
# be misparsed rather than risk writing a truncated secret.
_KEYCHAIN_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-=+[]{}:,.?/|~")


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

    # -- backends ----------------------------------------------------------
    def _resolve_backend(self) -> str:
        requested = self.config.backend
        if requested != "auto":
            self._require_available(requested)
            return requested
        if platform.system() == "Darwin" and shutil.which("security"):
            return "keychain"
        if shutil.which("secret-tool"):
            return "secret-service"
        return "file"

    def _require_available(self, backend: str) -> None:
        if backend == "keychain" and not shutil.which("security"):
            raise SecretError("the 'security' command is required for the keychain backend")
        if backend == "secret-service" and not shutil.which("secret-tool"):
            raise SecretError("'secret-tool' is required for the secret-service backend")
        if backend == "command" and not self.config.command:
            raise SecretError("secrets.command is empty")

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
        existing = self.get(account, allow_missing=True)
        if existing:
            return existing
        if self.backend in ("env", "prompt"):
            raise SecretError(
                f"the {self.backend} backend cannot generate a secret; set the environment "
                "variable or run 'pycert secret set --backend file'"
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
        if not path.is_file():
            return {}
        for warning in check_private_permissions(path):
            print(f"warning: {warning}", file=sys.stderr)
        try:
            return json.loads(read_private_file(path).decode("utf-8"))
        except (OSError, ValueError) as exc:
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
        if self.backend == "keychain":
            result = subprocess_run(
                ["security", "find-generic-password", "-a", account, "-s", self.service, "-w"],
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
            return result.stdout[:-1] if result.stdout.endswith("\n") else result.stdout
        if self.backend == "secret-service":
            result = subprocess_run(
                ["secret-tool", "lookup", "service", self.service, "account", account],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return result.stdout.rstrip("\n")
        if self.backend == "command":
            result = subprocess_run(self.config.command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                return None
            value = result.stdout.strip()
            return value or None
        if self.backend == "env":
            return os.environ.get(self.config.env_var)
        if self.backend == "prompt":
            return getpass.getpass(f"Passphrase for {self.service}/{account}: ")
        raise SecretError(f"unknown backend: {self.backend}")

    def _set(self, account: str, value: str) -> None:
        key = f"{self.service}/{account}"
        if self.backend == "file":
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
            bad = set(value) - _KEYCHAIN_SAFE
            if bad:
                raise SecretError(
                    "the keychain backend cannot store secrets containing "
                    f"{''.join(sorted(bad))!r}; use a generated secret or another backend"
                )
            command = f'add-generic-password -U -a {_quote(account)} -s {_quote(self.service)} -w "{value}"\n'
            result = subprocess_run(["security", "-i"], input=command, capture_output=True, text=True)
            if result.returncode != 0:
                raise SecretError(
                    "could not store the secret in the keychain "
                    f"({result.stderr.strip() or result.stdout.strip()}); is the login keychain unlocked?"
                )
            return
        if self.backend == "secret-service":
            result = subprocess_run(
                [
                    "secret-tool",
                    "store",
                    f"--label=pyCert {self.service} {account}",
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
            result = subprocess_run(
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
        if self.backend == "file":
            data = self._read_file()
            if key not in data:
                return False
            del data[key]
            self._write_file(data)
            return True
        if self.backend == "keychain":
            result = subprocess_run(
                ["security", "delete-generic-password", "-a", account, "-s", self.service],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        if self.backend == "secret-service":
            result = subprocess_run(
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
