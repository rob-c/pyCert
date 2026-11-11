"""Java PKCS#12 keystores as a live certificate store.

CertWizard keeps every certificate a person or site owns in one Java keystore,
``cakeystore.pkcs12``: one *key entry* (private key + certificate + chain) per
certificate, named by an alias.  pyCertWiz can use such a file directly:

* :class:`Keystore` reads every key entry (CertWizard's legacy RC2/3DES files,
  modern keytool/OpenSSL PBES2 files) and adds, replaces or removes single
  entries while every other entry is written back **byte for byte**, so keys
  pyCertWiz does not touch are never decrypted or re-encrypted.  New entries use
  the PBE-SHA1-3DES profile every Java release can read.
* A *linked* keystore (``[[keystores]]`` in the configuration, ``pycert
  keystore link``) is kept in step with pyCertWiz's store by :func:`sync`:
  key entries that pyCertWiz does not manage yet are imported automatically,
  certificates pyCertWiz issues or renews are written back into the keystore
  (:func:`write_state`, called after every issuance), and certificates
  renewed elsewhere (e.g. by CertWizard) are picked up.
* CertWizard stores a request that is still waiting for the CA as a key entry
  with a self-signed placeholder certificate.  Such entries are imported as
  *pending requests*: pyCertWiz polls the CA for them and, once the certificate
  is issued, replaces the placeholder in the keystore.

Keystore passphrases are **never stored**: not in the configuration, the
secret store or the environment.  A keystore is *unlocked* for the current
session only (the GUI asks at start-up, the CLI when it needs it); a locked
keystore is skipped, and certificates waiting to be written to it are reported
by ``pycert check``.  Writes take an advisory lock, refuse to overwrite a file
that changed underneath them, keep ``<file>.bak`` and preserve the file's
permissions.
"""

import contextlib
import hashlib
import json
import os
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from . import ber, bundles, certs
from .errors import CryptoError, NotFound, PyCertError, SecretError
from .pkcs12_writer import _certificate_bag, _key_bag, encode_raw_pkcs12
from .util import SECRET_FILE_MODE, atomic_write, ensure_dir, iso

try:  # POSIX advisory locking; other platforms rely on the change check only
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

Progress = Callable[[str], None]

#: PBE iterations for key bags pyCertWiz writes (3DES, readable by every Java)
KEY_BAG_ITERATIONS = 10000
_LOCAL_KEY_ID_OID = "1.2.840.113549.1.9.21"
_process_lock = threading.RLock()


def _noop(_message: str) -> None:
    pass


class KeystoreChanged(PyCertError):
    """The keystore file was modified by another program while pyCertWiz worked on it."""


class KeystoreLocked(SecretError):
    """The keystore's passphrase has not been given in this session (it is never stored)."""


# ---------------------------------------------------------------------------
# The keystore file
# ---------------------------------------------------------------------------


@dataclass
class KeystoreEntry:
    """One key entry: private key, certificate and issuer chain under an alias."""

    alias: str
    key: Any = field(repr=False)
    certificate: x509.Certificate
    chain: "list[x509.Certificate]" = field(default_factory=list)
    #: a CertWizard request still waiting for the CA (self-signed placeholder)
    pending: bool = False

    @property
    def fingerprint(self) -> str:
        return certs.fingerprint(self.certificate)

    @property
    def common_name(self) -> str:
        return certs.common_name(self.certificate.subject) or self.alias

    def as_dict(self) -> dict:
        info = certs.describe_certificate(self.certificate)
        return {
            "alias": self.alias,
            "common_name": self.common_name,
            "pending": self.pending,
            "not_after": info.not_after.isoformat(),
            "sha256": self.fingerprint,
            "key": info.key,
        }


def _bag_local_key_id(bag) -> bytes:
    for child in bag.children[2:]:
        if child.tag != 0x11:  # pragma: no cover - malformed attributes
            continue
        for attribute in child.children:
            if len(attribute.children) >= 2 and ber.decode_oid(attribute.children[0].content) == _LOCAL_KEY_ID_OID:
                values = attribute.children[1]
                if values.children:
                    return values.children[0].content
    return b""


def _cert_bag_certificate(raw: bytes) -> "x509.Certificate | None":
    try:
        bag = ber.parse(raw)
        value = bag.children[1]
        cert_bag = value.children[0] if value.children else value
        return x509.load_der_x509_certificate(ber.octets(cert_bag.children[1]))
    except (ber.BERError, IndexError, ValueError):  # pragma: no cover - malformed bag
        return None


def is_placeholder(certificate: x509.Certificate) -> bool:
    """CertWizard's stand-in certificate for a request that is not yet signed."""
    return (
        certificate.subject == certificate.issuer
        and certs.basic_constraints_ca(certificate) is not True
        and certs.is_self_signed(certificate)
    )


class Keystore:
    """A multi-entry PKCS#12 keystore that can be edited entry by entry."""

    def __init__(self, path: "str | Path", password: str):
        self.path = Path(path).expanduser()
        self.password = password
        self.entries: "list[KeystoreEntry]" = []
        #: human-readable problems with entries that could not be decoded (kept untouched)
        self.problems: "list[str]" = []
        self._key_bags: "list[bytes]" = []
        self._cert_bags: "list[bytes]" = []
        self._entry_bags: "dict[str, int]" = {}  # alias (lower) -> index into _key_bags
        self._signature: "tuple[int, int] | None" = None
        self.changed = False

    # -- loading -------------------------------------------------------------
    @classmethod
    def load(cls, path: "str | Path", password: str) -> "Keystore":
        keystore = cls(path, password)
        if keystore.path.exists():
            keystore._read()
        return keystore

    def _read(self) -> None:
        if not self.password:
            raise SecretError("the keystore passphrase is required")
        stat = self.path.stat()
        data = self.path.read_bytes()
        self._signature = (stat.st_mtime_ns, stat.st_size)
        bundle = bundles.load_bundle_bytes(data, password=self.password, path=str(self.path), prefer_raw=True)
        if bundle.format != "pkcs12":
            raise CryptoError(
                f"{self.path} is a {bundle.format.upper()} file; only PKCS#12 keystores can be used as a "
                "certificate store (convert it with the bundle inspector's 'Save as Java PKCS#12', or "
                "keytool -importkeystore -deststoretype pkcs12)"
            )
        if bundle.has_private_key and not bundle.raw_key_bags:  # pragma: no cover - layout outside the raw parser
            raise CryptoError(f"{self.path}: this PKCS#12 layout cannot be edited entry by entry")
        self._key_bags = list(bundle.raw_key_bags)
        self._cert_bags = list(bundle.raw_cert_bags)
        candidates = [entry.certificate for entry in bundle.certificates]
        for index, raw in enumerate(self._key_bags):
            node = ber.parse(raw)
            alias = bundles._bag_alias(node) or f"entry-{index + 1}"
            try:
                key = self._decrypt_key(raw)
            except (ValueError, TypeError, CryptoError) as exc:
                self.problems.append(f"entry '{alias}': the private key could not be decrypted ({exc})")
                continue
            leaf = next((c for c in candidates if certs.public_keys_equal(c, key.public_key())), None)
            if leaf is None:
                self.problems.append(f"entry '{alias}': no certificate matches its private key")
                continue
            others = [c for c in candidates if certs.fingerprint(c) != certs.fingerprint(leaf)]
            from .p12 import _ordered_chain

            entry = KeystoreEntry(
                alias=alias,
                key=key,
                certificate=leaf,
                chain=_ordered_chain(leaf, others),
                pending=is_placeholder(leaf),
            )
            if alias.lower() in self._entry_bags:
                self.problems.append(f"entry '{alias}' appears more than once; only the first is used")
                continue
            self._entry_bags[alias.lower()] = index
            self.entries.append(entry)

    def _decrypt_key(self, raw_key_bag: bytes):
        """Decrypt one shrouded key bag (3DES, RC2 or PBES2) without touching the others."""
        cert_bags = self._cert_bags or [_certificate_bag(_dummy_certificate(), "", None, False)]
        blob = encode_raw_pkcs12([raw_key_bag], cert_bags, self.password)
        key, _certificate, _extra = pkcs12.load_key_and_certificates(blob, self.password.encode("utf-8"))
        if key is None:  # pragma: no cover - a key bag always yields a key
            raise CryptoError("empty key bag")
        return key

    # -- queries -------------------------------------------------------------
    def entry(self, alias: str) -> "KeystoreEntry | None":
        needle = alias.lower()
        return next((e for e in self.entries if e.alias.lower() == needle), None)

    def entry_for(self, fingerprint: str) -> "KeystoreEntry | None":
        return next((e for e in self.entries if e.fingerprint == fingerprint), None)

    @property
    def aliases(self) -> "list[str]":
        return [entry.alias for entry in self.entries]

    # -- editing -------------------------------------------------------------
    def _cert_bag_index(self, fingerprint: str) -> "int | None":
        for index, raw in enumerate(self._cert_bags):
            certificate = _cert_bag_certificate(raw)
            if certificate is not None and certs.fingerprint(certificate) == fingerprint:
                return index
        return None

    def _certificate_in_use(self, fingerprint: str, *, except_alias: str) -> bool:
        return any(e.fingerprint == fingerprint for e in self.entries if e.alias.lower() != except_alias.lower()) or any(
            certs.fingerprint(c) == fingerprint
            for e in self.entries
            if e.alias.lower() != except_alias.lower()
            for c in e.chain
        )

    def put(self, alias: str, key: Any, certificate: x509.Certificate, chain: "list[x509.Certificate]") -> str:
        """Add or replace the entry *alias*; returns 'added', 'replaced' or 'unchanged'."""
        if not certs.certificate_matches_key(certificate, key):
            raise CryptoError("the certificate does not match the private key; not writing it to the keystore")
        existing = self.entry(alias)
        if existing is not None and existing.fingerprint == certs.fingerprint(certificate) and certs.public_keys_equal(
            existing.key.public_key(), key.public_key()
        ):
            return "unchanged"
        local_key_id = hashlib.sha1(certs.cert_der(certificate)).digest()  # noqa: S324 - an identifier, not security
        new_key_bag = _key_bag(key, self.password, KEY_BAG_ITERATIONS, alias, local_key_id, legacy=True)
        new_cert_bag = _certificate_bag(certificate, alias, local_key_id, True)
        if existing is not None:
            index = self._entry_bags[alias.lower()]
            self._key_bags[index] = new_key_bag
            if not self._certificate_in_use(existing.fingerprint, except_alias=alias):
                old = self._cert_bag_index(existing.fingerprint)
                if old is not None:
                    del self._cert_bags[old]
            self.entries.remove(existing)
            outcome = "replaced"
        else:
            self._entry_bags[alias.lower()] = len(self._key_bags)
            self._key_bags.append(new_key_bag)
            outcome = "added"
        self._cert_bags.append(new_cert_bag)
        for issuer in chain:
            if self._cert_bag_index(certs.fingerprint(issuer)) is None:
                self._cert_bags.append(_certificate_bag(issuer, "", None, False))
        self.entries.append(
            KeystoreEntry(alias=alias, key=key, certificate=certificate, chain=list(chain), pending=is_placeholder(certificate))
        )
        self.changed = True
        return outcome

    def rename(self, alias: str, new_alias: str) -> None:
        """Give the entry *alias* a new name; only that entry is re-encoded."""
        existing = self.entry(alias)
        if existing is None:
            raise NotFound(f"the keystore has no entry '{alias}'")
        if new_alias == existing.alias:
            return
        clash = self.entry(new_alias)
        if clash is not None and clash is not existing:
            raise PyCertError(f"the keystore already has an entry called '{clash.alias}'")
        self.remove(existing.alias)
        self.put(new_alias, existing.key, existing.certificate, existing.chain)

    def remove(self, alias: str) -> bool:
        existing = self.entry(alias)
        if existing is None:
            return False
        index = self._entry_bags.pop(alias.lower())
        del self._key_bags[index]
        self._entry_bags = {name: (i - 1 if i > index else i) for name, i in self._entry_bags.items()}
        self.entries.remove(existing)
        if not self._certificate_in_use(existing.fingerprint, except_alias=alias):
            old = self._cert_bag_index(existing.fingerprint)
            if old is not None:
                del self._cert_bags[old]
        self.changed = True
        return True

    # -- writing -------------------------------------------------------------
    def save(self, *, backup: bool = True) -> Path:
        if not self._cert_bags:
            raise PyCertError("refusing to write a keystore with no certificates")
        if self.path.exists():
            stat = self.path.stat()
            if self._signature is not None and (stat.st_mtime_ns, stat.st_size) != self._signature:
                raise KeystoreChanged(f"{self.path} was changed by another program; it was not overwritten")
            mode = stat.st_mode & 0o777
            if backup:
                backup_path = self.path.with_name(self.path.name + ".bak")
                shutil.copy2(self.path, backup_path)
                os.chmod(backup_path, mode)
        else:
            mode = SECRET_FILE_MODE
            if not self.path.parent.is_dir():
                ensure_dir(self.path.parent)
        blob = encode_raw_pkcs12(self._key_bags, self._cert_bags, self.password)
        atomic_write(self.path, blob, mode=mode)
        stat = self.path.stat()
        self._signature = (stat.st_mtime_ns, stat.st_size)
        self.changed = False
        return self.path


@contextlib.contextmanager
def open_keystore(path: "str | Path", password: str):
    """Load *path* under an exclusive lock and save it on exit if it was changed."""
    path = Path(path).expanduser()
    with _process_lock, _file_lock(path):
        keystore = Keystore.load(path, password)
        yield keystore
        if keystore.changed:
            keystore.save()


@contextlib.contextmanager
def _file_lock(path: Path):
    if fcntl is None or not path.parent.is_dir():  # pragma: no cover - Windows / missing directory
        yield
        return
    lock_path = path.with_name(f".{path.name}.pycert-lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError:  # pragma: no cover - read-only directory: rely on the change check
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


_DUMMY: "list[x509.Certificate]" = []


def _dummy_certificate() -> x509.Certificate:
    """A throw-away certificate so a key-only bag can be decoded by the PKCS#12 parser."""
    if not _DUMMY:  # pragma: no cover - only for keystores without certificate bags
        import datetime as dt

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pyCertWiz placeholder")])
        now = dt.datetime.now(dt.timezone.utc)
        _DUMMY.append(
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
    return _DUMMY[0]  # pragma: no cover


# ---------------------------------------------------------------------------
# Passwords and links
# ---------------------------------------------------------------------------


def _session_passwords(ctx: Any) -> dict:
    cache = getattr(ctx, "keystore_passwords", None)
    if cache is None:  # pragma: no cover - AppContext always has one
        cache = {}
        ctx.keystore_passwords = cache
    return cache


def unlock(ctx: Any, link: Any, password: str) -> "Keystore":
    """Check *password* opens the keystore and keep it in memory for this session only."""
    keystore = Keystore.load(ctx.config.resolve(link.path), password)
    _session_passwords(ctx)[link.name] = password
    return keystore


def lock(ctx: Any, name: str) -> None:
    _session_passwords(ctx).pop(name, None)


def is_unlocked(ctx: Any, name: str) -> bool:
    return name in _session_passwords(ctx)


def keystore_password(ctx: Any, link: Any) -> str:
    """The session passphrase for *link*, asking the front-end if it can; never stored."""
    cache = _session_passwords(ctx)
    if link.name in cache:
        return cache[link.name]
    ask = getattr(ctx, "ask_keystore_password", None)
    if ask is not None:
        password = ask(link)
        if password:
            unlock(ctx, link, password)
            return password
    raise KeystoreLocked(
        f"keystore '{link.name}' is locked: its passphrase is never stored, so it must be given each session "
        f"(unlock it in the GUI, or run 'pycert keystore sync {link.name}')"
    )


def link_keystore(
    ctx: Any,
    path: "str | Path",
    password: str,
    *,
    name: str = "",
    ca: str = "",
    auto_import: bool = True,
    write_back: bool = True,
    create: bool = False,
):
    """Add a ``[[keystores]]`` link (validating the passphrase, which is kept for this session only)."""
    from .config import KeystoreLink, validate_config, write_config

    resolved = Path(path).expanduser().resolve()
    if not resolved.exists() and not create:
        raise NotFound(f"keystore not found: {resolved} (use --create to start a new one)")
    keystore = Keystore.load(resolved, password)  # raises on a wrong passphrase
    name = name or _default_name(resolved, ctx.config)
    config = ctx.config
    if any(link.name == name for link in config.keystores):
        raise PyCertError(f"a keystore called '{name}' is already linked")
    if any(Path(link.path).expanduser().resolve() == resolved for link in config.keystores):
        raise PyCertError(f"{resolved} is already linked")
    link = KeystoreLink(
        name=name,
        path=str(resolved),
        ca=ca or config.primary_profile.name,
        auto_import=auto_import,
        write_back=write_back,
    )
    config.keystores.append(link)
    try:
        validate_config(config)
        write_config(config.path, config)
    except Exception:
        # Leave the in-memory configuration as it was, so a retry is possible.
        config.keystores.remove(link)
        raise
    _session_passwords(ctx)[name] = password
    return link, keystore


def unlink_keystore(ctx: Any, name: str) -> int:
    """Remove a link; returns how many stored certificates were linked to it."""
    from .config import write_config

    config = ctx.config
    link = config.keystore(name)
    config.keystores.remove(link)
    write_config(config.path, config)
    count = 0
    for state in ctx.store.list():
        if state.keystore.get("name") == name:
            with ctx.store.lock(state):
                state.keystore = {}
                state.notes.append(f"unlinked from keystore '{name}'")
                ctx.store.save(state)
            count += 1
    lock(ctx, name)
    _status_path(ctx, name).unlink(missing_ok=True)
    return count


def _default_name(path: Path, config: Any) -> str:
    import re

    base = re.sub(r"[^a-z0-9_.-]+", "-", path.stem.lower()).strip("-.") or "keystore"
    if base[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":  # pragma: no cover - stripped above
        base = "ks-" + base
    name, counter = base, 2
    existing = {link.name for link in config.keystores}
    while name in existing:
        name = f"{base}-{counter}"
        counter += 1
    return name


# ---------------------------------------------------------------------------
# Synchronisation
# ---------------------------------------------------------------------------


@dataclass
class SyncReport:
    keystore: str
    imported: "list[str]" = field(default_factory=list)
    pending: "list[str]" = field(default_factory=list)
    updated: "list[str]" = field(default_factory=list)
    written: "list[str]" = field(default_factory=list)
    unlinked: "list[str]" = field(default_factory=list)
    problems: "list[str]" = field(default_factory=list)
    skipped: bool = False
    #: the passphrase has not been given this session (it is never stored)
    locked: bool = False
    #: the keystore could not be synchronised at all (wrong passphrase, unreadable file...)
    error: str = ""

    @property
    def changes(self) -> int:
        return len(self.imported) + len(self.pending) + len(self.updated) + len(self.written) + len(self.unlinked)

    def as_dict(self) -> dict:
        return {
            "keystore": self.keystore,
            "imported": list(self.imported),
            "pending": list(self.pending),
            "updated": list(self.updated),
            "written": list(self.written),
            "unlinked": list(self.unlinked),
            "problems": list(self.problems),
            "skipped": self.skipped,
            "locked": self.locked,
            "error": self.error,
        }

    def summary(self) -> str:
        if self.locked:
            return f"{self.keystore}: locked (give its passphrase to synchronise)"
        if self.error:
            return f"{self.keystore}: not synchronised: {self.error}"
        if self.skipped:
            return f"{self.keystore}: unchanged"
        parts = [
            f"{len(items)} {label}"
            for items, label in (
                (self.imported, "imported"),
                (self.pending, "pending imported"),
                (self.updated, "updated from the keystore"),
                (self.written, "written to the keystore"),
                (self.unlinked, "unlinked"),
            )
            if items
        ]
        text = ", ".join(parts) or "in sync"
        if self.problems:
            text += f" ({len(self.problems)} problem(s))"
        return f"{self.keystore}: {text}"


def _status_path(ctx: Any, name: str) -> Path:
    return ctx.config.data_dir / "keystores" / f"{name}.json"


def _file_signature(path: Path) -> "list[int] | None":
    try:
        stat = path.stat()
    except OSError:
        return None
    return [stat.st_mtime_ns, stat.st_size]


def _linked_states(ctx: Any, name: str) -> list:
    return [s for s in ctx.store.list() if s.keystore.get("name") == name]


def _needs_write(state: Any) -> bool:
    return bool(state.cert.sha256) and state.status != "REVOKED" and not state.renewal and (
        state.keystore.get("written") != state.cert.sha256
    )


def sync_all(ctx: Any, *, progress: Progress = _noop, only_if_changed: bool = False) -> "list[SyncReport]":
    """Synchronise every linked keystore; errors are reported per keystore, never raised."""
    reports = []
    for link in ctx.config.keystores:
        try:
            reports.append(sync(ctx, link, progress=progress, only_if_changed=only_if_changed))
        except KeystoreLocked:
            reports.append(SyncReport(keystore=link.name, locked=True))
        except PyCertError as exc:
            progress(f"keystore '{link.name}': {exc}")
            reports.append(SyncReport(keystore=link.name, error=str(exc)))
    return reports


def sync(ctx: Any, link: Any, *, progress: Progress = _noop, only_if_changed: bool = False) -> SyncReport:
    """Bring pyCertWiz's store and the linked keystore *link* into agreement."""
    report = SyncReport(keystore=link.name)
    path = ctx.config.resolve(link.path)
    status_file = _status_path(ctx, link.name)
    if only_if_changed and not is_unlocked(ctx, link.name) and getattr(ctx, "ask_keystore_password", None) is None:
        report.locked = True
        return report
    if only_if_changed:
        try:
            last = json.loads(status_file.read_text())
        except (OSError, ValueError):
            last = {}
        unchanged = last.get("signature") == _file_signature(path)
        if unchanged and not any(_needs_write(s) for s in _linked_states(ctx, link.name)):
            report.skipped = True
            return report
    password = keystore_password(ctx, link)
    with open_keystore(path, password) as keystore:
        report.problems.extend(keystore.problems)
        by_alias = {s.keystore.get("alias", "").lower(): s for s in _linked_states(ctx, link.name)}
        by_fingerprint = {s.cert.sha256: s for s in ctx.store.list() if s.cert.sha256}
        by_spki = {s.active_spki_b64: s for s in ctx.store.list() if s.active_spki_b64}
        for entry in keystore.entries:
            state = by_alias.get(entry.alias.lower())
            if state is None:
                if entry.pending:
                    existing = by_spki.get(certs.spki_b64(entry.certificate))
                else:
                    existing = by_fingerprint.get(entry.fingerprint)
                if existing is not None and not existing.keystore:
                    _link_state(ctx, existing, link, entry)
                    report.updated.append(existing.alias)
                    continue
                if existing is not None:
                    continue  # managed through another keystore
                if not link.auto_import:
                    continue
                state = _import_entry(ctx, link, entry, progress)
                (report.pending if entry.pending else report.imported).append(state.alias)
                continue
            _reconcile(ctx, link, keystore, entry, state, report, progress)
        present = {entry.alias.lower() for entry in keystore.entries}
        for state in _linked_states(ctx, link.name):
            alias = state.keystore.get("alias", "")
            if alias.lower() in present:
                continue
            if state.keystore.get("written") and state.keystore.get("written") == state.cert.sha256:
                with ctx.store.lock(state):
                    state.keystore = {}
                    state.notes.append(f"removed from keystore '{link.name}' outside pyCertWiz; no longer linked")
                    ctx.store.save(state)
                report.unlinked.append(state.alias)
            elif link.write_back and _needs_write(state):
                _write_entry(ctx, keystore, state)
                report.written.append(state.alias)
    ensure_dir(status_file.parent)
    atomic_write(status_file, json.dumps({"signature": _file_signature(path), "synced_at": iso()}) + "\n")
    if report.changes:
        progress(report.summary())
    return report


def _reconcile(ctx, link, keystore, entry, state, report, progress) -> None:
    if state.renewal or state.status == "REVOKED":
        return
    if entry.fingerprint == state.cert.sha256:
        if state.keystore.get("written") != entry.fingerprint:
            with ctx.store.lock(state):
                state.keystore["written"] = entry.fingerprint
                ctx.store.save(state)
        return
    if entry.pending:
        if state.cert.sha256 and link.write_back:
            # pyCertWiz collected the certificate for a CertWizard request: replace the placeholder.
            _write_entry(ctx, keystore, state)
            report.written.append(state.alias)
        return
    keystore_newer = not state.cert.not_after or certs.not_valid_after(entry.certificate).isoformat() > state.cert.not_after
    if keystore_newer:
        _adopt(ctx, state, entry, link, progress)
        report.updated.append(state.alias)
    elif link.write_back:
        _write_entry(ctx, keystore, state)
        report.written.append(state.alias)


def _write_entry(ctx: Any, keystore: Keystore, state: Any) -> str:
    certificate = ctx.store.load_certificate(state)
    key = ctx.store.load_key(state, ctx.key_passphrase())
    chain = ctx.store.load_chain(state)
    alias = state.keystore.get("alias") or state.alias
    outcome = keystore.put(alias, key, certificate, chain)
    with ctx.store.lock(state):
        state.keystore["alias"] = alias
        state.keystore["written"] = certs.fingerprint(certificate)
        ctx.store.save(state)
    return outcome


def _link_state(ctx: Any, state: Any, link: Any, entry: KeystoreEntry) -> None:
    with ctx.store.lock(state):
        state.keystore = {"name": link.name, "alias": entry.alias, "written": "" if entry.pending else entry.fingerprint}
        state.notes.append(f"linked to keystore '{link.name}' (alias {entry.alias})")
        ctx.store.save(state)


def _unique_alias(ctx: Any, alias: str, keystore_name: str) -> str:
    candidate = alias.strip() or "entry"
    if not ctx.store.exists(candidate):
        return candidate
    candidate = f"{alias} ({keystore_name})"
    counter = 2
    while ctx.store.exists(candidate):
        candidate = f"{alias} ({keystore_name} {counter})"
        counter += 1
    return candidate


def _record_certificate(ctx: Any, state: Any, entry: KeystoreEntry, ca: str) -> None:
    from .workflow import cert_info

    result = ctx.build_chain(entry.certificate, ca, entry.chain)
    state.cert = cert_info(certs.describe_certificate(entry.certificate), result)
    state.server.start_date = certs.not_valid_before(entry.certificate).strftime("%d/%m/%Y")
    state.server.end_date = certs.not_valid_after(entry.certificate).strftime("%d/%m/%Y")
    ctx.store.save_certificate(state, entry.certificate, result.issuers or entry.chain)
    if not result.trusted:
        state.notes.extend(f"chain: {problem}" for problem in result.problems)


#: CertWizard names a pending request's self-signed placeholder "<CN> CSR cert".
PLACEHOLDER_SUFFIX = " CSR cert"


def requested_cn(entry: KeystoreEntry) -> str:
    """The common name an entry stands for (without CertWizard's placeholder suffix)."""
    cn = entry.common_name
    if entry.pending and cn.endswith(PLACEHOLDER_SUFFIX):
        cn = cn[: -len(PLACEHOLDER_SUFFIX)].strip() or cn
    return cn


def _import_entry(ctx: Any, link: Any, entry: KeystoreEntry, progress: Progress) -> Any:
    from .store import STATUS_IMPORTED, STATUS_SUBMITTED

    cn = requested_cn(entry)
    cert_type = (
        "host" if "." in cn and " " not in cn else "user"
    ) if entry.pending else certs.certificate_kind(entry.certificate, cn)
    alias = _unique_alias(ctx, entry.alias, link.name)
    state = ctx.store.new_state(alias=alias, type=cert_type, cn=cn, email="")
    state.ca = link.ca or ctx.config.primary_profile.name
    state.subject = entry.certificate.subject.rfc4514_string()
    public_key = entry.key.public_key()
    state.key_algorithm = certs.key_description(public_key)
    state.key_bits = getattr(entry.key, "key_size", 0) or 0
    state.spki_b64 = certs.spki_b64(public_key)
    state.public_key_sha256 = certs.key_fingerprint(public_key)
    state.keystore = {"name": link.name, "alias": entry.alias, "written": "" if entry.pending else entry.fingerprint}
    ctx.store.save_key(state, entry.key, ctx.key_passphrase())
    if entry.pending:
        state.submitted_at = iso()
        state.set_status(
            STATUS_SUBMITTED, f"pending request imported from keystore '{link.name}' (alias {entry.alias})"
        )
        progress(f"Imported the pending request '{entry.alias}' from keystore '{link.name}'")
    else:
        _record_certificate(ctx, state, entry, state.ca)
        state.set_status(STATUS_IMPORTED, f"imported from keystore '{link.name}' (alias {entry.alias})")
        progress(f"Imported '{entry.alias}' from keystore '{link.name}'")
    ctx.store.save(state)
    return state


def _adopt(ctx: Any, state: Any, entry: KeystoreEntry, link: Any, progress: Progress) -> None:
    """The keystore holds a newer certificate for this entry (renewed elsewhere): take it."""
    from .store import STATUS_IMPORTED

    with ctx.store.lock(state):
        if state.cert.sha256:
            ctx.store.archive_current(state)
        public_key = entry.key.public_key()
        state.spki_b64 = certs.spki_b64(public_key)
        state.public_key_sha256 = certs.key_fingerprint(public_key)
        state.key_algorithm = certs.key_description(public_key)
        state.key_bits = getattr(entry.key, "key_size", 0) or 0
        ctx.store.save_key(state, entry.key, ctx.key_passphrase())
        _record_certificate(ctx, state, entry, state.ca)
        state.p12_path = ""
        state.p12_sha256 = ""
        state.keystore["written"] = entry.fingerprint
        state.set_status(STATUS_IMPORTED, f"newer certificate taken from keystore '{link.name}'")
        ctx.store.save(state)
    progress(f"'{state.alias}' was renewed outside pyCertWiz; took the newer certificate from keystore '{link.name}'")
    if state.deploy:
        from .deploy import deploy_state

        try:
            deploy_state(ctx, state, progress=progress)
        except PyCertError as exc:
            progress(f"warning: deployment failed: {exc}")


def write_state(ctx: Any, state: Any, *, progress: Progress = _noop) -> str:
    """Write a linked certificate into its keystore (after issuance or renewal)."""
    name = state.keystore.get("name")
    if not name:
        return "not linked"
    link = ctx.config.keystore(name)
    if not link.write_back:
        return "write-back disabled"
    path = ctx.config.resolve(link.path)
    with open_keystore(path, keystore_password(ctx, link)) as keystore:
        outcome = _write_entry(ctx, keystore, state)
    progress(f"Keystore '{name}': {outcome} entry '{state.keystore.get('alias')}' ({path})")
    status_file = _status_path(ctx, name)
    ensure_dir(status_file.parent)
    atomic_write(status_file, json.dumps({"signature": _file_signature(path), "synced_at": iso()}) + "\n")
    return outcome


def import_keystore(
    ctx: Any, path: "str | Path", password: str, *, ca: str = "", progress: Progress = _noop
) -> "tuple[list[Any], list[str]]":
    """One-off import of every key entry (without linking): returns (states, problems)."""
    from types import SimpleNamespace

    keystore = Keystore.load(path, password)
    if not keystore.path.exists():
        raise NotFound(f"keystore not found: {keystore.path}")
    origin = SimpleNamespace(name=Path(path).name, ca=ca or ctx.config.primary_profile.name)
    by_fingerprint = {s.cert.sha256 for s in ctx.store.list() if s.cert.sha256}
    by_spki = {s.active_spki_b64 for s in ctx.store.list() if s.active_spki_b64}
    imported, problems = [], list(keystore.problems)
    for entry in keystore.entries:
        if entry.fingerprint in by_fingerprint or (entry.pending and certs.spki_b64(entry.certificate) in by_spki):
            problems.append(f"entry '{entry.alias}' is already managed by pyCertWiz; skipped")
            continue
        state = _import_entry(ctx, origin, entry, progress)
        with ctx.store.lock(state):
            state.keystore = {}
            ctx.store.save(state)
        imported.append(state)
    return imported, problems
