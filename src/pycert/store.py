"""Local state: one directory per certificate request.

Layout (all under ``paths.data_dir``, default ``~/.local/share/pycert``)::

    requests/<slug>/state.json     request metadata (no secrets)
    requests/<slug>/key.pem        PKCS#8 private key, encrypted, mode 0600
    requests/<slug>/request.csr    the submitted PKCS#10 request
    requests/<slug>/cert.pem       the issued leaf certificate
    requests/<slug>/chain.pem      issuers, leaf first
    requests/<slug>/fullchain.pem  leaf + issuers
    requests/<slug>/<cn>.p12       exported PKCS#12 bundle
    requests/<slug>/previous/      the previous key/cert/p12 before a renewal

Private files are always written atomically with mode 0600.  An advisory
``flock`` on the request directory serialises state updates between the CLI and
the GUI (or two terminals), so a status refresh cannot clobber a concurrent
export.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import certs
from . import csr as csr_module
from .errors import NotFound, PyCertError
from .util import (
    DIR_MODE,
    SECRET_FILE_MODE,
    atomic_write,
    ensure_dir,
    iso,
    parse_iso,
    slugify,
)

try:  # POSIX only; Windows falls back to no locking (documented).
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

STATE_VERSION = 1
STATE_FILE = "state.json"
KEY_FILE = "key.pem"
CSR_FILE = "request.csr"
PENDING_KEY_FILE = "key.next.pem"
PENDING_CSR_FILE = "request.next.csr"
CERT_FILE = "cert.pem"
CHAIN_FILE = "chain.pem"
FULLCHAIN_FILE = "fullchain.pem"
PREVIOUS_DIR = "previous"

STATUS_DRAFT = "DRAFT"
STATUS_SUBMITTED = "SUBMITTED"
STATUS_APPROVED = "APPROVED"
STATUS_SIGNED = "SIGNED"
STATUS_DOWNLOADED = "DOWNLOADED"
STATUS_REVOKED = "REVOKED"
STATUS_EXPIRED = "EXPIRED"
STATUS_FAILED = "FAILED"
STATUS_IMPORTED = "IMPORTED"

STATUSES = (
    STATUS_DRAFT,
    STATUS_SUBMITTED,
    STATUS_APPROVED,
    STATUS_SIGNED,
    STATUS_DOWNLOADED,
    STATUS_REVOKED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_IMPORTED,
)

#: statuses for which pyCert should keep polling the CA
PENDING_STATUSES = (STATUS_DRAFT, STATUS_SUBMITTED, STATUS_APPROVED, STATUS_SIGNED)


@dataclass
class ServerInfo:
    csr_id: str = ""
    cert_id: str = ""
    status: str = ""
    owner: str = ""
    role: str = ""
    email: str = ""
    start_date: str = ""
    end_date: str = ""
    life_days: str = ""
    renew: str = ""
    description: str = ""
    last_checked: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, data: dict) -> ServerInfo:
        return cls(**{k: str(v) for k, v in data.items() if k in cls.__annotations__})


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    sha256: str = ""
    key: str = ""
    sans: list[str] = field(default_factory=list)
    chain_sha256: list[str] = field(default_factory=list)
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "sha256": self.sha256,
            "key": self.key,
            "sans": list(self.sans),
            "chain_sha256": list(self.chain_sha256),
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CertInfo:
        return cls(
            subject=data.get("subject", ""),
            issuer=data.get("issuer", ""),
            serial=data.get("serial", ""),
            not_before=data.get("not_before", ""),
            not_after=data.get("not_after", ""),
            sha256=data.get("sha256", ""),
            key=data.get("key", ""),
            sans=list(data.get("sans", [])),
            chain_sha256=list(data.get("chain_sha256", [])),
            verified=bool(data.get("verified", False)),
        )


@dataclass
class RequestState:
    alias: str
    slug: str
    type: str  # "user" | "host"
    cn: str
    email: str = ""
    subject: str = ""
    key_algorithm: str = ""
    key_bits: int = 0
    spki_b64: str = ""
    public_key_sha256: str = ""
    csr_sha256: str = ""
    pending_spki_b64: str = ""
    pending_key_sha256: str = ""
    pending_csr_sha256: str = ""
    renewal: bool = False
    status: str = STATUS_DRAFT
    created_at: str = field(default_factory=iso)
    submitted_at: str = ""
    updated_at: str = field(default_factory=iso)
    auth_alias: str = ""
    server: ServerInfo = field(default_factory=ServerInfo)
    cert: CertInfo = field(default_factory=CertInfo)
    p12_path: str = ""
    p12_sha256: str = ""
    history: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    version: int = STATE_VERSION

    # -- helpers -----------------------------------------------------------
    @property
    def is_pending(self) -> bool:
        return self.status in PENDING_STATUSES

    @property
    def active_spki_b64(self) -> str:
        """The public key the CA should be asked about (pending wins)."""
        return self.pending_spki_b64 or self.spki_b64

    @property
    def days_remaining(self) -> int | None:
        if not self.cert.not_after:
            return None
        try:
            expiry = parse_iso(self.cert.not_after)
        except ValueError:
            return None
        return (expiry - datetime.now(UTC)).days

    def add_history(self, status: str, detail: str = "") -> None:
        self.history.append({"at": iso(), "status": status, "detail": detail})
        self.updated_at = iso()

    def set_status(self, status: str, detail: str = "") -> None:
        if status not in STATUSES:
            raise PyCertError(f"unknown status: {status}")
        self.status = status
        self.add_history(status, detail)

    def touch(self) -> None:
        self.updated_at = iso()

    def to_dict(self) -> dict:
        return {
            "version": STATE_VERSION,
            "alias": self.alias,
            "slug": self.slug,
            "type": self.type,
            "cn": self.cn,
            "email": self.email,
            "subject": self.subject,
            "key_algorithm": self.key_algorithm,
            "key_bits": self.key_bits,
            "spki_b64": self.spki_b64,
            "public_key_sha256": self.public_key_sha256,
            "csr_sha256": self.csr_sha256,
            "pending_spki_b64": self.pending_spki_b64,
            "pending_key_sha256": self.pending_key_sha256,
            "pending_csr_sha256": self.pending_csr_sha256,
            "renewal": self.renewal,
            "status": self.status,
            "created_at": self.created_at,
            "submitted_at": self.submitted_at,
            "updated_at": self.updated_at,
            "auth_alias": self.auth_alias or "",
            "server": self.server.to_dict(),
            "cert": self.cert.to_dict(),
            "p12_path": self.p12_path,
            "p12_sha256": self.p12_sha256,
            "history": list(self.history),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict) -> RequestState:
        return cls(
            alias=data["alias"],
            slug=data["slug"],
            type=data.get("type", "user"),
            cn=data.get("cn", ""),
            email=data.get("email", ""),
            subject=data.get("subject", ""),
            key_algorithm=data.get("key_algorithm", ""),
            key_bits=int(data.get("key_bits", 0)),
            spki_b64=data.get("spki_b64", ""),
            public_key_sha256=data.get("public_key_sha256", ""),
            csr_sha256=data.get("csr_sha256", ""),
            pending_spki_b64=data.get("pending_spki_b64", ""),
            pending_key_sha256=data.get("pending_key_sha256", ""),
            pending_csr_sha256=data.get("pending_csr_sha256", ""),
            renewal=bool(data.get("renewal", False)),
            status=data.get("status", STATUS_DRAFT),
            created_at=data.get("created_at", iso()),
            submitted_at=data.get("submitted_at", ""),
            updated_at=data.get("updated_at", iso()),
            auth_alias=data.get("auth_alias") or "",
            server=ServerInfo.from_dict(data.get("server", {})),
            cert=CertInfo.from_dict(data.get("cert", {})),
            p12_path=data.get("p12_path", ""),
            p12_sha256=data.get("p12_sha256", ""),
            history=list(data.get("history", [])),
            notes=list(data.get("notes", [])),
        )


class Store:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.requests_dir = self.data_dir / "requests"

    # -- enumeration -------------------------------------------------------
    def list(self) -> list[RequestState]:
        if not self.requests_dir.is_dir():
            return []
        states = []
        for state_file in sorted(self.requests_dir.glob(f"*/{STATE_FILE}")):
            try:
                states.append(self._read(state_file))
            except (OSError, ValueError, KeyError):
                continue
        states.sort(key=lambda s: s.created_at)
        return states

    def pending(self) -> list[RequestState]:
        return [s for s in self.list() if s.is_pending]

    def exists(self, alias: str) -> bool:
        try:
            self.get(alias)
            return True
        except NotFound:
            return False

    # -- lookup ------------------------------------------------------------
    def get(self, alias_or_cn: str) -> RequestState:
        needle = alias_or_cn.strip()
        states = self.list()
        exact = [s for s in states if s.alias == needle]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:  # pragma: no cover - aliases are unique by construction
            raise NotFound(f"'{needle}' is ambiguous")
        folded = [s for s in states if s.alias.lower() == needle.lower()]
        if len(folded) == 1:
            return folded[0]
        if len(folded) > 1:
            raise NotFound(
                f"'{needle}' matches {len(folded)} certificates: " + ", ".join(s.alias for s in folded)
            )
        direct = self.requests_dir / slugify(needle) / STATE_FILE
        if direct.is_file():
            return self._read(direct)
        matches = [s for s in states if s.cn.lower() == needle.lower()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise NotFound(
                f"'{needle}' matches {len(matches)} certificates: " + ", ".join(s.alias for s in matches)
            )
        raise NotFound(f"no certificate request matching '{needle}'")

    def get_by_slug(self, slug: str) -> RequestState:
        path = self.requests_dir / slug / STATE_FILE
        if not path.is_file():
            raise NotFound(f"no certificate request with directory '{slug}'")
        return self._read(path)

    # -- creation ----------------------------------------------------------
    def new_state(self, *, alias: str, type: str, cn: str, email: str) -> RequestState:
        slug = self._unique_slug(alias)
        state = RequestState(alias=alias, slug=slug, type=type, cn=cn, email=email)
        ensure_dir(self.path(state), DIR_MODE)
        self.save(state)
        return state

    def _unique_slug(self, alias: str) -> str:
        base = slugify(alias)
        candidate = base
        counter = 2
        while (self.requests_dir / candidate).exists():
            candidate = f"{base}-{counter}"
            counter += 1
            if counter > 1000:  # pragma: no cover
                raise PyCertError("could not allocate a unique directory name")
        return candidate

    # -- paths -------------------------------------------------------------
    def path(self, state: RequestState) -> Path:
        return self.requests_dir / state.slug

    def file(self, state: RequestState, name: str) -> Path:
        return self.path(state) / name

    def p12_filename(self, state: RequestState) -> str:
        name = state.alias.replace("/", "-")
        return f"{name}.p12"

    # -- persistence -------------------------------------------------------
    def _read(self, state_file: Path) -> RequestState:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        return RequestState.from_dict(data)

    def save(self, state: RequestState) -> None:
        state.version = STATE_VERSION
        ensure_dir(self.path(state), DIR_MODE)
        with self.lock(state):
            atomic_write(
                self.file(state, STATE_FILE),
                json.dumps(state.to_dict(), indent=2, ensure_ascii=False) + "\n",
                mode=SECRET_FILE_MODE,
            )

    @contextlib.contextmanager
    def lock(self, state: RequestState) -> Iterator[None]:
        ensure_dir(self.path(state), DIR_MODE)
        if fcntl is None:  # pragma: no cover - Windows
            yield
            return
        lock_path = self.path(state) / ".lock"
        with open(lock_path, "a+") as handle:
            try:
                os.chmod(lock_path, SECRET_FILE_MODE)
            except OSError:  # pragma: no cover - read-only directory
                pass
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    # -- key / csr / certificate I/O --------------------------------------
    def save_key(self, state: RequestState, key, password: str) -> Path:
        return atomic_write(self.file(state, KEY_FILE), certs.key_pem(key, password), SECRET_FILE_MODE)

    def load_key(self, state: RequestState, password: str):
        path = self.file(state, KEY_FILE)
        if not path.is_file():
            raise NotFound(f"private key not found for '{state.alias}': {path}")
        return certs.load_private_key(path.read_bytes(), password)

    def save_csr(self, state: RequestState, csr) -> Path:
        return atomic_write(self.file(state, CSR_FILE), csr_module.csr_pem(csr), SECRET_FILE_MODE)

    def load_csr(self, state: RequestState):
        return csr_module.load_csr(self.file(state, CSR_FILE).read_bytes())

    def cert_path(self, state: RequestState) -> Path:
        return self.file(state, CERT_FILE)

    def load_certificate(self, state: RequestState):
        path = self.cert_path(state)
        if not path.is_file():
            raise NotFound(f"no certificate yet for '{state.alias}' (status {state.status})")
        return certs.load_certificate(path.read_bytes())

    def save_pending_key(self, state: RequestState, key, password: str) -> Path:
        return atomic_write(
            self.file(state, PENDING_KEY_FILE), certs.key_pem(key, password), SECRET_FILE_MODE
        )

    def load_pending_key(self, state: RequestState, password: str):
        path = self.file(state, PENDING_KEY_FILE)
        if not path.is_file():
            raise NotFound(f"no pending private key for '{state.alias}' ({path})")
        return certs.load_private_key(path.read_bytes(), password)

    def save_pending_csr(self, state: RequestState, csr) -> Path:
        return atomic_write(self.file(state, PENDING_CSR_FILE), csr_module.csr_pem(csr), SECRET_FILE_MODE)

    def load_pending_csr(self, state: RequestState):
        return csr_module.load_csr(self.file(state, PENDING_CSR_FILE).read_bytes())

    def adopt_pending(self, state: RequestState) -> None:
        """Promote key.next.pem / request.next.csr to the current files."""
        for source, target in (
            (PENDING_KEY_FILE, KEY_FILE),
            (PENDING_CSR_FILE, CSR_FILE),
        ):
            src = self.file(state, source)
            if src.is_file():
                os.replace(src, self.file(state, target))

    def discard_pending(self, state: RequestState) -> None:
        for name in (PENDING_KEY_FILE, PENDING_CSR_FILE):
            path = self.file(state, name)
            if path.is_file():
                path.unlink()

    def save_certificate(self, state: RequestState, cert, chain: list) -> None:
        atomic_write(self.cert_path(state), certs.cert_pem(cert), SECRET_FILE_MODE)
        atomic_write(self.file(state, CHAIN_FILE), certs.certs_pem(chain), SECRET_FILE_MODE)
        atomic_write(self.file(state, FULLCHAIN_FILE), certs.certs_pem([cert, *chain]), SECRET_FILE_MODE)

    def load_chain(self, state: RequestState) -> list:
        path = self.file(state, CHAIN_FILE)
        if not path.is_file() or path.stat().st_size == 0:
            return []
        return certs.load_certificates(path.read_bytes())

    # -- renewal history ---------------------------------------------------
    def archive_current(self, state: RequestState) -> Path:
        """Move key/cert/p12 aside before a renewal; returns the archive dir."""
        stamp = iso().replace(":", "-").replace(".", "")
        target = self.path(state) / PREVIOUS_DIR / stamp
        counter = 2
        while target.exists():
            target = self.path(state) / PREVIOUS_DIR / f"{stamp}-{counter}"
            counter += 1
        ensure_dir(target, DIR_MODE)
        for name in (KEY_FILE, CERT_FILE, CHAIN_FILE, FULLCHAIN_FILE):
            source = self.file(state, name)
            if source.is_file():
                os.replace(source, target / name)
        if state.p12_path:
            p12 = Path(state.p12_path)
            if p12.is_file():
                os.replace(p12, target / p12.name)
        return target

    # -- deletion ----------------------------------------------------------
    def delete(self, state: RequestState) -> None:
        import shutil

        shutil.rmtree(self.path(state))

    # -- audit -------------------------------------------------------------
    def audit(self) -> list[str]:
        """Report files in the data directory that are accessible by others."""
        problems = []
        for root, dirs, files in os.walk(self.data_dir):
            for name in dirs:
                path = Path(root) / name
                mode = path.stat().st_mode & 0o777
                if mode & 0o077:
                    problems.append(f"directory {path} has mode {oct(mode)} (expected 0700)")
            for name in files:
                if name == ".lock":
                    continue
                path = Path(root) / name
                mode = path.stat().st_mode & 0o777
                if mode & 0o077:
                    problems.append(f"file {path} has mode {oct(mode)} (expected 0600)")
        return problems


def parse_alias_set(texts: list[str]) -> list[str]:
    return [t.strip() for t in texts if t.strip()]
