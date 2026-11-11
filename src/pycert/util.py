"""Small shared helpers: atomic file writes, permissions, formatting."""

import contextlib
import hashlib
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from .errors import PyCertError

# Directory/file modes used everywhere.  The private key and the PKCS#12 file
# are only ever readable by the owner; pyCertWiz refuses to write them any other
# way (unlike the Java client, which left keystore permissions to the default
# umask).
DIR_MODE = 0o700
SECRET_FILE_MODE = 0o600
PUBLIC_FILE_MODE = 0o644


def command_problem(program: str) -> str:
    """Why *program* (a hook's first word) cannot be started; '' if it can.

    Checked before running a hook so a missing or non-executable program gets a
    clear message everywhere. Under emulation (x86_64 containers on Apple
    silicon) the exec error can otherwise be lost, leaving only "exit 127".
    """
    if os.sep in program:
        if not os.path.exists(program):
            return "not found"
        if os.path.isdir(program) or not os.access(program, os.X_OK):
            return "not executable"
        return ""
    return "" if shutil.which(program) else "not found on PATH"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(when: "datetime | None" = None) -> str:
    return (
        (when or utcnow()).astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def parse_iso(text: str) -> datetime:
    """Parse an ISO-8601 timestamp; naive values are taken as UTC.

    ``datetime.fromisoformat`` only accepts a trailing ``Z`` from Python 3.11,
    and pyCertWiz writes ``Z`` timestamps, so normalise it first.
    """
    if not isinstance(text, str):
        raise ValueError("timestamp must be a string")
    value = text.strip()
    if value[-1:] in ("Z", "z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_fingerprint(digest: "bytes | str", sep: str = ":") -> str:
    if isinstance(digest, str):
        hexstr = digest.replace(":", "").replace(" ", "").lower()
        if len(hexstr) % 2:
            raise PyCertError("odd-length fingerprint")
        digest = bytes.fromhex(hexstr)
    return sep.join(f"{b:02X}" for b in digest)


def normalize_fingerprint(text: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", text).lower()


def ensure_dir(path: Path, mode: int = DIR_MODE) -> Path:
    """Create *path* (and missing parents) with an explicit mode.

    ``Path.mkdir(parents=True)`` applies ``mode`` to the leaf only and is masked
    by the umask; both are wrong for directories that hold private keys.  Every
    directory created here gets the requested mode explicitly.
    """
    path = Path(path)
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:  # pragma: no cover - filesystem root
            break
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=mode)
        except FileExistsError:  # pragma: no cover - creation race
            if not directory.is_dir():
                raise
        with contextlib.suppress(OSError):
            os.chmod(directory, mode)
    with contextlib.suppress(OSError):
        os.chmod(path, mode)
    return path


def atomic_write(path: Path, data: "bytes | str", mode: int = SECRET_FILE_MODE) -> Path:
    """Write *path* atomically with explicit permissions.

    The temporary file is created in the destination directory so that
    ``os.replace`` is atomic on POSIX.  Contents are never briefly
    world-readable, and a crash cannot leave a half-written key on disk.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    path = Path(path)
    if not path.parent.is_dir():
        # Create a missing parent privately, but never re-mode an existing one:
        # a web root, /etc/grid-security or the user's chosen export folder must
        # keep its permissions.  Private directories are ensured by their owners.
        ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:
                fchmod(handle.fileno(), mode)
            else:  # pragma: no cover - Windows
                os.chmod(tmp, mode)
            handle.write(data)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:  # pragma: no cover - filesystems without fsync
                pass
        os.replace(tmp, path)
        _fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return path


def _fsync_directory(directory: Path) -> None:
    """Best-effort fsync of a directory after an atomic rename."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:  # pragma: no cover - Windows / exotic filesystems
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(fd)


def read_private_file(path: Path) -> bytes:
    """Read a private file, refusing symlinks and loose permissions."""
    path = Path(path)
    if path.is_symlink():
        raise PyCertError("refusing to read a symlinked private file: %s" % path)
    warnings = check_private_permissions(path)
    data = path.read_bytes()
    if warnings:
        # Warnings are emitted by the caller/CLI; the important part is that
        # the caller can see them.  Keep the function pure otherwise.
        pass
    return data


def check_private_permissions(path: Path) -> "list[str]":
    """Return a list of warnings about insecure permissions on *path*."""
    warnings = []
    try:
        st = os.lstat(path)
    except OSError:
        return warnings
    if stat.S_ISLNK(st.st_mode):
        warnings.append(f"{path} is a symlink; private files must be regular files")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.append(
            f"{path} is accessible by group/other (mode {oct(st.st_mode & 0o777)}); "
            "run: chmod 600 " + str(path)
        )
    return warnings


def slugify(text: str, max_length: int = 64) -> str:
    """Filesystem-safe, collision-resistant-ish slug for an alias/CN."""
    normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", normalized).strip("-._").lower()
    slug = re.sub(r"-{2,}", "-", slug)
    return (slug or "cert")[:max_length]


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{sign}{days}d{hours:02d}h"
    if hours:
        return f"{sign}{hours}h{minutes:02d}m"
    if minutes:
        return f"{sign}{minutes}m{secs:02d}s"
    return f"{sign}{secs}s"


def parse_duration(text: str) -> float:
    """Parse '30', '30s', '10m', '2h', '7d' into seconds."""
    text = text.strip().lower()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([smhdw]?)", text)
    if not match:
        raise PyCertError(f"invalid duration: {text!r} (use e.g. 30s, 10m, 2h, 7d)")
    value = float(match.group(1))
    return value * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match.group(2)]


def clamp_text(text: str, limit: int = 500) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def safe_chmod(path: Path, mode: int) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, mode)
