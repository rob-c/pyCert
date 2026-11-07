"""Exception hierarchy for pyCert.

Every error raised deliberately by pyCert derives from :class:`PyCertError`, so
the CLI can print a one-line message (and a traceback only with ``--debug``) and
the GUI can show a clean dialog.  Unexpected exceptions are never swallowed.
"""


class PyCertError(Exception):
    """Base class for all pyCert errors."""


class ConfigError(PyCertError):
    """The configuration file is missing, malformed or inconsistent."""


class SecretError(PyCertError):
    """A secret could not be stored, retrieved or decrypted."""


class CryptoError(PyCertError):
    """Key generation, parsing, signing or decryption failed."""


class UnsupportedAlgorithm(CryptoError):
    """A cryptographic algorithm or key type is not supported."""


class ProtocolError(PyCertError):
    """The CA server returned something pyCert cannot understand."""


class NetworkError(PyCertError):
    """A connection failed, timed out or violated the TLS policy."""


class CAError(PyCertError):
    """The CA server rejected a request."""

    def __init__(self, message: str, status: "int | None" = None, detail: "str | None" = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class ChainError(PyCertError):
    """A certificate chain could not be built or did not validate."""


class NotFound(PyCertError):
    """A local request/alias does not exist."""


class TimeoutWaiting(PyCertError):
    """The certificate did not appear before the deadline (still pending)."""
