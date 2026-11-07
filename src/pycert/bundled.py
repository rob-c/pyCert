"""The CA certificates shipped with pyCert.

These are the same four UK e-Science CA certificates that CertWizard bundled.
Each one is pinned by the SHA-256 fingerprint of its DER encoding; a resource
that does not match its pin is treated as tampered with and loading fails.  It
is better to refuse to start than to build (or trust) a chain from the wrong CA.

The fingerprints were cross-checked against the IGTF accredited distribution and
the CA's own publication at https://ca.grid-support.ac.uk/cacerts/.
"""

from functools import lru_cache
from pathlib import Path

from cryptography import x509

from . import certs
from .compat import package_data_dir
from .errors import ConfigError

#: file name -> expected SHA-256 fingerprint of the certificate (lower-case hex)
PINNED: "dict[str, str]" = {
    # C=UK, O=eScienceRoot, OU=Authority, CN=UK e-Science Root (2007-2027, RSA)
    "escience-root.pem": "76f3a5942e22012d7e10e11b416fb2eea21d8f4583f2d2fc799bd4ced0210323",
    # C=UK, O=eScienceCA, OU=Authority, CN=UK e-Science CA 2B (2011-2027, RSA)
    "escience-2b.pem": "b6d140a765d165d8917bb9941f7ab21ff89c04155a4dce52cad345862c3e686e",
    # C=UK, O=eScienceRoot, OU=Authority, CN=UK e-Science Root 2026 (2026-2046, ECDSA)
    "escience-root-2026.pem": "565c16e7d6ff0f602aefca2a585634c190d7d9da411c7750d79cac6b351ffffa",
    # C=UK, O=eScienceCA, OU=Authority, CN=UK e-Science CA 3B (2026-2046, ECDSA)
    "escience-3b.pem": "16383860bc6e61488ffb945e961963967c4fe8d73d2b2e9641d0b535cca4b845",
}


def data_dir() -> Path:
    """Filesystem path of the bundled certificate directory (for copying)."""
    return Path(package_data_dir())


def path_for(name: str) -> Path:
    return data_dir() / name


@lru_cache(maxsize=1)
def certificates() -> "tuple[x509.Certificate, ...]":
    """Load and pin-check every bundled CA certificate."""
    result = []
    for name, expected in PINNED.items():
        path = path_for(name)
        if not path.is_file():
            raise ConfigError(f"bundled CA certificate is missing: {path}")
        try:
            cert = certs.load_certificate(path.read_bytes())
        except Exception as exc:  # noqa: BLE001
            raise ConfigError(f"cannot parse bundled CA certificate {name}: {exc}") from exc
        actual = certs.fingerprint(cert)
        if actual != expected:
            raise ConfigError(
                f"bundled CA certificate {name} does not match its pinned SHA-256 fingerprint "
                f"(expected {expected}, got {actual}); refusing to use it"
            )
        result.append(cert)
    return tuple(result)


@lru_cache(maxsize=1)
def pem_bundle() -> str:
    """All bundled certificates as one PEM string (ready for ssl context)."""
    return "".join(certs.cert_pem(c) for c in certificates())
