"""Compatibility shim: the mock CA implementation now lives in ``sandbox_ca``.

Tests and older scripts may keep importing ``mock_ca``; the implementation is
shared with the standalone sandbox CA so the two cannot drift apart.
"""

from sandbox_ca.mock_ca import (  # noqa: F401
    Captured,
    CertRecord,
    CSRRecord,
    Fault,
    MockCA,
    _der_cert,
    _pem,
    _spki_b64,
    _xml_escape,
)
