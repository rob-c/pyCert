"""The provider interface every CA protocol implements.

The shared workflow in :mod:`pycert.workflow` owns everything that is the same
for every CA: validating the request, generating the key, building the CSR,
storing state, verifying the issued certificate and its chain, archiving on
renewal, exporting and deploying.  A provider only has to:

* say what it can do (:class:`Capabilities`), so the CLI and GUI can offer the
  right options (an RA PIN, host authentication, domain validation...);
* check the CA is reachable and do any per-request preparation (``preflight``);
* submit a new request or a renewal (``submit`` / ``submit_renewal``);
* report the request's progress and hand back the issued certificate
  (``poll``);
* revoke a certificate (``revoke``).

Providers must never log or return private key material, PINs or passphrases,
and must store any protocol state they need between calls (an ACME order URL,
say) in ``state.provider`` - a JSON-serialisable dict saved with the request.
"""

import abc
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from cryptography import x509

from ..errors import PyCertError

Progress = Callable[[str], None]


def _noop(_message: str) -> None:
    pass


@dataclass(frozen=True)
class Capabilities:
    """What a CA protocol supports; the front-ends adapt to it."""

    user_certificates: bool = True
    host_certificates: bool = True
    #: requests carry a PIN that the requester reads to the RA
    pin: bool = False
    #: the requester chooses a Registration Authority (OU/L)
    ra: bool = False
    #: host requests must be authenticated by an existing personal certificate
    host_authentication: bool = False
    #: the CA validates control of DNS names (ACME challenges)
    domain_validation: bool = False
    #: the CA can revoke certificates on request
    revoke: bool = True
    #: revocation needs the CA's certificate id (looked up by polling first)
    revoke_needs_id: bool = False
    #: the CA publishes an RA list / message of the day / policy
    ca_info: bool = False
    #: the subject DN carries organisation attributes (O/OU/L/C)
    organisation_subject: bool = True
    #: issuance can take days (human RA approval) rather than seconds
    manual_approval: bool = False
    #: supported revocation reasons, in display order
    revocation_reasons: "tuple[str, ...]" = ("unspecified", "keyCompromise", "superseded", "cessationOfOperation")

    def as_dict(self) -> dict:
        return {
            "user_certificates": self.user_certificates,
            "host_certificates": self.host_certificates,
            "pin": self.pin,
            "ra": self.ra,
            "host_authentication": self.host_authentication,
            "domain_validation": self.domain_validation,
            "revoke": self.revoke,
            "ca_info": self.ca_info,
            "organisation_subject": self.organisation_subject,
            "manual_approval": self.manual_approval,
            "revocation_reasons": list(self.revocation_reasons),
        }


@dataclass
class SubmitResult:
    success: bool
    message: str
    detail: str = ""
    status: int = 0

    def as_dict(self) -> dict:
        return {"success": self.success, "message": self.message, "detail": self.detail, "status": self.status}


@dataclass
class PingResult:
    ok: bool
    latency_ms: float = 0.0
    detail: str = ""
    tls: Any = None
    url: str = ""

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "latency_ms": round(self.latency_ms, 1),
            "detail": self.detail,
            "url": self.url,
            "tls": self.tls.as_dict() if self.tls is not None and hasattr(self.tls, "as_dict") else None,
        }


@dataclass
class PollOutcome:
    state: Any
    server_status: str
    pending: bool
    message: str
    certificate: "x509.Certificate | None" = None
    cert_id: str = ""
    terminal: bool = False
    #: intermediates supplied by the CA with the certificate (used as chain hints)
    chain: "list[x509.Certificate]" = field(default_factory=list)


class CAProvider(abc.ABC):
    """Base class for CA protocol implementations."""

    kind: ClassVar[str] = ""
    label: ClassVar[str] = ""
    capabilities: ClassVar[Capabilities] = Capabilities()

    def __init__(self, ctx: Any, profile: Any):
        self.ctx = ctx
        self.profile = profile

    # -- identity ------------------------------------------------------------
    @property
    def name(self) -> str:
        return self.profile.name

    @property
    def display_name(self) -> str:
        return self.profile.display_name

    @property
    def url(self) -> str:
        return self.profile.ca.base_url

    def describe(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "label": self.label,
            "display_name": self.display_name,
            "url": self.url,
            "primary": bool(getattr(self.profile, "primary", False)),
            "capabilities": self.capabilities.as_dict(),
        }

    # -- validation ----------------------------------------------------------
    def validate_request(self, spec: Any) -> None:
        """Reject a request this CA cannot handle (before any key is generated)."""
        caps = self.capabilities
        if spec.type == "user" and not caps.user_certificates:
            raise PyCertError(f"{self.display_name} only issues host certificates")
        if spec.type == "host" and not caps.host_certificates:
            raise PyCertError(f"{self.display_name} only issues personal certificates")
        if spec.auth_alias and not caps.host_authentication:
            raise PyCertError(f"{self.display_name} does not authenticate requests with an existing certificate")

    def subject_for(self, spec: Any) -> x509.Name:
        """The subject DN to request (default: the spec's full DN)."""
        return spec.subject()

    # -- protocol ------------------------------------------------------------
    @abc.abstractmethod
    def ping(self, *, stop_event: Any = None) -> PingResult:
        """Check the CA is reachable."""

    def ensure_reachable(self, *, progress: Progress = _noop, stop_event: Any = None) -> None:
        """Raise :class:`~pycert.errors.CAError` when the CA cannot be reached."""
        from ..errors import CAError

        result = self.ping(stop_event=stop_event)
        if not result.ok:
            detail = f" ({result.detail})" if result.detail else ""
            raise CAError(
                f"cannot reach the CA server at {self.url}{detail}. "
                "Check your network, proxy, TLS pin and the CA URL."
            )

    def preflight(self, spec: Any, *, progress: Progress = _noop, stop_event: Any = None) -> Any:
        """Prepare a new request before the key is generated; returns opaque data for ``submit``."""
        self.ensure_reachable(progress=progress, stop_event=stop_event)
        return None

    @abc.abstractmethod
    def submit(
        self,
        state: Any,
        csr: x509.CertificateSigningRequest,
        spec: Any,
        *,
        prepared: Any = None,
        progress: Progress = _noop,
        on_pin: "Callable[[str], None] | None" = None,
        stop_event: Any = None,
    ) -> SubmitResult:
        """Submit a new request.  ``state`` is saved by the caller afterwards."""

    @abc.abstractmethod
    def submit_renewal(
        self,
        state: Any,
        csr: x509.CertificateSigningRequest,
        *,
        old_certificate: x509.Certificate,
        old_key: Any,
        contact: str,
        pin: str = "",
        progress: Progress = _noop,
        on_pin: "Callable[[str], None] | None" = None,
        stop_event: Any = None,
    ) -> SubmitResult:
        """Submit a renewal for an issued certificate (new key in ``csr``)."""

    @abc.abstractmethod
    def poll(self, state: Any, *, progress: Progress = _noop, stop_event: Any = None) -> PollOutcome:
        """Ask the CA about the request; return the certificate once issued."""

    def revoke(
        self,
        state: Any,
        reason: str,
        *,
        certificate: x509.Certificate,
        key: Any,
        progress: Progress = _noop,
        stop_event: Any = None,
    ) -> SubmitResult:
        raise PyCertError(f"{self.display_name} does not support revocation through pyCertWiz")

    def info(self, *, stop_event: Any = None) -> dict:
        """CA metadata for display (RA list, terms of service, message of the day...)."""
        return {}

    def refresh_record(
        self, state: Any, certificate: x509.Certificate, *, progress: Progress = _noop, stop_event: Any = None
    ) -> bool:
        """Update ``state.server`` with what the CA holds for *certificate*.

        Returns False when the CA has no such lookup (nothing was asked).
        """
        return False

    def renewal_problem(self, state: Any, certificate: x509.Certificate, contact: str) -> str:
        """Why the CA would refuse to renew *certificate* for *contact* ('' if it would not).

        Called after :meth:`refresh_record`, so ``state.server`` is current.
        """
        return ""

    def forget(self, state: Any) -> None:
        """Called when a request is deleted locally (clean up provider state)."""
        return


def timed_ping(check: "Callable[[], tuple[bool, str, Any]]", url: str) -> PingResult:
    """Helper: run *check* and wrap its ``(ok, detail, tls)`` result with the latency."""
    started = time.monotonic()
    ok, detail, tls = check()
    return PingResult(ok=ok, latency_ms=(time.monotonic() - started) * 1000, detail=detail, tls=tls, url=url)
