"""The UK e-Science CA provider (CertWizard / OpenCA protocol).

This is the protocol the Java CertWizard client speaks; the wire format lives
in :mod:`pycert.ca` and is documented in ``docs/PROTOCOL.md``.  The provider
adds the request-level behaviour:

* user requests are submitted unauthenticated with an RA PIN hash;
* host requests are authenticated (PPPK) with an existing, valid RSA
  certificate chosen by the requester;
* renewals are authenticated with the certificate being renewed and carry its
  modulus/exponent in ``<PublicKey>``;
* the CA is polled by SubjectPublicKeyInfo until the RA approves and a CA
  operator signs, which can take days.
"""

import datetime as dt
from collections.abc import Callable
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .. import certs
from .. import csr as csr_module
from ..ca import REVOCATION_REASONS, CAClient, Lookup
from ..errors import CAError, NotFound, ProtocolError, PyCertError
from ..store import STATUS_APPROVED, STATUS_FAILED, STATUS_SUBMITTED
from ..util import iso
from .base import Capabilities, CAProvider, PingResult, PollOutcome, Progress, SubmitResult, _noop

_CSR_STATUS_MAP = {
    "NEW": STATUS_SUBMITTED,
    "RENEW": STATUS_SUBMITTED,
    "APPROVED": STATUS_APPROVED,
    "DELETED": STATUS_FAILED,
}

_CSR_DESCRIPTIONS = {
    "NEW": "submitted, awaiting RA approval",
    "RENEW": "renewal submitted, awaiting RA approval",
    "APPROVED": "approved by the RA, awaiting CA operator signing",
    "DELETED": "deleted by the CA",
}

_CERT_TERMINAL = {"REVOKED", "EXPIRED", "SUSPENDED", "DELETED"}

#: The CA renews a certificate up to this long after it expired (as CertWizard).
RENEWAL_GRACE = dt.timedelta(days=30)


def _matching_certificate(lookup: Lookup, certificate: x509.Certificate) -> "Any | None":
    """The lookup entry for *certificate*: the one carrying it, else the latest."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    for entry in reversed(lookup.certificates):
        body = entry.certificate()
        if body is not None and body.public_bytes(serialization.Encoding.DER) == der:
            return entry
    return lookup.latest_certificate


def _submission(result: Any) -> SubmitResult:
    return SubmitResult(
        success=bool(result.success),
        message=result.message,
        detail=getattr(result, "detail", "") or "",
        status=int(getattr(result, "status", 0) or 0),
    )


class UKCAProvider(CAProvider):
    kind = "ukca"
    label = "UK e-Science CA (CertWizard protocol)"
    capabilities = Capabilities(
        user_certificates=True,
        host_certificates=True,
        pin=True,
        ra=True,
        host_authentication=True,
        domain_validation=False,
        revoke=True,
        revoke_needs_id=True,
        ca_info=True,
        organisation_subject=True,
        manual_approval=True,
        revocation_reasons=tuple(REVOCATION_REASONS),
    )

    # -- plumbing ------------------------------------------------------------
    def client(self) -> CAClient:
        # ``ctx.client()`` (no argument) is the primary CA; tests and embedders
        # may replace it, so the primary profile always goes through it.
        if getattr(self.profile, "primary", False):
            return self.ctx.client()
        return self.ctx.client(self.profile.name)

    def validate_request(self, spec: Any) -> None:
        super().validate_request(spec)
        if spec.type == "host" and not spec.auth_alias:
            raise PyCertError(
                "host certificate requests must be authenticated by an existing certificate: "
                "pass --auth <alias> (see 'pycert list')"
            )
        if not spec.ou or not spec.l:
            raise PyCertError(
                "an RA is required: set identity.ra / identity.ou / identity.l in the "
                "configuration, or pass --ra 'OU L'"
            )

    # -- reachability ----------------------------------------------------------
    def ping(self, *, stop_event: Any = None) -> PingResult:
        import time

        client = self.client()
        started = time.monotonic()
        ok = client.ping()
        return PingResult(
            ok=bool(ok),
            latency_ms=(time.monotonic() - started) * 1000,
            detail=getattr(client, "last_error", "") or "",
            tls=getattr(client, "last_tls", None),
            url=self.url,
        )

    def ensure_reachable(self, *, progress: Progress = _noop, stop_event: Any = None) -> None:
        client = self.client()
        if not client.ping():
            detail = f" ({client.last_error})" if client.last_error else ""
            raise CAError(
                f"cannot reach the CA server at {self.profile.ca.base_url}{detail}. "
                "Check your network, proxy, TLS pin and ca.base_url."
            )

    def preflight(self, spec: Any, *, progress: Progress = _noop, stop_event: Any = None) -> Any:
        self.ensure_reachable(progress=progress, stop_event=stop_event)
        if (spec.key_algorithm or "").lower() == "ec":
            progress(
                "note: this CA authenticates renewals and host requests with RSA keys only (PPPK); "
                "an EC certificate cannot be renewed in place - request a new one when it expires"
            )
        if spec.type != "host":
            return None
        ctx = self.ctx
        auth_state = ctx.store.get(spec.auth_alias)
        try:
            auth_cert = ctx.store.load_certificate(auth_state)
        except NotFound as exc:
            raise PyCertError(
                f"the authenticating certificate '{spec.auth_alias}' has not been issued yet"
            ) from exc
        if not certs.certificate_valid_at(auth_cert):
            raise PyCertError(f"the authenticating certificate '{spec.auth_alias}' is outside its validity period")
        auth_key = ctx.store.load_key(auth_state, ctx.key_passphrase())
        if not certs.certificate_matches_key(auth_cert, auth_key):
            raise PyCertError(f"the private key stored for '{spec.auth_alias}' does not match its certificate")
        return (auth_cert, auth_key)

    # -- submission ------------------------------------------------------------
    def _pin(self, pin: str, on_pin: "Callable[[str], None] | None", progress: Progress) -> str:
        from .. import workflow

        value = pin or workflow.generate_pin()
        if not pin:
            workflow._report_pin(value, on_pin, progress)
        if len(value) < workflow.PIN_MIN_LENGTH:
            raise PyCertError(f"the PIN must be at least {workflow.PIN_MIN_LENGTH} characters")
        return workflow.pin_hash(value, self.ctx.config.csr.pin_hash)

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
        hashed_pin = self._pin(spec.pin, on_pin, progress)
        progress("Submitting to the CA...")
        client = self.client()
        if spec.type == "host":
            auth_cert, auth_key = prepared
            result = client.submit_authenticated(
                csr_pem=csr_module.csr_pem(csr),
                pin_hash=hashed_pin,
                email=spec.email,
                auth_cert=auth_cert,
                auth_key=auth_key,
                host_request=True,
            )
        else:
            result = client.submit_csr(csr_module.csr_pem(csr), hashed_pin, spec.email)
        return _submission(result)

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
        from .. import workflow

        hashed_pin = self._pin(pin, on_pin, progress)
        progress("Submitting the renewal (authenticated with the current certificate)...")
        result = self.client().submit_authenticated(
            csr_pem=csr_module.csr_pem(csr),
            pin_hash=hashed_pin,
            email=contact,
            auth_cert=old_certificate,
            auth_key=old_key,
            host_request=False,
            public_key=workflow.modulus_exponent(old_certificate),
        )
        return _submission(result)

    # -- polling ---------------------------------------------------------------
    def poll(self, state: Any, *, progress: Progress = _noop, stop_event: Any = None) -> PollOutcome:
        ctx = self.ctx
        spki = state.active_spki_b64
        if not spki:
            raise PyCertError(f"'{state.alias}' has no public key recorded; cannot query the CA")
        client = self.client()
        lookup: Lookup = client.lookup_public_key(spki, stop_event=stop_event)
        state.server.last_checked = iso()

        certificate_entry = lookup.latest_certificate
        if certificate_entry is not None:
            state.server.cert_id = certificate_entry.id
            state.server.status = certificate_entry.status
            state.server.owner = certificate_entry.owner
            state.server.role = certificate_entry.role
            state.server.email = certificate_entry.email
            state.server.start_date = certificate_entry.start_date
            state.server.end_date = certificate_entry.end_date
            state.server.life_days = certificate_entry.life_days
            state.server.renew = certificate_entry.renew

            if certificate_entry.status.upper() in _CERT_TERMINAL:
                ctx.store.save(state)
                return PollOutcome(
                    state=state,
                    server_status=certificate_entry.status,
                    pending=False,
                    message=f"the CA reports the certificate as {certificate_entry.status}",
                    terminal=True,
                )
            certificate = certificate_entry.certificate()
            if certificate is None and certificate_entry.id:
                progress(f"Downloading certificate {certificate_entry.id}...")
                certificate = client.download_certificate(certificate_entry.id, stop_event=stop_event)
            if certificate is not None:
                if state.active_spki_b64 and certs.spki_b64(certificate) != state.active_spki_b64:
                    raise ProtocolError(
                        "the CA returned a certificate whose public key does not match this request; "
                        "refusing to use it"
                    )
                ctx.store.save(state)
                return PollOutcome(
                    state=state,
                    server_status=certificate_entry.status,
                    pending=False,
                    message=f"certificate available (status {certificate_entry.status})",
                    certificate=certificate,
                    cert_id=certificate_entry.id,
                )
            ctx.store.save(state)
            return PollOutcome(state, certificate_entry.status or "UNKNOWN", True, "waiting for a certificate body")

        csr_entry = lookup.latest_csr
        if csr_entry is not None:
            state.server.csr_id = csr_entry.id
            state.server.status = csr_entry.status
            state.server.owner = csr_entry.owner
            state.server.role = csr_entry.role
            state.server.email = csr_entry.email
            mapped = _CSR_STATUS_MAP.get(csr_entry.status.upper(), state.status)
            description = _CSR_DESCRIPTIONS.get(csr_entry.status.upper(), f"status {csr_entry.status}")
            terminal = mapped == STATUS_FAILED
            if mapped != state.status:
                state.set_status(mapped, description)
            else:
                state.touch()
            ctx.store.save(state)
            return PollOutcome(
                state=state,
                server_status=csr_entry.status,
                pending=not terminal,
                message=description,
                terminal=terminal,
            )

        # The server may not have indexed the request yet.
        state.touch()
        ctx.store.save(state)
        return PollOutcome(
            state=state,
            server_status="",
            pending=True,
            message="the CA does not know this public key yet (the request may still be processing)",
        )

    # -- the CA's record of an issued certificate --------------------------------
    def refresh_record(
        self, state: Any, certificate: x509.Certificate, *, progress: Progress = _noop, stop_event: Any = None
    ) -> bool:
        """Look the certificate up by its public key, as CertWizard does at start-up.

        The record gives the CA's status (VALID, REVOKED...) and the contact
        e-mail it holds, which a renewal must keep unless the user changes it.
        """
        progress("Asking the CA for its record of this certificate...")
        lookup: Lookup = self.client().lookup_public_key(certs.spki_b64(certificate), stop_event=stop_event)
        entry = _matching_certificate(lookup, certificate)
        server = state.server
        server.last_checked = iso()
        if entry is None:
            server.cert_id = server.status = server.email = server.owner = server.role = ""
            return True
        server.cert_id = entry.id
        server.status = entry.status
        server.owner = entry.owner
        server.role = entry.role
        server.email = entry.email
        server.start_date = entry.start_date or server.start_date
        server.end_date = entry.end_date or server.end_date
        server.life_days = entry.life_days
        server.renew = entry.renew
        return True

    def renewal_problem(self, state: Any, certificate: x509.Certificate, contact: str) -> str:
        """CertWizard's renewal rules: a VALID certificate known to the CA, not long expired."""
        server = state.server
        if not server.cert_id and not server.status:
            return (
                "the CA has no record of this certificate (looked up by its public key). Only certificates "
                "the UK e-Science CA knows as VALID can be renewed; request a new certificate instead"
            )
        status = (server.status or "UNKNOWN").upper()
        if status != "VALID":
            return f"the CA reports this certificate as {status}; only VALID certificates can be renewed"
        now = dt.datetime.now(dt.timezone.utc)
        if now < certs.not_valid_before(certificate):
            return "the certificate is not yet valid"
        if now > certs.not_valid_after(certificate) + RENEWAL_GRACE:
            return (
                f"the certificate expired more than {RENEWAL_GRACE.days} days ago and can no longer be "
                "renewed; request a new certificate instead"
            )
        dn_email = certs.name_attribute(certificate.subject, NameOID.EMAIL_ADDRESS)
        if dn_email and contact and dn_email.strip() != contact.strip():
            return (
                f"the certificate's name contains the e-mail address {dn_email}, which differs from "
                f"{contact}; renew with that address"
            )
        return ""

    # -- revocation ------------------------------------------------------------
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
        progress(f"Requesting revocation of certificate {state.server.cert_id} ({reason})...")
        return _submission(self.client().revoke(state.server.cert_id, reason, certificate, key))

    # -- information -----------------------------------------------------------
    def info(self, *, stop_event: Any = None) -> dict:
        client = self.client()
        info = client.info()
        motd = ""
        try:
            motd = client.motd()
        except PyCertError:
            pass
        return {
            "motd": motd,
            "ras": [ra.label for ra in info.ras],
            "preferred_ra": info.preferred_ra.label if info.preferred_ra else "",
            "policy": dict(info.policy),
            "certificates": list(info.certificates),
            "problems": list(info.problems),
        }

    def ras(self) -> list:
        return self.client().info().ras
