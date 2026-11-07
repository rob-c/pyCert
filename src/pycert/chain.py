"""Certificate chain building and validation.

Given a leaf certificate, build the ordered chain ``[leaf, issuer, ..., root]``
and decide whether it validates against the configured trust anchors.

An issuer candidate is accepted only if *all* of the following hold:

* its subject name equals the child's issuer name;
* if both the child's AuthorityKeyIdentifier and the candidate's
  SubjectKeyIdentifier are present, they match;
* it is not explicitly marked as a non-CA (``basicConstraints CA=false``);
* the child's signature verifies with the candidate's public key.

The signature check is what makes AIA fetching safe: certificates downloaded
over plain HTTP from an ``authorityInfoAccess`` URL cannot forge a valid
issuer, because the child's signature would not verify.

Validation additionally requires that the chain reaches a configured anchor, that
no certificate uses a weak signature hash (MD5/SHA-1) unless explicitly allowed,
that every certificate is inside its validity window, and that no DNS name
violates the issuer's NameConstraints.
"""

import ssl
import urllib.error
import urllib.request
import warnings
from datetime import datetime, timezone
from typing import Callable, Iterable, Sequence

from cryptography import x509

from . import certs
from .compat import dataclass, field, not_valid_after, not_valid_before
from .errors import ChainError

MAX_DEPTH = 10
MAX_AIA_BYTES = 1024 * 1024


@dataclass
class ChainResult:
    chain: "list[x509.Certificate]"
    complete: bool
    trusted: bool
    problems: "list[str]" = field(default_factory=list)
    fetched: "list[str]" = field(default_factory=list)

    @property
    def leaf(self) -> x509.Certificate:
        return self.chain[0]

    @property
    def issuers(self) -> "list[x509.Certificate]":
        return self.chain[1:]

    def pem(self) -> str:
        return "".join(certs.cert_pem(c) for c in self.chain)

    def require_valid(self) -> "ChainResult":  # noqa: F821
        if not self.trusted:
            detail = "; ".join(self.problems) or "the chain does not reach a configured trust anchor"
            raise ChainError(f"certificate chain did not validate: {detail}")
        return self

    def as_dict(self) -> dict:
        return {
            "trusted": self.trusted,
            "complete": self.complete,
            "problems": list(self.problems),
            "fetched": list(self.fetched),
            "chain": [certs.describe_certificate(c).as_dict() for c in self.chain],
        }


AiaFetcher = Callable[[x509.Certificate], Sequence[x509.Certificate]]


class ChainBuilder:
    def __init__(
        self,
        *,
        anchors: Sequence[x509.Certificate] = (),
        extra: Sequence[x509.Certificate] = (),
        fetcher: "AiaFetcher | None" = None,
        allow_sha1: bool = False,
        now: "datetime | None" = None,
        max_depth: int = MAX_DEPTH,
    ):
        self.anchors = list(anchors)
        self.pool = _dedupe([*extra, *anchors])
        self.fetcher = fetcher
        self.allow_sha1 = allow_sha1
        self.now = now or datetime.now(timezone.utc)
        self.max_depth = max_depth
        self._fetched_urls: "list[str]" = []
        self._anchor_fingerprints = {certs.fingerprint(c) for c in anchors}

    def build(self, leaf: x509.Certificate, extra: Iterable[x509.Certificate] = ()) -> ChainResult:
        if extra:
            self.pool = _dedupe([*self.pool, *extra])
        chain = [leaf]
        seen = {certs.fingerprint(leaf)}
        current = leaf
        notes: "list[str]" = []
        anchor_index = 0 if self._is_trusted(leaf) else None

        while True:
            if self._is_trusted(current) and anchor_index is None:
                anchor_index = len(chain) - 1
            if certs.is_self_signed(current):
                break
            if len(chain) >= self.max_depth:
                notes.append(f"chain is longer than {self.max_depth} certificates; stopped")
                break
            issuer = self._select_issuer(current, seen)
            if issuer is None and self.fetcher is not None:
                fetched = self._fetch_for(current)
                if fetched:
                    self.pool = _dedupe([*self.pool, *fetched])
                    issuer = self._select_issuer(current, seen)
            if issuer is None:
                if anchor_index is None:
                    notes.append(
                        f"no issuer certificate found for '{_name(current)}' "
                        f"(issued by '{current.issuer.rfc4514_string()}')"
                    )
                break
            chain.append(issuer)
            seen.add(certs.fingerprint(issuer))
            current = issuer

        problems = self._path_problems(chain, anchor_index)
        if anchor_index is None:
            problems.extend(notes)
            problems.append("chain does not include a configured trust anchor")
        trusted = anchor_index is not None and not problems
        complete = certs.is_self_signed(chain[-1])
        return ChainResult(chain, complete, trusted, problems, list(self._fetched_urls))

    def _path_problems(self, chain: "list[x509.Certificate]", anchor_index: "int | None") -> "list[str]":
        """Validate the part of the chain that actually leads to the anchor.

        The trust anchor itself is trusted out of band: per RFC 5280 its expiry
        and self-signature are not part of path validation.  Everything below it
        (the leaf and every intermediate) must be inside its validity window, use
        an acceptable signature hash, and respect name constraints.
        """
        problems: "list[str]" = []
        limit = len(chain) if anchor_index is None else anchor_index + 1
        for index in range(limit):
            cert = chain[index]
            # A self-signed root anchor is trusted out of band (RFC 5280 skips
            # its expiry and self-signature).  An *intermediate* configured as
            # an anchor is still validated like any other CA certificate: its
            # validity window and signature hash matter.
            out_of_band = anchor_index is not None and index == anchor_index and certs.is_self_signed(cert)
            if not out_of_band and not certs.certificate_valid_at(cert, self.now):
                problems.append(
                    f"certificate is not valid at the current time: '{_name(cert)}' "
                    f"({not_valid_before(cert).isoformat()} .. {not_valid_after(cert).isoformat()})"
                )
            if not out_of_band and not self.allow_sha1 and self._weak(cert):
                try:
                    digest = cert.signature_hash_algorithm.name.upper()
                except (ValueError, AttributeError):
                    digest = "an unknown hash"
                problems.append(
                    f"certificate '{_name(cert)}' is signed with {digest}, which is not "
                    "accepted (set ca.allow_sha1 = true to allow it)"
                )
            if index + 1 < len(chain):
                problems.extend(certs.has_name_constraints_violation(cert, chain[index + 1]))
        return problems

    # -- internals ---------------------------------------------------------
    def _is_trusted(self, cert: x509.Certificate) -> bool:
        return certs.fingerprint(cert) in self._anchor_fingerprints

    @staticmethod
    def _weak(cert: x509.Certificate) -> bool:
        try:
            return certs.is_weak_hash(cert.signature_hash_algorithm.name)
        except (ValueError, AttributeError):  # pragma: no cover
            return False

    def _select_issuer(self, child: x509.Certificate, seen: "set[str]") -> "x509.Certificate | None":
        candidates = []
        for candidate in self.pool:
            fp = certs.fingerprint(candidate)
            if fp in seen:
                continue
            if candidate.subject != child.issuer:
                continue
            if certs.basic_constraints_ca(candidate) is False:
                continue
            if not self._key_ids_consistent(child, candidate):
                continue
            try:
                certs.verify_certificate_signature(child, candidate)
            except Exception:  # noqa: BLE001 - a non-matching candidate is normal
                continue
            candidates.append(candidate)
        if not candidates:
            return None
        # Prefer a currently valid issuer; among those prefer one with a path length.
        candidates.sort(key=lambda c: (not certs.certificate_valid_at(c, self.now), _path_length(c)))
        return candidates[0]

    @staticmethod
    def _key_ids_consistent(child: x509.Certificate, issuer: x509.Certificate) -> bool:
        try:
            aki = child.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        except x509.ExtensionNotFound:
            aki = None
        try:
            ski = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        except x509.ExtensionNotFound:
            ski = None
        if aki is None or ski is None:
            return True
        if aki.key_identifier is None:
            return True
        return aki.key_identifier == ski.digest

    def _fetch_for(self, cert: x509.Certificate) -> "list[x509.Certificate]":
        if self.fetcher is None:
            return []
        try:
            fetched = list(self.fetcher(cert) or [])
        except Exception:  # noqa: BLE001 - fetching is best effort
            return []
        if fetched:
            self._fetched_urls.extend(certs.aia_urls(cert))
        return fetched


def _path_length(cert: x509.Certificate) -> int:
    try:
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return basic.path_length if basic.path_length is not None else 10_000
    except x509.ExtensionNotFound:
        return 10_000


def _name(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _dedupe(certificates: Iterable[x509.Certificate]) -> "list[x509.Certificate]":
    seen: "set[str]" = set()
    result = []
    for cert in certificates:
        fp = certs.fingerprint(cert)
        if fp not in seen:
            seen.add(fp)
            result.append(cert)
    return result


def build_chain(
    leaf: x509.Certificate,
    *,
    anchors: Sequence[x509.Certificate] = (),
    extra: Sequence[x509.Certificate] = (),
    fetcher: "AiaFetcher | None" = None,
    allow_sha1: bool = False,
    now: "datetime | None" = None,
) -> ChainResult:
    return ChainBuilder(anchors=anchors, extra=extra, fetcher=fetcher, allow_sha1=allow_sha1, now=now).build(
        leaf
    )


_system_anchors_cache: "list[x509.Certificate] | None" = None


def system_anchors() -> "list[x509.Certificate]":
    """Certificates from the operating system trust store (best effort)."""
    global _system_anchors_cache
    if _system_anchors_cache is not None:
        return _system_anchors_cache
    result: "list[x509.Certificate]" = []
    try:
        context = ssl.create_default_context()
        with warnings.catch_warnings():
            # Some OS trust stores contain certificates with a zero/negative
            # serial; cryptography warns about it.  We are not trusting them as
            # anchors for anything but a full signature-built path.
            from cryptography.utils import CryptographyDeprecationWarning

            warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            for der in context.get_ca_certs(binary_form=True):
                try:
                    result.append(x509.load_der_x509_certificate(der))
                except ValueError:  # pragma: no cover
                    continue
    except (ssl.SSLError, OSError):  # pragma: no cover - no usable store
        result = []
    _system_anchors_cache = result
    return result


def aia_fetch(certificate: x509.Certificate, *, timeout: float = 10.0) -> "list[x509.Certificate]":
    """Fetch ``caIssuers`` certificates for *certificate*.

    HTTP(S) only, 1 MiB limit, one level of content.  Nothing is trusted: the
    chain builder verifies the signature of the fetched certificate against the
    child before it is used.
    """
    try:
        aia = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    urls = [
        description.access_location.value
        for description in aia
        if description.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
        and isinstance(description.access_location, x509.UniformResourceIdentifier)
    ]
    results: "list[x509.Certificate]" = []
    failures: "list[str]" = []
    for url in urls:
        if not url.lower().startswith(("http://", "https://")):
            failures.append(f"{url}: unsupported scheme")
            continue
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "pyCert/1.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked
                data = response.read(MAX_AIA_BYTES + 1)
            if len(data) > MAX_AIA_BYTES:
                failures.append(f"{url}: response too large")
                continue
            results.extend(certs.load_certificates(data))
        except (urllib.error.URLError, ssl.SSLError, ValueError, OSError) as exc:
            failures.append(f"{url}: {exc}")
            continue
    if not results and failures:
        raise ChainError("AIA fetch failed: " + "; ".join(failures))
    return results
