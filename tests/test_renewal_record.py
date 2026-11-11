"""Renewals start from the CA's record of the certificate, as in CertWizard.

The UK e-Science CA renews only certificates it knows as VALID (looked up by
public key), not long expired, and the renewal sets the contact e-mail the CA
holds. The sandbox issues names in production order and challenges with the
production PPPK realm.
"""

import datetime as dt
import io
import sys
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pycert import certs, cli
from pycert.ca import Lookup, ServerCertificate
from pycert.errors import CAError, PyCertError
from pycert.providers.base import CAProvider
from pycert.providers.ukca import RENEWAL_GRACE, _matching_certificate
from pycert.workflow import check_renewal, describe_record, refresh_records, renew
from sandbox_ca.mock_ca import PPPK_REALM, production_subject

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _certificate(*, days_before=1, days_after=30, email=None, cn="renew.example.org"):
    attributes = [x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"), x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if email:
        attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    name = x509.Name(attributes)
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=days_before))
        .not_valid_after(now + dt.timedelta(days=days_after))
        .sign(_KEY, hashes.SHA256())
    )


def _valid_state(**server):
    values = {"cert_id": "77", "status": "VALID", "email": "ops@example.org", **server}
    return SimpleNamespace(server=SimpleNamespace(**values))


# -- the CA's rules -------------------------------------------------------------


def test_ukca_renewal_rules(ctx):
    provider = ctx.provider()
    good = _certificate()
    assert provider.renewal_problem(_valid_state(), good, "ops@example.org") == ""
    assert "no record" in provider.renewal_problem(_valid_state(cert_id="", status=""), good, "x@example.org")
    assert "REVOKED" in provider.renewal_problem(_valid_state(status="revoked"), good, "x@example.org")
    assert "UNKNOWN" in provider.renewal_problem(_valid_state(cert_id="9", status=""), good, "x@example.org")
    assert "not yet valid" in provider.renewal_problem(_valid_state(), _certificate(days_before=-2), "x@example.org")
    # expired: allowed within the grace period, refused after it
    recent = _certificate(days_before=400, days_after=-(RENEWAL_GRACE.days - 1))
    assert provider.renewal_problem(_valid_state(), recent, "x@example.org") == ""
    stale = _certificate(days_before=400, days_after=-(RENEWAL_GRACE.days + 1))
    assert "expired more than 30 days" in provider.renewal_problem(_valid_state(), stale, "x@example.org")
    # an e-mail address in the name must be the one sent
    named = _certificate(email="jane@example.org", cn="jane doe")
    assert provider.renewal_problem(_valid_state(), named, "jane@example.org") == ""
    assert "differs from other@example.org" in provider.renewal_problem(_valid_state(), named, "other@example.org")


def test_providers_without_records_impose_nothing():
    state = _valid_state()
    assert CAProvider.refresh_record(None, state, _certificate()) is False
    assert CAProvider.renewal_problem(None, state, _certificate(), "") == ""


def test_matching_certificate_prefers_the_entry_carrying_it():
    ours, other = _certificate(), _certificate(cn="other.example.org")
    mine = ServerCertificate(id="1", status="VALID", pem=certs.cert_pem(ours))
    latest = ServerCertificate(id="2", status="VALID", pem=certs.cert_pem(other))
    assert _matching_certificate(Lookup(certificates=[mine, latest]), ours) is mine
    bare = ServerCertificate(id="3", status="VALID")
    assert _matching_certificate(Lookup(certificates=[latest, bare]), ours) is bare
    assert _matching_certificate(Lookup(), ours) is None


def test_describe_record():
    assert describe_record(_valid_state(cert_id="", status="")) == "the CA has no record of this certificate"
    assert describe_record(_valid_state()) == "CA status VALID, contact ops@example.org, certificate id 77"
    assert describe_record(_valid_state(email="", cert_id="", status="VALID")) == "CA status VALID"


# -- checking before a renewal ----------------------------------------------------


def test_check_uses_the_cas_contact_and_records_it(ctx, ca, issued):
    state = issued("record holder")
    state.server.email = state.server.status = state.server.cert_id = state.server.last_checked = ""
    state.email = "local@example.org"
    ctx.store.save(state)
    check = check_renewal(ctx, state.alias)
    assert check.ok and check.asked
    assert check.record_email == "test@example.org" and check.contact == "test@example.org"
    stored = ctx.store.get(state.alias)
    assert stored.server.status == "VALID" and stored.server.cert_id and stored.server.last_checked
    assert check_renewal(ctx, state.alias, email="other@example.org").contact == "other@example.org"
    assert "not a valid e-mail" in check_renewal(ctx, state.alias, email="nonsense").problem


def test_check_refusals(ctx, ca, issued):
    state = issued("refusal case")
    # revoked at the CA
    ca.certificates[int(ctx.store.get(state.alias).server.cert_id)].status = "REVOKED"
    assert "REVOKED" in check_renewal(ctx, state.alias).problem
    # no contact known anywhere (the CA gives none)
    ca.certificates[int(ctx.store.get(state.alias).server.cert_id)].status = "VALID"
    for record in ca.csrs.values():
        record.email = ""
    state = ctx.store.get(state.alias)
    state.email = ""
    ctx.store.save(state)
    ctx.config.identity.email = ""
    assert "no contact e-mail" in check_renewal(ctx, state.alias).problem
    # a renewal already in flight, or nothing to renew
    state.renewal = True
    ctx.store.save(state)
    assert "already in progress" in check_renewal(ctx, state).problem
    bare = ctx.store.new_state(alias="bare", type="user", cn="bare", email="b@example.org")
    assert "no certificate" in check_renewal(ctx, bare).problem


def test_renewal_is_refused_before_anything_is_generated(ctx, ca, issued):
    state = issued("unknown to the ca")
    ca.reset()  # the CA no longer knows the certificate (e.g. imported from another CA)
    messages = []
    with pytest.raises(PyCertError, match="no record of this certificate"):
        renew(ctx, state.alias, progress=messages.append)
    after = ctx.store.get(state.alias)
    assert after.status == state.status and not after.renewal
    assert not ctx.store.file(after, "key.next.pem").exists()
    assert not any("Generating" in m for m in messages)


def test_renewal_notes_a_changed_contact(ctx, ca, issued):
    state = issued("contact change")
    ca.auto_approve = False
    messages = []
    renewed = renew(ctx, state.alias, email="new-contact@example.org", progress=messages.append)
    assert renewed.email == "new-contact@example.org"
    assert any("changes from test@example.org to new-contact@example.org" in m for m in messages)
    # the challenge came with the production realm, which pyCertWiz echoes back
    assert any(c.headers.get("realm") == PPPK_REALM for c in ca.captured if c.path == "/CSR")


def test_renewal_with_the_record_contact_is_silent(ctx, ca, issued):
    state = issued("same contact")
    ca.auto_approve = False
    messages = []
    renew(ctx, state.alias, progress=messages.append)
    assert not any("changes from" in m for m in messages)
    assert ctx.store.get(state.alias).email == "test@example.org"


# -- refreshing records (imported certificates) ------------------------------------


def test_refresh_records(ctx, ca, issued, monkeypatch):
    first, second = issued("first record"), issued("second record")
    for alias in (first.alias, second.alias):
        state = ctx.store.get(alias)
        state.server.last_checked = state.server.email = ""
        ctx.store.save(state)
    messages = []
    results = refresh_records(ctx, only_missing=True, progress=messages.append)
    assert sorted(s.alias for s, _ in results) == [first.alias, second.alias]
    assert all("CA status VALID, contact test@example.org" in m for _, m in results) and len(messages) == 2
    assert refresh_records(ctx, only_missing=True) == []  # checked now
    assert [s.alias for s, _ in refresh_records(ctx, aliases={first.alias})] == [first.alias]
    stop = SimpleNamespace(is_set=lambda: True)
    assert refresh_records(ctx, stop_event=stop) == []
    # in-flight renewals and pending requests keep their CSR status: not refreshed
    state = ctx.store.get(first.alias)
    state.renewal = True
    ctx.store.save(state)
    assert [s.alias for s, _ in refresh_records(ctx)] == [second.alias]
    # errors are reported per certificate
    provider = type(ctx.provider())
    monkeypatch.setattr(provider, "refresh_record", lambda *a, **k: (_ for _ in ()).throw(CAError("down")))
    assert refresh_records(ctx)[0][1] == "error: down"
    # a CA without records is skipped
    monkeypatch.setattr(provider, "refresh_record", lambda *a, **k: False)
    assert refresh_records(ctx) == []


def test_cli_status_refresh_fetches_records(config, ctx, ca, issued, capsys, monkeypatch):
    state = issued("cli record")
    state.server.last_checked = ""
    ctx.store.save(state)
    base = ["--config", str(config.path)]

    def run(args):
        old, sys.stdin = sys.stdin, io.StringIO("")
        try:
            code = cli.main(args)
        finally:
            sys.stdin = old
        captured = capsys.readouterr()
        return code, captured.out + captured.err

    code, out = run([*base, "status", "--refresh"])
    assert code == 0 and "cli record: CA status VALID, contact test@example.org" in out
    code, out = run([*base, "status", "--refresh", state.alias])
    assert code == 0 and "DOWNLOADED; CA status VALID" in out
    monkeypatch.setattr(type(ctx.provider()), "refresh_record", lambda *a, **k: False)
    code, out = run([*base, "status", "--refresh", state.alias])
    assert "no need to poll" in out


# -- the sandbox ------------------------------------------------------------------


def test_sandbox_issues_names_in_production_order(ca):
    cn_first = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "dev4.example.org"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "NeSC"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Edinburgh"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eScience"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "7"),
        ]
    )
    order = [next(iter(rdn)).oid for rdn in production_subject(cn_first).rdns]
    assert order == [
        NameOID.COUNTRY_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.COMMON_NAME,
        NameOID.SERIAL_NUMBER,
    ]
    csr = x509.CertificateSigningRequestBuilder().subject_name(cn_first).sign(_KEY, hashes.SHA256())
    issued = ca.issue(csr, kind="host")
    assert next(iter(issued.subject.rdns[0])).oid == NameOID.COUNTRY_NAME
    assert set(issued.subject) == set(cn_first)
