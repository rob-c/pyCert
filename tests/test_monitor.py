"""Health evaluation, the monitoring probe and the inventory report."""

from datetime import datetime, timedelta, timezone

import pytest

from pycert import monitor
from pycert.monitor import (
    CRITICAL,
    OK,
    UNKNOWN,
    WARNING,
    CheckReport,
    Finding,
    check,
    evaluate,
    inventory,
    select,
)
from pycert.store import RequestState
from pycert.util import iso

NOW = datetime.now(timezone.utc)


def _state(alias="cert", *, days=None, status="DOWNLOADED", verified=True, **fields):
    state = RequestState(alias=alias, slug=alias, type=fields.pop("type", "user"), cn=alias)
    state.status = status
    if days is not None:
        state.cert.not_before = iso(NOW - timedelta(days=30))
        state.cert.not_after = iso(NOW + timedelta(days=days, hours=1))
        state.cert.sha256 = "ab" * 32
        state.cert.verified = verified
    for key, value in fields.items():
        setattr(state, key, value)
    return state


def _levels(findings):
    return [(f.level, f.message) for f in findings]


@pytest.mark.parametrize(
    "state, category, level, fragment",
    [
        (_state(status="REVOKED", days=100), "revoked", OK, "revoked"),
        (_state(days=200), "valid", OK, "valid for 200"),
        (_state(days=20), "expiring", WARNING, "expires in 20"),
        (_state(days=3), "expiring", CRITICAL, "expires in 3"),
        (_state(days=-5), "expired", CRITICAL, "expired 5 day(s) ago"),
        (_state(days=3, renewal=True), "expiring", CRITICAL, "(renewal in progress)"),
    ],
)
def test_certificate_categories(ctx, state, category, level, fragment):
    got, findings = evaluate(ctx, state)
    assert got == category
    assert findings[0].level == level and fragment in findings[0].message


def test_failed_and_pending_requests(ctx):
    failed = _state(status="FAILED", history=[{"at": iso(), "status": "FAILED", "detail": "RA rejected: wrong RA"}])
    category, findings = evaluate(ctx, failed)
    assert category == "failed" and findings[0].level == WARNING and "wrong RA" in findings[0].message
    silent = _state(status="FAILED")
    assert "see pycert show" in evaluate(ctx, silent)[1][0].message

    fresh = _state(status="SUBMITTED", submitted_at=iso(NOW - timedelta(days=2)))
    category, findings = evaluate(ctx, fresh, now=NOW)
    assert category == "pending" and findings[0].level == OK
    stale = _state(status="APPROVED", submitted_at=iso(NOW - timedelta(days=20)))
    category, findings = evaluate(ctx, stale, now=NOW)
    assert findings[0].level == WARNING and "pending for 20 days" in findings[0].message
    undated = _state(status="DRAFT", created_at="not a date")
    assert evaluate(ctx, undated, now=NOW)[1][0].level == OK
    assert monitor._days_since("", NOW) is None


def test_unverified_chain_failed_renewal_and_thresholds(ctx):
    unverified = _state(days=100, verified=False)
    assert (WARNING, "chain was not verified against a trust anchor") in _levels(evaluate(ctx, unverified)[1])
    assert len(evaluate(ctx, _state(days=-1, verified=False))[1]) == 1  # expiry dominates
    failed_renewal = _state(days=100, status="FAILED", renewal=True)
    assert (WARNING, "the last renewal attempt failed") in _levels(evaluate(ctx, failed_renewal)[1])
    assert evaluate(ctx, _state(days=20), warn_days=10)[1][0].level == OK
    assert evaluate(ctx, _state(days=20), warn_days=60, crit_days=25)[1][0].level == CRITICAL


def test_deployment_drift_is_reported(ctx, tmp_path):
    state = _state(days=100, deploy=[{"name": "web", "cert": str(tmp_path / "missing.pem")}])
    findings = evaluate(ctx, state)[1]
    assert any(f.level == WARNING and "deployment 'web'" in f.message and "missing" in f.message for f in findings)
    assert len(evaluate(ctx, state, check_deployments=False)[1]) == 1


def test_report_summary_and_dict():
    report = CheckReport(counts={"valid": 3, "pending": 1})
    assert report.summary().startswith("PYCERT OK - 3 certificate(s) valid, 1 pending |")
    assert "drift=0" in report.summary() and report.exit_code == 0 and report.problems() == []
    for index in range(5):
        report.findings.append(Finding(f"c{index}", WARNING if index else CRITICAL, f"problem {index}"))
        report.raise_to(WARNING if index else CRITICAL)
    report.raise_to(WARNING)  # never lowers the level
    assert report.level == CRITICAL and report.exit_code == 2
    text = report.summary()
    assert text.startswith("PYCERT CRITICAL - c0: problem 0;") and "and 2 more" in text
    data = report.as_dict()
    assert data["exit_code"] == 2 and len(data["findings"]) == 5 and data["findings"][0]["alias"] == "c0"
    assert Finding("a", OK, "m", 5).as_dict() == {"alias": "a", "level": OK, "message": "m", "days_remaining": 5}


@pytest.fixture
def store_states(ctx, issued):
    """A user and a host certificate, one expiring, plus a stale pending request."""
    user = issued("monitor person")
    host = issued("web.example.org", type="host", auth_alias=user.alias)
    expiring = ctx.store.get(host.alias)
    expiring.cert.not_after = iso(NOW + timedelta(days=10, hours=1))
    expiring.description = "front end"
    ctx.store.save(expiring)
    pending = ctx.store.new_state(alias="queued person", type="user", cn="queued person", email="x@example.org")
    pending.status = "SUBMITTED"
    pending.submitted_at = iso(NOW - timedelta(days=30))
    ctx.store.save(pending)
    return user, expiring, pending


def test_check_counts_filters_and_levels(ctx, store_states):
    user, host, pending = store_states
    report = check(ctx, now=NOW)
    assert report.level == WARNING and report.exit_code == 1
    assert report.counts["valid"] == 1 and report.counts["expiring"] == 1 and report.counts["pending"] == 1
    assert check(ctx, crit_days=15, warn_days=30).level == CRITICAL
    only_user = check(ctx, aliases=[user.alias])
    assert only_user.level == OK and only_user.counts["valid"] == 1
    assert check(ctx, cert_type="host").counts == {**dict.fromkeys(only_user.counts, 0), "expiring": 1}
    assert check(ctx, ca="elsewhere").counts["valid"] == 0
    unknown = check(ctx, aliases=["no such certificate"])
    assert unknown.level == UNKNOWN and unknown.exit_code == 3
    with pytest.raises(ValueError, match="critical threshold"):
        check(ctx, warn_days=5, crit_days=10)


def test_check_counts_drift(ctx, store_states, tmp_path):
    user = store_states[0]
    state = ctx.store.get(user.alias)
    state.deploy = [{"name": "globus", "cert": str(tmp_path / "usercert.pem")}]
    ctx.store.save(state)
    assert check(ctx, aliases=[user.alias]).counts["drift"] == 1
    assert check(ctx, aliases=[user.alias], check_deployments=False).counts["drift"] == 0


def test_select_and_inventory(ctx, store_states):
    user, host, pending = store_states
    primary = ctx.config.primary_profile.name
    assert {s.alias for s in select(ctx)} == {user.alias, host.alias, pending.alias}
    assert [s.alias for s in select(ctx, aliases=[host.alias, "missing"])] == [host.alias]
    assert [s.alias for s in select(ctx, ca=primary, cert_type="host")] == [host.alias]
    rows = {row["alias"]: row for row in inventory(ctx)}
    assert rows[user.alias]["health"] == OK and rows[user.alias]["note"] == ""
    assert rows[host.alias]["health"] == WARNING and "expires in 10" in rows[host.alias]["note"]
    assert rows[host.alias]["ca"] == primary and rows[host.alias]["description"] == "front end"
    assert rows[host.alias]["sans"] and rows[host.alias]["type"] == "host"
    assert rows[pending.alias]["category"] == "pending" and rows[pending.alias]["days_remaining"] is None
    assert [row["alias"] for row in inventory(ctx, cert_type="user", aliases=[user.alias])] == [user.alias]
