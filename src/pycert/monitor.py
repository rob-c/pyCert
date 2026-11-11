"""Inventory and health checks for every managed certificate.

:func:`check` evaluates the local store the way a monitoring system wants it:
one overall level (OK / WARNING / CRITICAL / UNKNOWN, with the Nagios/Icinga
exit codes 0 / 1 / 2 / 3), a one-line summary, per-certificate findings and
performance data.  ``pycert check`` is therefore usable directly as a Nagios,
Icinga, Zabbix (external check) or cron+mail probe, and the GUI dashboard uses
the same findings.

:func:`inventory` returns one flat row per certificate for ``pycert report``
(table, CSV or JSON).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .store import STATUS_FAILED, STATUS_REVOKED, RequestState
from .util import parse_iso

OK, WARNING, CRITICAL, UNKNOWN = "OK", "WARNING", "CRITICAL", "UNKNOWN"
LEVELS = (OK, WARNING, CRITICAL, UNKNOWN)
EXIT_CODES = {OK: 0, WARNING: 1, CRITICAL: 2, UNKNOWN: 3}
_SEVERITY = {OK: 0, WARNING: 1, UNKNOWN: 2, CRITICAL: 3}

DEFAULT_WARN_DAYS = 30
DEFAULT_CRIT_DAYS = 7
DEFAULT_STALE_PENDING_DAYS = 14


@dataclass
class Finding:
    alias: str
    level: str
    message: str
    days_remaining: "int | None" = None

    def as_dict(self) -> dict:
        return {"alias": self.alias, "level": self.level, "message": self.message, "days_remaining": self.days_remaining}


@dataclass
class CheckReport:
    level: str = OK
    findings: "list[Finding]" = field(default_factory=list)
    counts: "dict[str, int]" = field(default_factory=dict)
    warn_days: int = DEFAULT_WARN_DAYS
    crit_days: int = DEFAULT_CRIT_DAYS

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.level]

    def raise_to(self, level: str) -> None:
        if _SEVERITY[level] > _SEVERITY[self.level]:
            self.level = level

    def problems(self) -> "list[Finding]":
        return [f for f in self.findings if f.level != OK]

    def summary(self) -> str:
        problems = self.problems()
        counts = self.counts
        if not problems:
            text = f"{counts.get('valid', 0)} certificate(s) valid"
            if counts.get("pending"):
                text += f", {counts['pending']} pending"
        else:
            worst = sorted(problems, key=lambda f: -_SEVERITY[f.level])
            text = "; ".join(f"{f.alias}: {f.message}" for f in worst[:3])
            if len(worst) > 3:
                text += f"; and {len(worst) - 3} more"
        perf = " ".join(f"{key}={counts.get(key, 0)}" for key in ("valid", "expiring", "expired", "pending", "failed", "drift"))
        return f"PYCERT {self.level} - {text} | {perf}"

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "exit_code": self.exit_code,
            "summary": self.summary(),
            "counts": dict(self.counts),
            "warn_days": self.warn_days,
            "crit_days": self.crit_days,
            "findings": [f.as_dict() for f in self.findings],
        }


def _days_since(text: str, now: datetime) -> "int | None":
    if not text:
        return None
    try:
        return (now - parse_iso(text)).days
    except ValueError:
        return None


def evaluate(
    ctx: Any,
    state: RequestState,
    *,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
    stale_pending_days: int = DEFAULT_STALE_PENDING_DAYS,
    check_deployments: bool = True,
    now: "datetime | None" = None,
) -> "tuple[str, list[Finding]]":
    """Classify one certificate: returns ``(category, findings)``.

    Categories: valid, expiring, expired, pending, failed, revoked.
    """
    now = now or datetime.now(timezone.utc)
    alias = state.alias
    findings: "list[Finding]" = []
    if state.status == STATUS_REVOKED:
        return "revoked", [Finding(alias, OK, "revoked")]
    if state.status == STATUS_FAILED and not state.cert.not_after:
        return "failed", [Finding(alias, WARNING, f"request failed ({_last_detail(state) or 'see pycert show'})")]
    days = state.days_remaining
    if not state.cert.not_after:
        age = _days_since(state.submitted_at or state.created_at, now)
        if age is not None and age >= stale_pending_days:
            findings.append(Finding(alias, WARNING, f"pending for {age} days ({state.status}); contact the RA"))
        else:
            findings.append(Finding(alias, OK, f"pending ({state.status})"))
        return "pending", findings
    renewing = " (renewal in progress)" if state.renewal else ""
    if days is None:  # pragma: no cover - not_after is set but unparsable
        return "failed", [Finding(alias, UNKNOWN, "cannot parse the expiry date")]
    if days < 0:
        category = "expired"
        findings.append(Finding(alias, CRITICAL, f"expired {-days} day(s) ago{renewing}", days))
    elif days <= crit_days:
        category = "expiring"
        findings.append(Finding(alias, CRITICAL, f"expires in {days} day(s){renewing}", days))
    elif days <= warn_days:
        category = "expiring"
        findings.append(Finding(alias, WARNING, f"expires in {days} day(s){renewing}", days))
    else:
        category = "valid"
        findings.append(Finding(alias, OK, f"valid for {days} day(s)", days))
    if not state.cert.verified and category != "expired":
        findings.append(Finding(alias, WARNING, "chain was not verified against a trust anchor", days))
    if state.renewal and state.status == STATUS_FAILED:
        findings.append(Finding(alias, WARNING, "the last renewal attempt failed", days))
    link = state.keystore
    if link.get("name") and state.cert.sha256 and link.get("written") != state.cert.sha256 and not state.renewal:
        findings.append(
            Finding(alias, WARNING, f"not yet written to Java keystore '{link['name']}' (unlock it to synchronise)", days)
        )
    if check_deployments and state.deploy:
        from .deploy import check_drift

        for item in check_drift(ctx, state):
            where = f" {item.path}" if item.path else ""
            findings.append(Finding(alias, WARNING, f"deployment '{item.target}'{where}: {item.problem}", days))
    return category, findings


def _last_detail(state: RequestState) -> str:
    for entry in reversed(state.history):
        if entry.get("detail"):
            return str(entry["detail"])[:120]
    return ""


def check(
    ctx: Any,
    *,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
    stale_pending_days: int = DEFAULT_STALE_PENDING_DAYS,
    aliases: "list[str] | None" = None,
    ca: str = "",
    cert_type: str = "",
    check_deployments: bool = True,
    now: "datetime | None" = None,
) -> CheckReport:
    if crit_days > warn_days:
        raise ValueError("the critical threshold must not be larger than the warning threshold")
    report = CheckReport(warn_days=warn_days, crit_days=crit_days)
    counts = dict.fromkeys(("valid", "expiring", "expired", "pending", "failed", "revoked", "drift"), 0)
    states = select(ctx, aliases=aliases, ca=ca, cert_type=cert_type)
    for state in states:
        category, findings = evaluate(
            ctx,
            state,
            warn_days=warn_days,
            crit_days=crit_days,
            stale_pending_days=stale_pending_days,
            check_deployments=check_deployments,
            now=now,
        )
        counts[category] += 1
        if any("deployment" in f.message for f in findings):
            counts["drift"] += 1
        for finding in findings:
            report.findings.append(finding)
            report.raise_to(finding.level)
    if aliases and not states:
        report.findings.append(Finding(",".join(aliases), UNKNOWN, "no matching certificates"))
        report.raise_to(UNKNOWN)
    report.counts = counts
    return report


def select(ctx: Any, *, aliases: "list[str] | None" = None, ca: str = "", cert_type: str = "") -> "list[RequestState]":
    """Stored requests filtered by alias, CA profile and type."""
    if aliases:
        states = []
        for alias in aliases:
            try:
                states.append(ctx.store.get(alias))
            except Exception:  # noqa: BLE001 - reported as UNKNOWN by check()
                continue
    else:
        states = ctx.store.list()
    primary = ctx.config.primary_profile.name
    if ca:
        states = [s for s in states if (s.ca or primary) == ca]
    if cert_type:
        states = [s for s in states if s.type == cert_type]
    return states


def inventory(ctx: Any, **filters: Any) -> "list[dict]":
    """One flat row per certificate (for reports and spreadsheets)."""
    primary = ctx.config.primary_profile.name
    rows = []
    for state in select(ctx, **filters):
        category, findings = evaluate(ctx, state)
        worst = max((f for f in findings), key=lambda f: _SEVERITY[f.level], default=None)
        rows.append(
            {
                "alias": state.alias,
                "common_name": state.cn,
                "type": state.type,
                "ca": state.ca or primary,
                "status": state.status,
                "health": worst.level if worst else OK,
                "category": category,
                "not_before": state.cert.not_before[:10],
                "not_after": state.cert.not_after[:10],
                "days_remaining": state.days_remaining,
                "serial": state.cert.serial,
                "sha256": state.cert.sha256,
                "issuer": state.cert.issuer,
                "sans": ";".join(state.cert.sans),
                "key": state.cert.key or state.key_algorithm,
                "renewal_in_progress": state.renewal,
                "auto_renew": state.auto_renew,
                "deploy_targets": ";".join(str(t.get("name")) for t in state.deploy),
                "description": state.description,
                "note": worst.message if worst and worst.level != OK else "",
            }
        )
    return rows
