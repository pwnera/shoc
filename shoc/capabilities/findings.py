"""Finding capabilities (API-1, DET-3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from shoc.capabilities.registry import Context, Result, capability
from shoc.db.pool import fetch_all, fetch_one
from shoc.errors import NotFound
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json

_COLS = """finding_uid, rule_id, title, severity, confidence, status, entity_key,
           window_start, window_end, first_seen, last_seen, event_count,
           event_uids, attack, evidence, created_at, updated_at"""


@dataclass
class FindingFilter:
    """List findings, newest first."""

    status: str = f("", doc="new, triage, closed or false_positive")
    severity: str = f("", doc="informational, low, medium, high or critical")
    rule_id: str = f("", doc="Only this rule")
    entity: str = f("", doc="Only this entity key (a user, key or IP)")
    since: str = f("-7d", doc="Relative window like -7d, or an ISO-8601 timestamp")
    limit: int = f(50, doc="Maximum rows, capped at 500")


@dataclass
class FindingPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="finding.list",
    summary="List findings the detection engine produced",
    input=FindingFilter,
    output=FindingPage,
    scope="findings:read",
    tags=("findings", "read"),
)
def list_findings(ctx: Context, inp: FindingFilter) -> Result:
    from shoc.capabilities.events import parse_since

    limit = max(1, min(int(inp.limit), 500))
    where = ["tenant_id = %(tenant_id)s", "last_seen >= %(since)s"]
    params: dict[str, Any] = {
        "tenant_id": ctx.tenant_id,
        "since": parse_since(inp.since, default_hours=24 * 7),
    }
    for value, column in (
        (inp.status, "status"),
        (inp.severity, "severity"),
        (inp.rule_id, "rule_id"),
        (inp.entity, "entity_key"),
    ):
        if value:
            params[column] = value
            where.append(f"{column} = %({column})s")
    rows = fetch_all(
        ctx.db,
        f"SELECT {_COLS} FROM shoc.findings WHERE {' AND '.join(where)} "
        f"ORDER BY last_seen DESC LIMIT {limit}",
        params,
    )
    data = [to_json(r) for r in rows]
    citations = [uid for r in rows for uid in (r["event_uids"] or [])][:50]
    top = ", ".join(sorted({r["severity"] for r in rows})) or "none"
    return Result(
        data=FindingPage(rows=data, count=len(data)),
        summary=f"{len(data)} finding(s); severities: {top}.",
        citations=citations,
    )


@dataclass
class FindingRef:
    finding_uid: str = f(doc="The finding identifier, e.g. F-1a2b…")


@dataclass
class FindingDetail:
    finding: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    rule: dict[str, Any] = field(default_factory=dict)


@capability(
    name="finding.get",
    summary="Get one finding with the events that back it",
    input=FindingRef,
    output=FindingDetail,
    scope="findings:read",
    tags=("findings", "read"),
)
def get_finding(ctx: Context, inp: FindingRef) -> Result:
    row = fetch_one(
        ctx.db,
        f"SELECT {_COLS} FROM shoc.findings WHERE tenant_id = %s AND finding_uid = %s",
        (ctx.tenant_id, inp.finding_uid),
    )
    if not row:
        raise NotFound(f"no finding '{inp.finding_uid}'")
    uids = list(row["event_uids"] or [])
    events: list[dict[str, Any]] = []
    if uids:
        from shoc.capabilities.events import EventQuery, build_query

        sql, params, limit = build_query(
            EventQuery(event_uids=uids, limit=len(uids)), ctx.tenant_id
        )
        events = [to_json(r) for r in ctx.store.query(sql, params, limit).rows]
    rule: dict[str, Any] = {}
    try:
        from shoc.detect import hunts
        from shoc.detect import rules as ruleset

        # A hunt's finding is keyed `hunt:<pack>`; its pack stands in for the rule.
        found = (
            [
                p
                for p in hunts.load(ctx.config, ctx.db, ctx.tenant_id)
                if f"hunt:{p.id}" == row["rule_id"]
            ]
            if row["rule_id"].startswith("hunt:")
            else [
                r for r in ruleset.load(ctx.config, ctx.db, ctx.tenant_id) if r.id == row["rule_id"]
            ]
        )
        rule = found[0].to_json() if found else {}
    except Exception:
        rule = {}
    return Result(
        data=FindingDetail(finding=to_json(row), events=events, rule=rule),
        summary=(
            f"{row['severity'].upper()} · {row['title']} · entity {row['entity_key']} · "
            f"{row['event_count']} event(s) between {row['first_seen']:%Y-%m-%d %H:%M} and "
            f"{row['last_seen']:%H:%M} UTC."
        ),
        citations=uids,
    )


@dataclass
class StatusUpdate:
    finding_uid: str = f(doc="The finding to update")
    status: Literal["new", "triage", "closed", "false_positive"] = f(
        "triage", doc="New status for the finding"
    )
    note: str = f("", doc="Why — kept in the audit log")


@dataclass
class StatusResult:
    finding_uid: str = ""
    status: str = ""
    updated_at: datetime | None = None


@capability(
    name="finding.set_status",
    summary="Change a finding's status (triage, close, mark a false positive)",
    input=StatusUpdate,
    output=StatusResult,
    scope="findings:write",
    principals=("human", "agent"),
    audit=True,
    tags=("findings", "write"),
)
def set_status(ctx: Context, inp: StatusUpdate) -> Result:
    row = fetch_one(
        ctx.db,
        """UPDATE shoc.findings SET status = %s, updated_at = now()
           WHERE tenant_id = %s AND finding_uid = %s
           RETURNING finding_uid, status, updated_at""",
        (inp.status, ctx.tenant_id, inp.finding_uid),
    )
    if not row:
        raise NotFound(f"no finding '{inp.finding_uid}'")
    return Result(
        data=StatusResult(**{k: row[k] for k in ("finding_uid", "status", "updated_at")}),
        summary=f"{inp.finding_uid} is now {inp.status}.",
        citations=[inp.finding_uid],
    )
