"""Health capabilities: store, sources, rules and the audit chain (OPS-1, SEC-1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.db.jobs import overdue_schedules
from shoc.db.migrate import drift
from shoc.db.pool import fetch_all, fetch_one
from shoc.detect import rules as ruleset
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json
from shoc.store import kept


@dataclass
class Empty:
    pass


@dataclass
class SystemHealth:
    ok: bool = True
    store: dict[str, Any] = field(default_factory=dict)
    sources: list[dict[str, Any]] = field(default_factory=list)
    rules: dict[str, Any] = field(default_factory=dict)
    jobs: dict[str, Any] = field(default_factory=dict)
    findings: dict[str, Any] = field(default_factory=dict)
    # Migrations the database has and this release does not: it was migrated
    # by a newer one, and only a restore takes it back (sre-14).
    schema_ahead: list[str] = field(default_factory=list)
    # How shoc reaches a person: pager, slack, mail and webhook. None of them
    # is not ok, whatever else works.
    reachable: dict[str, bool] = field(default_factory=dict)
    # Postgres' size in bytes, and the share of SHOC_DISK_BUDGET_GB it uses
    # (0 with no budget set).
    disk: dict[str, Any] = field(default_factory=dict)
    # Whether an outside monitor hears from shoc (SHOC_HEARTBEAT_URL). Unset is
    # a notice, not a fault: the ping is egress a deployer opts into.
    heartbeat: bool = False


@capability(
    name="health.status",
    summary="Pipeline health: store, sources, rules, jobs and finding volume",
    input=Empty,
    output=SystemHealth,
    scope="health:read",
    tags=("health", "read"),
)
def status(ctx: Context, inp: Empty) -> Result:
    from shoc.agents import manager, ops

    # Kept in Postgres between loads, so polling it does not wake a warehouse (D161).
    store = kept.health(ctx.db, ctx.store, ctx.tenant_id)
    # The same reading `health.sources` gives. This used to be a second query
    # here, which compared `now() - last_ok_at` against a fixed hour: NULL for a
    # source that had never succeeded, so the worst state a connector can be in
    # was the one state that never counted as stale.
    source_health = ops.source_health(ctx.db, ctx.tenant_id)
    # Over the rules `rule.list` gives, so the Overview and Detection count the
    # same: `rule_state` also holds the indicator matcher's watermark
    # (ioc_match, whose failure `detect.run` reports with its errors) and the
    # state of reverted rules.
    loaded = [r.id for r in ruleset.load(ctx.config, ctx.db, ctx.tenant_id)]
    # `firings` is every time a rule fired, summed, not how many rules did.
    rules = {
        "tracked": len(loaded),
        **(
            fetch_one(
                ctx.db,
                """SELECT count(*) FILTER (WHERE last_error IS NOT NULL) AS failing,
                      coalesce(sum(fires), 0) AS firings
               FROM shoc.rule_state WHERE tenant_id = %s AND rule_id = ANY(%s)""",
                (ctx.tenant_id, loaded),
            )
            or {}
        ),
    }
    jobs = (
        fetch_one(
            ctx.db,
            """SELECT count(*) FILTER (WHERE state='pending') AS pending,
                  count(*) FILTER (WHERE state='running') AS running,
                  count(*) FILTER (WHERE state='failed') AS failed,
                  count(*) FILTER (
                      WHERE state='failed'
                        AND coalesce(finished_at, created_at) > now() - interval '24 hours'
                  ) AS failed_recently
           FROM shoc.jobs WHERE tenant_id = %s""",
            (ctx.tenant_id,),
        )
        or {}
    )
    # Every scheduled job, ops.check included, needs a cron leader to tick it,
    # so a stalled scheduler can only be seen from outside the schedule. `serve`
    # pages on the same reading (manager.scheduler).
    jobs["overdue_schedules"] = overdue_schedules(ctx.db, ctx.tenant_id)
    findings = (
        fetch_one(
            ctx.db,
            # shoc's own credentials at work and what was set aside are not
            # high findings, as the weekly does not count them either.
            """SELECT count(*) AS total,
                  count(*) FILTER (WHERE status IN ('new', 'triage')) AS open,
                  count(*) FILTER (WHERE severity IN ('high','critical')
                                   AND status NOT IN ('self', 'suppressed')) AS high
           FROM shoc.findings WHERE tenant_id = %s""",
            (ctx.tenant_id,),
        )
        or {}
    )
    stale = [s.source for s in source_health if s.stale]
    # A pull that read some streams and had others refused still worked: a
    # tenant without one licensed stream (Entra without P2) is not failing.
    erroring = [s.source for s in source_health if s.error and not s.partial]
    partial = [s.source for s in source_health if s.error and s.partial]
    # Only jobs that gave up recently: a job that failed, was fixed and now
    # runs would otherwise hold health red forever.
    failed_jobs = int(jobs.get("failed_recently") or 0)
    _, ahead = drift(ctx.db)
    reachable = manager.reachable(ctx.db, ctx.tenant_id, ctx.config)
    room = ops.disk(ctx.db, ctx.config)
    full = room["used"] >= ops.DISK_PAGE
    # Its refresh job succeeds whatever each feed did, so only this says so (DET-4).
    feeds = [feed["feed"] for feed in ops.failing_feeds(ctx.db, ctx.tenant_id)]
    ok = (
        store.ok
        and not stale
        and not erroring
        and not int(rules.get("failing") or 0)
        and not failed_jobs
        and not jobs["overdue_schedules"]
        and not ahead
        and any(reachable.values())
        and not full
        and not feeds
    )
    detail = "healthy" if ok else "degraded"
    if not any(reachable.values()):
        detail += "; no way to reach a person"
    if full:
        detail += f"; the database uses {room['used']:.0%} of SHOC_DISK_BUDGET_GB"
    if ahead:
        detail += "; the database was migrated by a newer release: " + ", ".join(ahead)
    if stale:
        never = [s.source for s in source_health if s.stale and s.last_ok_at is None]
        detail += f"; stale source(s): {', '.join(stale)}"
        if never:
            detail += f" ({', '.join(never)} has never succeeded)"
    if erroring:
        detail += f"; failing source(s): {', '.join(erroring)}"
    if partial:
        detail += f"; source(s) with a stream refused: {', '.join(partial)}"
    if feeds:
        detail += f"; failing intel feed(s): {', '.join(feeds)}"
    if failed_jobs:
        detail += f"; {failed_jobs} job(s) failed in the last 24h"
    if jobs["overdue_schedules"]:
        detail += "; no worker is ticking the scheduler, over an hour overdue: " + ", ".join(
            jobs["overdue_schedules"]
        )
    from shoc.db.pool import is_superuser

    if is_superuser(ctx.db):
        detail += "; running as a Postgres superuser, which bypasses row-level security"
    heartbeat = bool(getattr(ctx.config, "heartbeat_url", ""))
    if not heartbeat:
        detail += "; nothing outside shoc hears from it: set SHOC_HEARTBEAT_URL"
    return Result(
        data=SystemHealth(
            ok=ok,
            store=to_json(store),
            sources=[to_json(s.__dict__) for s in source_health],
            rules=to_json(rules),
            jobs=to_json(jobs),
            findings=to_json(findings),
            schema_ahead=ahead,
            reachable=reachable,
            disk=room,
            heartbeat=heartbeat,
        ),
        summary=(
            f"Pipeline {detail}: {store.event_count} events stored, "
            f"{findings.get('open', 0)} open finding(s), {len(source_health)} source(s)."
        ),
    )


@dataclass
class JobsQuery:
    days: int = f(7, doc="How far back to look for failed jobs")


@dataclass
class FailedJobs:
    """Failed jobs, one row per kind and error: forty retries of one broken
    sync are one problem."""

    failed: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="health.jobs",
    summary="Which worker jobs gave up, and why",
    input=JobsQuery,
    output=FailedJobs,
    scope="health:read",
    tags=("health", "read"),
)
def failed_jobs(ctx: Context, inp: JobsQuery) -> Result:
    rows = fetch_all(
        ctx.db,
        """SELECT kind, last_error AS error, count(*) AS jobs,
                  max(coalesce(finished_at, created_at)) AS last_at
           FROM shoc.jobs
           WHERE tenant_id = %s AND state = 'failed'
             AND coalesce(finished_at, created_at) > now() - %s * interval '1 day'
           GROUP BY kind, last_error
           ORDER BY last_at DESC
           LIMIT 100""",
        (ctx.tenant_id, max(1, inp.days)),
    )
    total = sum(int(r["jobs"]) for r in rows)
    return Result(
        data=FailedJobs(failed=[to_json(r) for r in rows]),
        summary=(
            f"{total} job(s) failed in {inp.days} day(s), {len(rows)} distinct error(s)"
            + (f"; latest: {rows[0]['kind']}: {str(rows[0]['error'])[:160]}" if rows else ".")
        ),
        citations=sorted({str(r["kind"]) for r in rows}),
    )


@dataclass
class AuditQuery:
    limit: int = f(20, doc="How many recent audit rows to return")
    head: str = f(
        "",
        doc="A seq:hash kept outside the database, e.g. from a webhook delivery; "
        "the chain must still hold that row",
    )
    verify: bool = f(
        True,
        doc="Check the chain from where the last check that found it whole ended; "
        "false only lists rows",
    )
    since: str = f("", doc="Only rows from this time: ISO-8601 or relative like -7d")
    until: str = f("", doc="Only rows before this ISO-8601 time")
    principal: str = f("", doc="Only this caller, as kind:id (human:<id>, agent:worker)")
    capability: str = f("", doc="Only calls of this capability")
    before: int = f(0, doc="Only rows before this seq: the last row of the previous page")


@dataclass
class AuditReport:
    # Says nothing when `checked` is false: the call only listed rows.
    chain_ok: bool = True
    rows_verified: int = 0
    detail: str = ""
    checked: bool = True
    head: str = ""
    recent: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="health.audit",
    summary="Verify the hash-chained audit log and show recent entries",
    input=AuditQuery,
    output=AuditReport,
    scope="audit:read",
    principals=("human", "agent", "service"),
    tags=("health", "security"),
)
def audit(ctx: Context, inp: AuditQuery) -> Result:
    from shoc.capabilities.events import parse_since
    from shoc.db.audit import chain_head, check

    ok, count, detail = True, 0, "not checked"
    if inp.verify:
        ok, count, detail = check(ctx.db, ctx.tenant_id, head=inp.head.strip())
    where = ["tenant_id = %(t)s"]
    params: dict[str, Any] = {"t": ctx.tenant_id, "limit": max(1, min(int(inp.limit), 200))}
    if inp.since:
        where.append("ts >= %(since)s")
        params["since"] = parse_since(inp.since)
    if inp.until:
        where.append("ts < %(until)s")
        params["until"] = parse_since(inp.until)
    if inp.principal:
        where.append("principal_kind || ':' || principal_id = %(principal)s")
        params["principal"] = inp.principal
    if inp.capability:
        where.append("capability = %(capability)s")
        params["capability"] = inp.capability
    if inp.before:
        where.append("seq < %(before)s")
        params["before"] = int(inp.before)
    recent = fetch_all(
        ctx.db,
        f"""SELECT seq, ts, principal_kind, principal_id, capability, error, hash, subject
            FROM shoc.audit_log WHERE {" AND ".join(where)} ORDER BY seq DESC LIMIT %(limit)s""",
        params,
    )
    return Result(
        data=AuditReport(
            chain_ok=ok,
            rows_verified=count,
            detail=detail,
            checked=inp.verify,
            head=chain_head(ctx.db, ctx.tenant_id),
            recent=[to_json(r) for r in recent],
        ),
        summary=(
            ("Audit chain intact: " if ok else "AUDIT CHAIN BROKEN: ") + detail
            if inp.verify
            else f"{len(recent)} audit row(s); the chain was not checked."
        ),
    )
