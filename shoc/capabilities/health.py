"""Health capabilities: store, sources, rules and the audit chain (OPS-1, SEC-1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.db.jobs import overdue_schedules
from shoc.db.pool import fetch_all, fetch_one
from shoc.detect import rules as ruleset
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


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


@capability(
    name="health.status",
    summary="Pipeline health: store, sources, rules, jobs and finding volume",
    input=Empty,
    output=SystemHealth,
    scope="health:read",
    tags=("health", "read"),
)
def status(ctx: Context, inp: Empty) -> Result:
    from shoc.agents import ops

    store = ctx.store.health()
    # The same reading `health.sources` gives. This used to be a second query
    # here, which compared `now() - last_ok_at` against a fixed hour: NULL for a
    # source that had never succeeded, so the worst state a connector can be in
    # was the one state that never counted as stale.
    source_health = ops.source_health(ctx.db, ctx.tenant_id)
    # Over the rules `rule.list` gives, so the Overview and Detection count the
    # same: `rule_state` also holds the indicator matcher's watermark
    # (ioc_match, whose failure fails its job) and the state of reverted rules.
    loaded = [r.id for r in ruleset.load(ctx.config, ctx.db, ctx.tenant_id)]
    rules = {
        "tracked": len(loaded),
        **(
            fetch_one(
                ctx.db,
                """SELECT count(*) FILTER (WHERE last_error IS NOT NULL) AS failing,
                      coalesce(sum(fires), 0) AS fires
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
            """SELECT count(*) AS total,
                  count(*) FILTER (WHERE status IN ('new', 'triage')) AS open,
                  count(*) FILTER (WHERE severity IN ('high','critical')) AS high
           FROM shoc.findings WHERE tenant_id = %s""",
            (ctx.tenant_id,),
        )
        or {}
    )
    stale = [s.source for s in source_health if s.stale]
    erroring = [s.source for s in source_health if s.error]
    # Only jobs that gave up recently: a job that failed, was fixed and now
    # runs would otherwise hold health red forever.
    failed_jobs = int(jobs.get("failed_recently") or 0)
    ok = (
        store.ok
        and not stale
        and not erroring
        and not int(rules.get("failing") or 0)
        and not failed_jobs
        and not jobs["overdue_schedules"]
    )
    detail = "healthy" if ok else "degraded"
    if stale:
        never = [s.source for s in source_health if s.stale and s.last_ok_at is None]
        detail += f"; stale source(s): {', '.join(stale)}"
        if never:
            detail += f" ({', '.join(never)} has never succeeded)"
    if erroring:
        detail += f"; failing source(s): {', '.join(erroring)}"
    if failed_jobs:
        detail += f"; {failed_jobs} job(s) failed in the last 24h"
    if jobs["overdue_schedules"]:
        detail += "; no worker is ticking the scheduler, over an hour overdue: " + ", ".join(
            jobs["overdue_schedules"]
        )
    from shoc.db.pool import is_superuser

    if is_superuser(ctx.db):
        detail += "; running as a Postgres superuser, which bypasses row-level security"
    return Result(
        data=SystemHealth(
            ok=ok,
            store=to_json(store),
            sources=[to_json(s.__dict__) for s in source_health],
            rules=to_json(rules),
            jobs=to_json(jobs),
            findings=to_json(findings),
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


@dataclass
class AuditReport:
    chain_ok: bool = True
    rows_verified: int = 0
    detail: str = ""
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
    from shoc.db.audit import chain_head, verify

    ok, count, detail = verify(ctx.db, ctx.tenant_id, head=inp.head.strip())
    recent = fetch_all(
        ctx.db,
        """SELECT seq, ts, principal_kind, principal_id, capability, error, hash
           FROM shoc.audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT %s""",
        (ctx.tenant_id, max(1, min(int(inp.limit), 200))),
    )
    return Result(
        data=AuditReport(
            chain_ok=ok,
            rows_verified=count,
            detail=detail,
            head=chain_head(ctx.db, ctx.tenant_id),
            recent=[to_json(r) for r in recent],
        ),
        summary=("Audit chain intact: " if ok else "AUDIT CHAIN BROKEN: ") + detail,
    )
