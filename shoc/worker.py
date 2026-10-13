"""`shoc worker`: connectors, detections and housekeeping off the jobs table.

Every worker runs the same loop. Jobs are claimed with SKIP LOCKED, the cron
leader is whoever holds the advisory lock, and LISTEN/NOTIFY wakes workers so an
idle deployment makes no noise (AGT-1). Scale by running more of them.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import psycopg

from shoc.agents.llm import CALL_SECONDS
from shoc.agents.openspace import Budget
from shoc.capabilities.registry import Caller, Context
from shoc.cases.engine import SEVERITY_ORDER
from shoc.config import Config
from shoc.db import jobs
from shoc.db.pool import ALL_TENANTS, connect, execute, fetch_one, set_tenant

log = logging.getLogger("shoc.worker")

# Everything the worker's own scheduled jobs need, and nothing else. Note what
# is missing: `actions:approve`, `detection:write` and `detection:merge`. The
# worker proposes actions and starts the Detection Engineer's turn; running an
# approved action is SYSTEM_CALLER's, merging runs under that role's own
# principal and gate (D48), approving an action and overriding a backlog
# decision are a human's, and the registry refuses both anyway (D8).
WORKER_CALLER = Caller(
    kind="agent",
    id="worker",
    scopes=(
        "events:*",
        "findings:*",
        "sources:*",
        "detection:run",
        "detection:read",
        "detection:work",
        "intel:*",
        "hunts:*",
        "graph:*",
        "posture:*",
        "memory:*",
        "cases:*",
        "playbooks:*",
        "actions:propose",
        "reports:read",
        "stream:*",
        "health:read",
        "audit:read",
        "meta:read",
    ),
)

# The worker carrying out what is already decided, not judging anything: running
# an action the policy or a human approved, delivering webhooks and pages,
# dropping expired partitions, sending the reports, and enforcing deadlines. A
# service principal, because `action.run` stays closed to agents (D8) and a
# partition is dropped with the writer's credential (D22).
SYSTEM_CALLER = Caller(
    kind="service",
    id="worker",
    scopes=(
        "actions:run",
        "stream:deliver",
        "manager:deliver",
        "cases:chase",
        "events:retain",
        "reports:send",
        "cases:recheck",
    ),
)

# The job kinds run as SYSTEM_CALLER; every other kind runs as WORKER_CALLER.
SYSTEM_JOBS = frozenset(
    {
        "action.run",
        "action.expire",
        "stream.deliver",
        "manager.deliver",
        "unattended",
        "retention",
        "report.weekly",
        "report.exec",
        "report.exception",
        "case.recheck",
    }
)

# Every job kind the worker dispatches, and the capability behind it. The test
# suite walks this to prove the worker can actually call everything it schedules.
JOB_CAPABILITIES: dict[str, str] = {
    "source.sync": "source.sync",
    "detect.run": "detect.run",
    "case.investigate": "case.investigate",
    "playbook.run": "playbook.run",
    "playbook.resume": "playbook.resume",
    "graph.refresh": "graph.refresh",
    "posture.survey": "posture.get",
    "detection.backlog": "detection.backlog",
    "hunt.daily": "hunt.daily",
    "ops.check": "ops.alerts",
    "case.sweep": "case.investigate",
    "unattended": "case.chase",
    "intel.refresh": "intel.refresh",
    "source.onboard": "source.onboard",
    "action.run": "action.run",
    "action.expire": "action.expire",
    "stream.deliver": "stream.deliver",
    "manager.deliver": "manager.deliver",
    "retention": "events.retain",
    # A second, blind read of what the crew closed as nothing (RFC 0020). It
    # reopens a case and queues the crew; it acts on nothing itself.
    "case.recheck": "case.recheck",
    # The Manager's reports, to the Slack channel and the stream (AGT-14), and
    # the exception report, sent only when a decision needs a person (D52).
    "report.weekly": "report.send",
    "report.exec": "report.send",
    "report.exception": "report.send",
}


def handle(job: dict[str, Any], config: Config) -> str:
    """Run one job, then hand this thread's connection back to the shared queue.

    The job's Context pins the connection the loop also claims with to the
    job's tenant, and a job that raises would otherwise leave it there. The
    event store the job opened is closed with it (STO-4).
    """
    ctx: Context | None = None
    try:
        ctx = Context(
            tenant_id=job["tenant_id"],
            caller=SYSTEM_CALLER if job["kind"] in SYSTEM_JOBS else WORKER_CALLER,
            config=config,
        )
        return _handle(job, config, ctx)
    finally:
        if ctx is not None:
            ctx.close()
        set_tenant(connect(config), ALL_TENANTS)


_LISTS_LOADING = threading.Lock()
_LISTS_ANNOUNCED = False


def _warm_lists(ctx: Any) -> str:
    """Start loading the lists lookups answer from (RFC 0030); what the last load said.

    The digest holds back values on a warninglist only if this process has the
    lists, and a lookup should not wait on a download. DB-IP alone is several
    megabytes, so the load runs beside the job queue, never in front of it.
    Each list's host is an outbound connection nobody asked for, so they are
    named once (D57), and SHOC_INTEL_FEEDS=off leaves them to load on the first
    lookup instead.
    """
    global _LISTS_ANNOUNCED
    from shoc.detect import intel, osint

    if not intel.default_feeds(ctx.config.intel_feeds):
        return ""
    if _LISTS_LOADING.acquire(blocking=False):

        def load() -> None:
            try:
                for name, why in sorted(osint.warm().items()):
                    log.warning("lookup list %s: %s", name, why)
            finally:
                _LISTS_LOADING.release()

        if not _LISTS_ANNOUNCED:
            _LISTS_ANNOUNCED = True
            log.info("loading lookup lists from: %s", ", ".join(osint.LIST_HOSTS))
        threading.Thread(target=load, name="shoc-lookup-lists", daemon=True).start()
    return "; ".join(f"{name}: {why}" for name, why in sorted(osint.LIST_WARNINGS.items()))


def heartbeat(config: Config) -> str:
    """Tell the outside monitor at SHOC_HEARTBEAT_URL that a check just passed (OPS-1).

    Sent only after `ops.check` read Postgres to the end, so a dead database,
    host or worker stops the pings and the monitor, not shoc, raises it.
    Returns what the job summary adds: nothing, or why the ping failed.
    """
    import httpx

    if not config.heartbeat_url:
        return ""
    try:
        httpx.get(config.heartbeat_url, timeout=10).raise_for_status()
    except Exception as exc:  # never the check's failure; the URL is a secret, so not logged
        log.warning("heartbeat ping failed: %s", type(exc).__name__)
        return f" Heartbeat not sent: {type(exc).__name__}."
    return ""


def _handle(job: dict[str, Any], config: Config, ctx: Context) -> str:
    """Handlers go through the registry, like every other caller."""
    from shoc.capabilities.registry import call

    tenant = job["tenant_id"]
    payload = job["payload"] or {}
    kind = job["kind"]
    if kind == "source.sync":
        from shoc.errors import UpstreamError

        # A source that refuses us is reported by `source.sync` as an error, so
        # that a shell exits non-zero and REST answers 502. For the worker it is
        # ordinary weather: the failure is already written to connector_state,
        # which is what health reads. Letting the job fail too would park one
        # row per polling cycle for as long as the credential stays wrong, and
        # say the same thing twice.
        # What it loaded wakes one detection run for every source of the
        # cycle (`events.loaded`); on a warehouse each run is minutes (D71).
        try:
            return call("source.sync", ctx, {"source": payload["source"]}).summary
        except UpstreamError as exc:
            return str(exc)
    if kind == "detect.run":
        pushed = _flush_pushes(ctx)
        result = call(
            "detect.run", ctx, {k: v for k, v in payload.items() if k in ("rule_id", "lookback")}
        )
        _queue_investigations(ctx, result.data.cases_opened)
        _reread(ctx)
        return result.summary + pushed
    if kind == "case.investigate":
        result = call("case.investigate", ctx, {"case_uid": payload["case_uid"]})
        started = _start_playbooks(ctx, payload["case_uid"])
        # Whatever was said to the crew while it worked is answered now, not at
        # the next scheduled sweep: a few seconds on, once this job is done, as
        # the sweep leaves a case whose run is still going.
        jobs.enqueue(
            ctx.db,
            ctx.tenant_id,
            "case.sweep",
            run_at=datetime.now(UTC) + timedelta(seconds=5),
            idempotency_key=f"sweep:after:{job['job_id']}",
        )
        return result.summary + (f" Started: {', '.join(started)}." if started else "")
    if kind == "playbook.run":
        result = call(
            "playbook.run",
            ctx,
            {
                "playbook_id": payload["playbook_id"],
                "case_uid": payload["case_uid"],
                # False leaves each action's own dry-run setting in charge;
                # True would make the run a preview (RSP-7).
                "dry_run": bool(payload.get("dry_run", False)),
            },
        )
        return result.summary
    if kind == "playbook.resume":
        return call("playbook.resume", ctx, {"run_uid": payload["run_uid"]}).summary
    if kind == "action.run":
        # `dry_run` False leaves the action's own setting in charge.
        ran = call("action.run", ctx, {"action_uid": payload["action_uid"], "dry_run": False})
        return f"{payload['action_uid']}: {ran.data.state} — {ran.summary}"
    if kind == "action.expire":
        return call("action.expire", ctx, {"action_uid": payload["action_uid"]}).summary
    if kind == "stream.deliver":
        # Every minute: with no webhook to send to, no audited call (D163).
        if not fetch_one(
            ctx.db, "SELECT 1 FROM shoc.webhooks WHERE tenant_id = %s AND enabled", (tenant,)
        ):
            return "stream: no webhook to deliver to"
        return call("stream.deliver", ctx, {}).summary
    if kind == "graph.refresh":
        return call("graph.refresh", ctx, {"days": int(payload.get("days", 30))}).summary
    if kind == "hunt.daily":
        # The backlog first, so a pack merged today runs in today's cycle (RFC 0032).
        worked = call("hunt.work", ctx, {})
        return f"{worked.summary} {call('hunt.daily', ctx, {}).summary}"
    if kind == "detection.backlog":
        # Nightly: sweep every intake, expire what has run out, then the
        # Detection Engineer works the top of the backlog to an end (D48).
        result = call("detection.backlog", ctx, {"run": True})
        expired = call("suppression.list", ctx, {"review": True})
        worked = call("detection.work", ctx, {})
        return f"{result.summary} {expired.summary} {worked.summary}"
    if kind == "posture.survey":
        from shoc.agents import surveyor
        from shoc.jsonschema import to_json

        result = call("posture.get", ctx, {"days": int(payload.get("days", 30)), "refresh": True})
        # The queries answered; the Surveyor's model reads them (D47).
        said = surveyor.read(ctx.db, ctx.store, tenant, to_json(result.data), config)
        return result.summary + (
            f" Surveyor: {len(said['items'])} coverage item(s), {len(said['facts'])} change(s)."
            if said["read"]
            else f" Surveyor did not read it: {said['why']}."
        )
    if kind == "case.sweep":
        return _sweep_cases(ctx)
    if kind == "unattended":
        return call("case.chase", ctx, {}).summary
    if kind == "manager.deliver":
        return call("manager.deliver", ctx, {}).summary
    if kind == "ops.check":
        return _ops_check(ctx, tenant, config)
    if kind == "source.onboard":
        return call("source.onboard", ctx, {"source": payload.get("source", "")}).summary
    if kind == "intel.refresh":
        warned = _warm_lists(ctx)
        summary = call("intel.refresh", ctx, {"retro_hunt": True}).summary
        return summary + (f" Lists: {warned}" if warned else "")
    if kind == "report.weekly":
        return call("report.send", ctx, {"kind": "weekly"}).summary
    if kind == "report.exec":
        return call("report.send", ctx, {"kind": "exec"}).summary
    if kind == "report.exception":
        return call("report.send", ctx, {"kind": "exception"}).summary
    if kind == "case.recheck":
        return call("case.recheck", ctx, {}).summary
    if kind == "retention":
        # The control plane first: it is Postgres, and a warehouse that is down
        # should not keep copies of old events here too.
        from shoc.capabilities.events import retention_days

        days = int(payload.get("days") or retention_days(ctx))
        try:
            pruned = prune(ctx.db, tenant, days)
        except psycopg.Error:
            # A purge that timed out still lets old partitions go tonight; the
            # job then fails and is retried, and both steps are safe to repeat.
            call("events.retain", ctx, {"days": days})
            raise
        retained = call("events.retain", ctx, {"days": days}).summary
        return f"{retained}; {pruned}"
    raise ValueError(f"unknown job kind '{kind}'")


# Job keys that still guard a once-only effect after the job is done: a playbook
# started on a case, an action run or expired, a page, a recheck, a crew run, a
# playbook's wait or retry. A purged key would let the same effect happen again.
GUARD_KEYS = [
    "playbook:%",
    "action:%",
    "expire:%",
    "recheck:%",
    "investigate:%",
    "deliver:%",
    "lost:%",
    "timer:%",
    "retry:%",
]

# What the nightly retention job deletes besides event partitions, per table
# (OPS-1). Copies of events (hunt rows, graph entities, lookups, stream payloads)
# go with the events they came from. Finished jobs go after a week and failed
# ones after 30 days, except those `resume_waiting_runs` counts. Stream events
# wait for every enabled webhook to have sent them. Cases, findings, openspace
# and the audit log are incident records and stay.
PRUNE = {
    "jobs": """(state = 'done' AND finished_at < now() - interval '7 days'
                OR state = 'failed' AND finished_at < now() - interval '30 days'
                   AND kind <> 'playbook.resume')
               AND NOT coalesce(idempotency_key, '') LIKE ANY(%(guards)s)""",
    "stream_events": """created_at < now() - %(days)s * interval '1 day'
               AND NOT EXISTS (SELECT 1 FROM shoc.webhooks w
                               WHERE w.tenant_id = %(tenant)s AND w.enabled
                                 AND w.last_seq < seq)""",
    "hunt_observations": "seen_at < now() - %(days)s * interval '1 day'",
    "graph_edges": "last_seen < now() - %(days)s * interval '1 day'",
    "graph_nodes": "last_seen < now() - %(days)s * interval '1 day'",
    "intel_lookups": "looked_up_at < now() - %(days)s * interval '1 day'",
    # A push kept past the retention could only load events already due to go.
    "push_spool": "received_at < now() - %(days)s * interval '1 day'",
    "memory": "expires_at < now()",
}
PRUNE_BATCH = 10_000


def prune(conn: Any, tenant_id: str, days: int) -> str:
    """Delete one tenant's control-plane rows past their window, a batch at a time."""
    params = {
        "tenant": tenant_id,
        "days": max(1, days),
        "guards": GUARD_KEYS,
        "batch": PRUNE_BATCH,
    }
    removed: dict[str, int] = {}
    for table, where in PRUNE.items():
        sql = f"""DELETE FROM shoc.{table} WHERE ctid = ANY(ARRAY(
                      SELECT ctid FROM shoc.{table}
                      WHERE tenant_id = %(tenant)s AND ({where}) LIMIT %(batch)s))"""
        while (n := execute(conn, sql, params)) > 0:
            removed[table] = removed.get(table, 0) + n
            if n < PRUNE_BATCH:
                break
    said = ", ".join(f"{n} {table}" for table, n in removed.items())
    return f"pruned {said or 'nothing'}"


# How long the sweep leaves a case after a crew run that did not come back:
# a quarter hour, doubling with each failed try, never longer than the case's
# own deadline. A flat five tries an hour, reset every hour, sent the crew at
# the same four cases around the clock through a two-day provider outage and
# wrote a failure into each case every time (CASE-9f7294571950d508fb74 took 46).
FIRST_RETRY_HOURS = 0.25


def _flush_pushes(ctx: Context) -> str:
    """Load the pushes a warehouse kept since the last cycle, before detection reads (ING-2).

    A load that fails leaves them kept for the next cycle, and detection runs anyway.
    """
    from shoc.capabilities.events import flush_spool

    try:
        loaded, failed = flush_spool(ctx)
    except Exception as exc:
        log.warning("could not load the kept pushes: %s", exc)
        return f" Kept pushes not loaded, tried again next cycle: {type(exc).__name__}."
    said = f" Loaded {loaded} pushed event(s) first." if loaded else ""
    if failed:
        said += f" {failed} kept push(es) not loaded, tried again next cycle."
    return said


def _queue_investigations(ctx: Context, case_uids: list[str], attempt: str = "opened") -> None:
    """One job per case per attempt. A repeated key is a silent no-op, so a key
    that recurs over a case's life (an attempt number that resets every hour)
    stops the crew from ever going back to it."""
    from shoc.agents.llm import stored

    cfg = stored(ctx.config, ctx.db, ctx.tenant_id)
    if cfg.llm_provider in ("none", "", "off"):
        # Nobody investigates, so the Manager hears of each case. A critical one
        # pages; the gate holds anything else for the weekly (RFC 0015).
        from shoc.agents import manager

        for case_uid in case_uids:
            manager.tell(
                ctx.db,
                ctx.tenant_id,
                "shoc",
                "page",
                "No model is configured, so nobody investigated this case.",
                case_uid=case_uid,
                condition="critical_severity",
            )
        return
    for case_uid in case_uids:
        jobs.enqueue(
            ctx.db,
            ctx.tenant_id,
            "case.investigate",
            {"case_uid": case_uid},
            idempotency_key=f"investigate:{case_uid}:{attempt}",
        )


# What makes an open case worth another look. A case used to be finished the
# moment one token had been spent on it — `tokens_used = 0` is true exactly once
# — so a case that gained ten new findings, or that a human posted a fact into,
# or whose containment has since completed or been turned down, was never returned to. Nobody
# watches this tool most days: if the crew does not go back on its own, nothing
# does (017).
NEEDS_ATTENTION = """
    c.worked_at IS NULL
    OR EXISTS (
        SELECT 1 FROM shoc.findings f
        WHERE f.tenant_id = c.tenant_id AND f.case_uid = c.case_uid
          AND f.created_at > c.worked_at)
    OR EXISTS (
        SELECT 1 FROM shoc.openspace_messages m
        WHERE m.tenant_id = c.tenant_id AND m.case_uid = c.case_uid
          AND (m.kind = 'inject' OR m.principal = 'human')
          AND greatest(m.created_at, coalesce(m.last_repeat_at, m.created_at)) > c.worked_at)
    OR EXISTS (
        SELECT 1 FROM shoc.actions a
        WHERE a.tenant_id = c.tenant_id AND a.case_uid = c.case_uid
          AND (a.state IN ('done', 'failed', 'rolled_back')
               OR (a.state = 'rejected' AND a.approved_by LIKE 'human:%%'))
          AND a.type NOT LIKE 'notify.%%'
          AND a.updated_at > c.worked_at)
"""


def _sweep_cases(ctx: Context) -> str:
    """Send the crew at every open case that has something new to say.

    Three things bring a case back: the crew has never worked it, something has
    happened to it since the crew last did — a finding, an action completing, a
    fact somebody posted — or `shoc/cases/unattended.py` has told it that the
    human it was waiting for is not coming. Each of those events wakes the sweep
    (`engine.WAKES`), so a case the crew is already queued or running on is left
    alone: two runs on one case argue the same thing twice.

    A case whose last try did not come back waits before the next one, longer
    each time and never past its deadline, so an outage costs a handful of
    tries per case instead of one every sweep.
    """
    from shoc.agents import ops
    from shoc.agents.llm import stored
    from shoc.cases.unattended import DEADLINE_HOURS
    from shoc.db.pool import fetch_all, fetch_one

    cfg = stored(ctx.config, ctx.db, ctx.tenant_id)
    if cfg.llm_provider in ("none", "", "off"):
        return "sweep: no LLM is configured, so there is nobody to send"
    failing = ops.provider_failing(ctx.db, ctx.tenant_id)
    if failing:
        return f"sweep: the model provider is failing, nothing queued — {failing[:200]}"
    # A run in which the crew spoke moves `worked_at` past the last try, and
    # that restarts the count.
    rows = fetch_all(
        ctx.db,
        f"""SELECT c.case_uid, t.attempts
            FROM shoc.cases c,
                 LATERAL (SELECT CASE WHEN c.worked_at > c.crew_attempted_at
                                  THEN 0 ELSE c.crew_attempts END AS attempts) t
            WHERE c.tenant_id = %s AND c.state <> 'closed' AND ({NEEDS_ATTENTION})
              AND NOT EXISTS (
                  SELECT 1 FROM shoc.jobs j
                  WHERE j.tenant_id = c.tenant_id AND j.kind = 'case.investigate'
                    AND j.state IN ('pending', 'running')
                    AND j.payload->>'case_uid' = c.case_uid)
              AND (c.crew_attempted_at IS NULL OR t.attempts = 0
                   OR c.crew_attempted_at < now() - interval '1 hour' * least(
                        %s * power(2, t.attempts - 1),
                        (%s::jsonb ->> coalesce(c.severity, 'medium'))::int))
            ORDER BY
              array_position(ARRAY['critical','high','medium','low','informational'], c.severity),
              c.opened_at
            LIMIT 25""",
        (ctx.tenant_id, FIRST_RETRY_HOURS, json.dumps(DEADLINE_HOURS)),
    )
    for row in rows:
        stamped = fetch_one(
            ctx.db,
            """UPDATE shoc.cases SET crew_attempts = %s, crew_attempted_at = now()
               WHERE tenant_id = %s AND case_uid = %s
               RETURNING (extract(epoch FROM crew_attempted_at) * 1e6)::bigint AS at""",
            (int(row["attempts"]) + 1, ctx.tenant_id, str(row["case_uid"])),
        )
        _queue_investigations(
            ctx, [str(row["case_uid"])], attempt=f"sweep@{stamped['at'] if stamped else 0}"
        )
    return f"sweep: queued {len(rows)} case(s) with something new"


# How often `ops.check` walks the whole audit chain, by this process's clock;
# the hourly walks start where the last whole one ended (data-11, SEC-1). The
# first check after a worker starts walks it all.
FULL_WALK_SECONDS = 86400
_WALKED: dict[str, float] = {}


def _ops_check(ctx: Context, tenant: str, config: Config) -> str:
    """The hourly check (OPS-1), the steps that decide a page first (sre-10).

    Each step runs whatever the one before it did: a bad model setting in Ops'
    review used to raise exactly when a source was down, every hour, so the
    dark-source page and the audit check after it never ran. A step that
    failed fails the job once every step has run, naming it, and sends no
    heartbeat. The dark-source page carries the diagnosis Ops' review wrote in
    an earlier hour: a source pages after a day dark, and review runs hourly.
    """
    from shoc.agents import manager, ops
    from shoc.capabilities.registry import call
    from shoc.db import audit

    failed: list[str] = []

    def step(name: str, run: Any) -> Any:
        try:
            return run()
        except Exception as exc:
            if isinstance(exc, psycopg.OperationalError) and (ctx.db.closed or ctx.db.broken):
                raise  # the database went away; the loop reconnects
            log.warning("ops.check %s failed for %s: %s", name, tenant, exc)
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
            return None

    def chain() -> None:
        # Nobody runs `health audit` by hand, so the chain is checked here (SEC-1).
        full = time.monotonic() - _WALKED.get(tenant, -FULL_WALK_SECONDS) >= FULL_WALK_SECONDS
        ok, _, detail = audit.check(ctx.db, tenant, full=full)
        if full:
            _WALKED[tenant] = time.monotonic()
        if not ok and manager.audit_broken(ctx.db, tenant, detail):
            _publish_alert(
                ctx,
                {
                    "kind": "audit.broken",
                    "subject": "audit_log",
                    "detail": detail,
                    "severity": "critical",
                },
            )

    step("coverage", lambda: manager.coverage(ctx.db, tenant, config))
    step("audit", chain)
    result = step("alerts", lambda: call("ops.alerts", ctx, {}))
    raised = result.data.alerts if result else []
    for alert in step("unpublished", lambda: ops.unpublished(ctx.db, tenant, raised)) or []:
        step(f"publish {alert['kind']}", lambda alert=alert: _publish_alert(ctx, alert))
    step("review", lambda: ops.review(ctx.db, ctx.store, tenant, config))
    # A source that fails or whose key fields went empty goes back to the
    # Integrator, once a day at most (D50: Ops wakes it when a vendor changes
    # shape). A source still learning its baseline has nothing to repair (live-12).
    if any(
        a["kind"] == "source.failing" or (a["kind"] == "source.quality" and EMPTY in a["detail"])
        for a in raised
    ):
        step(
            "onboard",
            lambda: jobs.enqueue(
                ctx.db,
                tenant,
                "source.onboard",
                {},
                idempotency_key=f"onboard:drift:{int(time.time() // 86400)}",
            ),
        )
    if failed:
        raise RuntimeError("ops.check: " + "; ".join(failed))
    return result.summary + heartbeat(config)


# The field-fidelity note `ops.source_quality` writes: a column rules read gone empty.
EMPTY = " is empty in "


def _publish_alert(ctx: Context, alert: dict[str, Any]) -> None:
    from shoc.cases import engine

    engine.publish(ctx.db, ctx.tenant_id, f"health.{alert['kind']}", alert["subject"], alert)


def _start_playbooks(ctx: Context, case_uid: str) -> list[str]:
    """Queue every playbook whose trigger matches this case (RSP-2)."""
    from shoc.cases import engine, playbooks

    case = engine.require(ctx.db, ctx.tenant_id, case_uid)
    started: list[str] = []
    books = playbooks.match(ctx.db, ctx.tenant_id, case, ctx.config)
    context = playbooks.context_for(ctx.db, ctx.tenant_id, case, ctx.config) if books else {}
    for book in books:
        # Keyed on what the steps act on: a key or account that joins the case
        # later is answered by a run of its own (RSP-2).
        jobs.enqueue(
            ctx.db,
            ctx.tenant_id,
            "playbook.run",
            {"playbook_id": book.id, "case_uid": case_uid},
            idempotency_key=playbooks.job_key(book, context, ctx.config),
        )
        started.append(book.id)
    return started


# A run left `running` or `waiting_timer` this long with no job to wake it lost
# that job: the worker died, or the job was parked as failed (RSP-2).
STALE_RUN_MINUTES = 30

# How many resumes of one run may be parked as failed before the run is failed.
RUN_RESUMES = 2


def resume_waiting_runs(conn: Any) -> int:
    """Nudge runs whose blocking action a human has since approved, and lost runs."""
    from shoc.cases import playbooks
    from shoc.db.pool import fetch_all

    lost = fetch_all(
        conn,
        """SELECT r.run_uid, r.tenant_id,
                  (SELECT count(*) FROM shoc.jobs j
                    WHERE j.kind = 'playbook.resume' AND j.state = 'failed'
                      AND j.payload->>'run_uid' = r.run_uid) AS parked,
                  (SELECT j.last_error FROM shoc.jobs j
                    WHERE j.kind IN ('playbook.run', 'playbook.resume') AND j.state = 'failed'
                      AND (j.payload->>'run_uid' = r.run_uid
                           OR (j.payload->>'case_uid' = r.case_uid
                               AND j.payload->>'playbook_id' = r.playbook_id))
                    ORDER BY j.job_id DESC LIMIT 1) AS last_error
           FROM shoc.playbook_runs r
           WHERE r.state IN ('running', 'waiting_timer')
             AND r.updated_at < now() - %s * interval '1 minute'
             AND NOT EXISTS (
                 SELECT 1 FROM shoc.jobs j
                 WHERE j.kind IN ('playbook.run', 'playbook.resume')
                   AND j.state IN ('pending', 'running')
                   AND (j.payload->>'run_uid' = r.run_uid
                        OR (j.payload->>'case_uid' = r.case_uid
                            AND j.payload->>'playbook_id' = r.playbook_id)))""",
        (STALE_RUN_MINUTES,),
    )
    for row in lost:
        tenant, run = str(row["tenant_id"]), str(row["run_uid"])
        if int(row["parked"]) >= RUN_RESUMES:
            playbooks.give_up(
                conn,
                tenant,
                run,
                f"its job failed {row['parked']} times: {row['last_error'] or 'no error recorded'}",
            )
            continue
        jobs.enqueue(
            conn,
            tenant,
            "playbook.resume",
            {"run_uid": run},
            idempotency_key=f"lost:{run}:{row['parked']}",
        )

    waiting = fetch_all(
        conn,
        """SELECT r.run_uid, r.tenant_id FROM shoc.playbook_runs r
           JOIN shoc.playbook_steps s
             ON s.run_uid = r.run_uid AND s.step_index = r.step_index
           JOIN shoc.actions a ON a.action_uid = s.action_uid
           WHERE r.state = 'waiting_approval' AND a.state IN ('approved', 'rejected')""",
    )
    for row in waiting:
        jobs.enqueue(
            conn,
            str(row["tenant_id"]),
            "playbook.resume",
            {"run_uid": row["run_uid"]},
            idempotency_key=f"resume:{row['run_uid']}:{int(time.time() // 60)}",
        )
    return len(waiting) + len(lost)


def run_approved_actions(conn: Any) -> int:
    """Queue every approved action nobody is going to run otherwise.

    An action the policy allowed at L1, or one a human approved in Slack, used
    to be born `approved` and stay there: only the playbook runner executed
    anything, and only the steps it owned. This is the other half — the crew's
    own proposals and a human's approvals — and it is idempotent, so an action
    already queued is not queued twice.
    """
    from shoc.cases import actions as action_store

    pending = action_store.approved_unrun(conn)
    for row in pending:
        action_store.queue_run(conn, str(row["tenant_id"]), str(row["action_uid"]))
    return len(pending)


# A load this recent still has a warehouse's compute up: the run it wakes
# starts within a minute (`events.loaded`).
JUST_LOADED = timedelta(minutes=5)


def _reread(ctx: Context) -> None:
    """Read again what the console and the hourly Ops check ask the store,
    after a load and only then (`shoc.store.kept`): the load woke this run, so
    on a warehouse the compute it reads with is already up (D161)."""
    from shoc.agents import ops
    from shoc.store import kept

    if not fetch_one(
        ctx.db,
        "SELECT 1 FROM shoc.store_loads WHERE tenant_id = %s AND loaded_at > now() - %s",
        (ctx.tenant_id, JUST_LOADED),
    ):
        return
    try:
        ops.source_quality(ctx.db, ctx.store, ctx.tenant_id)
        kept.health(ctx.db, ctx.store, ctx.tenant_id)
    except Exception as exc:  # a reader reads it itself
        log.warning("could not reread the kept store reads: %s", exc)


def check_agent_can_read(config: Config) -> bool:
    """Prove the read-only role can actually read, before a rule discovers it cannot.

    A read-only role without a grant on the tenant schema makes every rule fail
    with "relation ocsf_events does not exist", five minutes after startup and
    fifty times over. One line at boot is better.
    """
    if not config.readonly_configured():
        return True
    from shoc.store import open_store

    store = open_store(config, config.tenant_id, readonly=True)
    try:
        # `health()` reports a failure by returning `ok=False`, it does not
        # raise. Waiting for an exception here meant the check always passed
        # while every agent read failed a minute later, once a cycle, forever.
        health = store.health()
        if health.ok:
            return True
        detail = health.detail
    except Exception as exc:  # a diagnosis, not a failure
        detail = str(exc)
    finally:
        store.close()
    fix = (
        "Run `shoc grant-readonly --role <role>` (again, if you have added a tenant)."
        if config.backend == "postgres"
        else "Run `shoc migrate`, which grants the reader on the tenant's "
        + {"databricks": "catalog.", "redshift": "schema.", "bigquery": "dataset."}.get(
            config.backend, "database."
        )
    )
    log.error(
        "agents cannot read tenant '%s' through their read-only credential: %s\n%s",
        config.tenant_id,
        detail,
        fix,
    )
    return False


def wait_for_schema(conn: Any, attempts: int = 30, delay: float = 2.0) -> bool:
    """Wait for `shoc migrate` to have run, rather than crash-looping on first boot.

    Only the control plane is waited on. A worker that also waited for the
    event store ran nothing while a warehouse was down, case sweeps and webhook
    deliveries included, and restarted every minute until it came back. A
    detection cycle that cannot reach the store, or finds its table not made
    yet, stops without marking a rule broken instead (`detect.engine.run_all`).

    Every migration this code ships has to be applied, not only the first
    tables, so new code never runs job after job against an old schema. A
    schema newer than the code (a rollback) is logged and reported by
    `health.status`; it is not waited on, since only a restore undoes it.
    `serve` waits the same way.
    """
    from shoc.db.migrate import drift

    for attempt in range(attempts):
        missing, ahead = drift(conn)
        if not missing:
            if ahead:
                log.error(
                    "the database has migrations this release does not know (%s); it was "
                    "migrated by a newer release, and rolling back means restoring a backup",
                    ", ".join(ahead),
                )
            return True
        if attempt == 0:
            log.info(
                "waiting for %d migration(s) (%s); run `shoc migrate`",
                len(missing),
                ", ".join(missing[:3]) + ("…" if len(missing) > 3 else ""),
            )
        time.sleep(delay)
    return False


def tenants_without_schedules(conn: Any) -> list[str]:
    """Tenants `shoc migrate` created that have no schedule yet, the newest included."""
    from shoc.db.pool import fetch_all

    return [
        str(r["tenant_id"])
        for r in fetch_all(
            conn,
            """SELECT t.tenant_id FROM shoc.tenants t
               WHERE NOT EXISTS (SELECT 1 FROM shoc.schedules s
                                 WHERE s.schedule_id = t.tenant_id || ':detect')""",
        )
    ]


def ensure_default_schedules(conn: Any, config: Config, tenant: str = "") -> None:
    """Every tenant's schedules, or one tenant's when `tenant` is named (DET-3, API-1).

    A tenant is whatever `shoc migrate` registered in `shoc.tenants`. The
    worker's own SHOC_TENANT always counts, registered or not.
    """
    if not tenant:
        for each in jobs.tenants(conn, config.tenant_id):
            ensure_default_schedules(conn, config, each)
        return
    jobs.upsert_schedule(conn, f"{tenant}:detect", tenant, "detect.run", config.cycle_seconds, {})
    # `source.configure` floors a sync at the cycle only when it runs, so a
    # source configured before the cycle grew kept polling at its old rate
    # (D151, D153).
    execute(
        conn,
        """UPDATE shoc.schedules s SET interval_seconds = greatest(c.interval_seconds, %s)
           FROM shoc.connector_config c
           WHERE c.tenant_id = %s AND s.schedule_id = c.tenant_id || ':sync:' || c.source""",
        (config.cycle_seconds, tenant),
    )
    jobs.upsert_schedule(
        conn, f"{tenant}:retention", tenant, "retention", 86400, {"days": config.retention_days}
    )
    jobs.upsert_schedule(conn, f"{tenant}:webhooks", tenant, "stream.deliver", 60, {})
    jobs.upsert_schedule(conn, f"{tenant}:intel", tenant, "intel.refresh", 21600, {})
    jobs.upsert_schedule(conn, f"{tenant}:graph", tenant, "graph.refresh", 86400, {"days": 30})
    jobs.upsert_schedule(conn, f"{tenant}:posture", tenant, "posture.survey", 86400, {"days": 30})
    jobs.upsert_schedule(conn, f"{tenant}:detection", tenant, "detection.backlog", 86400, {})
    jobs.upsert_schedule(conn, f"{tenant}:hunt", tenant, "hunt.daily", 86400, {})
    jobs.upsert_schedule(conn, f"{tenant}:ops", tenant, "ops.check", 3600, {})
    jobs.upsert_schedule(conn, f"{tenant}:integrator", tenant, "source.onboard", 86400, {})
    jobs.upsert_schedule(conn, f"{tenant}:sweep", tenant, "case.sweep", 900, {})
    jobs.upsert_schedule(conn, f"{tenant}:unattended", tenant, "unattended", 1800, {})
    jobs.upsert_schedule(conn, f"{tenant}:recheck", tenant, "case.recheck", 604800, {})
    jobs.upsert_schedule(conn, f"{tenant}:weekly", tenant, "report.weekly", 604800, {})
    jobs.upsert_schedule(conn, f"{tenant}:exec", tenant, "report.exec", 2592000, {})
    jobs.upsert_schedule(conn, f"{tenant}:exceptions", tenant, "report.exception", 86400, {})


# A worker whose loop has not come round in this long is hung, stuck in a job or
# a call that never returns. A pass runs one job, so this is how long one job
# may take. Exiting ends its sessions, which frees the cron lock for a follower
# and gives the job back (`requeue_stale`, parked after its fifth try), and the
# supervisor (`restart: unless-stopped`, a Deployment) starts a fresh worker.
# The longest job is the crew on a critical case with reports: its budget is
# checked between steps, so a model call already running at the deadline, the
# final answer and a typed reply's retry can each still take CALL_SECONDS.
# Thirty minutes killed that investigation and started it over.
HUNG_AFTER_SECONDS = (
    max(Budget.for_case(s, reports=1).max_seconds for s in SEVERITY_ORDER)
    + 3 * CALL_SECONDS
    + 10 * 60
)

# How often the running job's lease is renewed. `requeue_stale` takes a job
# back once its lease is 30 minutes old.
LEASE_SECONDS = 60

# The most jobs `shoc worker --once` runs before it exits.
ONCE_JOBS = 4


def watchdog(last_pass: list[float], stop: threading.Event, hung_after: float) -> None:
    """Exit the process when the loop has not started a pass in `hung_after` seconds."""
    while not stop.wait(hung_after / 10):
        if time.monotonic() - last_pass[0] > hung_after:
            log.error("no pass in %.0fs; exiting so another worker can lead", hung_after)
            os._exit(1)


def keep_lease(
    config: Config, running: list[int | None], stop: threading.Event, every: float
) -> None:
    """Renew the lease of the job the loop is running, on a connection of its own.

    Without it a job past 30 minutes looked abandoned while its worker still ran
    it, and a second worker ran it again.
    """
    from shoc.db import pool

    while not stop.wait(every):
        job_id = running[0]
        if job_id is None:
            continue
        try:
            beat = connect(config)
            set_tenant(beat, ALL_TENANTS)
            jobs.renew(beat, job_id)
        except psycopg.Error as exc:
            log.warning("could not renew the lease of job %s: %s", job_id, exc)
            pool.close()  # this thread's connection; the next beat opens a new one
    pool.close()


def listen(config: Config) -> Any:
    """A connection of its own, LISTENing on `shoc_jobs` (AGT-1).

    `jobs.enqueue` sends a NOTIFY with every job, so the worker wakes when work
    exists instead of asking every two seconds. None when it cannot connect: the
    poll then does all the waking, as it did before.
    """
    try:
        conn = psycopg.connect(config.dsn, autocommit=True, application_name=jobs.WORKER_ID)
        conn.execute("LISTEN shoc_jobs")
        return conn
    except psycopg.Error as exc:
        log.warning("cannot LISTEN for jobs (%s); polling instead", exc)
        return None


def wait_for_jobs(listener: Any, seconds: float, stop: threading.Event) -> None:
    """Return when a job is queued, `seconds` have passed, or the worker must stop.

    The caller passes the time until the next queued job falls due
    (`jobs.seconds_to_next`), since a job queued for later sent its NOTIFY when
    it was queued; the cron leader ticks on this same loop, so the poll stays as
    the longest wait. The wait is taken a second at a time, without a query, so
    SIGTERM is not kept waiting.
    """
    deadline = time.monotonic() + seconds
    while not stop.is_set() and (left := deadline - time.monotonic()) > 0:
        if listener is None:
            stop.wait(min(1.0, left))
            continue
        try:
            if list(listener.notifies(timeout=min(1.0, left), stop_after=1)):
                return
        except psycopg.Error:
            return  # the loop's own connection finds out what happened


def run(
    config: Config | None = None,
    once: bool = False,
    poll_seconds: float = 30.0,
    stop: threading.Event | None = None,
    urgent: bool = False,
) -> int:
    """Claim and run jobs until stopped.

    Between passes the worker waits on NOTIFY, and polls every `poll_seconds`
    whatever happens. `stop` lets an embedder (or a test) end the loop the same
    way SIGTERM does. An `urgent` worker is the fast lane: it takes only pages,
    actions, deliveries, detection, syncs, playbooks and the crew's runs on
    high and critical cases (`jobs.TIER`), so a routine model job never holds
    up a page.
    """
    most_tier = jobs.URGENT if urgent else 2
    cfg = config or Config.load()
    cfg.check_llm_provider()
    conn = connect(cfg)
    set_tenant(conn, ALL_TENANTS)  # the queue is shared; each job scopes itself
    if not wait_for_schema(conn):
        log.error("giving up waiting for the database schema; run `shoc migrate`")
        return 0
    from shoc.db import audit

    # As `serve` does: a key the audit log was not keyed with would let a job's
    # change commit and then fail to write its row.
    audit.check_key(cfg)
    ensure_default_schedules(conn, cfg)
    check_agent_can_read(cfg)
    stopping = stop or threading.Event()

    def ask_to_stop(*_: Any) -> None:
        stopping.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        # Not the main thread (tests): signal handlers are not ours to set.
        with contextlib.suppress(ValueError):
            signal.signal(sig, ask_to_stop)

    leader = False
    listener = None if once else listen(cfg)
    log.info("worker started%s", " (fast lane)" if urgent else "")
    if cfg.heartbeat_url:
        # Egress a deployer asked for is still named once (D57); its path is a secret.
        log.info(
            "heartbeat pings go to %s after each ops.check", urlsplit(cfg.heartbeat_url).hostname
        )
    processed = 0
    last_pass = [time.monotonic()]
    running: list[int | None] = [None]
    if not once:
        threading.Thread(
            target=watchdog, args=(last_pass, stopping, HUNG_AFTER_SECONDS), daemon=True
        ).start()
        threading.Thread(
            target=keep_lease, args=(cfg, running, stopping, LEASE_SECONDS), daemon=True
        ).start()
    # A pass runs one job. A page queued meanwhile waits for that job alone,
    # the leader's ticks and sweeps run between any two jobs, and SIGTERM stops
    # the worker at the next job instead of after a batch of them.
    while not stopping.is_set():
        last_pass[0] = time.monotonic()
        try:
            # A follower asks for the lock on every pass. The lock frees as soon
            # as the leader's session ends (a killed pod, a rolling update), so
            # another worker takes over without waiting for a database error.
            if not leader and jobs.become_cron_leader(conn):
                leader = True
                log.info("this worker is now the cron leader")
            if leader:
                # A tenant migrated while this worker runs is scheduled on the next pass.
                for tenant in tenants_without_schedules(conn):
                    ensure_default_schedules(conn, cfg, tenant)
                jobs.tick(conn)
                jobs.requeue_stale(conn)
                resume_waiting_runs(conn)
                run_approved_actions(conn)
            claimed = [] if stopping.is_set() else jobs.claim(conn, most_tier=most_tier)
            for job in claimed:
                running[0] = job["job_id"]
                # `handle` hands the connection back to every tenant either way.
                try:
                    summary = handle(job, cfg)
                    jobs.finish(conn, job["job_id"])
                    log.info("job %s %s: %s", job["job_id"], job["kind"], summary)
                except Exception as exc:
                    # Only a lost database is left to the reconnect below. A query
                    # that timed out, deadlocked or waited too long for a lock, on
                    # this connection or the store's, fails the job like any other
                    # error, so a job that always does it is parked.
                    if isinstance(exc, psycopg.OperationalError) and (conn.closed or conn.broken):
                        raise
                    jobs.fail(conn, job["job_id"], f"{type(exc).__name__}: {exc}")
                    log.warning("job %s %s failed: %s", job["job_id"], job["kind"], exc)
                finally:
                    running[0] = None
                processed += 1
            pause = 0.0 if claimed else jobs.seconds_to_next(conn, poll_seconds, most_tier)
        except psycopg.OperationalError as exc:
            # A restarted or briefly unreachable database is an ordinary event
            # for a process meant to run for months: reconnect rather than die
            # and leave it to something else to restart us.
            if once:
                raise
            log.warning("lost the database (%s); reconnecting", exc)
            conn = reconnect(cfg, stop=stopping)
            # The job in hand died with the old session, but the new one has
            # the same name, so `requeue_stale` would leave it for half an hour.
            jobs.release_own(conn)
            leader = False  # the lock went with the old session
            if listener is not None:
                listener.close()
            listener = listen(cfg)
            continue
        if once and (not claimed or processed >= ONCE_JOBS):
            break
        if pause:
            wait_for_jobs(listener, pause, stopping)
    if listener is not None:
        listener.close()
    return processed


def reconnect(
    config: Config,
    attempts: int = 60,
    delay: float = 2.0,
    stop: threading.Event | None = None,
) -> Any:
    """Come back after the database went away, with a bounded wait."""
    from shoc.db import pool

    for attempt in range(attempts):
        if stop is not None and stop.is_set():
            raise ConnectionError("asked to stop while waiting for the database")
        pool.close()
        try:
            conn = connect(config)
            set_tenant(conn, ALL_TENANTS)
            if attempt:
                log.info("database is back after about %.0fs", attempt * delay)
            return conn
        except psycopg.Error as exc:
            if attempt == 0:
                log.warning("waiting for the database: %s", exc)
            time.sleep(delay)
    raise ConnectionError("the database did not come back")


def dump(value: Any) -> str:
    return json.dumps(value, default=str)
