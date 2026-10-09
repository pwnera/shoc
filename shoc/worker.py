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

import psycopg

from shoc.capabilities.registry import Caller, Context
from shoc.config import Config
from shoc.db import jobs
from shoc.db.pool import ALL_TENANTS, connect, set_tenant

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
    job's tenant, and a job that raises would otherwise leave it there.
    """
    try:
        return _handle(job, config)
    finally:
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


def _handle(job: dict[str, Any], config: Config) -> str:
    """Handlers go through the registry, like every other caller."""
    from shoc.capabilities.registry import call

    tenant = job["tenant_id"]
    payload = job["payload"] or {}
    kind = job["kind"]
    ctx = Context(
        tenant_id=tenant,
        caller=SYSTEM_CALLER if kind in SYSTEM_JOBS else WORKER_CALLER,
        config=config,
    )
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
        result = call(
            "detect.run", ctx, {k: v for k, v in payload.items() if k in ("rule_id", "lookback")}
        )
        _queue_investigations(ctx, result.data.cases_opened)
        return result.summary
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
                "dry_run": bool(payload.get("dry_run", config.dry_run)),
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
        from shoc.agents import manager, ops

        result = call("ops.alerts", ctx, {})
        for alert in ops.unpublished(ctx.db, tenant, result.data.alerts):
            _publish_alert(ctx, alert)
        # Ops' model diagnoses a new outage first, so the page carries it (D47).
        ops.review(ctx.db, ctx.store, tenant, config)
        manager.coverage(ctx.db, tenant)
        # A source that fails or has changed shape goes back to the Integrator,
        # once a day at most (D50: Ops wakes it when a vendor changes shape).
        if any(a["kind"] in ("source.failing", "source.quality") for a in result.data.alerts):
            jobs.enqueue(
                ctx.db,
                tenant,
                "source.onboard",
                {},
                idempotency_key=f"onboard:drift:{int(time.time() // 86400)}",
            )
        # Nobody runs `health audit` by hand, so the chain is checked here (SEC-1).
        chain = call("health.audit", ctx, {"limit": 1}).data
        if not chain.chain_ok and manager.audit_broken(ctx.db, tenant, chain.detail):
            _publish_alert(
                ctx,
                {
                    "kind": "audit.broken",
                    "subject": "audit_log",
                    "detail": chain.detail,
                    "severity": "critical",
                },
            )
        return result.summary
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
        return call("events.retain", ctx, {"days": int(payload.get("days", 90))}).summary
    raise ValueError(f"unknown job kind '{kind}'")


# How long the sweep leaves a case after a crew run that did not come back:
# a quarter hour, doubling with each failed try, never longer than the case's
# own deadline. A flat five tries an hour, reset every hour, sent the crew at
# the same four cases around the clock through a two-day provider outage and
# wrote a failure into each case every time (CASE-9f7294571950d508fb74 took 46).
FIRST_RETRY_HOURS = 0.25


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


def _publish_alert(ctx: Context, alert: dict[str, Any]) -> None:
    from shoc.cases import engine

    engine.publish(ctx.db, ctx.tenant_id, f"health.{alert['kind']}", alert["subject"], alert)


def _start_playbooks(ctx: Context, case_uid: str) -> list[str]:
    """Queue every playbook whose trigger matches this case (RSP-2)."""
    from shoc.cases import engine, playbooks

    case = engine.require(ctx.db, ctx.tenant_id, case_uid)
    started: list[str] = []
    for book in playbooks.match(ctx.db, ctx.tenant_id, case, ctx.config):
        jobs.enqueue(
            ctx.db,
            ctx.tenant_id,
            "playbook.run",
            {"playbook_id": book.id, "case_uid": case_uid},
            idempotency_key=f"playbook:{book.id}:{case_uid}",
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
    """
    from shoc.db.pool import fetch_one

    for attempt in range(attempts):
        row = fetch_one(conn, "SELECT to_regclass('shoc.schedules') IS NOT NULL AS ready")
        if row and row["ready"]:
            return True
        if attempt == 0:
            log.info("waiting for the database schema; run `shoc migrate` to create it")
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
# a call that never returns. `requeue_stale` gave its jobs to other workers at 30
# minutes. Exiting ends its session, which frees the cron lock for a follower,
# and the supervisor (`restart: unless-stopped`, a Deployment) starts a fresh one.
HUNG_AFTER_SECONDS = 30 * 60


def watchdog(last_pass: list[float], stop: threading.Event, hung_after: float) -> None:
    """Exit the process when the loop has not started a pass in `hung_after` seconds."""
    while not stop.wait(hung_after / 10):
        if time.monotonic() - last_pass[0] > hung_after:
            log.error("no pass in %.0fs; exiting so another worker can lead", hung_after)
            os._exit(1)


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
) -> int:
    """Claim and run jobs until stopped.

    Between passes the worker waits on NOTIFY, and polls every `poll_seconds`
    whatever happens. `stop` lets an embedder (or a test) end the loop the same
    way SIGTERM does.
    """
    cfg = config or Config.load()
    conn = connect(cfg)
    set_tenant(conn, ALL_TENANTS)  # the queue is shared; each job scopes itself
    if not wait_for_schema(conn):
        log.error("giving up waiting for the database schema; run `shoc migrate`")
        return 0
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
    log.info("worker started")
    processed = 0
    last_pass = [time.monotonic()]
    if not once:
        threading.Thread(
            target=watchdog, args=(last_pass, stopping, HUNG_AFTER_SECONDS), daemon=True
        ).start()
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
            claimed = jobs.claim(conn, limit=4)
            for job in claimed:
                # `handle` hands the connection back to every tenant either way.
                try:
                    summary = handle(job, cfg)
                    jobs.finish(conn, job["job_id"])
                    log.info("job %s %s: %s", job["job_id"], job["kind"], summary)
                except psycopg.OperationalError:
                    raise  # the database went away; reconnect below
                except Exception as exc:
                    jobs.fail(conn, job["job_id"], f"{type(exc).__name__}: {exc}")
                    log.warning("job %s %s failed: %s", job["job_id"], job["kind"], exc)
                processed += 1
            pause = 0.0 if claimed else jobs.seconds_to_next(conn, poll_seconds)
        except psycopg.OperationalError as exc:
            # A restarted or briefly unreachable database is an ordinary event
            # for a process meant to run for months: reconnect rather than die
            # and leave it to something else to restart us. Whatever job we were
            # holding is requeued by `requeue_stale` on the way back.
            if once:
                raise
            log.warning("lost the database (%s); reconnecting", exc)
            conn = reconnect(cfg, stop=stopping)
            leader = False  # the lock went with the old session
            if listener is not None:
                listener.close()
            listener = listen(cfg)
            continue
        if once:
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
