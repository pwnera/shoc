"""The job queue and cron, on Postgres (decision D6: no Celery, Redis or Temporal).

Workers claim with SELECT ... FOR UPDATE SKIP LOCKED, so adding workers is the
only scaling knob. Cron leadership uses an advisory lock, so every worker can
run the scheduler loop and only one of them actually ticks.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import PROCESS, Conn, execute, fetch_all, fetch_one

CRON_LOCK = 0x4853_4F43  # "SHOC"
WORKER_ID = PROCESS


def now() -> datetime:
    return datetime.now(UTC)


def enqueue(
    conn: Conn,
    tenant_id: str,
    kind: str,
    payload: dict[str, Any] | None = None,
    *,
    run_at: datetime | None = None,
    idempotency_key: str | None = None,
) -> int | None:
    """Add a job. A repeated idempotency key is a no-op (RSP-2 needs this)."""
    row = fetch_one(
        conn,
        """INSERT INTO shoc.jobs (tenant_id, kind, payload, run_at, idempotency_key)
           VALUES (%s, %s, %s, COALESCE(%s, now()), %s)
           ON CONFLICT (idempotency_key) DO NOTHING
           RETURNING job_id""",
        (tenant_id, kind, json.dumps(payload or {}), run_at, idempotency_key),
    )
    if row:
        execute(conn, "SELECT pg_notify('shoc_jobs', %s)", (kind,))
        return row["job_id"]
    return None


# How urgent a pending job `q` is: 0 for a page, an approved action and a
# webhook delivery; 1 for detection, syncs, playbooks and the crew's run on a
# high or critical case, which is where that case's page comes from; 2 for the
# rest, the model jobs that take minutes.
TIER = """CASE
    WHEN q.kind IN ('manager.deliver', 'action.run', 'action.expire', 'stream.deliver') THEN 0
    WHEN q.kind IN ('detect.run', 'source.sync', 'playbook.run', 'playbook.resume')
      OR q.kind = 'case.investigate' AND EXISTS (
           SELECT 1 FROM shoc.cases c
           WHERE c.tenant_id = q.tenant_id AND c.case_uid = q.payload ->> 'case_uid'
             AND c.severity IN ('high', 'critical')) THEN 1
    ELSE 2 END"""
URGENT = 1


def claim(conn: Conn, limit: int = 1, most_tier: int = 2) -> list[dict[str, Any]]:
    """Take the most urgent due jobs (`TIER`), then the oldest.

    A critical page queued behind 25 investigations used to wait for all of
    them. `most_tier=URGENT` is the fast lane (`shoc worker --urgent`): a worker
    that never starts a routine model job, so one is always free for a page.
    """
    # MATERIALIZED runs the locking select once. As an `IN (subquery)` the
    # planner may rescan it per row, and LIMIT then stops bounding the claim.
    return fetch_all(
        conn,
        f"""WITH next AS MATERIALIZED (
               SELECT q.job_id FROM shoc.jobs q
               WHERE q.state = 'pending' AND q.run_at <= now() AND {TIER} <= %s
               ORDER BY {TIER}, q.run_at
               FOR UPDATE OF q SKIP LOCKED
               LIMIT %s)
           UPDATE shoc.jobs j SET state = 'running', attempts = attempts + 1,
                  locked_by = %s, locked_at = now()
           FROM next WHERE j.job_id = next.job_id
           RETURNING j.job_id, j.tenant_id, j.kind, j.payload, j.attempts""",
        (most_tier, limit, WORKER_ID),
    )


def seconds_to_next(conn: Conn, most: float, most_tier: int = 2) -> float:
    """How long until the next pending job this worker may claim falls due,
    `most` at the longest.

    A job queued to run later sends its NOTIFY when it is queued, so without
    this a worker woke for it only on its next poll. The fast lane skips the
    jobs it leaves to others, or it would ask again every half second.
    """
    row = fetch_one(
        conn,
        f"""SELECT extract(epoch FROM min(q.run_at) - now()) AS s FROM shoc.jobs q
            WHERE q.state = 'pending' AND {TIER} <= %s""",
        (most_tier,),
    )
    s = row["s"] if row else None
    return most if s is None else min(most, max(0.5, float(s)))


# `finish` and `fail` write only a job this process still holds. One taken back
# from it (`requeue_stale`) may be running again elsewhere, and that run's
# outcome is the one to keep.
def finish(conn: Conn, job_id: int) -> None:
    execute(
        conn,
        """UPDATE shoc.jobs SET state='done', finished_at=now(), locked_by=NULL
           WHERE job_id=%s AND state='running' AND locked_by=%s""",
        (job_id, WORKER_ID),
    )


def fail(conn: Conn, job_id: int, error: str, max_attempts: int = 5) -> None:
    """Retry with backoff until `max_attempts`, then park the job as failed."""
    execute(
        conn,
        """UPDATE shoc.jobs
           SET state = CASE WHEN attempts >= %s THEN 'failed' ELSE 'pending' END,
               run_at = now() + (least(attempts, 6) * interval '30 seconds'),
               finished_at = CASE WHEN attempts >= %s THEN now() END,
               last_error = %s, locked_by = NULL
           WHERE job_id = %s AND state = 'running' AND locked_by = %s""",
        (max_attempts, max_attempts, error[:2000], job_id, WORKER_ID),
    )


def renew(conn: Conn, job_id: int) -> None:
    """Keep the lease on a job this process is still running (`requeue_stale`)."""
    execute(
        conn,
        """UPDATE shoc.jobs SET locked_at = now()
           WHERE job_id = %s AND state = 'running' AND locked_by = %s""",
        (job_id, WORKER_ID),
    )


def upsert_schedule(
    conn: Conn,
    schedule_id: str,
    tenant_id: str,
    kind: str,
    interval_seconds: int,
    payload: dict[str, Any] | None = None,
    enabled: bool = True,
) -> None:
    # A payload marked `set_by` (`config.apply`'s retention, API-4) is replaced
    # only by another marked one, so the worker's defaults on start leave it be.
    execute(
        conn,
        """INSERT INTO shoc.schedules
               (schedule_id, tenant_id, kind, payload, interval_seconds, enabled)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (schedule_id) DO UPDATE
             SET kind = EXCLUDED.kind,
                 payload = CASE
                     WHEN shoc.schedules.payload ->> 'set_by' IS NOT NULL
                          AND EXCLUDED.payload ->> 'set_by' IS NULL
                     THEN shoc.schedules.payload ELSE EXCLUDED.payload END,
                 interval_seconds = EXCLUDED.interval_seconds,
                 enabled = EXCLUDED.enabled""",
        (schedule_id, tenant_id, kind, json.dumps(payload or {}), interval_seconds, enabled),
    )


def tenants(conn: Conn, own: str) -> list[str]:
    """Every tenant `shoc migrate` registered, and this process's own (`own`) first.

    Reads `shoc.tenants`, so `conn` must be an all-tenants session.
    """
    named = [str(r["tenant_id"]) for r in fetch_all(conn, "SELECT tenant_id FROM shoc.tenants")]
    return list(dict.fromkeys([own, *named]))


def tick(conn: Conn) -> int:
    """Turn every due schedule into a job. Only the cron leader should call this.

    The next run falls on the clock's next multiple of the interval, so every
    schedule of one period, and of the periods it divides, fires together: a
    warehouse wakes once for the polls and the detection cycle instead of once
    for each (D71).
    """
    due = fetch_all(
        conn,
        """UPDATE shoc.schedules s
           SET next_run_at = to_timestamp(
               (floor(extract(epoch FROM now()) / interval_seconds) + 1) * interval_seconds)
           WHERE enabled AND next_run_at <= now()
           RETURNING schedule_id, tenant_id, kind, payload, next_run_at,
                     EXISTS (SELECT 1 FROM shoc.jobs j
                             WHERE j.tenant_id = s.tenant_id AND j.kind = s.kind
                               AND j.payload = s.payload
                               AND j.state IN ('pending', 'running')) AS queued,
                     s.kind = 'stream.deliver'
                       AND NOT EXISTS (SELECT 1 FROM shoc.webhooks w
                                       WHERE w.tenant_id = s.tenant_id AND w.enabled) AS idle""",
    )
    for s in due:
        # The last one has not run yet. A second copy would only repeat it, and
        # a queue a slow warehouse cannot drain grew by one per tick. Webhook
        # delivery with no webhook to send to added 1,440 idle jobs a day.
        if s["queued"] or s["idle"]:
            continue
        enqueue(
            conn,
            s["tenant_id"],
            s["kind"],
            s["payload"],
            idempotency_key=f"{s['schedule_id']}@{s['next_run_at'].isoformat()}",
        )
    return len(due)


def become_cron_leader(conn: Conn) -> bool:
    """Take the cron lock if it is free. It is held until this session ends.

    Session advisory locks stack, so the leader should not call this again.

    When the leader's node is lost or cut off, nothing closes its session, and
    with Linux defaults the server only notices after about two hours of TCP
    keepalive. The lock holder asks the server to probe it after a minute and
    give up on it within about 90 seconds, so a follower takes over in minutes.
    """
    row = fetch_one(conn, "SELECT pg_try_advisory_lock(%s) AS got", (CRON_LOCK,))
    if not (row and row["got"]):
        return False
    execute(
        conn,
        """SELECT set_config('tcp_keepalives_idle', '60', false),
                  set_config('tcp_keepalives_interval', '10', false),
                  set_config('tcp_keepalives_count', '3', false),
                  set_config('tcp_user_timeout', '90000', false)""",
    )
    return True


def overdue_schedules(conn: Conn, tenant_id: str) -> list[str]:
    """Enabled schedules more than an hour late, which means no worker is ticking."""
    return [
        r["kind"]
        for r in fetch_all(
            conn,
            """SELECT kind FROM shoc.schedules
               WHERE tenant_id = %s AND enabled AND next_run_at < now() - interval '1 hour'
               ORDER BY kind""",
            (tenant_id,),
        )
    ]


# A job taken back from a worker that lost it goes back to the queue, later each
# time, and is parked as failed after its fifth try like any other (`fail`): a
# job that kills its worker every time came back for ever, and said nothing.
TAKE_BACK = """UPDATE shoc.jobs j
    SET state = CASE WHEN attempts >= %(most)s THEN 'failed' ELSE 'pending' END,
        finished_at = CASE WHEN attempts >= %(most)s THEN now() END,
        run_at = now() + least(attempts - 1, 6) * interval '30 seconds',
        last_error = 'the worker running it was lost, after ' || attempts || ' attempt(s)',
        locked_by = NULL
    WHERE state = 'running' AND """


def requeue_stale(
    conn: Conn, older_than: timedelta = timedelta(minutes=30), max_attempts: int = 5
) -> int:
    """Take back running jobs whose lease ran out, or whose worker has no session left.

    A running job's lease is renewed every minute (`renew`), so it runs out
    only when its worker stopped renewing it. A worker killed mid-job (a
    container restart) takes its sessions with it, and its jobs come back on
    the next pass instead of half an hour later.
    """
    stale = """(locked_at < now() - %(older)s
               OR NOT EXISTS (SELECT 1 FROM pg_stat_activity a
                              WHERE a.application_name = j.locked_by))"""
    return execute(conn, TAKE_BACK + stale, {"most": max_attempts, "older": older_than})


def release_own(conn: Conn, max_attempts: int = 5) -> int:
    """Take back what this process held, once it has lost its database session.

    The worker runs one job at a time, so nothing it claimed is still running.
    Its new session carries the same name, which kept `requeue_stale` from
    seeing these jobs as orphaned for half an hour.
    """
    mine = "locked_by = %(me)s"
    return execute(conn, TAKE_BACK + mine, {"most": max_attempts, "me": WORKER_ID})
