"""The job queue and cron, on Postgres (decision D6: no Celery, Redis or Temporal).

Workers claim with SELECT ... FOR UPDATE SKIP LOCKED, so adding workers is the
only scaling knob. Cron leadership uses an advisory lock, so every worker can
run the scheduler loop and only one of them actually ticks.
"""

from __future__ import annotations

import json
import os
import socket
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one

CRON_LOCK = 0x4853_4F43  # "SHOC"
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


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


def claim(conn: Conn, limit: int = 1) -> list[dict[str, Any]]:
    # MATERIALIZED runs the locking select once. As an `IN (subquery)` the
    # planner may rescan it per row, and LIMIT then stops bounding the claim.
    return fetch_all(
        conn,
        """WITH next AS MATERIALIZED (
               SELECT job_id FROM shoc.jobs
               WHERE state = 'pending' AND run_at <= now()
               ORDER BY run_at
               FOR UPDATE SKIP LOCKED
               LIMIT %s)
           UPDATE shoc.jobs j SET state = 'running', attempts = attempts + 1,
                  locked_by = %s, locked_at = now()
           FROM next WHERE j.job_id = next.job_id
           RETURNING j.job_id, j.tenant_id, j.kind, j.payload, j.attempts""",
        (limit, WORKER_ID),
    )


def finish(conn: Conn, job_id: int) -> None:
    execute(
        conn,
        "UPDATE shoc.jobs SET state='done', finished_at=now(), locked_by=NULL WHERE job_id=%s",
        (job_id,),
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
           WHERE job_id = %s""",
        (max_attempts, max_attempts, error[:2000], job_id),
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
        """UPDATE shoc.schedules
           SET next_run_at = to_timestamp(
               (floor(extract(epoch FROM now()) / interval_seconds) + 1) * interval_seconds)
           WHERE enabled AND next_run_at <= now()
           RETURNING schedule_id, tenant_id, kind, payload, next_run_at""",
    )
    for s in due:
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


def requeue_stale(conn: Conn, older_than: timedelta = timedelta(minutes=30)) -> int:
    return execute(
        conn,
        """UPDATE shoc.jobs SET state='pending', locked_by=NULL
           WHERE state='running' AND locked_at < now() - %s""",
        (older_than,),
    )
