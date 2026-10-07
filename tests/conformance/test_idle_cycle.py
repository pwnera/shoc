"""A cycle with nothing new to read leaves the store alone (DET-3, D71)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db import jobs
from shoc.db.pool import execute, fetch_one
from shoc.detect.engine import run_all
from shoc.ingest import batch
from tests.conformance.test_rules import MATCH


class Unreachable:
    """A store a skipped cycle must not touch, as a stopped warehouse."""

    dialect = "postgres"

    def query(self, *args, **kwargs):
        raise RuntimeError("the store was read")


# Typed loosely: it stands in for a store only as far as a skipped cycle goes.
UNREACHABLE: Any = Unreachable()


def _stamp(conn, tenant, at):
    execute(
        conn, "INSERT INTO shoc.store_loads (tenant_id, loaded_at) VALUES (%s, %s)", (tenant, at)
    )


def _watermark(conn, tenant):
    row = fetch_one(
        conn,
        "SELECT watermark FROM shoc.rule_state WHERE tenant_id = %s AND rule_id = %s",
        (tenant, MATCH.id),
    )
    assert row
    return row["watermark"]


def test_a_cycle_reads_nothing_when_nothing_was_loaded_since_its_range(
    conn, store, config, clean, now
):
    tenant = config.tenant_id
    run_all(conn, store, tenant, [MATCH], now=now)
    _stamp(conn, tenant, now - timedelta(hours=1))
    later = now + timedelta(hours=8)
    stats = run_all(conn, UNREACHABLE, tenant, [MATCH], now=later)
    assert not stats.errors
    assert _watermark(conn, tenant) == later, "moved to now, not by the six-hour catch-up"

    _stamp(conn, tenant, later)
    stats = run_all(conn, UNREACHABLE, tenant, [MATCH], now=later + timedelta(minutes=5))
    assert "the store was read" in stats.errors[MATCH.id]


def test_every_load_stamps_the_tenant(conn, config, clean):
    batch.loaded(
        conn,
        config.tenant_id,
        [
            {"ingested_at": "2026-09-20T10:00:00+00:00"},
            {"ingested_at": "2026-09-20T09:00:00+00:00"},
        ],
    )
    row = fetch_one(
        conn,
        "SELECT loaded_at, stamped_from FROM shoc.store_loads WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert row and row["loaded_at"]
    assert row["stamped_from"] == datetime(2026, 9, 20, 9, tzinfo=UTC)


def test_a_load_that_commits_long_after_its_events_were_stamped_is_still_read(
    conn, store, config, clean, now
):
    """A warehouse load, or a kept batch replayed, can commit long after mapping (DET-3)."""
    from tests.conformance.test_rules import _findings, _trail

    tenant = config.tenant_id
    run_all(conn, store, tenant, [MATCH], now=now - timedelta(minutes=5))
    rows = _trail(
        tenant, [now - timedelta(hours=2)], now - timedelta(hours=2), "slow", op="DeleteTrail"
    )
    batch.load(store, rows)
    batch.loaded(conn, tenant, rows)
    stats = run_all(conn, store, tenant, [MATCH], now=now)
    assert not stats.errors and stats.findings_new == 1
    assert _findings(conn, tenant, MATCH.id)


def test_a_store_that_never_stamped_a_load_is_read(conn, store, config, clean, now):
    tenant = config.tenant_id
    run_all(conn, store, tenant, [MATCH], now=now)
    stats = run_all(conn, UNREACHABLE, tenant, [MATCH], now=now + timedelta(minutes=5))
    assert MATCH.id in stats.errors


def test_schedules_of_one_period_fire_on_the_same_clock_boundary(conn, config):
    tenant = config.tenant_id
    for key in ("a", "b"):
        jobs.upsert_schedule(conn, f"{tenant}:align:{key}", tenant, "noop", 900)
    try:
        jobs.tick(conn)
        rows = [
            fetch_one(
                conn,
                "SELECT next_run_at FROM shoc.schedules WHERE schedule_id = %s",
                (f"{tenant}:align:{key}",),
            )
            for key in ("a", "b")
        ]
        runs = [row["next_run_at"] for row in rows if row]
        assert runs[0] == runs[1]
        assert runs[0].timestamp() % 900 == 0 and runs[0] > datetime.now(runs[0].tzinfo)
    finally:
        execute(
            conn, "DELETE FROM shoc.schedules WHERE schedule_id LIKE %s", (f"{tenant}:align:%",)
        )
        execute(conn, "DELETE FROM shoc.jobs WHERE tenant_id = %s AND kind = 'noop'", (tenant,))
