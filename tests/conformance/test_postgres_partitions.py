"""Postgres loads that one bad row or a busy table cannot stop (STO-2, ING-1)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from shoc.ingest import batch, ocsf
from shoc.store.base import RetentionPolicy

pytestmark = pytest.mark.postgres


@pytest.fixture
def pg(store):
    if store.dialect != "postgres":
        pytest.skip("postgres-specific")
    return store


def _rows(tenant, n, when):
    mapping = ocsf.load_mapping("okta")
    return [
        mapping.map_record(
            {"uuid": f"pg-{i}", "eventType": "user.session.start", "published": when.isoformat()},
            tenant,
        )
        for i in range(n)
    ]


def _uids(store):
    result = store.query(
        "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id ORDER BY event_uid",
        {"tenant_id": store.tenant_id},
    )
    return [str(r["event_uid"]) for r in result.rows]


TABLES = """SELECT c.relname AS name FROM pg_class c
             JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s"""


def _names(store, sql):
    with store.conn.cursor() as cur:
        cur.execute(sql, (store.schema,))
        return {r["name"] for r in cur.fetchall()}


def test_a_row_postgres_refuses_is_left_out_and_the_rest_load(pg, clean, config, now):
    rows = _rows(config.tenant_id, 7, now)
    # What map_record cleans, written past it: NUL in text, a lone surrogate,
    # NUL inside jsonb.
    rows[1]["message"] = "bad\x00byte"
    rows[2]["message"] = "lone \ud800 surrogate"
    rows[5]["raw"] = {"note": "nul \x00 in json"}
    assert batch.load(pg, rows).rows == 4
    assert _uids(pg) == ["pg-0", "pg-3", "pg-4", "pg-6"]


def test_a_batch_postgres_refuses_most_of_fails_loudly(pg, clean, config, now):
    rows = _rows(config.tenant_id, 3, now)
    for row in rows[1:]:
        row["message"] = "bad\x00byte"
    with pytest.raises(psycopg.DataError):
        batch.load(pg, rows)


def test_retention_makes_the_coming_months_and_drops_any_year(pg, clean):
    pg.ensure_partition(datetime(1970, 1, 1, tzinfo=UTC))
    assert pg.apply_retention(RetentionPolicy(days=90)) >= 1
    tables = _names(pg, TABLES)
    month = datetime.now(UTC).replace(day=1)
    following = (month + timedelta(days=32)).replace(day=1)
    assert f"ocsf_events_{month:%Y%m}" in tables
    assert f"ocsf_events_{following:%Y%m}" in tables
    assert "ocsf_events_197001" not in tables


def test_the_unused_api_operation_index_is_gone(pg):
    indexes = _names(pg, "SELECT indexname AS name FROM pg_indexes WHERE schemaname = %s")
    assert "ocsf_api" not in indexes
    assert {"ocsf_actor", "ocsf_src", "ocsf_time"} <= indexes


def test_a_late_row_for_a_dropped_month_lands_in_the_default(pg, clean, config, now):
    pg.apply_retention(RetentionPolicy(days=90))  # no partition left for a year ago
    late = now - timedelta(days=400)
    assert batch.load(pg, _rows(config.tenant_id, 2, late)).rows == 2
    assert f"ocsf_events_{late:%Y%m}" not in _names(pg, TABLES)
    assert _uids(pg) == ["pg-0", "pg-1"]
    with pg.conn.cursor() as cur:
        cur.execute(
            "SELECT event_uid FROM ocsf_events_default WHERE tenant_id = %s", (config.tenant_id,)
        )
        assert len(cur.fetchall()) == 2
    # Retention reaches rows the default partition holds.
    pg.apply_retention(RetentionPolicy(days=90))
    assert _uids(pg) == []


def test_a_month_held_in_the_default_is_not_partitioned_again(pg, clean, config, now, monkeypatch):
    pg.apply_retention(RetentionPolicy(days=90))  # this month and the next have partitions
    later = (now.replace(day=1) + timedelta(days=95)).replace(day=1)
    rows = _rows(config.tenant_id, 1, now)
    rows[0]["time"] = later.isoformat()  # past the mapping's bound, as an older row could be

    def busy(_ts):
        raise psycopg.errors.LockNotAvailable("canceling statement due to lock timeout")

    with monkeypatch.context() as patch:
        patch.setattr(pg, "ensure_partition", busy)
        assert batch.load(pg, rows).rows == 1
    # CREATE would fail on the row the default holds; the month stays there.
    pg.ensure_partition(later)
    tables = _names(pg, TABLES)
    assert f"ocsf_events_{later:%Y%m}" not in tables


def test_a_session_answers_in_utc_whatever_the_server_zone(config, pg):
    """A histogram's day buckets match the warehouses' on a server set to a local zone."""
    from psycopg.conninfo import make_conninfo

    from shoc.store.postgres import PostgresStore

    paris = PostgresStore(
        make_conninfo(config.dsn, options="-c TimeZone=Europe/Paris"),
        config.tenant_id,
        config.tenant_schema(config.tenant_id),
    )
    try:
        with paris.conn.cursor() as cur:
            cur.execute("SELECT current_setting('TimeZone') AS tz")
            row = cur.fetchone()
        assert row is not None and row["tz"] == "UTC"
    finally:
        paris.close()
