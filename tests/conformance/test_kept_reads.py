"""Reads Postgres keeps until a load can change them (STO-1, OPS-1, D161)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from shoc.agents import ops
from shoc.db.pool import execute
from shoc.ingest import batch
from shoc.store import kept
from shoc.store.base import StoreHealth
from tests.conformance.test_quality_and_handover import _event, _load

SQL = (
    "SELECT metadata_product AS product, COUNT(*) AS n, MAX(time) AS newest "
    "FROM ocsf_events WHERE tenant_id = :tenant_id GROUP BY metadata_product"
)


class Counting:
    """The store under test, counting what reaches it."""

    def __init__(self, store: Any, up: bool = True) -> None:
        self.store, self.up, self.queries, self.healths = store, up, 0, 0
        self.dialect = store.dialect

    def query(self, *args, **kwargs):
        self.queries += 1
        return self.store.query(*args, **kwargs)

    def health(self) -> StoreHealth:
        self.healths += 1
        return self.store.health() if self.up else StoreHealth(ok=False, detail="down")


def test_a_read_is_answered_from_postgres_until_a_load_commits(conn, store, config, clean, now):
    tenant = config.tenant_id
    _load(store, tenant, now, [_event()])
    counting = Counting(store)
    first = kept.rows(conn, counting, tenant, "t", SQL, {"tenant_id": tenant}, 10)
    again = kept.rows(conn, counting, tenant, "t", SQL, {"tenant_id": tenant}, 10)
    assert counting.queries == 1
    assert again == first and isinstance(again[0]["newest"], datetime), "times come back as times"

    batch.loaded(conn, tenant, [{"metadata_product": "AWS CloudTrail"}])
    kept.rows(conn, counting, tenant, "t", SQL, {"tenant_id": tenant}, 10)
    assert counting.queries == 2, "a load since the read reads it again"


def test_a_read_older_than_a_day_is_read_again(conn, store, config, clean):
    tenant = config.tenant_id
    counting = Counting(store)
    kept.rows(conn, counting, tenant, "t", SQL, {"tenant_id": tenant}, 10)
    execute(
        conn,
        "UPDATE shoc.store_reads SET read_at = read_at - %s WHERE tenant_id = %s",
        (kept.STALE, tenant),
    )
    kept.rows(conn, counting, tenant, "t", SQL, {"tenant_id": tenant}, 10)
    assert counting.queries == 2


def test_source_quality_is_scored_once_between_loads(ctx, store, config, clean, now):
    _load(store, config.tenant_id, now, [{**_event(), "_repeat": 3}], conn=ctx.db)
    counting = Counting(store)
    first = ops.source_quality(ctx.db, counting, config.tenant_id)
    again = ops.source_quality(ctx.db, counting, config.tenant_id)
    assert [(q.product, q.events) for q in again] == [(q.product, q.events) for q in first]
    assert counting.queries == 1
    ops.source_quality(ctx.db, counting, config.tenant_id, days=7)
    assert counting.queries == 2, "another window is another read"


def test_store_health_is_kept_for_an_hour_and_a_failure_never(conn, store, config, clean):
    tenant = config.tenant_id
    counting = Counting(store)
    assert kept.health(conn, counting, tenant).ok
    assert kept.health(conn, counting, tenant).ok
    assert counting.healths == 1
    execute(
        conn,
        "UPDATE shoc.store_reads SET read_at = read_at - %s WHERE tenant_id = %s",
        (kept.HEALTH + timedelta(minutes=1), tenant),
    )
    down = Counting(store, up=False)
    assert not kept.health(conn, down, tenant).ok
    assert not kept.health(conn, down, tenant).ok
    assert down.healths == 2, "a store that is down is asked again"
