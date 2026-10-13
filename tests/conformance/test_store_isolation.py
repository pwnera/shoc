"""Stores and loads side by side (STO-1, ING-3).

`shoc.store.conformance` checks one store at a time. These open a second one:
for another tenant, to show that a namespace keeps its housekeeping to itself,
and for the same tenant on another thread, as serve loads webhooks.
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest

from shoc.ingest import batch
from shoc.store import RetentionPolicy, open_store
from shoc.store.conformance import _rows, _uids

pytestmark = pytest.mark.postgres


@pytest.fixture
def neighbour(config, conn, store):
    """A store for a second tenant on the backend under test, emptied afterwards."""
    from shoc.db.pool import q

    if config.backend != "postgres" and not os.environ.get("SHOC_TEST_TENANT"):
        # Only Postgres drops the neighbour's namespace here: on a warehouse a
        # fixed tenant reuses one catalog, database or dataset across runs.
        pytest.skip("set SHOC_TEST_TENANT to check a neighbour tenant on a warehouse")
    tenant = f"{config.tenant_id}n"
    other = open_store(config, tenant)
    other.migrate()
    other.reset()
    yield other
    other.reset()
    other.close()
    if config.backend == "postgres":
        with conn.cursor() as cur:
            cur.execute(q(f'DROP SCHEMA IF EXISTS "{config.tenant_schema(tenant)}" CASCADE'))


def _count(store) -> int:
    sql = "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id"
    return len(store.query(sql, {"tenant_id": store.tenant_id}).rows)


def test_reset_and_retention_leave_another_tenant_alone(store, neighbour, clean):
    now = datetime.now(UTC)
    for s in (store, neighbour):
        batch.load(s, _rows(s.tenant_id, 2, now))
        batch.load(s, _rows(s.tenant_id, 2, now - timedelta(days=400), tag="old"))
    store.apply_retention(RetentionPolicy(days=90))
    assert _count(store) == 2
    assert _count(neighbour) == 4, "retention reached another tenant"
    store.reset()
    assert _count(store) == 0
    assert _count(neighbour) == 4, "a reset reached another tenant"


def test_a_tenant_schema_hides_another_tenants_events(config, store, neighbour, clean):
    """Postgres keeps a schema per tenant: bound with the other tenant's id, a query
    still reads only its own schema (STO-1, SEC-1)."""
    if config.backend != "postgres":
        pytest.skip("the shared-table warehouses isolate by the tenant_id filter alone")
    batch.load(neighbour, _rows(neighbour.tenant_id, 3, datetime.now(UTC)))
    assert len(_uids(neighbour)) == 3
    assert _uids(store, neighbour.tenant_id) == [], "a tenant's schema showed another's events"


class _Together:
    """Holds a load until the other batch is written too, as two webhooks at once."""

    def __init__(self, store: Any, both: threading.Barrier) -> None:
        self.store, self.both = store, both
        self.tenant_id = store.tenant_id

    def load_batch(self, path: str) -> Any:
        self.both.wait(30)
        return self.store.load_batch(path)


def test_two_loads_in_one_millisecond_both_land(config, store, clean, monkeypatch):
    """A batch named by the time and the pid was shared by two threads of serve, and
    one load stored the other's rows while its own were lost (ING-3)."""
    monkeypatch.setattr(batch, "time", SimpleNamespace(time=lambda: 1_790_000_000.0))
    now = datetime.now(UTC)
    both = threading.Barrier(2)

    def load(tag: str) -> int:
        own = open_store(config, config.tenant_id)
        try:
            rows = _rows(config.tenant_id, 3, now, tag=tag)
            return batch.load(cast(Any, _Together(own, both)), rows).rows
        finally:
            own.close()

    with ThreadPoolExecutor(2) as pool:
        loaded = list(pool.map(load, ("first", "second")))
    assert loaded == [3, 3]
    assert _count(store) == 6
