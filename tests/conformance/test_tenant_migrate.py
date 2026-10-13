"""`shoc migrate` and the merge gates bring every events table to the current columns (STO-2).

A tenant other than SHOC_TENANT, and the scratch stores the gates load fixtures
into, kept the columns they were created with; a load into one without a newly
added column failed.
"""

from __future__ import annotations

import pytest

from shoc.db import pool
from shoc.db.pool import q

pytestmark = pytest.mark.postgres

DROPPED = "metadata_profiles"  # stands for a column a later release adds


@pytest.fixture
def pg(store):
    if store.dialect != "postgres":
        pytest.skip("postgres-specific")
    return store


def _columns(conn, schema: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT column_name FROM information_schema.columns
               WHERE table_schema = %s AND table_name = 'ocsf_events'""",
            (schema,),
        )
        return {r["column_name"] for r in cur.fetchall()}


def _older(conn, schema: str) -> None:
    with conn.cursor() as cur:
        cur.execute(q(f'ALTER TABLE "{schema}".ocsf_events DROP COLUMN "{DROPPED}"'))
    assert DROPPED not in _columns(conn, schema)


def test_migrate_brings_every_registered_tenant_current(pg, conn, config, monkeypatch):
    from shoc.cli import _migrate_other_tenants
    from shoc.store import open_store

    tenant = f"{config.tenant_id}m"
    schema = config.tenant_schema(tenant)
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.tenants (tenant_id, name, backend, schema_name)
               VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (tenant, tenant, config.backend, schema),
        )
    other = open_store(config, tenant)
    try:
        other.migrate()
        _older(conn, schema)
        # Only this test's tenant: other sessions' tenants are not this test's to touch.
        real = pool.fetch_all
        monkeypatch.setattr(
            pool,
            "fetch_all",
            lambda c, sql, params=None: [
                r for r in real(c, sql, params) if r["tenant_id"] == tenant
            ],
        )
        _migrate_other_tenants(conn, config)
        assert DROPPED in _columns(conn, schema)
    finally:
        other.close()
        with conn.cursor() as cur:
            cur.execute(q(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
            cur.execute(q("DELETE FROM shoc.tenants WHERE tenant_id = %s"), (tenant,))


def test_a_gate_scratch_store_is_brought_current(pg, conn, config):
    from shoc.agents.detection_engineer import _scratch

    schema = config.tenant_schema(f"{config.tenant_id}_gate")
    scratch = _scratch(config, config.tenant_id)
    try:
        _older(conn, schema)
        scratch.close()
        scratch = _scratch(config, config.tenant_id)
        assert DROPPED in _columns(conn, schema)
    finally:
        scratch.close()
        with conn.cursor() as cur:
            cur.execute(q(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
