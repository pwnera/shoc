"""The suite refuses a database a deployment uses: its worker tests empty the
shared job queue, and the session migrates the schema."""

from __future__ import annotations

import uuid

import pytest

from shoc.db.pool import ALL_TENANTS, execute, set_tenant
from tests.support import live_tenants

pytestmark = pytest.mark.postgres


def test_a_tenant_with_a_source_marks_the_database_live(conn, config):
    set_tenant(conn, ALL_TENANTS)
    live, ours = f"acme{uuid.uuid4().hex[:8]}", f"{config.tenant_id}g"
    # Never committed: a run killed mid-test leaves no live tenant behind to
    # refuse every later session on this database.
    with conn.transaction(force_rollback=True):
        for tenant in (live, ours):
            execute(
                conn,
                """INSERT INTO shoc.tenants (tenant_id, name, schema_name)
                   VALUES (%s, %s, %s) ON CONFLICT DO NOTHING""",
                (tenant, tenant, config.tenant_schema(tenant)),
            )
        assert live not in live_tenants(conn), "`shoc migrate` alone registers an empty tenant"
        for tenant in (live, ours):
            execute(
                conn,
                "INSERT INTO shoc.connector_config (tenant_id, source) VALUES (%s, 'okta')",
                (tenant,),
            )
        found = live_tenants(conn)
        assert live in found
        assert ours not in found, "a test session's own tenant is never live"
