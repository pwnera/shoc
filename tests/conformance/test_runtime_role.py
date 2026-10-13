"""The suite runs as the role serve and worker run as, which does not own the schema
(SEC-1, RFC 0024). A path that needs the owner's rights fails here, not in production."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from shoc.capabilities.registry import call
from shoc.db.pool import fetch_all, fetch_one, owns_audit_log

pytestmark = pytest.mark.postgres


def test_capabilities_run_as_a_role_that_does_not_own_the_schema(ctx, config):
    if not config.migrate_dsn:
        pytest.skip("SHOC_MIGRATE_DSN is not set: the suite runs as the schema's owner")
    assert not owns_audit_log(ctx.db)


def test_retention_drops_a_month_of_a_schema_the_runtime_role_made(ctx, store, config, clean):
    if store.dialect != "postgres":
        pytest.skip("postgres-specific")
    made = fetch_one(
        ctx.db,
        """SELECT pg_get_userbyid(nspowner) = current_user AS mine
           FROM pg_namespace WHERE nspname = %s""",
        (store.schema,),
    )
    assert made and made["mine"], "the store makes its tenant's schema as SHOC_DSN's role"
    store.ensure_partition(datetime(1970, 1, 1, tzinfo=UTC))
    assert call("events.retain", ctx, {"days": 3650}).data.dropped >= 1
    left = fetch_all(
        ctx.db,
        """SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = %s AND c.relname = 'ocsf_events_197001'""",
        (store.schema,),
    )
    assert not left
