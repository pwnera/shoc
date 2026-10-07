"""Tenant isolation and the read-only agent role (SEC-1, principle 7)."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import psycopg
import pytest
from psycopg.rows import DictRow, dict_row

from shoc.capabilities.registry import Caller, Context, call
from shoc.db.pool import ALL_TENANTS, fetch_all, is_superuser, q, set_tenant
from shoc.errors import Denied

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="session")
def app_conn(conn, config):
    """A second connection as a *non-superuser* application role.

    Postgres superusers bypass row-level security entirely, so the policies can
    only be demonstrated, and are only worth anything in production, through an
    ordinary role. CI connects as one; a superuser run creates one here.
    """
    dsn = config.dsn
    if is_superuser(conn):
        role, password = "shoc_app_test", "app-test-password"
        with conn.cursor() as cur:
            cur.execute(
                q(
                    f"""DO $$ BEGIN
                            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                                CREATE ROLE {role} LOGIN PASSWORD '{password}';
                            END IF;
                            -- deploy/postgres-init revokes CONNECT from PUBLIC.
                            EXECUTE format('GRANT CONNECT ON DATABASE %I TO {role}', current_database());
                        END $$;
                        GRANT USAGE ON SCHEMA shoc TO {role};
                        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shoc TO {role};"""
                )
            )
        parts = urlsplit(config.dsn)
        dsn = (
            f"postgresql://{role}:{password}@{parts.hostname}:{parts.port or 5432}"
            f"{parts.path or '/shoc'}"
        )
    c: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        dsn, row_factory=dict_row, autocommit=True
    )
    yield c
    c.close()


@pytest.fixture
def two_tenants(conn, config, clean):
    """One finding for this tenant and one for a neighbour."""
    other = f"{config.tenant_id}_neighbour"
    for tenant, uid in ((config.tenant_id, "F-mine"), (other, "F-theirs")):
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO shoc.findings
                       (finding_uid, tenant_id, rule_id, title, severity, entity_key,
                        window_start, window_end, first_seen, last_seen, event_uids)
                   VALUES (%s,%s,'r','t','high','e', now(), now(), now(), now(), ARRAY['e1'])
                   ON CONFLICT (finding_uid) DO NOTHING""",
                (f"{uid}-{config.tenant_id}", tenant),
            )
    yield other
    with conn.cursor() as cur:
        set_tenant(conn, ALL_TENANTS)
        cur.execute("DELETE FROM shoc.findings WHERE tenant_id = %s", (other,))


def test_row_level_security_hides_other_tenants(app_conn, config, two_tenants):
    set_tenant(app_conn, config.tenant_id)
    rows = fetch_all(app_conn, "SELECT finding_uid, tenant_id FROM shoc.findings")
    assert rows, "the tenant's own rows are still visible"
    assert {r["tenant_id"] for r in rows} == {config.tenant_id}


def test_a_query_that_forgets_its_where_clause_still_cannot_cross_tenants(
    app_conn, config, two_tenants
):
    set_tenant(app_conn, two_tenants)
    rows = fetch_all(app_conn, "SELECT tenant_id FROM shoc.findings")
    assert {r["tenant_id"] for r in rows} == {two_tenants}


def test_writing_into_another_tenant_is_refused(app_conn, config, two_tenants):
    set_tenant(app_conn, config.tenant_id)
    with pytest.raises(psycopg.errors.Error), app_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.findings
                   (finding_uid, tenant_id, rule_id, title, severity, entity_key,
                    window_start, window_end, first_seen, last_seen)
               VALUES ('F-sneaky', %s, 'r', 't', 'high', 'e', now(), now(), now(), now())""",
            (two_tenants,),
        )


def test_the_suite_runs_as_an_ordinary_role(conn):
    """A superuser bypasses every policy, so a suite run as one tests none of them.

    CI connects as an ordinary role. A local run as a superuser skips here, and
    only the `app_conn` tests exercise the policies.
    """
    if is_superuser(conn) and not os.environ.get("CI"):
        pytest.skip("connected as a superuser, which bypasses row-level security")
    assert not is_superuser(conn), "SHOC_DSN must name an ordinary role, not a superuser"


def test_a_session_that_never_names_a_tenant_sees_nothing(app_conn, config, two_tenants):
    fresh: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        app_conn.info.dsn,
        password=app_conn.info.password,
        row_factory=dict_row,
        autocommit=True,
    )
    try:
        assert fetch_all(fresh, "SELECT tenant_id FROM shoc.findings") == []
    finally:
        fresh.close()
    set_tenant(app_conn, "")
    assert fetch_all(app_conn, "SELECT tenant_id FROM shoc.findings") == []
    with pytest.raises(psycopg.errors.Error), app_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.findings
                   (finding_uid, tenant_id, rule_id, title, severity, entity_key,
                    window_start, window_end, first_seen, last_seen)
               VALUES ('F-unscoped', %s, 'r', 't', 'high', 'e', now(), now(), now(), now())""",
            (config.tenant_id,),
        )


def test_an_operational_session_still_sees_everything(conn, config, two_tenants):
    set_tenant(conn, ALL_TENANTS)
    tenants = {r["tenant_id"] for r in fetch_all(conn, "SELECT tenant_id FROM shoc.findings")}
    assert {config.tenant_id, two_tenants} <= tenants


def test_a_capability_call_scopes_its_connection(config, store, two_tenants):
    """Surfaces build a fresh Context per request on a connection the thread reuses.

    The previous request left it pinned to the neighbour; this call must not
    inherit that.
    """
    from shoc.db.pool import connect, current_tenant

    shared = connect(config)
    set_tenant(shared, two_tenants)
    ctx = Context(tenant_id=config.tenant_id, caller=Caller(kind="human", id="t"), config=config)
    ctx._store = store
    found = {r["finding_uid"] for r in call("finding.list", ctx, {}).data.rows}
    assert found == {f"F-mine-{config.tenant_id}"}
    assert current_tenant(shared) == config.tenant_id


def test_no_caller_can_name_the_all_tenants_setting_as_its_tenant(
    config, conn, store, clean, two_tenants
):
    """`shoc:all` is every tenant to the policy, and X-Shoc-Tenant is the caller's to set."""
    from starlette.testclient import TestClient

    from shoc.api.rest import build_app

    with pytest.raises(Denied):
        Context(tenant_id=ALL_TENANTS, caller=Caller(kind="human", id="t"), config=config)
    # Addressed to localhost, or single-user mode refuses before the tenant is read.
    with TestClient(build_app(config), base_url="http://localhost") as client:
        client.headers["x-shoc-tenant"] = ALL_TENANTS
        assert client.post("/v1/finding/list", json={}).status_code == 403
        assert client.post("/ingest/github", json=[]).status_code == 403
        assert client.post("/slack/commands", content=b"").status_code == 403
        assert client.get("/v1/stream").status_code == 403
        assert client.get("/metrics").status_code == 403


def test_an_agent_cannot_load_events(config):
    """Loading is a write; an agent on SHOC_READONLY_DSN could not do it anyway (D22)."""
    agent = Context(
        tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config
    )
    with pytest.raises(Denied):
        call("events.ingest", agent, {"source": "github", "records": []})


def test_a_fresh_context_pins_the_thread_connection_it_takes(config, clean):
    """REST, MCP and the stream build a fresh Context per call on a pooled thread.

    That thread's connection still carries the tenant of its last caller.
    """
    from shoc.db.pool import connect, current_tenant

    pooled = connect(config)
    set_tenant(pooled, f"other{config.tenant_id}")
    try:
        ctx = Context(
            tenant_id=config.tenant_id, caller=Caller(kind="human", id="t"), config=config
        )
        call("finding.list", ctx, {})
        assert current_tenant(pooled) == config.tenant_id
    finally:
        set_tenant(pooled, ALL_TENANTS)


@pytest.mark.skipif(not os.environ.get("SHOC_READONLY_DSN"), reason="no read-only role configured")
def test_the_read_only_role_cannot_write(config):
    ro: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        os.environ["SHOC_READONLY_DSN"], row_factory=dict_row, autocommit=True
    )
    try:
        with ro.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM shoc.findings")
            assert cur.fetchone() is not None
        with pytest.raises(psycopg.errors.InsufficientPrivilege), ro.cursor() as cur:
            cur.execute("DELETE FROM shoc.findings")
    finally:
        ro.close()


@pytest.mark.skipif(not os.environ.get("SHOC_READONLY_DSN"), reason="no read-only role configured")
def test_agents_read_through_the_read_only_role(config, conn, store, clean):
    from shoc.store import open_store

    agent = Context(
        tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config
    )
    assert agent.reads_only
    human = Context(
        tenant_id=config.tenant_id, caller=Caller(kind="human", id="sam"), config=config
    )
    assert not human.reads_only
    readonly = open_store(config, config.tenant_id, readonly=True)
    assert readonly.dialect == store.dialect
    if store.dialect == "postgres":
        assert getattr(readonly, "dsn") == config.readonly_dsn  # noqa: B009 - not on EventStore


def test_a_read_only_store_refuses_every_write(config, store):
    """Whatever credential it holds, and on any backend (SEC-1)."""
    from shoc.errors import StoreError
    from shoc.store import open_store
    from shoc.store.base import RetentionPolicy

    readonly = open_store(config, config.tenant_id, readonly=True)
    for write in (
        readonly.reset,
        readonly.create_tenant,
        readonly.migrate,
        lambda: readonly.load_batch("/nonexistent.ndjson.gz"),
        lambda: readonly.apply_retention(RetentionPolicy(days=1)),
    ):
        with pytest.raises(StoreError, match="read-only"):
            write()
    assert readonly.health().ok
