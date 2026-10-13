from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest

from shoc.config import Config
from tests.support import dsn, live_tenants


@pytest.fixture(scope="session")
def config() -> Config:
    """A throwaway tenant per test session, so tests never see each other's events.

    SHOC_TEST_TENANT names a fixed one instead, so runs on a warehouse reuse one
    catalog or database rather than leaving one behind each time.
    """
    if not dsn():
        pytest.skip("SHOC_DSN is not set; skipping the Postgres-backed tests")
    if os.environ.get("SHOC_TEST_ALLOW_MODEL") != "1":
        # Whatever the shell exported: no test spends model credit, and the
        # policy decides dry runs, as in CI. Set in the environment, so a
        # replay's own Config.load() reads it too (AGT-6).
        os.environ["SHOC_LLM_PROVIDER"] = "none"
        os.environ.pop("SHOC_DRY_RUN", None)
    cfg = Config()
    cfg.tenant_id = os.environ.get("SHOC_TEST_TENANT") or f"test{uuid.uuid4().hex[:8]}"
    cfg.master_key = cfg.master_key or "test-master-key"
    return cfg


@pytest.fixture(scope="session")
def conn(config: Config):
    import psycopg
    from psycopg.rows import DictRow, dict_row

    from shoc.db.migrate import migrate
    from shoc.db.pool import q

    # As the schema's owner, the way `shoc migrate` connects; capabilities and
    # stores use SHOC_DSN, the role serve and worker run as (RFC 0024).
    c = psycopg.Connection[DictRow].connect(
        config.migrate_dsn or config.dsn, row_factory=dict_row, autocommit=True
    )
    from shoc.db.pool import ALL_TENANTS, set_tenant

    set_tenant(c, ALL_TENANTS)  # fixtures set up and tear down across tenants
    live = live_tenants(c)
    if live and os.environ.get("SHOC_TEST_ALLOW_LIVE") != "1":
        c.close()
        pytest.exit(
            f"SHOC_DSN's database is in use by tenant(s) {', '.join(live)}: the suite "
            "migrates it and empties its job queue. Point SHOC_DSN at a scratch database, "
            "or set SHOC_TEST_ALLOW_LIVE=1."
        )
    migrate(c)
    _grant_runtime_for_tests(c, config)
    with c.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.tenants (tenant_id, name, backend, schema_name)
               VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (config.tenant_id, config.tenant_id, config.backend, config.tenant_schema()),
        )
    yield c
    with c.cursor() as cur:
        cur.execute(q(f'DROP SCHEMA IF EXISTS "{config.tenant_schema()}" CASCADE'))
        # The audit log is append-only on purpose, so it is left behind; the test
        # tenant id is unique per session, so those rows harm nothing.
        for table in (
            "actions",
            "playbook_runs",
            "findings",
            "rule_state",
            "connector_state",
            "connector_config",
            "jobs",
            "cases",
            "stream_events",
            "memory",
            "webhooks",
            "action_credentials",
            "iocs",
            "intel_feeds",
            "hunts",
            "rule_proposals",
            "reports",
            "llm_spend",
            "graph_edges",
            "graph_nodes",
            "merged_rules",
            "merged_hunts",
            "merged_playbooks",
            "suppressions",
            "detection_backlog",
            "case_routing",
            "source_onboarding",
            "mapping_overrides",
            "exposures",
            "posture_snapshots",
            "intel_reports",
            "intel_lookups",
            "intel_queue",
            "lookup_sources",
            "lookup_usage",
            "hunt_runs",
            "hunt_observations",
            "hunt_packs",
            "hunt_backlog",
            "notices",
            "store_loads",
            "store_reads",
            "push_deliveries",
            "push_spool",
            "api_tokens",
            "user_links",
            "users",
            "sso_providers",
            "own_identities",
            "own_token_requests",
            "source_history",
            "snapshots",
            "schedules",
            "rehearsals",
            "tenants",
        ):
            cur.execute(q(f"DELETE FROM shoc.{table} WHERE tenant_id = %s"), (config.tenant_id,))
    c.close()


def backends() -> list[str]:
    """Which backends this environment can run the conformance suite against.

    Postgres always; each warehouse when its credentials are in the environment.
    Set SHOC_BACKENDS to narrow it, e.g. SHOC_BACKENDS=postgres.
    """
    wanted = [b for b in os.environ.get("SHOC_BACKENDS", "").split(",") if b]
    if wanted:
        return wanted
    available = ["postgres"]
    if os.environ.get("SHOC_DATABRICKS_HOST") and os.environ.get("SHOC_DATABRICKS_TOKEN"):
        available.append("databricks")
    if os.environ.get("SHOC_SNOWFLAKE_ACCOUNT") and os.environ.get("SHOC_SNOWFLAKE_USER"):
        available.append("snowflake")
    if os.environ.get("SHOC_REDSHIFT_DSN"):
        available.append("redshift")
    if os.environ.get("SHOC_BIGQUERY_PROJECT") and os.environ.get("SHOC_BIGQUERY_CREDENTIALS"):
        available.append("bigquery")
    return available


@pytest.fixture(scope="session", params=backends())
def store(request, config: Config, conn):
    """The event store under test. Parametrised over every available backend."""
    from shoc.store import open_store

    config.backend = request.param
    s = open_store(config, config.tenant_id)
    s.migrate()
    _grant_readonly_for_tests(conn, config)
    yield s
    s.close()


def _grant_runtime_for_tests(conn, config: Config) -> None:
    """What `shoc migrate` does after migrating as the owner: let SHOC_DSN's role
    run shoc without owning the schema (RFC 0024)."""
    from urllib.parse import urlsplit

    from shoc.db.migrate import grant_runtime

    runtime = urlsplit(config.dsn)
    role = runtime.username or ""
    if config.migrate_dsn and role and role != urlsplit(config.migrate_dsn).username:
        grant_runtime(conn, role, (runtime.path or "/shoc").lstrip("/"))


def _grant_readonly_for_tests(conn, config: Config) -> None:
    """What an operator does after adding a tenant: re-run `shoc grant-readonly`."""
    from urllib.parse import urlsplit

    if not config.readonly_dsn or config.backend != "postgres":
        return
    parts = urlsplit(config.readonly_dsn)
    from shoc.db.migrate import grant_readonly

    grant_readonly(
        conn,
        parts.username or "shoc_agent",
        parts.password or "",
        (parts.path or "/shoc").lstrip("/"),
        config.tenant_schema(),
    )


@pytest.fixture
def ctx(config: Config, conn, store):
    from shoc.capabilities.registry import Caller, Context

    # No `_db`: the capability opens this thread's connection and pins it to the
    # tenant itself, which is what every surface does. `conn` stays all-tenants.
    c = Context(tenant_id=config.tenant_id, caller=Caller(kind="human", id="test"), config=config)
    c._store = store
    return c


@pytest.fixture
def clean(conn, store, config: Config):
    """Empty the tenant's events and findings before a test."""
    from shoc.db.pool import ALL_TENANTS, q, set_tenant

    def _clean() -> None:
        # A capability called with this connection (`ctx._db = conn`) pins it
        # to the test's tenant; a fixture that writes a neighbour's rows after
        # it would be refused by row-level security.
        set_tenant(conn, ALL_TENANTS)
        store.reset()
        with conn.cursor() as cur:
            # cases cascade to openspace_messages and case_entities.
            for table in (
                "actions",
                "playbook_runs",
                "findings",
                "rule_state",
                "connector_state",
                "connector_config",
                "jobs",
                "cases",
                "stream_events",
                "memory",
                "webhooks",
                "action_credentials",
                "iocs",
                "intel_feeds",
                "hunts",
                "rule_proposals",
                "reports",
                "llm_spend",
                "graph_edges",
                "graph_nodes",
                "merged_rules",
                "merged_hunts",
                "merged_playbooks",
                "suppressions",
                "detection_backlog",
                "case_routing",
                "source_onboarding",
                "mapping_overrides",
                "exposures",
                "posture_snapshots",
                "intel_reports",
                "intel_lookups",
                "intel_queue",
                "lookup_sources",
                "lookup_usage",
                "hunt_runs",
                "hunt_observations",
                "hunt_packs",
                "hunt_backlog",
                "notices",
                "store_loads",
                "store_reads",
                "push_deliveries",
                "push_spool",
                "own_identities",
                "own_token_requests",
                "source_history",
                "snapshots",
                "schedules",
                "rehearsals",
                "user_links",
                "users",
                "sso_providers",
            ):
                cur.execute(
                    q(f"DELETE FROM shoc.{table} WHERE tenant_id = %s"), (config.tenant_id,)
                )

    _clean()
    return _clean


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def pager(conn, config: Config, clean, monkeypatch):
    """A PagerDuty routing key, with every post shoc makes landing in `.posts`
    and answered with `.status`; never real PagerDuty (RSP-4)."""
    import json
    from functools import partial
    from types import SimpleNamespace

    import httpx

    from shoc.cases import credentials

    fake = SimpleNamespace(posts=[], urls=[], status=202)

    def handler(request: httpx.Request) -> httpx.Response:
        fake.posts.append(json.loads(request.content))
        fake.urls.append(str(request.url))
        return httpx.Response(fake.status, json={"status": "success", "dedup_key": "test"})

    monkeypatch.setattr(
        httpx, "Client", partial(httpx.Client, transport=httpx.MockTransport(handler))
    )
    credentials.store(
        conn, config.tenant_id, "notify", {}, {"routing_key": "test-routing-key"}, config.master_key
    )
    yield fake
    # Gone before the fake transport is: a later test that pages without
    # `clean` must not reach real PagerDuty.
    credentials.remove(conn, config.tenant_id, "notify")
