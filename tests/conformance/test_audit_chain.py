"""The audit chain as the operator and the unattended worker see it (SEC-1, OPS-1)."""

from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import DictRow, dict_row

from shoc import worker
from shoc.agents import ops
from shoc.capabilities.registry import Caller, Context, call
from shoc.db.audit import append, hash_payload
from shoc.db.pool import fetch_all, fetch_one, set_tenant

pytestmark = pytest.mark.postgres


def test_health_audit_verifies_the_chain_through_the_registry(ctx, clean):
    call("events.ingest", ctx, {"source": "github", "records": []})
    report = call("health.audit", ctx, {"limit": 5})
    assert report.data.chain_ok, report.data.detail
    assert report.data.rows_verified >= 1
    assert report.data.recent and report.data.recent[0]["capability"] == "events.ingest"
    assert report.summary.startswith("Audit chain intact")


def _forge(db: psycopg.Connection[DictRow], tenant: str) -> None:
    """INSERT is allowed; a row written without the key cannot chain."""
    with db.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.audit_log (tenant_id, ts, principal_kind, principal_id,
                   capability, input_hash, prev_hash, hash)
               SELECT tenant_id, now(), 'human', 'mallory', 'action.approve', 'x', hash,
                      repeat('0', 64)
               FROM shoc.audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1""",
            (tenant,),
        )


def test_a_broken_chain_pages_once_per_new_break_from_the_hourly_ops_check(config, conn):
    """Nobody logs in to run `health audit`; the worker's `ops.check` runs it every hour."""
    tenant = f"{config.tenant_id}_forged"
    db = psycopg.Connection[DictRow].connect(config.dsn, row_factory=dict_row, autocommit=True)
    set_tenant(db, tenant)

    def pages() -> list[dict[str, object]]:
        return fetch_all(
            db,
            """SELECT body FROM shoc.notices
               WHERE tenant_id = %s AND kind = 'page' AND condition = 'audit_broken'
               ORDER BY created_at""",
            (tenant,),
        )

    def alerts() -> int:
        row = fetch_one(
            db,
            """SELECT count(*) AS n FROM shoc.stream_events
               WHERE tenant_id = %s AND type = 'health.audit.broken'""",
            (tenant,),
        )
        return int(row["n"]) if row else 0

    try:
        append(db, tenant, "service", "worker", "events.ingest", hash_payload(1))
        _forge(db, tenant)
        forged = Context(tenant_id=tenant, caller=Caller(kind="human", id="test"), config=config)
        forged._db = db
        report = call("health.audit", forged, {})
        assert not report.data.chain_ok
        assert report.summary.startswith("AUDIT CHAIN BROKEN")
        assert not [a for a in ops.alerts(db, tenant) if a.kind == "audit.broken"], (
            "ops.alerts is a cheap read open to health:read; the chain is audit:read"
        )

        job = {"tenant_id": tenant, "kind": "ops.check", "payload": {}}
        worker.handle(job, config)
        assert len(pages()) == 1 and alerts() == 1
        worker.handle(job, config)
        assert len(pages()) == 1 and alerts() == 1, "the same break pages once"

        # Rows after the break are still checked, so a second forgery is news.
        append(db, tenant, "service", "worker", "events.ingest", hash_payload(2))
        worker.handle(job, config)
        assert len(pages()) == 1, "a good row after the break changes nothing"
        _forge(db, tenant)
        worker.handle(job, config)
        assert len(pages()) == 2 and alerts() == 2
        assert "2 audit row(s)" in str(pages()[-1]["body"])
    finally:
        db.close()


def test_the_scheduled_check_leaves_an_intact_chain_alone(ctx, config, clean):
    call("events.ingest", ctx, {"source": "github", "records": []})
    worker.handle({"tenant_id": config.tenant_id, "kind": "ops.check", "payload": {}}, config)
    assert not fetch_all(
        ctx.db,
        "SELECT 1 FROM shoc.notices WHERE tenant_id = %s AND condition = 'audit_broken'",
        (config.tenant_id,),
    )
