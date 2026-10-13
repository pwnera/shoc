"""The audit chain as the operator and the unattended worker see it (SEC-1, OPS-1)."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg.rows import DictRow, dict_row

from shoc import worker
from shoc.agents import ops
from shoc.capabilities.registry import Caller, Context, call
from shoc.db.audit import append, check, hash_payload
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


@pytest.fixture
def chain(config):
    """A tenant of its own per test: the log is append-only, so nothing resets it."""
    tenant = f"{config.tenant_id}_walk_{uuid.uuid4().hex[:8]}"
    db = psycopg.Connection[DictRow].connect(config.dsn, row_factory=dict_row, autocommit=True)
    set_tenant(db, tenant)
    ctx = Context(tenant_id=tenant, caller=Caller(kind="human", id="test"), config=config)
    ctx._db = db
    yield ctx
    db.close()


def test_a_check_walks_only_the_rows_after_the_last_whole_walk(chain):
    """The log is never pruned; a walk from the first row on every call grew with it (data-11)."""
    db, tenant = chain.db, chain.tenant_id
    for n in range(3):
        append(db, tenant, "service", "worker", "events.ingest", hash_payload(n))
    ok, count, _ = check(db, tenant)
    assert ok and count == 3
    append(db, tenant, "service", "worker", "events.ingest", hash_payload(3))
    ok, count, detail = check(db, tenant)
    assert ok and count == 1 and "which an earlier walk verified" in detail


def test_the_daily_full_walk_finds_what_a_moved_checkpoint_hides(chain):
    """The checkpoint is a row the runtime role can write, so it only saves work."""
    db, tenant = chain.db, chain.tenant_id
    append(db, tenant, "service", "worker", "events.ingest", hash_payload(1))
    _forge(db, tenant)
    append(db, tenant, "service", "worker", "events.ingest", hash_payload(2))
    last = fetch_one(
        db,
        "SELECT seq, hash FROM shoc.audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
        (tenant,),
    )
    assert last
    with db.cursor() as cur:
        cur.execute(
            """INSERT INTO shoc.audit_checkpoints (tenant_id, seq, hash) VALUES (%s, %s, %s)
               ON CONFLICT (tenant_id) DO UPDATE SET seq = EXCLUDED.seq, hash = EXCLUDED.hash""",
            (tenant, last["seq"], last["hash"]),
        )
    assert check(db, tenant)[0], "the hourly walk starts after the moved checkpoint"
    assert not check(db, tenant, full=True)[0]
    assert not check(db, tenant)[0], "a break before the checkpoint drops it"


def test_a_listing_need_not_walk_the_chain_and_filters_by_who_and_what(chain):
    db, tenant = chain.db, chain.tenant_id
    append(db, tenant, "service", "worker", "events.ingest", hash_payload("a"))
    append(db, tenant, "human", "jane", "action.approve", hash_payload("b"))
    append(db, tenant, "service", "worker", "source.sync", hash_payload("c"))
    listed = call("health.audit", chain, {"verify": False, "principal": "service:worker"})
    assert listed.summary.endswith("the chain was not checked.")
    assert [r["capability"] for r in listed.data.recent] == ["source.sync", "events.ingest"]
    newest = listed.data.recent[0]["seq"]
    older = call("health.audit", chain, {"verify": False, "before": newest, "limit": 1})
    assert [r["capability"] for r in older.data.recent] == ["action.approve"]
    approvals = call("health.audit", chain, {"verify": False, "capability": "action.approve"})
    assert [r["principal_id"] for r in approvals.data.recent] == ["jane"]
