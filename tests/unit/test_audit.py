from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from psycopg.rows import DictRow, dict_row

from shoc.db.audit import (
    CHECKPOINT,
    GENESIS,
    KEYED_FROM,
    append,
    chain_hash,
    chain_key,
    hash_payload,
    legacy_hash,
    verify,
)
from shoc.db.pool import ALL_TENANTS, fetch_all, fetch_one, q, set_tenant
from shoc.errors import ConfigError

pytestmark = pytest.mark.postgres

NOW = datetime(2026, 9, 29, 12, 0, 0, 123456, tzinfo=UTC)


def _connect(dsn: str, tenant: str) -> psycopg.Connection[DictRow]:
    """A session pinned the way shoc pins its own: unpinned, it sees no rows (026)."""
    conn = psycopg.Connection[DictRow].connect(dsn, row_factory=dict_row, autocommit=True)
    set_tenant(conn, tenant)
    return conn


def test_hash_chain_is_keyed_order_dependent_and_covers_ts():
    key, h = chain_key(), hash_payload({"x": 1})
    a = chain_hash(key, GENESIS, "t", NOW, "human:u", "cap", h, None, None)
    assert a == chain_hash(key, GENESIS, "t", NOW, "human:u", "cap", h, None, None)
    assert a != chain_hash(key, a, "t", NOW, "human:u", "cap", h, None, None)
    later = NOW + timedelta(microseconds=1)
    assert a != chain_hash(key, GENESIS, "t", later, "human:u", "cap", h, None, None)
    assert a != chain_hash(b"another key", GENESIS, "t", NOW, "human:u", "cap", h, None, None)
    # A field boundary cannot be moved without changing the hash.
    assert chain_hash(key, GENESIS, "t", NOW, "human:u|cap", "", h, None, None) != chain_hash(
        key, GENESIS, "t", NOW, "human:u", "|cap", h, None, None
    )


def test_audited_capability_appends_a_verifiable_chain(ctx, clean):
    from shoc.capabilities.registry import call

    for _ in range(3):
        call("events.ingest", ctx, {"source": "github", "records": []})
    ok, count, detail = verify(ctx.db, ctx.tenant_id)
    assert ok, detail
    assert count >= 3


def test_verify_reads_the_chain_in_batches(ctx, clean):
    from shoc.capabilities.registry import call

    for _ in range(3):
        call("events.ingest", ctx, {"source": "github", "records": []})
    assert verify(ctx.db, ctx.tenant_id, batch=2)[:2] == verify(ctx.db, ctx.tenant_id)[:2]


def test_audit_rows_cannot_be_updated(ctx, clean):
    from shoc.capabilities.registry import call

    call("events.ingest", ctx, {"source": "github", "records": []})
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"), ctx.db.cursor() as cur:
        cur.execute(
            "UPDATE shoc.audit_log SET capability = 'x' WHERE tenant_id = %s", (ctx.tenant_id,)
        )


def test_concurrent_appends_do_not_fork_the_chain(config, conn):
    """A second writer waits for the first to commit, then chains onto its row.

    `conn` is only here so the schema is migrated.
    """
    tenant = f"{config.tenant_id}_race"
    first, second = _connect(config.dsn, tenant), _connect(config.dsn, tenant)
    try:
        append(first, tenant, "service", "a", "cap", hash_payload(1))
        done = threading.Event()

        def race() -> None:
            append(second, tenant, "service", "b", "cap", hash_payload(2))
            done.set()

        racer = threading.Thread(target=race)
        with first.transaction():
            append(first, tenant, "service", "a", "cap", hash_payload(3))
            racer.start()
            time.sleep(0.5)
            assert not done.is_set(), "the second writer must wait for the first to commit"
        racer.join(10)
        assert done.is_set()
        ok, count, detail = verify(first, tenant)
        assert ok and count == 3, detail
    finally:
        first.close()
        second.close()


def test_a_process_without_the_key_or_with_another_touches_nothing(config, conn, monkeypatch):
    """A shell or `shoc mcp` started without the right key fails; the chain stays whole.

    `conn` is only here so the schema is migrated.
    """
    tenant = f"{config.tenant_id}_keys"
    db = _connect(config.dsn, tenant)
    try:
        append(db, tenant, "service", "worker", "cap", hash_payload(0))
        for key in ("", "not the key"):
            monkeypatch.setenv("SHOC_MASTER_KEY", key)
            with pytest.raises(ConfigError, match="SHOC_MASTER_KEY"):
                append(db, tenant, "human", "operator", "intel.add", hash_payload(1))
            with pytest.raises(ConfigError, match="SHOC_MASTER_KEY"):
                verify(db, tenant)
        monkeypatch.undo()
        ok, count, detail = verify(db, tenant)
        assert ok and count == 1, detail
    finally:
        db.close()


# -- a database that was running before migration 025 -----------------------
LEGACY = "legacy"


@pytest.fixture(scope="module")
def upgraded(config):
    """A database with three pre-025 audit rows, then upgraded by `migrate`."""
    from shoc.db.migrate import BOOTSTRAP, MIGRATIONS_DIR, migrate

    database = f"shoc_audit_{uuid.uuid4().hex[:8]}"
    admin = _connect(config.dsn, ALL_TENANTS)
    with admin.cursor() as cur:
        cur.execute(q(f'CREATE DATABASE "{database}"'))
    db = _connect(config.dsn.rsplit("/", 1)[0] + f"/{database}", LEGACY)
    try:
        with db.cursor() as cur:
            cur.execute(q(BOOTSTRAP))
            for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if path.stem < KEYED_FROM:
                    cur.execute(q(path.read_text()))
                    cur.execute(
                        "INSERT INTO shoc.schema_migrations (version) VALUES (%s)", (path.stem,)
                    )
            prev = GENESIS
            for n in range(3):
                digest = legacy_hash(
                    prev, LEGACY, "human:old", "events.ingest", hash_payload(n), None, None
                )
                cur.execute(
                    """INSERT INTO shoc.audit_log (tenant_id, principal_kind, principal_id,
                           capability, input_hash, prev_hash, hash)
                       VALUES (%s, 'human', 'old', 'events.ingest', %s, %s, %s)""",
                    (LEGACY, hash_payload(n), prev, digest),
                )
                prev = digest
        # Pinned to another tenant, `migrate` still seals LEGACY's chain.
        set_tenant(db, f"{LEGACY}_other")
        assert KEYED_FROM in migrate(db)
        set_tenant(db, LEGACY)
        yield db
    finally:
        db.close()
        with admin.cursor() as cur:
            cur.execute(q(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        admin.close()


def _rows(db: psycopg.Connection[DictRow]) -> list[dict[str, Any]]:
    return fetch_all(
        db,
        """SELECT seq, ts, principal_kind, principal_id, capability, input_hash, output_hash,
                  error, prev_hash, hash
           FROM shoc.audit_log WHERE tenant_id = %s ORDER BY seq""",
        (LEGACY,),
    )


def _replace(db: psycopg.Connection[DictRow], forged: list[dict[str, Any]]) -> None:
    """What the table's owner can do: switch the triggers off and write any rows."""
    with db.cursor() as cur:
        cur.execute("ALTER TABLE shoc.audit_log DISABLE TRIGGER USER")
        cur.execute("DELETE FROM shoc.audit_log WHERE tenant_id = %s", (LEGACY,))
        for r in forged:
            cur.execute(
                """INSERT INTO shoc.audit_log (tenant_id, ts, principal_kind, principal_id,
                       capability, input_hash, output_hash, error, prev_hash, hash)
                   VALUES (%(tenant_id)s, %(ts)s, %(principal_kind)s, %(principal_id)s,
                           %(capability)s, %(input_hash)s, %(output_hash)s, %(error)s,
                           %(prev_hash)s, %(hash)s)""",
                {**r, "tenant_id": LEGACY},
            )


def test_rows_from_before_025_still_verify_and_are_sealed(upgraded):
    ok, count, detail = verify(upgraded, LEGACY)
    assert ok and count >= 4, detail
    checkpoint = _rows(upgraded)[3]
    assert (checkpoint["capability"], checkpoint["principal_kind"], checkpoint["principal_id"]) == (
        CHECKPOINT,
        "service",
        "migrate",
    )
    append(upgraded, LEGACY, "service", "worker", "events.ingest", hash_payload("new"))
    ok, after, detail = verify(upgraded, LEGACY)
    assert ok and after == count + 1, detail


def test_the_owner_cannot_edit_or_rechain_without_the_key(upgraded):
    append(upgraded, LEGACY, "service", "worker", "events.ingest", hash_payload("keyed"))
    rows = _rows(upgraded)
    sealed = next(i for i, r in enumerate(rows) if r["capability"] == CHECKPOINT)

    def rechain(
        chain: list[dict[str, Any]], start: int, hasher: Callable[[str, dict[str, Any]], str]
    ) -> list[dict[str, Any]]:
        """Keep the rows before `start` as they are and re-chain the rest."""
        out = [dict(r) for r in chain]
        prev = out[start - 1]["hash"] if start else GENESIS
        for r in out[start:]:
            r["prev_hash"] = prev
            r["hash"] = prev = hasher(prev, r)
        return out

    def principal(r: dict[str, Any]) -> str:
        return f"{r['principal_kind']}:{r['principal_id']}"

    def unkeyed(prev: str, r: dict[str, Any]) -> str:
        return legacy_hash(
            prev,
            LEGACY,
            principal(r),
            r["capability"],
            r["input_hash"],
            r["output_hash"],
            r["error"],
        )

    def guessed_key(prev: str, r: dict[str, Any]) -> str:
        return chain_hash(
            b"not the key",
            prev,
            LEGACY,
            r["ts"],
            principal(r),
            r["capability"],
            r["input_hash"],
            r["output_hash"],
            r["error"],
        )

    edited = [dict(r) for r in rows]
    edited[-1]["input_hash"] = hash_payload("something else")
    moved = [dict(r) for r in rows]
    moved[-1]["ts"] = moved[-1]["ts"] + timedelta(seconds=1)
    for what, forged in (
        # Everything re-chained the way rows were before 025, checkpoint dropped.
        ("downgrade", rechain([r for r in rows if r["capability"] != CHECKPOINT], 0, unkeyed)),
        # The same, with the checkpoint kept in place.
        ("unkeyed checkpoint", rechain(rows, sealed, unkeyed)),
        # One keyed row edited and re-chained under a guessed key.
        ("guessed key", rechain(edited, len(rows) - 1, guessed_key)),
        # A keyed row's time moved, its hash left alone.
        ("moved ts", moved),
    ):
        with upgraded.transaction(force_rollback=True):
            _replace(upgraded, forged)
            ok, _count, detail = verify(upgraded, LEGACY)
            assert not ok, what
            assert "do not match" in detail, what
    assert verify(upgraded, LEGACY)[0], "each forgery was rolled back"


def test_truncate_is_refused(upgraded):
    before = fetch_one(upgraded, "SELECT count(*) AS n FROM shoc.audit_log")
    with (
        upgraded.transaction(force_rollback=True),
        pytest.raises(psycopg.errors.RaiseException, match="append-only"),
        upgraded.cursor() as cur,
    ):
        cur.execute("TRUNCATE shoc.audit_log")
    assert fetch_one(upgraded, "SELECT count(*) AS n FROM shoc.audit_log") == before


def test_a_writer_from_before_025_cannot_append(upgraded):
    """Its row would carry an unkeyed hash and break the chain for good."""
    with (
        upgraded.transaction(force_rollback=True),
        pytest.raises(psycopg.errors.NotNullViolation),
        upgraded.cursor() as cur,
    ):
        cur.execute(
            """INSERT INTO shoc.audit_log (tenant_id, principal_kind, principal_id, capability,
                   input_hash, prev_hash, hash)
               VALUES (%s, 'agent', 'worker', 'detect.run', 'x', 'y', 'z')""",
            (LEGACY,),
        )
