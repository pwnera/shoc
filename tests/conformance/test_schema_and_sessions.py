"""The schema the code runs on, migrations that wait on a lock, and session limits
(STO-2, OPS-1)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shoc.capabilities.registry import call
from shoc.db import migrate
from shoc.db.pool import execute, fetch_one

pytestmark = pytest.mark.postgres


@pytest.fixture
def migrations(tmp_path, monkeypatch):
    """The code's migrations as a directory a test can add to or take from."""
    for path in migrate.MIGRATIONS_DIR.glob("*.sql"):
        (tmp_path / path.name).symlink_to(path)
    monkeypatch.setattr(migrate, "MIGRATIONS_DIR", tmp_path)
    return tmp_path


# -- schema version (sre-14) ----------------------------------------------------
def test_code_with_a_migration_not_applied_waits_for_shoc_migrate(conn, migrations):
    """It used to check one table, so new code ran job after job on an old schema."""
    from shoc.worker import wait_for_schema

    (migrations / "999_not_yet.sql").write_text("SELECT 1;\n")
    assert migrate.drift(conn) == (["999_not_yet"], [])
    assert not wait_for_schema(conn, attempts=1, delay=0)


def test_a_schema_migrated_by_a_newer_release_is_reported(ctx, conn, migrations, clean, caplog):
    """A `helm rollback` leaves old code on a newer schema with nothing saying so."""
    from shoc.worker import wait_for_schema

    newest = max(migrations.glob("*.sql"))
    newest.unlink()
    assert wait_for_schema(conn, attempts=1, delay=0), "only a restore undoes it; not waited on"
    assert newest.stem in caplog.text
    status = call("health.status", ctx, {})
    assert status.data.schema_ahead == [newest.stem]
    assert not status.data.ok and "newer release" in status.summary


def test_a_current_schema_is_neither_behind_nor_ahead(conn, ctx, clean):
    assert migrate.drift(conn) == ([], [])
    assert call("health.status", ctx, {}).data.schema_ahead == []


# -- migration lock waits (data-13) -----------------------------------------------
def test_a_migration_behind_a_reader_tries_again(conn, config, migrations, monkeypatch):
    """An ALTER queued behind a long reader held every later query on its table."""
    import psycopg

    (migrations / "999_lock_test.sql").write_text(
        "LOCK TABLE shoc.tenants IN ACCESS EXCLUSIVE MODE;\n"
    )
    monkeypatch.setattr(migrate, "LOCK_TIMEOUT", "200ms")
    reader = psycopg.connect(config.dsn)  # a transaction left open on shoc.tenants
    reader.execute("SELECT 1 FROM shoc.tenants LIMIT 1")
    pauses: list[float] = []

    def pause(seconds: float) -> None:
        pauses.append(seconds)
        reader.rollback()  # the reader finishes while the migration waits to retry

    monkeypatch.setattr(migrate, "time", SimpleNamespace(sleep=pause))
    try:
        assert migrate.migrate(conn) == ["999_lock_test"]
        assert len(pauses) == 1
    finally:
        reader.close()
        execute(conn, "DELETE FROM shoc.schema_migrations WHERE version = '999_lock_test'")


def test_a_migration_that_never_gets_its_lock_fails(conn, config, migrations, monkeypatch):
    import psycopg

    (migrations / "999_lock_test.sql").write_text(
        "LOCK TABLE shoc.tenants IN ACCESS EXCLUSIVE MODE;\n"
    )
    monkeypatch.setattr(migrate, "LOCK_TIMEOUT", "100ms")
    monkeypatch.setattr(migrate, "time", SimpleNamespace(sleep=lambda s: None))
    reader = psycopg.connect(config.dsn)
    reader.execute("SELECT 1 FROM shoc.tenants LIMIT 1")
    try:
        with pytest.raises(psycopg.errors.LockNotAvailable):
            migrate.migrate(conn)
        assert not fetch_one(
            conn, "SELECT 1 AS yes FROM shoc.schema_migrations WHERE version = '999_lock_test'"
        )
    finally:
        reader.close()
        execute(conn, "DELETE FROM shoc.schema_migrations WHERE version = '999_lock_test'")


# -- session limits (data-14) ---------------------------------------------------
def test_serve_and_worker_sessions_stop_waiting_on_locks(config):
    """A lock wait behind a migration or an open transaction never ended."""
    from shoc.db.pool import connect

    row = fetch_one(
        connect(config),
        """SELECT current_setting('lock_timeout') AS lock,
                  current_setting('idle_in_transaction_session_timeout') AS idle,
                  current_setting('statement_timeout') AS statement""",
    )
    assert row and "0" not in (row["lock"], row["idle"], row["statement"])
