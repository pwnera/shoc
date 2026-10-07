"""Migrations are forward-only, idempotent, and produce the same schema every time."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg.rows import DictRow, dict_row

from shoc.db.migrate import MIGRATIONS_DIR, migrate, pending
from shoc.db.pool import ALL_TENANTS, Conn, fetch_all, q, set_tenant

pytestmark = pytest.mark.postgres

FORBIDDEN = ("drop table ", "drop column ", "drop schema shoc")


def test_migrations_are_numbered_and_ordered():
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    assert files, "there are migrations"
    numbers = [int(p.stem.split("_", 1)[0]) for p in files]
    assert numbers == sorted(numbers) == list(range(1, len(files) + 1)), (
        "migrations are numbered 001, 002, … with no gaps"
    )


def test_no_migration_destroys_data():
    """Forward-only means forward-only: nothing drops a table or a column."""
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        body = path.read_text().lower()
        for clause in FORBIDDEN:
            assert clause not in body, f"{path.name} contains '{clause.strip()}'"


def test_applying_them_twice_changes_nothing(conn):
    set_tenant(conn, ALL_TENANTS)
    migrate(conn)
    assert pending(conn) == [], "everything is applied"
    assert migrate(conn) == [], "a second run is a no-op"


def _columns(conn: Conn, schema: str = "shoc") -> set[tuple[str, str, str]]:
    return {
        (r["table_name"], r["column_name"], r["data_type"])
        for r in fetch_all(
            conn,
            """SELECT table_name, column_name, data_type FROM information_schema.columns
               WHERE table_schema = %s""",
            (schema,),
        )
    }


def test_a_fresh_database_ends_up_with_the_same_schema(config, conn):
    """An install today and an install that upgraded through every version must match."""
    database = f"shoc_migrate_{uuid.uuid4().hex[:8]}"
    admin: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
        config.dsn, row_factory=dict_row, autocommit=True
    )
    try:
        with admin.cursor() as cur:
            cur.execute(q(f'CREATE DATABASE "{database}"'))
        fresh: psycopg.Connection[DictRow] = psycopg.Connection[DictRow].connect(
            config.dsn.rsplit("/", 1)[0] + f"/{database}", row_factory=dict_row, autocommit=True
        )
        try:
            applied = migrate(fresh)
            assert len(applied) == len(list(MIGRATIONS_DIR.glob("*.sql")))
            assert _columns(fresh) == _columns(conn), (
                "a fresh install and an upgraded one disagree about the schema"
            )
        finally:
            fresh.close()
    finally:
        with admin.cursor() as cur:
            cur.execute(q(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        admin.close()


def test_row_level_security_is_on_for_every_tenant_table(conn):
    rows = fetch_all(
        conn,
        """SELECT c.relname AS table, c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'shoc' AND c.relkind = 'r'""",
    )
    with_tenant = {
        r["table_name"]
        for r in fetch_all(
            conn,
            """SELECT table_name FROM information_schema.columns
               WHERE table_schema = 'shoc' AND column_name = 'tenant_id'""",
        )
    }
    for row in rows:
        if row["table"] in with_tenant:
            assert row["enabled"] and row["forced"], f"{row['table']} has no forced RLS"
