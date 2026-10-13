"""One small connection helper. No ORM, no pool library (decision D6)."""

from __future__ import annotations

import os
import socket
import threading
from collections.abc import Mapping, Sequence
from typing import Any, LiteralString, cast

import psycopg
from psycopg.rows import DictRow, dict_row

from shoc.config import Config
from shoc.errors import ConfigError

type Params = Sequence[Any] | Mapping[str, Any] | None
type Conn = psycopg.Connection[DictRow]

_local = threading.local()

# Every session this process opens is named after it, so a job whose worker has
# no session left can be put back at once (`jobs.requeue_stale`). A restarted
# container keeps its hostname and runs shoc as PID 1 again, so the random part
# keeps the new process from passing for the one that died. Postgres cuts an
# application_name at 63 bytes, hence the short hostname.
PROCESS = f"{socket.gethostname()[:40]}:{os.getpid()}:{os.urandom(4).hex()}"


def q(text: str) -> LiteralString:
    """Mark assembled SQL as trusted.

    Type checkers require a `LiteralString` so that user input can never become
    SQL. Everything we interpolate is an identifier we control — a tenant schema
    name or a column list from `shoc.store.ocsf` — and every value is bound as a
    parameter, so the cast holds. Never pass caller-supplied text through here.
    """
    return cast(LiteralString, text)


def limit(conn: Conn, cfg: Config) -> Conn:
    """Set the session limits of every serve and worker connection (data-14).

    Without them a query queued behind a migration's ALTER, or behind a
    transaction left open, waited until the watchdog killed the whole worker
    half an hour later. A lock wait gives up after 10 s and fails its job or
    request. A transaction left idle is ended after 5 minutes, which still
    covers a vendor check or a mail sent inside an audited one. Migrations
    connect as the owner and take none of these. Set after connecting, not as
    the libpq `options` parameter, which would replace any `options` in the DSN
    and which PgBouncer refuses.
    """
    execute(
        conn,
        """SELECT set_config('statement_timeout', %s, false),
                  set_config('lock_timeout', '10s', false),
                  set_config('idle_in_transaction_session_timeout', '5min', false)""",
        (str(cfg.statement_timeout_seconds * 1000),),
    )
    return conn


def connect(config: Config | None = None) -> Conn:
    """Return this thread's connection, opening it on first use."""
    cfg = config or Config.load()
    conn = getattr(_local, "conn", None)
    if conn is not None and not conn.closed:
        return conn
    if not cfg.dsn:
        raise ConfigError("SHOC_DSN is not set")
    conn = limit(
        psycopg.Connection[DictRow].connect(
            cfg.dsn, row_factory=dict_row, autocommit=True, application_name=PROCESS
        ),
        cfg,
    )
    _local.conn = conn
    return conn


def connect_owner(config: Config | None = None) -> Conn:
    """A new connection as the schema owner, for `shoc migrate` and `shoc rotate-key` (RFC 0024)."""
    cfg = config or Config.load()
    if not (cfg.migrate_dsn or cfg.dsn):
        raise ConfigError("SHOC_DSN is not set")
    return psycopg.Connection[DictRow].connect(
        cfg.migrate_dsn or cfg.dsn, row_factory=dict_row, autocommit=True
    )


def owns_audit_log(conn: Conn) -> bool:
    """Whether this connection's role can disable the audit log's triggers (SEC-1)."""
    row = fetch_one(
        conn,
        """SELECT pg_has_role(current_user, c.relowner, 'USAGE') AS owns
           FROM pg_class c WHERE c.oid = to_regclass('shoc.audit_log')""",
    )
    return bool(row and row["owns"]) or is_superuser(conn)


def connect_readonly(config: Config | None = None) -> Conn | None:
    """This thread's connection as the read-only agent role, or None without one (D22)."""
    cfg = config or Config.load()
    if not cfg.readonly_dsn:
        return None
    conn = getattr(_local, "readonly", None)
    if conn is None or conn.closed:
        conn = limit(
            psycopg.Connection[DictRow].connect(
                cfg.readonly_dsn, row_factory=dict_row, autocommit=True, application_name=PROCESS
            ),
            cfg,
        )
        _local.readonly = conn
    return conn


ALL_TENANTS = "shoc:all"


def set_tenant(conn: Conn, tenant_id: str) -> None:
    """Scope this connection to one tenant, for row-level security (SEC-1).

    Every capability call sets this before the body runs, so a query that
    forgets its WHERE clause still cannot see another tenant. A session that
    never sets it sees no tenant rows (migration 026). Operational sessions
    (`shoc migrate`, a backup) pass `ALL_TENANTS`.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('shoc.tenant_id', %s, false)", (tenant_id,))


def current_tenant(conn: Conn) -> str:
    row = fetch_one(conn, "SELECT current_setting('shoc.tenant_id', true) AS tenant")
    return (row or {}).get("tenant") or ""


def is_superuser(conn: Conn) -> bool:
    """Superusers bypass row-level security, so shoc should not run as one (SEC-1)."""
    row = fetch_one(conn, "SELECT usesuper FROM pg_user WHERE usename = current_user")
    return bool(row and row["usesuper"])


def close() -> None:
    for name in ("conn", "readonly"):
        conn = getattr(_local, name, None)
        if conn is not None and not conn.closed:
            conn.close()
        setattr(_local, name, None)


def fetch_all(conn: Conn, sql: str, params: Params = None) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(q(sql), params)
        if cur.description is None:
            return []
        return list(cur.fetchall())


def fetch_one(conn: Conn, sql: str, params: Params = None) -> dict[str, Any] | None:
    rows = fetch_all(conn, sql, params)
    return rows[0] if rows else None


def execute(conn: Conn, sql: str, params: Params = None) -> int:
    with conn.cursor() as cur:
        cur.execute(q(sql), params)
        return cur.rowcount
