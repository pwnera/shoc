"""Event-store reads Postgres keeps until a load can have changed them (STO-1, OPS-1, D161).

The console, the hourly Ops check, the reports and the Integrator ask the same
few questions of the last 30 days of events: how each source scores, which
operations each product sends, how many events the store holds. Each answer
was a statement, and on a warehouse every statement wakes compute that bills
by the minute and stays up ten minutes after: on 2026-10-10 one open console
tab and the hourly check kept the Databricks Free Edition warehouse up for
most of each hour.

Such a read is kept in `shoc.store_reads` with the Postgres time it began, and
answered from there until a load commits after it (`shoc.store_loads`) or it is
a day old. The detection cycle a load woke reads it again while the warehouse
is up anyway (`shoc/worker.py`), so a reader rarely wakes it.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

import psycopg

from shoc.db.pool import execute, fetch_one
from shoc.store.base import StoreHealth

# The oldest read kept for a reader, loads or not: a 30-day window slides, and
# retention deletes.
STALE = timedelta(days=1)
# The oldest store health kept: it says whether the store answers, which no
# load proves.
HEALTH = timedelta(hours=1)


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return {"$time": value.isoformat()}
    if isinstance(value, Decimal):
        return float(value)
    return str(value)


def _decode(obj: dict[str, Any]) -> Any:
    return datetime.fromisoformat(obj["$time"]) if obj.keys() == {"$time"} else obj


def _kept(conn: Any, tenant_id: str, name: str, oldest: timedelta) -> Any:
    row = fetch_one(
        conn,
        """SELECT r.value::text AS value FROM shoc.store_reads r
           WHERE r.tenant_id = %s AND r.name = %s AND r.read_at > now() - %s
             AND NOT EXISTS (SELECT 1 FROM shoc.store_loads l
                             WHERE l.tenant_id = r.tenant_id AND l.loaded_at >= r.read_at)""",
        (tenant_id, name, oldest),
    )
    return json.loads(row["value"], object_hook=_decode) if row else None


def _keep(conn: Any, tenant_id: str, name: str, began: datetime, value: Any) -> None:
    """Keep a read. An agent reads on the read-only role (D22), which keeps
    nothing: the worker's next reread does."""
    with contextlib.suppress(psycopg.errors.InsufficientPrivilege):
        execute(
            conn,
            """INSERT INTO shoc.store_reads (tenant_id, name, read_at, value)
               VALUES (%s, %s, %s, %s::jsonb)
               ON CONFLICT (tenant_id, name) DO UPDATE SET
                 read_at = EXCLUDED.read_at, value = EXCLUDED.value""",
            (tenant_id, name, began, json.dumps(value, default=_encode)),
        )


def _began(conn: Any) -> datetime:
    """Postgres's now, before the read: a load that commits during it is newer."""
    row = fetch_one(conn, "SELECT now() AS t")
    assert row
    return row["t"]


def rows(
    conn: Any,
    store: Any,
    tenant_id: str,
    name: str,
    sql: str,
    params: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    """`store.query(sql, params, limit).rows`, kept under `name` and the SQL
    text. A parameter that slides with the clock, such as `since`, is not part
    of the key, so `name` carries anything else the rows depend on."""
    key = f"{name}:{hashlib.sha256(sql.encode()).hexdigest()[:16]}"
    kept = _kept(conn, tenant_id, key, STALE)
    if kept is not None:
        return kept
    began = _began(conn)
    out = store.query(sql, params, limit).rows
    _keep(conn, tenant_id, key, began, out)
    return out


def health(conn: Any, store: Any, tenant_id: str) -> StoreHealth:
    """`store.health()`, kept for at most `HEALTH`. A failure is never kept,
    so the next reader asks again."""
    kept = _kept(conn, tenant_id, "health", HEALTH)
    if kept is not None:
        return StoreHealth(**kept)
    began = _began(conn)
    out = store.health()
    if out.ok:
        _keep(conn, tenant_id, "health", began, out.__dict__)
    return out
