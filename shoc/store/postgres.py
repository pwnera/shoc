"""Postgres event store (STO-2): schema per tenant, monthly partitions, COPY loading."""

from __future__ import annotations

import gzip
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Json

from shoc.db.pool import Params, q
from shoc.errors import StoreError
from shoc.store import ocsf
from shoc.store.base import LoadStats, QueryResult, RetentionPolicy, StoreHealth
from shoc.store.sql import prepare


def _x(cur: psycopg.Cursor[DictRow], sql: str, params: Params = None) -> None:
    """Execute SQL this module assembled from its own identifiers (see `pool.q`)."""
    cur.execute(q(sql), params)


_PG_TYPES = {"TEXT": "text", "TIMESTAMPTZ": "timestamptz", "INTEGER": "integer", "JSON": "jsonb"}

# Past this many events, health reports the planner's row estimate instead of a count.
ESTIMATE_FROM = 1_000_000


def _month_start(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_month(ts: datetime) -> datetime:
    return _month_start(ts + timedelta(days=32))


class PostgresStore:
    dialect = "postgres"

    def __init__(
        self, dsn: str, tenant_id: str, schema: str, statement_timeout_seconds: int = 120
    ) -> None:
        self.dsn = dsn
        self.tenant_id = tenant_id
        self.schema = schema
        self.statement_timeout_seconds = statement_timeout_seconds
        self._conn: psycopg.Connection[DictRow] | None = None

    # -- connection -----------------------------------------------------
    @property
    def conn(self) -> psycopg.Connection[DictRow]:
        conn = self._conn
        if conn is None or conn.closed:
            conn = psycopg.Connection[DictRow].connect(
                self.dsn, row_factory=dict_row, autocommit=True
            )
            with conn.cursor() as cur:
                _x(cur, f'SET search_path TO "{self.schema}", public')
                # A rule that somehow becomes a cross join must not pin the
                # database for everybody else.
                if self.statement_timeout_seconds:
                    _x(cur, f"SET statement_timeout = {int(self.statement_timeout_seconds) * 1000}")
            self._conn = conn
        return conn

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None

    # -- schema ---------------------------------------------------------
    def create_tenant(self) -> None:
        cols = ",\n  ".join(f'"{name}" {_PG_TYPES[tp]}' for name, tp in ocsf.COLUMNS)
        with self.conn.cursor() as cur:
            _x(cur, f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
            _x(cur, f'SET search_path TO "{self.schema}", public')
            _x(
                cur,
                f"""CREATE TABLE IF NOT EXISTS "{self.schema}".{ocsf.EVENTS_TABLE} (
  {cols},
  PRIMARY KEY (event_uid, time)
) PARTITION BY RANGE (time)""",
            )
            _x(
                cur,
                f"""CREATE TABLE IF NOT EXISTS "{self.schema}".{ocsf.EVENTS_TABLE}_default
                    PARTITION OF "{self.schema}".{ocsf.EVENTS_TABLE} DEFAULT""",
            )
            for stmt in (
                f'CREATE INDEX IF NOT EXISTS ocsf_time ON "{self.schema}".{ocsf.EVENTS_TABLE} (time DESC)',
                f'CREATE INDEX IF NOT EXISTS ocsf_actor ON "{self.schema}".{ocsf.EVENTS_TABLE} (actor_user_name, time DESC)',
                f'CREATE INDEX IF NOT EXISTS ocsf_api ON "{self.schema}".{ocsf.EVENTS_TABLE} (api_operation, time DESC)',
                f'CREATE INDEX IF NOT EXISTS ocsf_src ON "{self.schema}".{ocsf.EVENTS_TABLE} (src_endpoint_ip, time DESC)',
                # Each detection cycle reads what was ingested since the last one (DET-3).
                f'CREATE INDEX IF NOT EXISTS ocsf_ingested ON "{self.schema}".{ocsf.EVENTS_TABLE} (ingested_at)',
            ):
                _x(cur, stmt)

    def migrate(self, ocsf_version: str = "1.3.0") -> None:
        """Add any column the current layout has and this tenant lacks."""
        self.create_tenant()
        with self.conn.cursor() as cur:
            _x(
                cur,
                """SELECT column_name FROM information_schema.columns
                   WHERE table_schema = %s AND table_name = %s""",
                (self.schema, ocsf.EVENTS_TABLE),
            )
            have = {r["column_name"] for r in cur.fetchall()}
            for name, tp in ocsf.COLUMNS:
                if name not in have:
                    _x(
                        cur,
                        f'ALTER TABLE "{self.schema}".{ocsf.EVENTS_TABLE} '
                        f'ADD COLUMN "{name}" {_PG_TYPES[tp]}',
                    )

    def ensure_partition(self, ts: datetime) -> None:
        start = _month_start(ts)
        end = _next_month(start)
        name = f"{ocsf.EVENTS_TABLE}_{start:%Y%m}"
        # Partition bounds cannot be bound parameters; both values come from a
        # datetime we computed, never from user input.
        with self.conn.cursor() as cur:
            _x(
                cur,
                f"""CREATE TABLE IF NOT EXISTS "{self.schema}".{name}
                    PARTITION OF "{self.schema}".{ocsf.EVENTS_TABLE}
                    FOR VALUES FROM ('{start:%Y-%m-%d %H:%M:%S%z}') TO ('{end:%Y-%m-%d %H:%M:%S%z}')""",
            )

    # -- load -----------------------------------------------------------
    def load_batch(self, path: str, table: str = ocsf.EVENTS_TABLE) -> LoadStats:
        """COPY a gzipped NDJSON batch in, ignoring event_uids already stored."""
        opener = gzip.open if str(path).endswith(".gz") else open
        started = time.monotonic()
        rows: list[dict[str, Any]] = []
        nbytes = 0
        with opener(path, "rt") as fh:  # type: ignore[operator]
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                nbytes += len(line)
                rows.append(json.loads(line))
        if not rows:
            return LoadStats(table=table)
        months = {_month_start(_parse_ts(r["time"])) for r in rows}
        for m in months:
            self.ensure_partition(m)
        cols = ocsf.COLUMN_NAMES
        collist = ", ".join(f'"{c}"' for c in cols)
        # COPY into a staging table, then insert once: duplicate event_uids from an
        # overlapping cursor window are dropped instead of failing the batch.
        staging = f"_stage_{int(time.time() * 1000)}"
        with self.conn.transaction(), self.conn.cursor() as cur:
            _x(
                cur,
                f'CREATE TEMP TABLE {staging} (LIKE "{self.schema}".{ocsf.EVENTS_TABLE}) ON COMMIT DROP',
            )
            with cur.copy(q(f"COPY {staging} ({collist}) FROM STDIN")) as copy:
                for r in rows:
                    copy.write_row(tuple(_pg_value(c, r.get(c)) for c in cols))
            _x(
                cur,
                f"""INSERT INTO "{self.schema}".{ocsf.EVENTS_TABLE} ({collist})
                    SELECT {collist} FROM {staging}
                    ON CONFLICT (event_uid, time) DO NOTHING""",
            )
            inserted = cur.rowcount
        return LoadStats(
            rows=inserted,
            bytes=nbytes,
            duration_ms=int((time.monotonic() - started) * 1000),
            table=table,
        )

    # -- read -----------------------------------------------------------
    def query(
        self, canonical_sql: str, params: dict[str, Any] | None = None, limit: int = 1000
    ) -> QueryResult:
        sql, args = prepare(canonical_sql, params, self.dialect, limit + 1)
        started = time.monotonic()
        try:
            with self.conn.cursor() as cur:
                _x(cur, sql, args)
                rows = list(cur.fetchmany(limit + 1)) if cur.description else []
        except psycopg.errors.UndefinedTable as exc:
            # Almost always one thing: the role cannot see the tenant schema.
            # The read-only role agents use needs a grant per tenant, and
            # without it every rule fails with an error about a missing table.
            raise StoreError(
                f"{ocsf.EVENTS_TABLE} is not visible to this database role in schema "
                f"'{self.schema}'. If agents are on SHOC_READONLY_DSN, run "
                f"`shoc grant-readonly` — it must be run again after a tenant is added. "
                f"({exc})"
            ) from exc
        except psycopg.Error as exc:
            raise StoreError(f"query failed: {exc}") from exc
        truncated = len(rows) > limit
        return QueryResult(
            rows=rows[:limit],
            sql=sql,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

    # -- housekeeping ---------------------------------------------------
    def apply_retention(self, policy: RetentionPolicy) -> int:
        """Drop whole partitions older than the policy — cheaper than DELETE."""
        cutoff = _month_start(datetime.now(UTC) - timedelta(days=policy.days))
        dropped = 0
        with self.conn.cursor() as cur:
            _x(
                cur,
                """SELECT c.relname AS name
                   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relname LIKE %s""",
                (self.schema, f"{policy.table}_2%"),
            )
            for row in cur.fetchall():
                stamp = row["name"].rsplit("_", 1)[-1]
                if len(stamp) != 6 or not stamp.isdigit():
                    continue
                part = datetime(int(stamp[:4]), int(stamp[4:]), 1, tzinfo=UTC)
                if part < cutoff:
                    _x(cur, f'DROP TABLE "{self.schema}"."{row["name"]}"')
                    dropped += 1
        return dropped

    def reset(self) -> None:
        with self.conn.cursor() as cur:
            _x(cur, f'TRUNCATE TABLE "{self.schema}".{ocsf.EVENTS_TABLE}')

    def health(self) -> StoreHealth:
        started = time.monotonic()
        table = f'"{self.schema}".{ocsf.EVENTS_TABLE}'
        try:
            with self.conn.cursor() as cur:
                # count(*) reads every partition, and health is asked for often.
                # The planner's estimate is free; below ESTIMATE_FROM rows, or
                # before ANALYZE has run, an exact count is cheap enough.
                _x(
                    cur,
                    f"""SELECT COALESCE(sum(greatest(c.reltuples, 0)), 0)::bigint AS n,
                               (SELECT max(time) FROM {table}) AS latest
                        FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                        WHERE i.inhparent = %s::regclass""",
                    (table,),
                )
                row = cur.fetchone() or {"n": 0, "latest": None}
                if row["n"] < ESTIMATE_FROM:
                    _x(cur, f"SELECT count(*) AS n FROM {table}")
                    row = {**row, "n": (cur.fetchone() or {"n": 0})["n"]}
        except psycopg.Error as exc:
            return StoreHealth(ok=False, detail=str(exc))
        return StoreHealth(
            ok=True,
            event_count=int(row["n"]),
            latest_event=row["latest"],
            latency_ms=int((time.monotonic() - started) * 1000),
            detail=f"schema {self.schema}",
        )


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _pg_value(column: str, value: Any) -> Any:
    if column in ocsf.JSON_COLUMNS:
        return Json(value if value is not None else {})
    if column == "time" or column == "ingested_at":
        if value is None:
            return datetime.now(UTC) if column == "ingested_at" else None
        return _parse_ts(value)
    return value
