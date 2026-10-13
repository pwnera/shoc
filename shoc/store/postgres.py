"""Postgres event store (STO-2): schema per tenant, monthly partitions, COPY loading."""

from __future__ import annotations

import gzip
import json
import logging
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

log = logging.getLogger("shoc.store.postgres")


def _x(cur: psycopg.Cursor[DictRow], sql: str, params: Params = None) -> None:
    """Execute SQL this module assembled from its own identifiers (see `pool.q`)."""
    cur.execute(q(sql), params)


_PG_TYPES = {"TEXT": "text", "TIMESTAMPTZ": "timestamptz", "INTEGER": "integer", "JSON": "jsonb"}

# Past this many events, health reports the planner's row estimate instead of a count.
ESTIMATE_FROM = 1_000_000

# Creating or dropping a partition locks the whole events table. Past this wait
# the DDL gives up rather than queue every read and load behind it. A drop is
# tried again by the next daily run; a month whose rows then went to the default
# partition stays there (STO-2).
LOCK_TIMEOUT = "5s"

# What Postgres refuses in one row: NUL in text, a bad escape in jsonb, a lone
# surrogate the client cannot encode.
_REFUSED_ROW = (psycopg.DataError, UnicodeEncodeError)


def _month_start(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_month(ts: datetime) -> datetime:
    return _month_start(ts + timedelta(days=32))


def _partition_month(name: str) -> datetime | None:
    """The month a monthly partition (`ocsf_events_202610`) holds; None for any other table."""
    stamp = name.rsplit("_", 1)[-1]
    if len(stamp) != 6 or not stamp.isdigit():
        return None
    return datetime(int(stamp[:4]), int(stamp[4:]), 1, tzinfo=UTC)


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
                # A time bound without an offset, and DATE_TRUNC over timestamptz,
                # follow the session's zone; the warehouses answer in UTC (STO-1).
                _x(cur, "SET TIME ZONE 'UTC'")
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
                # Rules and events.query compare api_operation through lower(),
                # so this index cost every insert and served no rule or search.
                f'DROP INDEX IF EXISTS "{self.schema}".ocsf_api',
                f'CREATE INDEX IF NOT EXISTS ocsf_src ON "{self.schema}".{ocsf.EVENTS_TABLE} (src_endpoint_ip, time DESC)',
                # Each detection cycle reads what was ingested since the last one (DET-3).
                f'CREATE INDEX IF NOT EXISTS ocsf_ingested ON "{self.schema}".{ocsf.EVENTS_TABLE} (ingested_at)',
            ):
                _x(cur, stmt)

    def migrate(self) -> None:
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
        with self.conn.cursor() as cur:
            # A load put this month's rows in the default partition when it could
            # not make the month's own. CREATE would then scan them under the
            # table lock and fail, on every later load, so the month stays there.
            _x(
                cur,
                f"""SELECT 1 FROM "{self.schema}".{ocsf.EVENTS_TABLE}_default
                    WHERE time >= %s AND time < %s LIMIT 1""",
                (start, end),
            )
            if cur.fetchone():
                return
        # Partition bounds cannot be bound parameters; both values come from a
        # datetime we computed, never from user input.
        self._partition_ddl(
            f"""CREATE TABLE IF NOT EXISTS "{self.schema}".{name}
                PARTITION OF "{self.schema}".{ocsf.EVENTS_TABLE}
                FOR VALUES FROM ('{start:%Y-%m-%d %H:%M:%S%z}') TO ('{end:%Y-%m-%d %H:%M:%S%z}')"""
        )

    def _partition_ddl(self, sql: str) -> None:
        """Run DDL that locks the events table, waiting at most LOCK_TIMEOUT for the lock."""
        with self.conn.transaction(), self.conn.cursor() as cur:
            _x(cur, f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
            _x(cur, sql)

    def _months(self) -> list[datetime]:
        """The months that have their own partition."""
        with self.conn.cursor() as cur:
            _x(
                cur,
                """SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                   WHERE i.inhparent = %s::regclass""",
                (f'"{self.schema}".{ocsf.EVENTS_TABLE}',),
            )
            names = [str(r["name"]) for r in cur.fetchall()]
        return [m for m in map(_partition_month, names) if m is not None]

    # -- load -----------------------------------------------------------
    def load_batch(self, path: str) -> LoadStats:
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
            return LoadStats()
        months = {_month_start(_parse_ts(r["time"])) for r in rows}
        have = self._months()
        for m in sorted(months - set(have)):
            if have and m < min(have):
                # Retention dropped this month, or it is older than every month
                # kept. Its rows go to the default partition, which retention's
                # DELETE reaches, rather than re-make a partition under the table
                # lock for the next daily run to drop (STO-2).
                continue
            try:
                self.ensure_partition(m)
            except (psycopg.Error, OverflowError) as exc:
                # The table was busy, or the month cannot be a partition: its rows
                # go to the default partition rather than fail the load.
                log.warning("no partition for %s, loading into the default: %s", m, exc)
        inserted, refused = self._insert_storable(rows)
        if len(refused) * 2 > len(rows):
            # Most rows refused is a mapping or schema fault, not one odd record:
            # fail the load, so the source shows as failing and its cursor waits.
            raise refused[0][1]
        for r, exc in refused:
            # One row Postgres refuses held the source's cursor at that page for
            # good, so it is left out and the rest load (ING-1, STO-2). The batch
            # file is deleted whether or not the load succeeds: this line, and
            # the source's count of rows left out, are the only record of the row.
            log.warning("left out event %s, which Postgres refused: %s", r.get("event_uid"), exc)
        return LoadStats(
            rows=inserted,
            bytes=nbytes,
            duration_ms=int((time.monotonic() - started) * 1000),
            skipped=len(refused),
        )

    def _insert_storable(
        self, rows: list[dict[str, Any]]
    ) -> tuple[int, list[tuple[dict[str, Any], Exception]]]:
        """Insert `rows`; on a refusal, halve and retry, so only refused rows stay out.

        Returns the rows inserted and each refused row with its error.
        """
        try:
            return self._insert(rows), []
        except _REFUSED_ROW as exc:
            if len(rows) == 1:
                return 0, [(rows[0], exc)]
        half = len(rows) // 2
        first, refused = self._insert_storable(rows[:half])
        second, more = self._insert_storable(rows[half:])
        return first + second, refused + more

    def _insert(self, rows: list[dict[str, Any]]) -> int:
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
            return cur.rowcount

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
        """Drop whole partitions older than the policy — cheaper than DELETE.

        Run daily, it also creates this month's and next month's partitions, so
        the first load of a month does not have to lock the table for one.
        """
        now = datetime.now(UTC)
        cutoff = _month_start(now - timedelta(days=policy.days))
        for month in (now, _next_month(_month_start(now))):
            try:
                self.ensure_partition(month)
            except psycopg.Error as exc:
                log.warning("could not create the partition for %s ahead: %s", month, exc)
        dropped = 0
        with self.conn.cursor() as cur:
            # Any year, so a partition a 1970 event made is dropped too.
            _x(
                cur,
                """SELECT c.relname AS name
                   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relname LIKE %s""",
                (self.schema, f"{ocsf.EVENTS_TABLE}_%"),
            )
            for row in cur.fetchall():
                part = _partition_month(row["name"])
                if part is not None and part < cutoff:
                    try:
                        self._partition_ddl(f'DROP TABLE "{self.schema}"."{row["name"]}"')
                    except psycopg.errors.LockNotAvailable:
                        continue  # busy now; tomorrow's run drops it
                    dropped += 1
            # Rows a load put in the default partition when it could not create
            # their month's.
            _x(
                cur,
                f'DELETE FROM "{self.schema}"."{ocsf.EVENTS_TABLE}_default" WHERE time < %s',
                (cutoff,),
            )
            # The contract counts rows or partitions removed (EventStore.apply_retention).
            dropped += max(cur.rowcount, 0)
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
