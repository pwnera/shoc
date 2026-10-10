"""Databricks SQL event store (STO-3).

Catalog per tenant, Delta tables with the same OCSF layout as every other
backend, and the warehouse-native load path: stage the NDJSON batch in a Unity
Catalog volume, insert the events the table lacks with one `MERGE` that reads
the staged file, then remove it. Nothing
warehouse-specific leaks into the core — rules still arrive as canonical SQL and
are translated here.

Install with the extra: `pip install "shoc[databricks]"`.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import ConfigError, StoreError
from shoc.ingest.batch import read_unique
from shoc.store import ocsf
from shoc.store.base import LoadStats, QueryResult, RetentionPolicy, StoreHealth
from shoc.store.sql import prepare, translate

log = logging.getLogger("shoc.store.databricks")

_DBX_TYPES = {
    "TEXT": "STRING",
    "TIMESTAMPTZ": "TIMESTAMP",
    "INTEGER": "INT",
    "JSON": "STRING",
}


def _utc(value: Any) -> Any:
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


@functools.cache
def _staging_dir() -> str:
    """One per process: a store is opened per request and per job, and a
    directory made per store was never removed (D162)."""
    return tempfile.mkdtemp(prefix="shoc-dbx-")


def _ddl_columns() -> str:
    return ",\n  ".join(f"`{name}` {_DBX_TYPES[tp]}" for name, tp in ocsf.COLUMNS)


class DatabricksStore:
    dialect = "databricks"

    def __init__(
        self,
        server_hostname: str,
        http_path: str,
        access_token: str,
        tenant_id: str,
        catalog: str,
        schema: str = "shoc",
        volume: str = "batches",
        reader: str = "",
        statement_timeout_seconds: float = 120,
    ) -> None:
        if not (server_hostname and http_path and access_token):
            raise ConfigError(
                "the databricks backend needs SHOC_DATABRICKS_HOST, SHOC_DATABRICKS_HTTP_PATH "
                "and SHOC_DATABRICKS_TOKEN"
            )
        self.server_hostname = server_hostname
        self.http_path = http_path
        self.access_token = access_token
        self.tenant_id = tenant_id
        self.catalog = catalog
        self.schema = schema
        self.volume = volume
        # The principal agents read as, granted USE and SELECT per catalog (SEC-1).
        self.reader = reader
        self.statement_timeout_seconds = statement_timeout_seconds
        self._conn: Any = None
        self._staging_dir = _staging_dir()

    # -- connection -----------------------------------------------------
    @property
    def conn(self) -> Any:
        if self._conn is None:
            try:
                # The extra is optional, so the import lives here and the type
                # checker cannot see it without it installed.
                from databricks import sql as dbsql  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise ConfigError(
                    'the databricks backend needs the extra: pip install "shoc[databricks]"'
                ) from exc
            self._conn = dbsql.connect(
                server_hostname=self.server_hostname,
                http_path=self.http_path,
                access_token=self.access_token,
                staging_allowed_local_path=self._staging_dir,
                session_configuration={"timezone": "UTC"},
            )
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = None

    def _execute(self, sql: str, params: Any = None) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            # The connector polls a statement until the warehouse answers, and
            # one that ran out of compute never does: it held the worker for 30
            # minutes. The deadline counts queueing and warehouse start too.
            deadline = threading.Timer(
                self.statement_timeout_seconds or threading.TIMEOUT_MAX, cur.cancel
            )
            deadline.start()
            try:
                cur.execute(sql, params or None)
            finally:
                deadline.cancel()
            if cur.description is None:
                return []
            names = [d[0] for d in cur.description]
            # TIMESTAMP comes back naive, in the session's zone, pinned to UTC
            # above; every other backend returns it aware.
            return [
                {n: _utc(v) for n, v in zip(names, row, strict=False)} for row in cur.fetchall()
            ]

    @property
    def table(self) -> str:
        return f"`{self.catalog}`.`{self.schema}`.{ocsf.EVENTS_TABLE}"

    @property
    def volume_path(self) -> str:
        return f"/Volumes/{self.catalog}/{self.schema}/{self.volume}"

    # -- schema ---------------------------------------------------------
    def create_tenant(self) -> None:
        self._execute(f"CREATE CATALOG IF NOT EXISTS `{self.catalog}`")
        self._execute(f"CREATE SCHEMA IF NOT EXISTS `{self.catalog}`.`{self.schema}`")
        self._execute(
            f"CREATE VOLUME IF NOT EXISTS `{self.catalog}`.`{self.schema}`.`{self.volume}`"
        )
        # Delta partitions by columns only, never by an expression such as
        # DATE(time); liquid clustering on `time` prunes by time without one.
        self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.table} (
  {_ddl_columns()}
) USING DELTA
  CLUSTER BY (`time`)"""
        )
        if self.reader:
            self._execute(f"GRANT USE CATALOG ON CATALOG `{self.catalog}` TO `{self.reader}`")
            self._execute(
                f"GRANT USE SCHEMA, SELECT ON SCHEMA `{self.catalog}`.`{self.schema}` "
                f"TO `{self.reader}`"
            )

    def migrate(self, ocsf_version: str = "1.3.0") -> None:
        self.create_tenant()
        have = {row["col_name"] for row in self._execute(f"DESCRIBE TABLE {self.table}")}
        missing = [(n, t) for n, t in ocsf.COLUMNS if n not in have]
        if missing:
            columns = ", ".join(f"`{n}` {_DBX_TYPES[t]}" for n, t in missing)
            self._execute(f"ALTER TABLE {self.table} ADD COLUMNS ({columns})")
        # A detection cycle selects rows by `ingested_at` (DET-3). Delta keeps
        # file statistics for the first 32 columns only, and that one is not
        # among them, so without this every cycle reads the whole table.
        stats = ",".join(n for n, t in ocsf.COLUMNS if t != "JSON")
        self._execute(
            f"ALTER TABLE {self.table} SET TBLPROPERTIES "
            f"('delta.dataSkippingStatsColumns' = '{stats}')"
        )

    # -- load -----------------------------------------------------------
    def load_batch(self, path: str, table: str = ocsf.EVENTS_TABLE) -> LoadStats:
        """Stage the batch in a UC volume and MERGE in the events the table lacks.

        Delta has no primary key. An insert-only MERGE on (event_uid, time)
        skips an event already stored, so a replay adds nothing and keeps what
        it repeats; a repeat inside the batch is dropped here first, because
        MERGE inserts every source row that matches nothing.
        """
        started = time.monotonic()
        rows = read_unique(path)
        if not rows:
            return LoadStats(table=table)

        # JSON columns are stored as strings so the layout matches every other
        # backend; every field is read as a string and cast in the MERGE.
        name = f"batch-{int(time.time() * 1000)}-{os.getpid()}-{threading.get_ident()}.ndjson"
        local = os.path.join(self._staging_dir, name)
        nbytes = 0
        with open(local, "w") as out:
            for row in rows:
                for column in ocsf.JSON_COLUMNS:
                    if row.get(column) is not None and not isinstance(row[column], str):
                        row[column] = json.dumps(row[column], default=str)
                text = json.dumps(row, default=str)
                nbytes += len(text)
                out.write(text + "\n")
        times = [datetime.fromisoformat(str(row["time"])) for row in rows]

        remote = f"{self.volume_path}/{name}"
        staged = False
        try:
            self._execute(f"PUT '{local}' INTO '{remote}' OVERWRITE")
            staged = True
            merged = self._execute(
                _merge_sql(self.table, remote),
                [min(times).isoformat(), max(times).isoformat()],
            )
            loaded = _affected(merged, "num_inserted_rows")
        except Exception as exc:  # the batch file stays on disk for a replay
            raise StoreError(f"databricks load failed: {exc}") from exc
        finally:
            os.unlink(local) if os.path.exists(local) else None
            if staged:
                self._remove(remote)
        return LoadStats(
            rows=loaded,
            bytes=nbytes,
            duration_ms=int((time.monotonic() - started) * 1000),
            table=table,
        )

    def _remove(self, remote: str) -> None:
        """Loaded or not, the staged copy is spent: a replay stages the batch again."""
        try:
            self._execute(f"REMOVE '{remote}'")
        except Exception as exc:
            log.warning("could not remove %s from the volume: %s", remote, exc)

    # -- read -----------------------------------------------------------
    def query(
        self, canonical_sql: str, params: dict[str, Any] | None = None, limit: int = 1000
    ) -> QueryResult:
        sql, args = prepare(self._qualify(canonical_sql), params, self.dialect, limit + 1)
        started = time.monotonic()
        try:
            rows = self._execute(sql, args)
        except Exception as exc:
            raise StoreError(f"query failed: {exc}") from exc
        truncated = len(rows) > limit
        return QueryResult(
            rows=rows[:limit],
            sql=sql,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

    def _qualify(self, canonical_sql: str) -> str:
        """Canonical SQL names bare tables; Databricks needs catalog.schema.

        Quoted the canonical way: SQLGlot writes the backticks when it translates.
        """
        return canonical_sql.replace(
            ocsf.EVENTS_TABLE, f'"{self.catalog}"."{self.schema}".{ocsf.EVENTS_TABLE}'
        )

    # -- housekeeping ---------------------------------------------------
    def apply_retention(self, policy: RetentionPolicy) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=policy.days)
        return _affected(
            self._execute(
                f"DELETE FROM {self.table} WHERE tenant_id = ? AND time < ?",
                [self.tenant_id, cutoff],
            ),
            "num_affected_rows",
        )

    def reset(self) -> None:
        self._execute(f"DELETE FROM {self.table} WHERE tenant_id = ?", [self.tenant_id])

    def health(self) -> StoreHealth:
        started = time.monotonic()
        try:
            rows = self._execute(
                f"SELECT count(*) AS n, max(time) AS latest FROM {self.table} WHERE tenant_id = ?",
                [self.tenant_id],
            )
        except Exception as exc:
            return StoreHealth(dialect=self.dialect, ok=False, detail=str(exc))
        row = rows[0] if rows else {"n": 0, "latest": None}
        return StoreHealth(
            dialect=self.dialect,
            ok=True,
            event_count=int(row["n"] or 0),
            latest_event=row["latest"],
            latency_ms=int((time.monotonic() - started) * 1000),
            detail=f"catalog {self.catalog}",
        )


def _merge_sql(table: str, staged: str) -> str:
    """Insert the staged file's events the table lacks. The two parameters
    bound the target's `time`, so only the batch's range is read."""
    schema = ", ".join(f"`{name}` STRING" for name, _ in ocsf.COLUMNS)
    columns = ", ".join(
        f"`{name}`"
        if _DBX_TYPES[tp] == "STRING"
        else f"CAST(`{name}` AS {_DBX_TYPES[tp]}) AS `{name}`"
        for name, tp in ocsf.COLUMNS
    )
    return f"""MERGE INTO {table} AS t
USING (SELECT {columns}
       FROM read_files('{staged}', format => 'json', schema => '{schema}')) AS s
ON t.tenant_id = s.tenant_id AND t.event_uid = s.event_uid AND t.time = s.time
   AND t.time >= ? AND t.time <= ?
WHEN NOT MATCHED THEN INSERT *"""


def _affected(rows: list[dict[str, Any]], column: str) -> int:
    """The row count a DML statement reports in its one-row result."""
    return int((rows[0].get(column) if rows else 0) or 0)


def translate_for_databricks(canonical_sql: str) -> str:
    """Exposed for tests: what a rule's SQL becomes on this backend."""
    return translate(canonical_sql, "databricks")
