"""Snowflake event store (STO-4).

Database per tenant, the same OCSF layout as every other backend, and the
warehouse-native load path: PUT the NDJSON batch to an internal stage, COPY
INTO a temporary table, then MERGE in the events the table lacks. As with Databricks, nothing Snowflake-specific leaks into the core —
rules arrive as canonical SQL and are translated here.

Install with the extra: `pip install "shoc[snowflake]"`.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import tempfile
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import ConfigError, StoreError
from shoc.ingest.batch import batch_name, orphaned, read_unique
from shoc.store import ocsf
from shoc.store.base import LoadStats, QueryResult, RetentionPolicy, StoreHealth
from shoc.store.sql import prepare

log = logging.getLogger("shoc.store.snowflake")

_SF_TYPES = {
    "TEXT": "STRING",
    "TIMESTAMPTZ": "TIMESTAMP_TZ",
    "INTEGER": "NUMBER(38,0)",
    "JSON": "VARIANT",
}


def _ddl_columns() -> str:
    return ",\n  ".join(f'"{name.upper()}" {_SF_TYPES[tp]}' for name, tp in ocsf.COLUMNS)


@functools.cache
def _staging_dir() -> str:
    """One per process, as for Databricks (D162): a store is opened per request
    and per job, and a directory made per store was never removed."""
    return tempfile.mkdtemp(prefix="shoc-sf-")


class SnowflakeStore:
    dialect = "snowflake"

    def __init__(
        self,
        account: str,
        user: str,
        password: str,
        warehouse: str,
        tenant_id: str,
        database: str,
        schema: str = "SHOC",
        role: str = "",
        private_key: str = "",
        reader: str = "",
        statement_timeout_seconds: int = 120,
    ) -> None:
        if not (account and user and (password or private_key) and warehouse):
            raise ConfigError(
                "the snowflake backend needs SHOC_SNOWFLAKE_ACCOUNT, _USER, _WAREHOUSE and "
                "either _PASSWORD or _PRIVATE_KEY"
            )
        self.account = account
        self.user = user
        self.password = password
        self.private_key = private_key
        self.warehouse = warehouse
        self.role = role
        # The role agents read as, granted USAGE and SELECT per database (SEC-1).
        self.reader = reader
        self.tenant_id = tenant_id
        self.database = database.upper()
        self.schema = schema.upper()
        self.stage = "SHOC_BATCHES"
        self.statement_timeout_seconds = statement_timeout_seconds
        self._conn: Any = None
        self._staging_dir = _staging_dir()

    # -- connection -----------------------------------------------------
    @property
    def conn(self) -> Any:
        if self._conn is None:
            try:
                # The extra is optional, so the import lives here.
                import snowflake.connector as sf  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - depends on the extra
                raise ConfigError(
                    'the snowflake backend needs the extra: pip install "shoc[snowflake]"'
                ) from exc
            kwargs: dict[str, Any] = {
                "account": self.account,
                "user": self.user,
                "warehouse": self.warehouse,
                # Snowflake runs a statement for two days and queues one for
                # ever: a busy warehouse held the worker until its watchdog.
                "session_parameters": {
                    "STATEMENT_TIMEOUT_IN_SECONDS": int(self.statement_timeout_seconds),
                    "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS": int(self.statement_timeout_seconds),
                    "TIMEZONE": "UTC",
                },
            }
            if self.role:
                kwargs["role"] = self.role
            if self.private_key:
                kwargs["private_key"] = _der(self.private_key)
            else:
                kwargs["password"] = self.password
            self._conn = sf.connect(**kwargs)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = None

    def _execute(self, sql: str, params: Any = None) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        try:
            cur.execute(sql, params or None)
            if cur.description is None:
                return []
            names = [d[0].lower() for d in cur.description]
            return [dict(zip(names, row, strict=False)) for row in cur.fetchall()]
        finally:
            cur.close()

    @property
    def table(self) -> str:
        return f'"{self.database}"."{self.schema}".{ocsf.EVENTS_TABLE.upper()}'

    # -- schema ---------------------------------------------------------
    def create_tenant(self) -> None:
        self._execute(f'CREATE DATABASE IF NOT EXISTS "{self.database}"')
        self._execute(f'CREATE SCHEMA IF NOT EXISTS "{self.database}"."{self.schema}"')
        self._execute(
            f'CREATE STAGE IF NOT EXISTS "{self.database}"."{self.schema}".{self.stage} '
            "FILE_FORMAT = (TYPE = JSON)"
        )
        # No clustering key: one turns on reclustering billed as serverless
        # credits, and load order already keeps `ingested_at`, which a cycle
        # prunes on, close within each micro-partition (D64).
        self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.table} (
  {_ddl_columns()}
)"""
        )
        if self.reader:
            self._execute(f'GRANT USAGE ON DATABASE "{self.database}" TO ROLE "{self.reader}"')
            self._execute(
                f'GRANT USAGE ON SCHEMA "{self.database}"."{self.schema}" TO ROLE "{self.reader}"'
            )
            self._execute(f'GRANT SELECT ON TABLE {self.table} TO ROLE "{self.reader}"')

    def migrate(self) -> None:
        self.create_tenant()
        have = {
            str(row.get("column_name", "")).lower()
            # Qualified: the session names no database, and an unqualified
            # information_schema then fails.
            for row in self._execute(
                f'SELECT column_name FROM "{self.database}".information_schema.columns '
                "WHERE table_schema = %s AND table_name = %s",
                (self.schema, ocsf.EVENTS_TABLE.upper()),
            )
        }
        for name, tp in ocsf.COLUMNS:
            if name.lower() not in have:
                self._execute(
                    f'ALTER TABLE {self.table} ADD COLUMN "{name.upper()}" {_SF_TYPES[tp]}'
                )

    # -- load -----------------------------------------------------------
    def load_batch(self, path: str) -> LoadStats:
        """Stage the batch, COPY it into a temporary table, MERGE in what is new.

        Snowflake enforces no primary key. An insert-only MERGE on
        (event_uid, time) skips an event already stored, so a replay adds
        nothing and keeps what it repeats; a repeat inside the batch is
        dropped here first, because MERGE inserts every source row that
        matches nothing.
        """
        started = time.monotonic()
        rows = read_unique(path)
        if not rows:
            return LoadStats()

        # The stage is shared by every worker, so the name is unique to this load.
        name = f"{batch_name()}.ndjson"
        local = os.path.join(self._staging_dir, name)
        nbytes = 0
        with open(local, "w") as out:
            for row in rows:
                text = json.dumps(row, default=str)
                nbytes += len(text)
                out.write(text + "\n")
        times = [datetime.fromisoformat(str(row["time"])) for row in rows]
        names = [c for c, _ in ocsf.COLUMNS]
        columns = ", ".join(f'"{c.upper()}"' for c in names)
        selects = ", ".join(
            (f"$1:{c}::VARIANT" if c in ocsf.JSON_COLUMNS else f"$1:{c}::{_SF_TYPES[t]}")
            for c, t in ocsf.COLUMNS
        )
        stage_path = f'@"{self.database}"."{self.schema}".{self.stage}'
        loading = f'"{self.database}"."{self.schema}"."{name.replace("-", "_").replace(".", "_").upper()}"'
        staged = False
        try:
            self._execute(f"PUT 'file://{local}' {stage_path} AUTO_COMPRESS = TRUE")
            staged = True
            self._execute(f"CREATE TEMPORARY TABLE {loading} LIKE {self.table}")
            self._execute(
                f"""COPY INTO {loading} ({columns})
                    FROM (SELECT {selects} FROM {stage_path}/{name}.gz)
                    FILE_FORMAT = (TYPE = JSON)
                    ON_ERROR = ABORT_STATEMENT"""
            )
            merged = self._execute(
                f"""MERGE INTO {self.table} AS t USING {loading} AS s
                    ON t."TENANT_ID" = s."TENANT_ID" AND t."EVENT_UID" = s."EVENT_UID"
                       AND t."TIME" = s."TIME" AND t."TIME" >= %s AND t."TIME" <= %s
                    WHEN NOT MATCHED THEN INSERT ({columns})
                    VALUES ({", ".join(f's."{c.upper()}"' for c in names)})""",
                (min(times).isoformat(), max(times).isoformat()),
            )
            loaded = int((merged[0].get("number of rows inserted") if merged else 0) or 0)
        except Exception as exc:
            raise StoreError(f"snowflake load failed: {exc}") from exc
        finally:
            if os.path.exists(local):
                os.unlink(local)
            if staged:
                self._remove(f"{stage_path}/{name}.gz", loading)
        return LoadStats(
            rows=loaded,
            bytes=nbytes,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    def _remove(self, staged: str, loading: str) -> None:
        """Loaded or not, the staged copy is spent: a replay stages the batch again."""
        for sql in (f"REMOVE {staged}", f"DROP TABLE IF EXISTS {loading}"):
            try:
                self._execute(sql)
            except Exception as exc:
                log.warning("could not clean up after a load (%s): %s", sql, exc)

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
            rows=ocsf.decoded(rows[:limit]),
            sql=sql,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

    def _qualify(self, canonical_sql: str) -> str:
        return canonical_sql.replace(ocsf.EVENTS_TABLE, self.table)

    # -- housekeeping ---------------------------------------------------
    def apply_retention(self, policy: RetentionPolicy) -> int:
        self._sweep()
        cutoff = datetime.now(UTC) - timedelta(days=policy.days)
        return _deleted(
            self._execute(
                f'DELETE FROM {self.table} WHERE "TENANT_ID" = %s AND "TIME" < %s',
                (self.tenant_id, cutoff),
            )
        )

    def _sweep(self) -> None:
        """Remove the batches a killed load left on the stage, which retention never reads."""
        stage = f'@"{self.database}"."{self.schema}".{self.stage}'
        try:
            listed = self._execute(f"LIST {stage}")
            for name in orphaned(str(r.get("name") or "").rsplit("/", 1)[-1] for r in listed):
                self._execute(f"REMOVE {stage}/{name}")
        except Exception as exc:
            log.warning("could not sweep %s: %s", stage, exc)

    def reset(self) -> None:
        self._execute(f'DELETE FROM {self.table} WHERE "TENANT_ID" = %s', (self.tenant_id,))

    def health(self) -> StoreHealth:
        started = time.monotonic()
        try:
            rows = self._execute(
                f'SELECT count(*) AS n, max("TIME") AS latest FROM {self.table} '
                'WHERE "TENANT_ID" = %s',
                (self.tenant_id,),
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
            detail=f"database {self.database}",
        )


def _der(pem: str) -> bytes:
    """The connector takes a private key as DER bytes, and people hold PEM.

    A PEM kept on one line of an .env file has its newlines written `\\n`.
    """
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _deleted(rows: list[dict[str, Any]]) -> int:
    """The count a DELETE reports, in its one column "number of rows deleted"."""
    return int((rows[0].get("number of rows deleted") if rows else 0) or 0)
