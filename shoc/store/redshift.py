"""Amazon Redshift event store (STO-5).

Schema per tenant, the same OCSF layout as every other backend, and the
warehouse-native load path: PUT the NDJSON batch to an S3 prefix, COPY it into
a temporary table, insert the events the table lacks, then delete the object.
Redshift speaks the Postgres protocol, so `psycopg` connects to it and S3 is
one signed request: no extra and no AWS SDK.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import DictRow, dict_row

from shoc.db.pool import Params, q
from shoc.errors import ConfigError, StoreError
from shoc.ingest.batch import read_unique
from shoc.ingest.connectors import awssig
from shoc.store import ocsf
from shoc.store.base import LoadStats, QueryResult, RetentionPolicy, StoreHealth
from shoc.store.sql import prepare

log = logging.getLogger("shoc.store.redshift")

# Redshift's TEXT is VARCHAR(256). 65535 bytes is its widest VARCHAR; COPY
# truncates a longer value, and a JSON column cut short reads as NULL (sql.py).
_RS_TYPES = {
    "TEXT": "VARCHAR(65535)",
    "TIMESTAMPTZ": "TIMESTAMPTZ",
    "INTEGER": "INTEGER",
    "JSON": "VARCHAR(65535)",
}


def _ddl_columns() -> str:
    return ",\n  ".join(f'"{name}" {_RS_TYPES[tp]}' for name, tp in ocsf.COLUMNS)


class RedshiftStore:
    dialect = "redshift"

    def __init__(
        self,
        dsn: str,
        tenant_id: str,
        schema: str,
        stage: str = "",
        access_key: str = "",
        secret_key: str = "",
        region: str = "",
        iam_role: str = "default",
        reader: str = "",
        statement_timeout_seconds: int = 120,
    ) -> None:
        if not dsn:
            raise ConfigError("the redshift backend needs SHOC_REDSHIFT_DSN")
        self.dsn = dsn
        self.tenant_id = tenant_id
        self.schema = schema
        # s3://bucket/prefix, which the COPY role reads and shoc's key writes.
        self.stage = stage.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.iam_role = iam_role
        # The user agents read as, granted USAGE and SELECT per schema (SEC-1).
        self.reader = reader
        self.statement_timeout_seconds = statement_timeout_seconds
        self._conn: Any = None

    # -- connection -----------------------------------------------------
    @property
    def conn(self) -> Any:
        if self._conn is None or self._conn.closed:
            # Redshift has no server-side binding to speak of: the client cursor
            # merges parameters as psycopg2 did.
            conn = psycopg.Connection[DictRow].connect(
                self.dsn,
                row_factory=dict_row,
                autocommit=True,
                cursor_factory=psycopg.ClientCursor[DictRow],
            )
            with conn.cursor() as cur:
                cur.execute(q(f'SET search_path TO "{self.schema}"'))
                if self.statement_timeout_seconds:
                    cur.execute(
                        q(f"SET statement_timeout TO {int(self.statement_timeout_seconds) * 1000}")
                    )
            self._conn = conn
        return self._conn

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None

    def _execute(self, sql: str, params: Params = None) -> tuple[list[dict[str, Any]], int]:
        with self.conn.cursor() as cur:
            cur.execute(q(sql), params)
            rows = list(cur.fetchall()) if cur.description else []
            return rows, cur.rowcount

    @property
    def table(self) -> str:
        return f'"{self.schema}".{ocsf.EVENTS_TABLE}'

    # -- schema ---------------------------------------------------------
    def create_tenant(self) -> None:
        self._execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
        self._execute(
            f"""CREATE TABLE IF NOT EXISTS {self.table} (
  {_ddl_columns()}
) SORTKEY ("time")"""
        )
        if self.reader:
            self._execute(f'GRANT USAGE ON SCHEMA "{self.schema}" TO "{self.reader}"')
            self._execute(f'GRANT SELECT ON {self.table} TO "{self.reader}"')

    def migrate(self, ocsf_version: str = "1.3.0") -> None:
        self.create_tenant()
        rows, _ = self._execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s",
            (self.schema, ocsf.EVENTS_TABLE),
        )
        have = {r["column_name"] for r in rows}
        for name, tp in ocsf.COLUMNS:
            if name not in have:
                self._execute(f'ALTER TABLE {self.table} ADD COLUMN "{name}" {_RS_TYPES[tp]}')

    # -- load -----------------------------------------------------------
    def load_batch(self, path: str, table: str = ocsf.EVENTS_TABLE) -> LoadStats:
        """Stage the batch in S3, COPY it into a temporary table, insert what is new.

        Redshift enforces no primary key. The insert skips an event already
        stored by (event_uid, time), so a replay adds nothing; a repeat inside
        the batch is dropped here first.
        """
        if not (self.stage.startswith("s3://") and self.access_key and self.secret_key):
            raise ConfigError(
                "loading into redshift needs SHOC_REDSHIFT_STAGE (s3://bucket/prefix) and "
                "SHOC_REDSHIFT_AWS_ACCESS_KEY_ID and _SECRET_ACCESS_KEY"
            )
        started = time.monotonic()
        rows = read_unique(path)
        if not rows:
            return LoadStats(table=table)
        body = "".join(json.dumps(row, default=str) + "\n" for row in rows)
        times = [datetime.fromisoformat(str(row["time"])) for row in rows]
        name = f"batch-{int(time.time() * 1000)}-{os.getpid()}"
        bucket, _, prefix = self.stage.removeprefix("s3://").partition("/")
        key = "/".join(p for p in (prefix, self.schema, f"{name}.ndjson") if p)
        role = "default" if self.iam_role == "default" else f"'{self.iam_role}'"
        loading = name.replace("-", "_")
        staged = False
        try:
            self._s3("PUT", bucket, key, body)
            staged = True
            self._execute(f"CREATE TEMP TABLE {loading} (LIKE {self.table})")
            self._execute(
                f"COPY {loading} FROM 's3://{bucket}/{key}' IAM_ROLE {role} "
                f"FORMAT AS JSON 'auto' TIMEFORMAT 'auto' TRUNCATECOLUMNS"
                + (f" REGION '{self.region}'" if self.region else "")
            )
            columns = ", ".join(f'"{c}"' for c in ocsf.COLUMN_NAMES)
            _, loaded = self._execute(
                f"""INSERT INTO {self.table} ({columns})
                    SELECT {columns} FROM {loading} s
                    WHERE NOT EXISTS (
                      SELECT 1 FROM {self.table} t
                      WHERE t.tenant_id = s.tenant_id AND t.event_uid = s.event_uid
                        AND t."time" = s."time" AND t."time" BETWEEN %s AND %s)""",
                (min(times), max(times)),
            )
        except Exception as exc:
            raise StoreError(f"redshift load failed: {exc}") from exc
        finally:
            if staged:
                self._remove(bucket, key, loading)
        return LoadStats(
            rows=max(loaded, 0),
            bytes=len(body),
            duration_ms=int((time.monotonic() - started) * 1000),
            table=table,
        )

    def _s3(self, method: str, bucket: str, key: str, body: str = "") -> None:
        host = f"{bucket}.s3.{self.region or 'us-east-1'}.amazonaws.com"
        path = "/" + quote(key, safe="/")
        signed = awssig.headers(
            access_key=self.access_key,
            secret_key=self.secret_key,
            session_token=None,
            region=self.region or "us-east-1",
            service="s3",
            host=host,
            method=method,
            path=path,
            body=body,
            extra={"x-amz-content-sha256": hashlib.sha256(body.encode()).hexdigest()},
        )
        with httpx.Client(timeout=120.0) as http:
            resp = http.request(method, f"https://{host}{path}", headers=signed, content=body)
        if resp.status_code >= 300:
            raise StoreError(f"s3 {method} {key}: {resp.status_code} {resp.text[:300]}")

    def _remove(self, bucket: str, key: str, loading: str) -> None:
        """Loaded or not, the staged copy is spent: a replay stages the batch again."""
        try:
            self._execute(f"DROP TABLE IF EXISTS {loading}")
            self._s3("DELETE", bucket, key)
        except Exception as exc:
            log.warning("could not clean up after a load (%s): %s", key, exc)

    # -- read -----------------------------------------------------------
    def query(
        self, canonical_sql: str, params: dict[str, Any] | None = None, limit: int = 1000
    ) -> QueryResult:
        sql, args = prepare(canonical_sql, params, self.dialect)
        started = time.monotonic()
        try:
            with self.conn.cursor() as cur:
                cur.execute(q(sql), args)
                rows = list(cur.fetchmany(limit + 1)) if cur.description else []
        except psycopg.Error as exc:
            raise StoreError(f"query failed: {exc}") from exc
        return QueryResult(
            rows=rows[:limit],
            sql=sql,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=len(rows) > limit,
        )

    # -- housekeeping ---------------------------------------------------
    def apply_retention(self, policy: RetentionPolicy) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=policy.days)
        _, deleted = self._execute(
            f'DELETE FROM {self.table} WHERE tenant_id = %s AND "time" < %s',
            (self.tenant_id, cutoff),
        )
        return max(deleted, 0)

    def reset(self) -> None:
        self._execute(f"DELETE FROM {self.table} WHERE tenant_id = %s", (self.tenant_id,))

    def health(self) -> StoreHealth:
        started = time.monotonic()
        try:
            rows, _ = self._execute(
                f'SELECT count(*) AS n, max("time") AS latest FROM {self.table} '
                "WHERE tenant_id = %s",
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
            detail=f"schema {self.schema}",
        )


def reader_of(dsn: str) -> str:
    """The user a read-only DSN signs in as, which `migrate` grants SELECT to."""
    return str(conninfo_to_dict(dsn).get("user") or "") if dsn else ""
