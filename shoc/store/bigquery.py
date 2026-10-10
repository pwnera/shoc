"""Google BigQuery event store (STO-6).

Dataset per tenant, the same OCSF layout as every other backend, partitioned
by day, and the warehouse-native load path: a load job writes the NDJSON batch
to a staging table, one insert-only MERGE adds the events the table lacks, and
the staging table is dropped. It talks to the REST API with `httpx` and signs
in as a service account through `googleauth`, so it needs no Google SDK.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from shoc.errors import ConfigError, StoreError
from shoc.ingest.batch import read_unique
from shoc.ingest.connectors import googleauth
from shoc.store import ocsf
from shoc.store.base import LoadStats, QueryResult, RetentionPolicy, StoreHealth
from shoc.store.sql import prepare

API = "https://bigquery.googleapis.com/bigquery/v2"
UPLOAD = "https://bigquery.googleapis.com/upload/bigquery/v2"
SCOPE = "https://www.googleapis.com/auth/bigquery"

log = logging.getLogger("shoc.store.bigquery")

_BQ_TYPES = {"TEXT": "STRING", "TIMESTAMPTZ": "TIMESTAMP", "INTEGER": "INT64", "JSON": "JSON"}


def _ddl_columns() -> str:
    return ",\n  ".join(f"`{name}` {_BQ_TYPES[tp]}" for name, tp in ocsf.COLUMNS)


def key_file(value: str) -> dict[str, Any]:
    """A service-account key, given as its JSON or as the path of the file."""
    if not value:
        return {}
    text = value if value.lstrip().startswith("{") else Path(value).read_text()
    return json.loads(text)


class BigQueryStore:
    dialect = "bigquery"

    def __init__(
        self,
        project: str,
        credentials: dict[str, Any],
        tenant_id: str,
        dataset: str,
        location: str = "US",
        reader: str = "",
    ) -> None:
        if not (project and credentials):
            raise ConfigError(
                "the bigquery backend needs SHOC_BIGQUERY_PROJECT and SHOC_BIGQUERY_CREDENTIALS"
            )
        self.project = project
        self.credentials = credentials
        self.tenant_id = tenant_id
        self.dataset = dataset
        self.location = location
        # The service account agents read as, granted dataViewer per dataset (SEC-1).
        self.reader = reader
        self._http: httpx.Client | None = None

    # -- connection -----------------------------------------------------
    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=120.0)
        return self._http

    def close(self) -> None:
        if self._http is not None:
            self._http.close()
        self._http = None

    def _call(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        token = googleauth.access_token(self.credentials, SCOPE)
        headers = {"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})}
        resp = self.http.request(method, url, headers=headers, **kwargs)
        if resp.status_code >= 300:
            try:
                detail = resp.json()["error"]["message"]
            except Exception:
                detail = resp.text[:300]
            raise StoreError(f"bigquery: {detail}")
        return resp

    def _run(
        self, sql: str, params: dict[str, Any] | None = None, limit: int = 100_000
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Run one statement; its rows (at most `limit` + 1) and the last response."""
        base = f"{API}/projects/{self.project}/queries"
        body: dict[str, Any] = {
            "query": sql,
            "useLegacySql": False,
            "location": self.location,
            "parameterMode": "NAMED",
            "queryParameters": [_param(n, v) for n, v in (params or {}).items()],
            "timeoutMs": 60_000,
            "maxResults": limit + 1,
            "formatOptions": {"useInt64Timestamp": True},
        }
        resp = self._call("POST", base, json=body).json()
        job = resp.get("jobReference", {}).get("jobId", "")
        query = {
            "location": self.location,
            "timeoutMs": 60_000,
            "maxResults": limit + 1,
            "formatOptions.useInt64Timestamp": "true",
        }
        while not resp.get("jobComplete"):
            resp = self._call("GET", f"{base}/{job}", params=query).json()
        fields = resp.get("schema", {}).get("fields", [])
        rows = [_row(fields, r) for r in resp.get("rows", [])]
        while resp.get("pageToken") and len(rows) <= limit:
            resp = self._call(
                "GET", f"{base}/{job}", params={**query, "pageToken": resp["pageToken"]}
            ).json()
            rows += [_row(fields, r) for r in resp.get("rows", [])]
        return rows, resp

    @property
    def table(self) -> str:
        return f"`{self.project}.{self.dataset}.{ocsf.EVENTS_TABLE}`"

    # -- schema ---------------------------------------------------------
    def create_tenant(self) -> None:
        self._run(
            f"CREATE SCHEMA IF NOT EXISTS `{self.project}.{self.dataset}` "
            f"OPTIONS (location = '{self.location}')"
        )
        self._run(
            f"""CREATE TABLE IF NOT EXISTS {self.table} (
  {_ddl_columns()}
) PARTITION BY DATE(time)
  CLUSTER BY tenant_id, metadata_product, api_operation, actor_user_name"""
        )
        if self.reader:
            self._run(
                f"GRANT `roles/bigquery.dataViewer` ON SCHEMA `{self.project}.{self.dataset}` "
                f'TO "serviceAccount:{self.reader}"'
            )

    def migrate(self, ocsf_version: str = "1.3.0") -> None:
        self.create_tenant()
        columns = ", ".join(
            f"ADD COLUMN IF NOT EXISTS `{n}` {_BQ_TYPES[t]}" for n, t in ocsf.COLUMNS
        )
        self._run(f"ALTER TABLE {self.table} {columns}")

    # -- load -----------------------------------------------------------
    def load_batch(self, path: str, table: str = ocsf.EVENTS_TABLE) -> LoadStats:
        """Load the batch into a staging table, then MERGE in the events the table lacks.

        BigQuery has no primary key. An insert-only MERGE on (event_uid, time)
        skips an event already stored, so a replay adds nothing; a repeat inside
        the batch is dropped here first.
        """
        started = time.monotonic()
        rows = read_unique(path)
        if not rows:
            return LoadStats(table=table)
        body = "".join(json.dumps(row, default=str) + "\n" for row in rows)
        times = [datetime.fromisoformat(str(row["time"])) for row in rows]
        staging = f"_stage_{int(time.time() * 1000)}_{os.getpid()}"
        try:
            self._load(staging, body)
            columns = ", ".join(f"`{c}`" for c in ocsf.COLUMN_NAMES)
            _, merged = self._run(
                f"""MERGE {self.table} AS t
USING `{self.project}.{self.dataset}.{staging}` AS s
ON t.tenant_id = s.tenant_id AND t.event_uid = s.event_uid AND t.time = s.time
   AND t.time BETWEEN @lo AND @hi
WHEN NOT MATCHED THEN INSERT ({columns})
VALUES ({", ".join(f"s.`{c}`" for c in ocsf.COLUMN_NAMES)})""",
                {"lo": min(times), "hi": max(times)},
            )
        except Exception as exc:
            raise StoreError(f"bigquery load failed: {exc}") from exc
        finally:
            self._drop(staging)
        return LoadStats(
            rows=int(merged.get("numDmlAffectedRows") or 0),
            bytes=len(body),
            duration_ms=int((time.monotonic() - started) * 1000),
            table=table,
        )

    def _load(self, staging: str, body: str) -> None:
        """A resumable upload: one call opens the load job, one sends the batch."""
        job = {
            "configuration": {
                "load": {
                    "destinationTable": {
                        "projectId": self.project,
                        "datasetId": self.dataset,
                        "tableId": staging,
                    },
                    "schema": {
                        "fields": [{"name": n, "type": _BQ_TYPES[t]} for n, t in ocsf.COLUMNS]
                    },
                    "sourceFormat": "NEWLINE_DELIMITED_JSON",
                    "writeDisposition": "WRITE_TRUNCATE",
                    "ignoreUnknownValues": True,
                }
            },
            "jobReference": {"projectId": self.project, "location": self.location},
        }
        opened = self._call(
            "POST",
            f"{UPLOAD}/projects/{self.project}/jobs",
            params={"uploadType": "resumable"},
            json=job,
        )
        done = self._call(
            "PUT",
            opened.headers["Location"],
            content=body.encode(),
            headers={"Content-Type": "application/octet-stream"},
        ).json()
        ref = done["jobReference"]
        while done.get("status", {}).get("state") != "DONE":
            time.sleep(1)
            done = self._call(
                "GET",
                f"{API}/projects/{self.project}/jobs/{ref['jobId']}",
                params={"location": self.location},
            ).json()
        error = done["status"].get("errorResult")
        if error:
            raise StoreError(f"bigquery load job: {error.get('message')}")

    def _drop(self, staging: str) -> None:
        """Loaded or not, the staging table is spent: a replay loads the batch again."""
        try:
            self._run(f"DROP TABLE IF EXISTS `{self.project}.{self.dataset}.{staging}`")
        except Exception as exc:
            log.warning("could not drop %s after a load: %s", staging, exc)

    # -- read -----------------------------------------------------------
    def query(
        self, canonical_sql: str, params: dict[str, Any] | None = None, limit: int = 1000
    ) -> QueryResult:
        sql, args = prepare(self._qualify(canonical_sql), params, self.dialect, limit + 1)
        started = time.monotonic()
        try:
            rows, _ = self._run(sql, args, limit)
        except (StoreError, httpx.HTTPError) as exc:
            raise StoreError(f"query failed: {exc}") from exc
        return QueryResult(
            rows=rows[:limit],
            sql=sql,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=len(rows) > limit,
        )

    def _qualify(self, canonical_sql: str) -> str:
        """Canonical SQL names bare tables; BigQuery needs project.dataset."""
        return canonical_sql.replace(
            ocsf.EVENTS_TABLE, f'"{self.project}"."{self.dataset}".{ocsf.EVENTS_TABLE}'
        )

    # -- housekeeping ---------------------------------------------------
    def apply_retention(self, policy: RetentionPolicy) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=policy.days)
        _, resp = self._run(
            f"DELETE FROM {self.table} WHERE tenant_id = @tenant AND time < @cutoff",
            {"tenant": self.tenant_id, "cutoff": cutoff},
        )
        return int(resp.get("numDmlAffectedRows") or 0)

    def reset(self) -> None:
        self._run(f"DELETE FROM {self.table} WHERE tenant_id = @tenant", {"tenant": self.tenant_id})

    def health(self) -> StoreHealth:
        started = time.monotonic()
        try:
            rows, _ = self._run(
                f"SELECT count(*) AS n, max(time) AS latest FROM {self.table} "
                "WHERE tenant_id = @tenant",
                {"tenant": self.tenant_id},
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
            detail=f"dataset {self.dataset}",
        )


def _param(name: str, value: Any) -> dict[str, Any]:
    """A named query parameter. BigQuery wants each one typed."""
    if isinstance(value, bool):
        kind, text = "BOOL", "true" if value else "false"
    elif isinstance(value, int):
        kind, text = "INT64", str(value)
    elif isinstance(value, float):
        kind, text = "FLOAT64", repr(value)
    elif isinstance(value, datetime):
        kind, text = "TIMESTAMP", value.isoformat()
    else:
        kind, text = "STRING", None if value is None else str(value)
    out: dict[str, Any] = {"name": name, "parameterType": {"type": kind}, "parameterValue": {}}
    if text is not None:
        out["parameterValue"]["value"] = text
    return out


def _row(fields: list[dict[str, Any]], row: dict[str, Any]) -> dict[str, Any]:
    return {f["name"]: _value(f, cell.get("v")) for f, cell in zip(fields, row["f"], strict=False)}


def _value(field: dict[str, Any], value: Any) -> Any:
    """REST returns every scalar as text; type it by the result schema."""
    if value is None:
        return None
    if field.get("mode") == "REPEATED":
        return [_value({**field, "mode": ""}, v.get("v")) for v in value]
    kind = field.get("type")
    if kind in ("INTEGER", "INT64"):
        return int(value)
    if kind in ("FLOAT", "FLOAT64", "NUMERIC", "BIGNUMERIC"):
        return float(value)
    if kind in ("BOOLEAN", "BOOL"):
        return value == "true"
    if kind == "TIMESTAMP":
        return datetime.fromtimestamp(int(value) / 1_000_000, UTC)
    return value
