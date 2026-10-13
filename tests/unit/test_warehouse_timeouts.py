"""SHOC_STATEMENT_TIMEOUT on every warehouse, and BigQuery's staging table (STO-3, STO-4, STO-6).

A statement queued on a busy warehouse held the worker until its watchdog
killed it, and the job hung again on its next run. No warehouse runs in CI,
so these check what each adapter asks of a fake one.
"""

from __future__ import annotations

import itertools
import sys
import types
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from shoc.config import Config
from shoc.errors import StoreError
from shoc.ingest import batch
from shoc.store import bigquery, open_store
from shoc.store.bigquery import BigQueryStore
from shoc.store.databricks import DatabricksStore
from shoc.store.snowflake import SnowflakeStore

STUCK = {"jobReference": {"jobId": "j1"}, "jobComplete": False, "status": {"state": "RUNNING"}}


def _module(monkeypatch, name: str, **attrs: Any) -> None:
    """Stand in for an optional extra's module, which CI does not install."""
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    monkeypatch.setitem(sys.modules, name, module)


def test_snowflake_bounds_a_statement_and_its_queueing(monkeypatch):
    opened: dict[str, Any] = {}
    _module(monkeypatch, "snowflake.connector", connect=lambda **kw: opened.update(kw))
    _module(monkeypatch, "snowflake", connector=sys.modules["snowflake.connector"])
    _ = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME", statement_timeout_seconds=45).conn
    session = opened["session_parameters"]
    assert session["STATEMENT_TIMEOUT_IN_SECONDS"] == 45
    assert session["STATEMENT_QUEUED_TIMEOUT_IN_SECONDS"] == 45


def test_databricks_asks_the_server_to_stop_a_statement_too(monkeypatch):
    """Should the worker die before its own timer cancels it (D148)."""
    opened: dict[str, Any] = {}
    sql = SimpleNamespace(connect=lambda **kw: opened.update(kw))
    _module(monkeypatch, "databricks", sql=sql)
    _ = DatabricksStore("h", "/p", "t", "acme", "shoc_acme", statement_timeout_seconds=45).conn
    assert opened["session_configuration"]["STATEMENT_TIMEOUT"] == "45"


def test_every_warehouse_is_opened_with_the_configured_timeout():
    cfg = Config()
    cfg.statement_timeout_seconds = 45
    cfg.backend = "snowflake"
    cfg.snowflake_account, cfg.snowflake_user = "a", "u"
    cfg.snowflake_password, cfg.snowflake_warehouse = "p", "w"
    assert getattr(open_store(cfg, "acme"), "statement_timeout_seconds", None) == 45
    cfg.backend = "bigquery"
    cfg.bigquery_project, cfg.bigquery_credentials = "proj", '{"client_email": "w@example.com"}'
    assert getattr(open_store(cfg, "acme"), "statement_timeout_seconds", None) == 45


def _fake(monkeypatch, store: BigQueryStore, answer: dict[str, Any], clock: bool = True):
    """Answer every call with `answer`; with `clock`, each reading of the clock is 10 s on."""
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def call(method: str, url: str, **kwargs: Any) -> httpx.Response:
        calls.append((method, url, kwargs))
        return httpx.Response(200, headers={"Location": "https://upload.example/s"}, json=answer)

    monkeypatch.setattr(store, "_call", call)
    if clock:
        ticks = itertools.count(0, 10)
        fake_time = SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None)
        monkeypatch.setattr(bigquery, "time", fake_time)
    return calls


def test_bigquery_cancels_a_query_past_the_statement_timeout(monkeypatch):
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme", statement_timeout_seconds=30)
    calls = _fake(monkeypatch, store, STUCK)
    with pytest.raises(StoreError, match="ran past 30s"):
        store.query("SELECT event_uid FROM ocsf_events WHERE tenant_id = :t", {"t": "acme"})
    assert calls[0][2]["json"]["jobTimeoutMs"] == "30000", "the server stops it too"
    polls = [kw["params"]["timeoutMs"] for m, _, kw in calls if m == "GET"]
    assert polls and max(polls) <= 30_000, "a poll waited past the deadline"
    method, url, _ = calls[-1]
    assert method == "POST" and url.endswith("/projects/proj/jobs/j1/cancel")


def test_bigquery_cancels_nothing_when_no_job_came_back(monkeypatch):
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme", statement_timeout_seconds=30)
    calls = _fake(monkeypatch, store, {"jobComplete": False})
    with pytest.raises(StoreError, match="ran past 30s"):
        store.query("SELECT event_uid FROM ocsf_events WHERE tenant_id = :t", {"t": "acme"})
    assert not any(url.endswith("/cancel") for _, url, _ in calls)


def test_bigquery_cancels_a_load_past_the_statement_timeout(monkeypatch):
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme", statement_timeout_seconds=30)
    calls = _fake(monkeypatch, store, STUCK)
    with pytest.raises(StoreError, match="ran past 30s"):
        store._load("_stage_x", "{}\n")
    job = calls[0][2]["json"]["configuration"]
    assert job["jobTimeoutMs"] == "30000"
    assert job["load"]["writeDisposition"] == "WRITE_EMPTY", "a load never replaces rows"
    assert calls[-1][1].endswith("/jobs/j1/cancel")


def test_bigquery_stages_each_load_in_its_own_table_that_expires(monkeypatch, tmp_path):
    """The dataset is shared by every worker, and a killed load never drops its table (STO-6)."""
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme")
    done = {"jobReference": {"jobId": "j1"}, "jobComplete": True, "status": {"state": "DONE"}}
    calls = _fake(monkeypatch, store, {**done, "numDmlAffectedRows": "1"}, clock=False)
    path, _ = batch.write_batch(
        [{"event_uid": "a", "time": "2026-09-20T10:00:00+00:00", "tenant_id": "acme"}],
        str(tmp_path),
    )
    store.load_batch(str(path))
    store.load_batch(str(path))
    queries = [c[2]["json"]["query"] for c in calls if c[1].endswith("/queries")]
    created = [q for q in queries if q.startswith("CREATE TABLE")]
    assert len(created) == 2 and created[0] != created[1]
    assert all("expiration_timestamp" in q for q in created)
    staging = created[0].split("`")[1].rsplit(".", 1)[1]
    assert staging.startswith("_stage_")
    assert f"DROP TABLE IF EXISTS `proj.shoc_acme.{staging}`" in queries
