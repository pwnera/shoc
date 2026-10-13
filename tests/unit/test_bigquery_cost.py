"""What a BigQuery statement may scan and bill (STO-6, DET-3).

Detection reads by ingestion time, and a table partitioned on event time read
every partition each cycle with no cap on the bill (wh-6). No warehouse runs in
CI, so these check what the adapter asks of a fake one.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.config import Config
from shoc.store.bigquery import BigQueryStore

DONE = {"jobReference": {"jobId": "j1"}, "jobComplete": True}


def _fake(monkeypatch, store: BigQueryStore) -> list[dict[str, Any]]:
    bodies: list[dict[str, Any]] = []

    def call(method: str, url: str, **kwargs: Any) -> httpx.Response:
        bodies.append(kwargs.get("json") or {})
        return httpx.Response(200, json=DONE)

    monkeypatch.setattr(store, "_call", call)
    return bodies


def test_the_table_is_partitioned_by_what_detection_reads(monkeypatch):
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme")
    bodies = _fake(monkeypatch, store)
    store.create_tenant()
    [ddl] = [b["query"] for b in bodies if "CREATE TABLE" in b.get("query", "")]
    assert "PARTITION BY DATE(ingested_at)" in ddl
    assert "CLUSTER BY time, metadata_product, api_operation, actor_user_name" in ddl
    assert "tenant_id," not in ddl.split("CLUSTER BY", 1)[1], "the dataset is the tenant's"


def test_only_a_read_carries_the_byte_cap(monkeypatch):
    """Retention, reset and the load prune only by clustering, whose upper-bound
    estimate the cap is checked against: capped, they would fail as the table grows."""
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme", max_bytes_billed=5_000)
    bodies = _fake(monkeypatch, store)
    store.query("SELECT event_uid FROM ocsf_events WHERE tenant_id = :t", {"t": "acme"})
    store.reset()
    assert [b.get("maximumBytesBilled") for b in bodies] == ["5000", None]


def test_a_zero_cap_sends_none(monkeypatch):
    store = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme", max_bytes_billed=0)
    bodies = _fake(monkeypatch, store)
    store.query("SELECT event_uid FROM ocsf_events WHERE tenant_id = :t", {"t": "acme"})
    assert "maximumBytesBilled" not in bodies[0]


def test_the_cap_comes_from_the_environment(monkeypatch):
    monkeypatch.delenv("SHOC_BIGQUERY_MAX_BYTES_BILLED", raising=False)
    assert Config().bigquery_max_bytes_billed == 0, "off until STO-6 measures it"
    monkeypatch.setenv("SHOC_BIGQUERY_MAX_BYTES_BILLED", "1000")
    assert Config().bigquery_max_bytes_billed == 1000
    assert BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme").max_bytes_billed == 1000
