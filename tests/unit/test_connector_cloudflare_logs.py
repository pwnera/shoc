"""Cloudflare Logpush from an R2 or S3 bucket: the requests built and the cursor kept (ING-1)."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from shoc.errors import ConfigError
from shoc.ingest import connectors
from shoc.ingest.connectors.cloudflare_logs import mark

KEYS = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "secret"}
R2 = {"bucket": "cf-logs", "account_id": "0123456789abcdef0123456789abcdef"}


def transport(monkeypatch, replies: list[dict[str, Any]]) -> list[httpx.Request]:
    """Answer each request with the next reply, and keep what was sent."""
    seen: list[httpx.Request] = []
    real_client = httpx.Client
    queue = list(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        reply: dict[str, Any] = queue.pop(0) if queue else {}
        body = (
            {"content": reply["content"]} if "content" in reply else {"json": reply.get("json", {})}
        )
        return httpx.Response(
            int(reply.get("status", 200)), headers=dict(reply.get("headers") or {}), **body
        )

    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    return seen


def s3_list(*keys: str) -> dict[str, Any]:
    body = "".join(f"<Contents><Key>{k}</Key></Contents>" for k in keys)
    xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
    return {"content": f'<ListBucketResult xmlns="{xmlns}">{body}</ListBucketResult>'.encode()}


def batch(*ids: str) -> dict[str, Any]:
    lines = "\n".join(json.dumps({"RayID": i}) for i in ids) + "\n"
    return {"content": gzip.compress(lines.encode())}


def key(prefix: str, when: datetime, suffix: str) -> str:
    end = when + timedelta(seconds=30)
    return f"{prefix}/{when:%Y%m%d}/{when:%Y%m%dT%H%M%SZ}_{end:%Y%m%dT%H%M%SZ}_{suffix}.log.gz"


T = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0)


def test_r2_is_addressed_path_style_and_signed_for_region_auto(monkeypatch):
    k = key("logs/http", T, "a1")
    seen = transport(
        monkeypatch, [s3_list(k, "logs/http/ownership-challenge-1.txt"), batch("r1", "r2")]
    )
    settings = {**R2, "datasets": {"http_requests": "logs/http"}}
    got = connectors.get("cloudflare_logs").fetch(settings, KEYS, {}, 1000)
    listed, read = seen
    assert listed.url.host == "0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
    assert listed.url.path == "/cf-logs/"
    assert dict(listed.url.params)["prefix"] == "logs/http/"
    assert dict(listed.url.params)["start-after"] < k
    assert "/auto/s3/aws4_request" in listed.headers["authorization"]
    assert read.url.path == f"/cf-logs/{k}"
    assert len(seen) == 2, "the ownership-challenge file is not a batch"
    assert got.records == [
        {"RayID": "r1", "_dataset": "http_requests"},
        {"RayID": "r2", "_dataset": "http_requests"},
    ]
    assert "bucket_region" not in got.cursor


def test_each_dataset_keeps_its_place_and_the_overlap_finds_a_late_batch(monkeypatch):
    later = T + timedelta(minutes=5)
    h1, h2 = key("logs/http", T, "b"), key("logs/http", later, "c")
    late = key("logs/http", later - timedelta(seconds=30), "a")
    f1 = key("logs/fw", T, "d")
    seen = transport(
        monkeypatch,
        [
            s3_list(h1, h2),
            batch("h1"),
            batch("h2"),
            s3_list(f1),
            batch("f1"),
            # `late` landed after the first read, and sorts before h2.
            s3_list(h1, late, h2),
            batch("late"),
            s3_list(f1),
        ],
    )
    connector = connectors.get("cloudflare_logs")
    settings = {**R2, "datasets": {"http_requests": "logs/http", "firewall_events": "logs/fw/"}}
    first = connector.fetch(settings, KEYS, {}, 1000)
    assert [(r["RayID"], r["_dataset"]) for r in first.records] == [
        ("h1", "http_requests"),
        ("h2", "http_requests"),
        ("f1", "firewall_events"),
    ]
    places = first.cursor["datasets"]
    assert places["http_requests"]["seen"] == [h1, h2]
    assert places["http_requests"]["after"] == mark(
        "logs/http/{DATE}", later - timedelta(minutes=15)
    )
    assert places["firewall_events"]["seen"] == [f1] and first.more is False

    second = connector.fetch(settings, KEYS, first.cursor, 1000)
    assert dict(seen[5].url.params)["start-after"] == places["http_requests"]["after"]
    assert [r["RayID"] for r in second.records] == ["late"]
    assert sum(r.url.path.endswith(".log.gz") for r in seen[5:]) == 1


def test_a_full_batch_leaves_the_rest_for_the_next_call(monkeypatch):
    h1, h2 = key("logs/http", T, "a"), key("logs/http", T + timedelta(minutes=1), "b")
    f1 = key("logs/fw", T, "c")
    seen = transport(
        monkeypatch,
        [s3_list(h1, h2), batch("h1"), s3_list(h2), batch("h2"), s3_list(f1), batch("f1")],
    )
    connector = connectors.get("cloudflare_logs")
    settings = {**R2, "datasets": {"http_requests": "logs/http", "firewall_events": "logs/fw"}}
    first = connector.fetch(settings, KEYS, {}, 1)
    assert [r["RayID"] for r in first.records] == ["h1"] and first.more is True
    assert first.cursor["datasets"]["firewall_events"]["more"] is True, "not read yet"

    second = connector.fetch(settings, KEYS, first.cursor, 1)
    assert [r["RayID"] for r in second.records] == ["h2"]
    assert len(seen) == 4, "the firewall dataset is still waiting"
    third = connector.fetch(settings, KEYS, second.cursor, 1)
    assert [r["RayID"] for r in third.records] == ["f1"]


def test_s3_bucket_with_a_date_path_and_an_inflated_body(monkeypatch):
    k = f"cf/date={T:%Y%m%d}/{T:%Y%m%dT%H%M%SZ}_{T:%Y%m%dT%H%M%SZ}_x.log.gz"
    plain = json.dumps({"QueryName": "www.example.com."}).encode()
    seen = transport(
        monkeypatch,
        [
            {"status": 301, "headers": {"x-amz-bucket-region": "eu-west-3"}},
            s3_list(k),
            {"content": plain},
        ],
    )
    settings = {"bucket": "cf-logs", "datasets": {"dns_logs": "cf/date={DATE}"}}
    got = connectors.get("cloudflare_logs").fetch(settings, KEYS, {}, 1000)
    assert seen[1].url.host == "cf-logs.s3.eu-west-3.amazonaws.com"
    assert dict(seen[1].url.params)["prefix"] == "cf/date="
    assert got.records == [{"QueryName": "www.example.com.", "_dataset": "dns_logs"}]
    assert got.cursor["bucket_region"] == "eu-west-3"


def test_cloudflare_logs_needs_a_bucket_datasets_and_keys():
    connector = connectors.get("cloudflare_logs")
    with pytest.raises(ConfigError):
        connector.fetch({"bucket": "b"}, KEYS, {}, 10)
    with pytest.raises(ConfigError):
        connector.fetch({**R2, "datasets": {"dns_logs": "dns"}}, {"access_key_id": "a"}, {}, 10)
