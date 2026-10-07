"""SentinelOne Cloud Funnel 2.0: what the connector lists, reads and remembers (ING-1)."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from shoc.errors import ConfigError
from shoc.ingest import connectors
from shoc.ingest.connectors.sentinelone_cloudfunnel import nest

AWS = {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "wJalrXUtnFEMI/K7MDENG"}


def transport(monkeypatch, replies: list[dict[str, Any]]) -> list[httpx.Request]:
    """Answer each request with the next reply, and keep what was sent.

    A reply is `{"json": …}` or `{"content": b"…"}` plus optional `headers` and `status`.
    """
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


def s3_list(*keys: str, truncated: bool = False) -> dict[str, Any]:
    body = "".join(f"<Contents><Key>{k}</Key></Contents>" for k in keys)
    flag = f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"
    xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
    return {
        "content": f'<ListBucketResult xmlns="{xmlns}">{flag}{body}</ListBucketResult>'.encode()
    }


def s3_object(*records: dict[str, Any], gz: bool = True) -> dict[str, Any]:
    body = "\n".join(json.dumps(r) for r in records).encode() + b"\n"
    return {"content": gzip.compress(body) if gz else body}


def event(uid: str, category: str = "process") -> dict[str, Any]:
    return {
        "event.id": uid,
        "event.category": category,
        "src.process.name": "cmd.exe",
        "endpoint.name": "laptop-1",
        "agent.uuid": "a1",
    }


TODAY = datetime.now(UTC).strftime("%Y/%m/%d")
BASE = "s1/cloud_funnel/"


def key(name: str) -> str:
    return f"{BASE}{TODAY}/account_id=1111111111111111111/{name}.gz"


def test_cloudfunnel_lists_reads_nests_and_filters(monkeypatch):
    k1, k2 = key("b"), key("c")
    seen = transport(
        monkeypatch,
        [
            {"status": 301, "headers": {"x-amz-bucket-region": "eu-west-3"}},
            s3_list(k1, k2),
            s3_object(event("e1"), event("e2", "registry"), {"not": "json"}),
            s3_object(event("e3", "dns"), gz=False),
        ],
    )
    page = connectors.get("sentinelone_cloudfunnel").fetch({"bucket": "cf-bucket"}, AWS, {}, 1000)
    assert seen[1].url.host == "cf-bucket.s3.eu-west-3.amazonaws.com", "followed to its region"
    listing = dict(seen[1].url.params)
    assert listing["prefix"] == BASE and listing["start-after"] < key("")
    assert [r["event"]["id"] for r in page.records] == ["e1", "e3"], "registry is off by default"
    assert page.records[0]["src"]["process"]["name"] == "cmd.exe"
    assert page.cursor["bucket_region"] == "eu-west-3" and page.more is False
    assert page.cursor["prefixes"][BASE]["seen"] == [k1, k2]


def test_cloudfunnel_resumes_without_rereading_and_finds_a_late_file(monkeypatch):
    k1, k2, k3 = key("b"), key("c"), key("a")
    seen = transport(
        monkeypatch,
        [
            s3_list(k1, k2),
            s3_object(event("e1")),
            s3_object(event("e2")),
            # k3 was written after the first run but sorts before k1.
            s3_list(k3, k1, k2),
            s3_object(event("e3")),
        ],
    )
    connector = connectors.get("sentinelone_cloudfunnel")
    settings = {"bucket": "cf-bucket", "bucket_region": "eu-west-3"}
    first = connector.fetch(settings, AWS, {}, 1000)
    second = connector.fetch(settings, AWS, first.cursor, 1000)
    assert [r["event"]["id"] for r in second.records] == ["e3"]
    assert sum(r.url.path.endswith(".gz") for r in seen[3:]) == 1
    assert dict(seen[3].url.params)["start-after"] == first.cursor["prefixes"][BASE]["after"]


def test_cloudfunnel_stops_at_the_limit_and_carries_on(monkeypatch):
    k1, k2 = key("b"), key("c")
    transport(
        monkeypatch,
        [s3_list(k1, k2), s3_object(event("e1")), s3_list(k1, k2), s3_object(event("e2"))],
    )
    connector = connectors.get("sentinelone_cloudfunnel")
    settings = {"bucket": "cf-bucket", "bucket_region": "eu-west-3", "event_categories": "all"}
    first = connector.fetch(settings, AWS, {}, 1)
    assert [r["event"]["id"] for r in first.records] == ["e1"] and first.more is True
    second = connector.fetch(settings, AWS, first.cursor, 1)
    assert [r["event"]["id"] for r in second.records] == ["e2"] and second.more is False


def test_cloudfunnel_pages_a_long_listing(monkeypatch):
    k1, k2 = key("b"), key("c")
    seen = transport(
        monkeypatch,
        [s3_list(k1, truncated=True), s3_object(event("e1")), s3_list(k2), s3_object(event("e2"))],
    )
    page = connectors.get("sentinelone_cloudfunnel").fetch(
        {"bucket": "cf-bucket", "bucket_region": "eu-west-3", "prefix": "/s1/cloud_funnel/"},
        AWS,
        {},
        1000,
    )
    assert [r["event"]["id"] for r in page.records] == ["e1", "e2"]
    assert dict(seen[2].url.params)["start-after"] == k1


def test_nest_keeps_a_value_that_is_also_a_prefix():
    record = nest(
        {
            "winEventLog.description": "A logon was attempted",
            "winEventLog.description.userid": "HOST$",
            "event.category": "windows_event_logs",
        }
    )
    assert record["winEventLog"]["description"] == {
        "_value": "A logon was attempted",
        "userid": "HOST$",
    }
    assert nest({"a.b.c": 1, "a.b": 2}) == {"a": {"b": {"c": 1, "_value": 2}}}
    assert record["event"]["category"] == "windows_event_logs"


def test_cloudfunnel_needs_a_bucket_and_both_keys():
    connector = connectors.get("sentinelone_cloudfunnel")
    with pytest.raises(ConfigError, match="bucket"):
        connector.fetch({}, AWS, {}, 10)
    with pytest.raises(ConfigError, match="secret_access_key"):
        connector.fetch({"bucket": "b"}, {"access_key_id": "a"}, {}, 10)
