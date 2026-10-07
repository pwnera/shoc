"""Defender Advanced Hunting from the Streaming API's Storage account (ING-1).

The account is faked behind a mock transport that answers container listings
and ranged blob reads the way Blob Storage does; the assertions are on the
requests the connector sent and the cursor it left.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from shoc.ingest import connectors

TENANT = "11111111-1111-1111-1111-111111111111"
NOW = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)


def name(hour: datetime) -> str:
    return f"tenantId={TENANT}/y={hour:%Y}/m={hour:%m}/d={hour:%d}/h={hour:%H}/m=00/PT1H.json"


def lines(table: str, *ids: str) -> bytes:
    rows = [
        {
            "time": "2026-09-20T10:00:00Z",
            "tenantId": TENANT,
            "category": f"AdvancedHunting-{table}",
            "properties": {"ReportId": i},
        }
        for i in ids
    ]
    return b"".join(json.dumps(r).encode() + b"\n" for r in rows)


def storage(
    monkeypatch, containers: dict[str, dict[str, bytes]], page: int = 1000
) -> list[httpx.Request]:
    """Answer listings and ranged reads from `containers`, and keep what was sent."""
    monkeypatch.setattr(
        "shoc.ingest.connectors.defender_hunting.access_token", lambda secret, scope: "tok"
    )
    seen: list[httpx.Request] = []
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        container, _, blob = request.url.path.lstrip("/").partition("/")
        blobs = containers.get(container)
        if blobs is None:
            return httpx.Response(404, content=b"<Error><Code>ContainerNotFound</Code></Error>")
        q = request.url.params
        if q.get("comp") == "list":
            if q.get("delimiter"):
                tops = sorted({n.split("/", 1)[0] + "/" for n in blobs})
                body = "".join(f"<BlobPrefix><Name>{t}</Name></BlobPrefix>" for t in tops)
                return httpx.Response(
                    200,
                    content=f"<EnumerationResults><Blobs>{body}</Blobs></EnumerationResults>".encode(),
                )
            names = sorted(n for n in blobs if n.startswith(q.get("prefix", "")))
            start = int(q.get("marker") or 0)
            chunk = names[start : start + page]
            body = "".join(
                f"<Blob><Name>{n}</Name><Properties><Content-Length>{len(blobs[n])}</Content-Length>"
                "<BlobType>AppendBlob</BlobType></Properties></Blob>"
                for n in chunk
            )
            marker = (
                f"<NextMarker>{start + page}</NextMarker>"
                if start + page < len(names)
                else "<NextMarker/>"
            )
            return httpx.Response(
                200,
                content=f"<EnumerationResults><Blobs>{body}</Blobs>{marker}</EnumerationResults>".encode(),
            )
        offset = int(request.headers["Range"].removeprefix("bytes=").rstrip("-"))
        return httpx.Response(206, content=blobs[unquote(blob)][offset:])

    mock = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": mock}))
    return seen


SETTINGS = {"storage_account": "shocexport"}
PROC = "insights-logs-advancedhunting-deviceprocessevents"
FILE = "insights-logs-advancedhunting-devicefileevents"


def ids(records: list[dict[str, Any]]) -> list[str]:
    return [r["properties"]["ReportId"] for r in records]


def test_each_table_is_read_from_its_own_container_with_its_own_cursor(monkeypatch):
    seen = storage(
        monkeypatch,
        {
            PROC: {name(NOW): lines("DeviceProcessEvents", "p1", "p2")},
            FILE: {name(NOW): lines("DeviceFileEvents", "f1")},
        },
    )
    result = connectors.get("defender_hunting").fetch(
        {**SETTINGS, "tables": ["DeviceProcessEvents", "DeviceFileEvents"]}, {}, {}, 100
    )
    assert sorted(ids(result.records)) == ["f1", "p1", "p2"]
    assert seen[0].url.host == "shocexport.blob.core.windows.net"
    assert seen[0].headers["Authorization"] == "Bearer tok" and seen[0].headers["x-ms-version"]
    assert {r.url.path.split("/")[1] for r in seen} == {PROC, FILE}
    listing = next(r for r in seen if r.url.params.get("prefix"))
    assert listing.url.params["restype"] == "container" and listing.url.params["comp"] == "list"
    streams = result.cursor["streams"]
    assert streams["DeviceProcessEvents"]["offsets"] == {
        name(NOW): len(lines("DeviceProcessEvents", "p1", "p2"))
    }
    assert streams["DeviceFileEvents"]["hour"] == NOW.isoformat()


def test_an_open_blob_is_read_on_from_its_offset(monkeypatch):
    first = lines("DeviceProcessEvents", "p1")
    blob = first + lines("DeviceProcessEvents", "p2") + b'{"partial'
    seen = storage(monkeypatch, {PROC: {name(NOW): blob}})
    cursor = {"hour": NOW.isoformat(), "offsets": {name(NOW): len(first)}}
    result = connectors.get("defender_hunting").fetch(
        {**SETTINGS, "tables": "DeviceProcessEvents"}, {}, cursor, 100
    )
    assert ids(result.records) == ["p2"]
    assert seen[-1].headers["Range"] == f"bytes={len(first)}-"
    # The half-written line waits for the rest of it.
    assert result.cursor["offsets"][name(NOW)] == len(blob) - len(b'{"partial')
    assert result.cursor["hour"] == NOW.isoformat() and not result.more


def test_a_closed_hour_is_retired_and_not_read_again(monkeypatch):
    old = NOW - timedelta(hours=3)
    done = lines("DeviceProcessEvents", "old")
    seen = storage(
        monkeypatch, {PROC: {name(old): done, name(NOW): lines("DeviceProcessEvents", "new")}}
    )
    cursor = {"hour": old.isoformat(), "offsets": {name(old): len(done)}}
    result = connectors.get("defender_hunting").fetch(
        {**SETTINGS, "tables": "DeviceProcessEvents"}, {}, cursor, 100
    )
    assert ids(result.records) == ["new"]
    assert not [
        r for r in seen if "Range" in r.headers and "h=" + f"{old:%H}" in unquote(r.url.path)
    ]
    assert result.cursor["hour"] == NOW.isoformat()
    assert list(result.cursor["offsets"]) == [name(NOW)]


def test_the_listing_follows_next_marker(monkeypatch):
    hours = [
        NOW - timedelta(hours=h)
        for h in (2, 1, 0)
        if (NOW - timedelta(hours=h)).date() == NOW.date()
    ]
    blobs = {name(h): lines("DeviceProcessEvents", f"h{h:%H}") for h in hours}
    seen = storage(monkeypatch, {PROC: blobs}, page=1)
    result = connectors.get("defender_hunting").fetch(
        {**SETTINGS, "tables": "DeviceProcessEvents"}, {}, {"hour": hours[0].isoformat()}, 100
    )
    assert ids(result.records) == [f"h{h:%H}" for h in hours]
    markers = [r.url.params.get("marker") for r in seen if r.url.params.get("prefix")]
    assert markers == [None] + [str(i) for i in range(1, len(hours))]


def test_a_page_stops_at_the_limit_and_says_there_is_more(monkeypatch):
    storage(monkeypatch, {PROC: {name(NOW): lines("DeviceProcessEvents", "p1", "p2", "p3")}})
    result = connectors.get("defender_hunting").fetch(
        {**SETTINGS, "tables": "DeviceProcessEvents"}, {}, {"hour": NOW.isoformat()}, 2
    )
    assert ids(result.records) == ["p1", "p2"] and result.more
    assert result.cursor["offsets"][name(NOW)] == len(lines("DeviceProcessEvents", "p1", "p2"))


@pytest.mark.parametrize("cursor", [{}, {"hour": NOW.isoformat()}])
def test_a_table_the_streaming_api_does_not_export_reads_as_empty(monkeypatch, cursor):
    storage(monkeypatch, {})
    result = connectors.get("defender_hunting").fetch(
        {**SETTINGS, "tables": "DeviceProcessEvents"}, {}, cursor, 100
    )
    assert result.records == [] and result.cursor == cursor and not result.more


def test_additional_fields_are_decoded_so_a_mapping_reads_inside_them():
    from shoc.ingest import ocsf
    from shoc.ingest.connectors.defender_hunting import _record

    record = {
        "time": "2026-09-20T10:00:00Z",
        "tenantId": TENANT,
        "category": "AdvancedHunting-DeviceEvents",
        "properties": {
            "ActionType": "DnsQueryResponse",
            "DeviceId": "a1b2c3",
            "DeviceName": "laptop-1",
            "AdditionalFields": json.dumps({"DnsQueryString": "c2.example.net"}),
        },
    }
    row = ocsf.load_mapping("defender_hunting").map_record(
        _record(json.dumps(record).encode()), "t1"
    )
    assert (row["class_uid"], row["dns_query_hostname"]) == (4003, "c2.example.net")
    assert (row["resource_type"], row["resource_uid"]) == ("host", "a1b2c3")
    record["properties"]["AdditionalFields"] = "[]"
    assert _record(json.dumps(record).encode())["properties"]["AdditionalFields"] == "[]"
