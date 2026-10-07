"""Microsoft Defender XDR telemetry: Advanced Hunting tables (ING-1).

Microsoft's SIEM route for this telemetry is the Defender XDR Streaming API,
which exports the tables to an Event Hub or to a Storage account. shoc reads the
Storage account, with outbound HTTPS and a token for an app that holds Storage
Blob Data Reader on it. Each table gets a container,
`insights-logs-advancedhunting-<table>`, holding one `PT1H.json` blob per hour
under `tenantId=<id>/y=YYYY/m=MM/d=DD/h=HH/m=00/`; every line is one record,
`{time, tenantId, category: "AdvancedHunting-<Table>", properties: {...}}`.
A table the Streaming API does not export has no container and reads as empty.

Settings: `storage_account`, and `tables` to read other tables than TABLES.
AlertInfo and AlertEvidence are left out by default: the `defender` connector
reads alerts from Graph `security/alerts_v2`. Name them in `tables` to read the
streamed copies as well.

A blob is an append blob that grows during its hour, and Azure Monitor may
still append to the previous hour's blob just after the hour turns. Each table
keeps a byte offset per blob and reads the rest with a `Range` header; a blob is
retired once its hour closed more than OVERLAP ago and every byte was read.
"""

from __future__ import annotations

import contextlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from shoc.ingest.connectors.base import OVERLAP, FetchResult, Streams, client, utc
from shoc.ingest.connectors.msgraph import access_token

SCOPE = "https://storage.azure.com/.default"
VERSION = "2023-11-03"
HOUR = re.compile(r"y=(\d{4})/m=(\d{2})/d=(\d{2})/h=(\d{2})/")

TABLES = (
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceLogonEvents",
    "DeviceRegistryEvents",
    "DeviceEvents",
    "EmailEvents",
    "EmailUrlInfo",
    "UrlClickEvents",
    "IdentityLogonEvents",
    "CloudAppEvents",
)


class DefenderHuntingConnector:
    source = "defender_hunting"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        table = str(settings["tables"])
        url = (
            f"https://{settings['storage_account']}.blob.core.windows.net/"
            f"insights-logs-advancedhunting-{table.lower()}"
        )
        now = datetime.now(UTC)
        if cursor.get("hour"):
            start = utc(str(cursor["hour"]))
        else:
            back = now - timedelta(hours=int(settings.get("backfill_hours", 24)))
            start = back.replace(minute=0, second=0, microsecond=0)
        offsets: dict[str, int] = dict(cursor.get("offsets") or {})
        headers = {
            "Authorization": f"Bearer {access_token(secret, SCOPE)}",
            "x-ms-version": VERSION,
        }
        records: list[dict[str, Any]] = []
        with client(headers) as http:
            try:
                bases = _list(http, url, {"delimiter": "/"})[1]
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:  # the table is not streamed
                    return FetchResult(cursor=dict(cursor))
                raise
            blobs: list[tuple[datetime, str, int]] = []
            for base in bases:
                day = start.date()
                while day <= now.date():
                    prefix = f"{base}y={day:%Y}/m={day:%m}/d={day:%d}/"
                    for name, size in _list(http, url, {"prefix": prefix})[0]:
                        when = _hour(name)
                        if when and when >= start:
                            blobs.append((when, name, size))
                    day += timedelta(days=1)
            blobs.sort()
            for when, name, size in blobs:
                done = offsets.get(name, 0)
                if done < size and len(records) < limit:
                    closed = when + timedelta(hours=1) + OVERLAP < now
                    offsets[name] = _read(
                        http, f"{url}/{quote(name)}", done, closed, records, limit
                    )
        # The oldest blob not yet retired is where the next walk starts; the
        # offsets of every blob from that hour on are kept.
        floor = (now - OVERLAP).replace(minute=0, second=0, microsecond=0)
        open_ = [
            when
            for when, name, size in blobs
            if offsets.get(name, 0) < size or when + timedelta(hours=1) + OVERLAP >= now
        ]
        hour = open_[0] if open_ else max(start, floor)
        offsets = {
            name: offsets[name] for when, name, _ in blobs if when >= hour and offsets.get(name)
        }
        return FetchResult(
            records=records,
            cursor={"hour": hour.isoformat(), "offsets": offsets},
            more=len(records) >= limit,
        )


def _list(
    http: httpx.Client, url: str, params: dict[str, str]
) -> tuple[list[tuple[str, int]], list[str]]:
    """(blob name and size, prefixes) of a container listing, every page of it."""
    blobs: list[tuple[str, int]] = []
    prefixes: list[str] = []
    marker = ""
    while True:
        query = {"restype": "container", "comp": "list", **params}
        if marker:
            query["marker"] = marker
        resp = http.get(url, params=query)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
        blobs += [
            (b.findtext("Name") or "", int(b.findtext("Properties/Content-Length") or 0))
            for b in root.iter("Blob")
        ]
        prefixes += [p.findtext("Name") or "" for p in root.iter("BlobPrefix")]
        marker = root.findtext("NextMarker") or ""
        if not marker:
            return blobs, prefixes


def _hour(name: str) -> datetime | None:
    m = HOUR.search(name)
    if not m:
        return None
    y, mo, d, h = (int(g) for g in m.groups())
    return datetime(y, mo, d, h, tzinfo=UTC)


def _read(
    http: httpx.Client,
    url: str,
    offset: int,
    closed: bool,
    records: list[dict[str, Any]],
    limit: int,
) -> int:
    """Append the whole lines after `offset` to `records`, up to `limit`, and
    return the offset after the last one read. A trailing line without its
    newline is read only once the hour has closed."""
    with http.stream("GET", url, headers={"Range": f"bytes={offset}-"}) as resp:
        resp.raise_for_status()
        rest = b""
        for chunk in resp.iter_bytes():
            *lines, rest = (rest + chunk).split(b"\n")
            for line in lines:
                offset += len(line) + 1
                if line.strip():
                    records.append(_record(line))
                if len(records) >= limit:
                    return offset
        if closed and rest.strip():
            records.append(_record(rest))
            offset += len(rest)
    return offset


def _record(line: bytes) -> dict[str, Any]:
    """One row, with AdditionalFields decoded: the Streaming API writes that
    column as JSON text, and mappings and rules read the keys inside it
    (DnsQueryString, GroupSid)."""
    record = json.loads(line)
    props = record.get("properties") or {}
    extra = props.get("AdditionalFields")
    if isinstance(extra, str) and extra.startswith("{"):
        with contextlib.suppress(ValueError):
            props["AdditionalFields"] = json.loads(extra)
    return record


CONNECTOR = Streams(DefenderHuntingConnector(), "tables", TABLES)
