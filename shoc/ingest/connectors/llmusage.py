"""Hourly usage per API key, shared by the OpenAI and Anthropic connectors (ING-1).

A leaked model API key shows up as usage, not as an audit event. Both platforms
report usage per key per hour, a few minutes late. A bucket is read once it has
closed and settled, so a record loaded once is final and the same hour is never
loaded twice.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from shoc.ingest.connectors.base import FetchResult, utc

SETTLE = timedelta(minutes=30)
MAX_HOURS = 168  # the most one-hour buckets either API returns per request

Params = Callable[[datetime, datetime], list[tuple[str, Any]]]


def _hour(when: datetime) -> datetime:
    return when.replace(minute=0, second=0, microsecond=0)


def _iso(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    return str(value)


def read(
    http: httpx.Client,
    url: str,
    cursor: dict[str, Any],
    hours: int,
    product: str,
    params: Params,
) -> FetchResult:
    """One page of usage buckets. `params(start, end)` is the platform's query."""
    if cursor.get("page"):
        start, end = utc(cursor["since"]), utc(cursor["end"])
    else:
        # A first read takes a week whatever the backfill, so the usage rules
        # know each key's own week from the start (their `first_seen` lookback).
        start = (
            utc(cursor["since"])
            if cursor.get("since")
            else _hour(datetime.now(UTC) - timedelta(hours=max(hours, MAX_HOURS)))
        )
        end = min(_hour(datetime.now(UTC) - SETTLE), start + timedelta(hours=MAX_HOURS))
        if end <= start:
            return FetchResult(cursor=dict(cursor))
    query = params(start, end)
    if cursor.get("page"):
        query.append(("page", cursor["page"]))
    resp = http.get(url, params=query)
    resp.raise_for_status()
    body = resp.json()
    records = []
    for bucket in body.get("data") or []:
        began = _iso(bucket.get("start_time") or bucket.get("starting_at"))
        for result in bucket.get("results") or []:
            key = result.get("api_key_id")
            scope = result.get("project_id") or result.get("workspace_id") or ""
            records.append(
                {
                    **result,
                    "id": f"{product}-usage-{key or 'console'}-{scope}-{began}",
                    "event": "usage",
                    "key_id": key,
                    "bucket_start": began,
                    "bucket_end": _iso(bucket.get("end_time") or bucket.get("ending_at")),
                }
            )
    if body.get("has_more") and body.get("next_page"):
        held = {"since": start.isoformat(), "end": end.isoformat(), "page": body["next_page"]}
        return FetchResult(records=records, cursor=held, more=True)
    return FetchResult(records=records, cursor={"since": end.isoformat()}, more=False)


def combine(**parts: FetchResult) -> FetchResult:
    """Several streams of one source as one page, each keeping its own cursor."""
    return FetchResult(
        records=[r for p in parts.values() for r in p.records],
        cursor={name: p.cursor for name, p in parts.items()},
        more=any(p.more for p in parts.values()),
    )
