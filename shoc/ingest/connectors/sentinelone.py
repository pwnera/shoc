"""SentinelOne connector (ING-1): threats, and the unified alerts.

The threats API holds EDR threats. STAR rules, identity and cloud detections
are only in Unified Alert Management, read through its GraphQL endpoint the way
Elastic's and Microsoft Sentinel's SentinelOne integrations read it. Each is a
stream with its own cursor, so a token Unified Alert Management refuses still
reads threats. Both are polled on their update time: a threat or alert that
changes is read again as a row of its own, marked `_update` as `updates` says
(ING-1, ING-3).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors import updates
from shoc.ingest.connectors.base import (
    FetchResult,
    Streams,
    client,
    reached,
    settled,
    since_default,
    utc,
)

STREAMS = ("threats", "alerts")

# The fields a rule or the crew reads; the rest stay in SentinelOne.
ALERTS = """query($after: String, $first: Int, $filters: [FilterInput!], $sort: SortInput) {
  alerts(after: $after, first: $first, filters: $filters, sort: $sort) {
    pageInfo { hasNextPage endCursor }
    edges { node {
      id name description severity status classification confidenceLevel
      analystVerdict detectedAt createdAt updatedAt
      detectionSource { product vendor }
      analytics { name category uid }
      assets { id name agentUuid osType lastLoggedInUser }
    } }
  }
}"""


class SentinelOneConnector:
    source = "sentinelone"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        console = (settings.get("console_url") or "").rstrip("/")
        token = secret.get("api_token")
        if not console or not token:
            raise ConfigError(
                "sentinelone: settings need console_url and the secret needs api_token"
            )
        stream = settings.get("stream")
        if stream not in STREAMS:
            raise ConfigError(f"sentinelone: unknown stream '{stream}' (have: threats, alerts)")
        with client({"Authorization": f"ApiToken {token}", "Accept": "application/json"}) as http:
            if stream == "threats":
                return _threats(http, console, cursor, limit, settings)
            return _alerts(http, console, token, cursor, limit, settings)


def _threats(
    http: httpx.Client, console: str, cursor: dict[str, Any], limit: int, settings: dict[str, Any]
) -> FetchResult:
    cursor = updates.upgrade(cursor)
    since = since_default(cursor, settings)
    params: dict[str, Any] = {
        "limit": min(int(limit), 1000),
        "sortBy": "updatedAt",
        "sortOrder": "asc",
    }
    if cursor.get("page_cursor"):
        params["cursor"] = cursor["page_cursor"]
    else:
        params["updatedAt__gt"] = since
    resp = http.get(f"{console}/web/api/v2.1/threats", params=params)
    resp.raise_for_status()
    payload = resp.json()
    records = payload.get("data", [])
    info = [r.get("threatInfo") or {} for r in records]
    marks = updates.mark(records, [i.get("createdAt") for i in info], cursor, since)
    newest = max([str(i.get("updatedAt", "")) for i in info] + [reached(cursor, since)])
    late = str(cursor.get("since") or "")
    page_cursor = (payload.get("pagination") or {}).get("nextCursor")
    if page_cursor and records:
        # The page cursor belongs to the updatedAt filter it was issued for:
        # hold its start until the pages run out.
        held = {**cursor, "start": since, "newest": newest, **marks, "page_cursor": page_cursor}
        return FetchResult(records=records, cursor=held, more=True, since=late)
    done = {"since": newest, "created": marks["created_newest"]}
    return FetchResult(records=records, cursor=done, more=False, since=late)


def _alerts(
    http: httpx.Client,
    console: str,
    token: str,
    cursor: dict[str, Any],
    limit: int,
    settings: dict[str, Any],
) -> FetchResult:
    """Unified alerts updated from the cursor on, oldest first; `after` pages
    through the window it was issued for, so the window's end is held with it.
    The start is inclusive, so an alert updated at that instant is read, and
    dropped as stored if a walk read it before (D150). A 200 that carries
    GraphQL `errors` and no alerts is a failure, not an empty page."""
    cursor = updates.upgrade(cursor)
    since = since_default(cursor, settings)
    until = settled(cursor, timedelta(0))
    window = {
        "fieldId": "updatedAt",
        "dateTimeRange": {
            "start": int(utc(since).timestamp() * 1000),
            "startInclusive": True,
            "end": int(utc(until).timestamp() * 1000),
        },
    }
    variables: dict[str, Any] = {
        "first": min(int(limit), 1000),
        "filters": [window],
        "sort": {"by": "updatedAt", "order": "ASC"},
    }
    if cursor.get("after"):
        variables["after"] = cursor["after"]
    resp = http.post(
        f"{console}/web/api/v2.1/unifiedalerts/graphql",
        json={"query": ALERTS, "variables": variables},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    body = resp.json()
    page = (body.get("data") or {}).get("alerts")
    if page is None and body.get("errors"):
        raise RuntimeError(f"unified alerts: {(body['errors'][0] or {}).get('message')}")
    records = [{**e["node"], "_stream": "unified_alerts"} for e in (page or {}).get("edges") or []]
    created = [r.get("detectedAt") or r.get("createdAt") for r in records]
    marks = updates.mark(records, created, cursor, since)
    newest = max([str(r.get("updatedAt") or "") for r in records] + [reached(cursor, since)])
    late = str(cursor.get("since") or "")
    info = (page or {}).get("pageInfo") or {}
    if info.get("hasNextPage") and info.get("endCursor"):
        held = {**cursor, "start": since, "until": until, "newest": newest, **marks}
        return FetchResult(
            records=records, cursor={**held, "after": info["endCursor"]}, more=True, since=late
        )
    done = {"since": newest, "created": marks["created_newest"]}
    return FetchResult(records=records, cursor=done, more=False, since=late)


class _Streams(Streams):
    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        """Before the streams were read apart, one cursor held both as
        {threats, alerts}; each goes on from its own place."""
        if "streams" not in cursor and cursor.keys() & set(STREAMS):
            old = {n: cursor.get(n) or {} for n in STREAMS}
            name = settings.get("stream")
            cursor = old[name] if isinstance(name, str) and name in old else {"streams": old}
        return super().fetch(settings, secret, cursor, limit)


CONNECTOR = _Streams(SentinelOneConnector(), "stream", STREAMS)
