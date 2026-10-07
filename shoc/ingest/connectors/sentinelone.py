"""SentinelOne connector (ING-1): threats, and the unified alerts.

The threats API holds EDR threats. STAR rules, identity and cloud detections
are only in Unified Alert Management, read through its GraphQL endpoint the way
Elastic's and Microsoft Sentinel's SentinelOne integrations read it. Each keeps
its own cursor. SentinelOne hands the same record back as it is updated, which
is fine: rows deduplicate on `event_uid`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, resume, since_default, utc

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
        hours = int(settings.get("backfill_hours", 24))
        with client({"Authorization": f"ApiToken {token}", "Accept": "application/json"}) as http:
            threats = _threats(http, console, cursor.get("threats") or {}, limit, hours)
            alerts = _alerts(http, console, token, cursor.get("alerts") or {}, limit, hours)
        return FetchResult(
            records=threats.records + alerts.records,
            cursor={"threats": threats.cursor, "alerts": alerts.cursor},
            more=threats.more or alerts.more,
        )


def _threats(
    http: httpx.Client, console: str, cursor: dict[str, Any], limit: int, hours: int
) -> FetchResult:
    since = since_default(cursor, hours=hours)
    params: dict[str, Any] = {
        "limit": min(int(limit), 1000),
        "sortBy": "createdAt",
        "sortOrder": "asc",
    }
    if cursor.get("page_cursor"):
        params["cursor"] = cursor["page_cursor"]
    else:
        params["createdAt__gt"] = since
    resp = http.get(f"{console}/web/api/v2.1/threats", params=params)
    resp.raise_for_status()
    payload = resp.json()
    records = payload.get("data", [])
    newest = max(
        [str((r.get("threatInfo") or {}).get("createdAt", "")) for r in records]
        + [str(cursor.get("newest") or since)]
    )
    page_cursor = (payload.get("pagination") or {}).get("nextCursor")
    if page_cursor and records:
        # The page cursor belongs to the createdAt filter it was issued for:
        # hold `since` until the pages run out.
        held = {"since": since, "newest": newest, "page_cursor": page_cursor}
        return FetchResult(records=records, cursor=held, more=True)
    # The run loop moves only a top-level `since`; this one moves itself.
    return FetchResult(records=records, cursor={"since": resume(since, newest)}, more=False)


def _alerts(
    http: httpx.Client, console: str, token: str, cursor: dict[str, Any], limit: int, hours: int
) -> FetchResult:
    """Unified alerts detected after the cursor, oldest first; `after` pages
    through the window it was issued for."""
    since = since_default(cursor, hours=hours)
    window = {
        "fieldId": "detectedAt",
        "dateTimeRange": {
            "start": int(utc(since).timestamp() * 1000),
            "startInclusive": False,
            "end": int(datetime.now(UTC).timestamp() * 1000),
        },
    }
    variables: dict[str, Any] = {
        "first": min(int(limit), 1000),
        "filters": [window],
        "sort": {"by": "detectedAt", "order": "ASC"},
    }
    if cursor.get("after"):
        variables["after"] = cursor["after"]
    resp = http.post(
        f"{console}/web/api/v2.1/unifiedalerts/graphql",
        json={"query": ALERTS, "variables": variables},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    resp.raise_for_status()
    page = ((resp.json().get("data") or {}).get("alerts")) or {}
    records = [{**e["node"], "_stream": "unified_alerts"} for e in page.get("edges") or []]
    newest = max(
        [str(r.get("detectedAt") or "") for r in records] + [str(cursor.get("newest") or since)]
    )
    info = page.get("pageInfo") or {}
    if info.get("hasNextPage") and info.get("endCursor"):
        held = {"since": since, "newest": newest, "after": info["endCursor"]}
        return FetchResult(records=records, cursor=held, more=True)
    return FetchResult(records=records, cursor={"since": resume(since, newest)}, more=False)


CONNECTOR = SentinelOneConnector()
