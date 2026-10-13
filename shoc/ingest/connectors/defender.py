"""Microsoft Defender connector (ING-1): Graph `security/alerts_v2`.

Defender for Business ships with Microsoft 365 Business Premium, so in a small
company this is usually the EDR that is already paid for. Alerts, not raw
telemetry: the volume of device events is a different order of magnitude and the
alert carries the evidence we cite. Graph updates an alert in place, so the
poll reads by `lastUpdateDateTime`: a change is read again as a row of its own,
marked `_update` as `updates` says (ING-3).
"""

from __future__ import annotations

from typing import Any

from shoc.ingest.connectors import updates
from shoc.ingest.connectors.base import FetchResult, client, reached, since_default
from shoc.ingest.connectors.msgraph import access_token

GRAPH = "https://graph.microsoft.com/v1.0/security/alerts_v2"


class DefenderConnector:
    source = "defender"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        token = access_token(secret)
        cursor = updates.upgrade(cursor)
        since = since_default(cursor, settings)
        url = cursor.get("next_link") or GRAPH
        params: dict[str, Any] = {}
        if not cursor.get("next_link"):
            params = {
                "$filter": f"lastUpdateDateTime gt {since}",
                "$orderby": "lastUpdateDateTime asc",
                "$top": min(int(limit), 1000),
            }
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            resp = http.get(url, params=params or None)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("value", [])
        marks = updates.mark(records, [r.get("createdDateTime") for r in records], cursor, since)
        newest = max(
            [str(r.get("lastUpdateDateTime", "")) for r in records] + [reached(cursor, since)]
        )
        late = str(cursor.get("since") or "")
        next_link = payload.get("@odata.nextLink")
        if next_link and records:
            # The nextLink carries the $filter it was issued for: hold its start
            # until the pages run out.
            held = {**cursor, "start": since, "newest": newest, **marks, "next_link": next_link}
            return FetchResult(records=records, cursor=held, more=True, since=late)
        done = {"since": newest, "created": marks["created_newest"]}
        return FetchResult(records=records, cursor=done, more=False, since=late)


CONNECTOR = DefenderConnector()
