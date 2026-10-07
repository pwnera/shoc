"""Microsoft Defender connector (ING-1): Graph `security/alerts_v2`.

Defender for Business ships with Microsoft 365 Business Premium, so in a small
company this is usually the EDR that is already paid for. Alerts, not raw
telemetry: the volume of device events is a different order of magnitude and the
alert carries the evidence we cite. The same records can also be pushed to
`/ingest/defender` (ING-2) by a customer who prefers a webhook.
"""

from __future__ import annotations

from typing import Any

from shoc.ingest.connectors.base import FetchResult, client, since_default
from shoc.ingest.connectors.msgraph import access_token

GRAPH = "https://graph.microsoft.com/v1.0/security/alerts_v2"


class DefenderConnector:
    source = "defender"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        token = access_token(secret)
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        url = cursor.get("next_link") or GRAPH
        params: dict[str, Any] = {}
        if not cursor.get("next_link"):
            params = {
                "$filter": f"createdDateTime gt {since}",
                "$orderby": "createdDateTime asc",
                "$top": min(int(limit), 1000),
            }
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            resp = http.get(url, params=params or None)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("value", [])
        newest = max(
            [str(r.get("createdDateTime", "")) for r in records]
            + [str(cursor.get("newest") or since)]
        )
        next_link = payload.get("@odata.nextLink")
        if next_link and records:
            # The nextLink carries the $filter it was issued for: hold `since`
            # until the pages run out.
            held = {"since": since, "newest": newest, "next_link": next_link}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


CONNECTOR = DefenderConnector()
