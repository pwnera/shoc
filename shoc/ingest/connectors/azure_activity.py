"""Azure Activity Log connector (ING-1): the subscription's control plane.

Same Azure AD application as Entra ID and M365, one more token scope. Azure
returns the whole window through `nextLink`, and the reader role is enough.
"""

from __future__ import annotations

from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, Streams, client, since_default
from shoc.ingest.connectors.msgraph import access_token

ARM = "https://management.azure.com"
SCOPE = "https://management.azure.com/.default"
API_VERSION = "2015-04-01"


class AzureActivityConnector:
    source = "azure_activity"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        subscription = settings.get("subscription_id")
        if not subscription:
            raise ConfigError("azure_activity: settings need subscription_id")
        token = access_token(secret, SCOPE)
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        url = cursor.get("next_link") or (
            f"{ARM}/subscriptions/{subscription}"
            "/providers/Microsoft.Insights/eventtypes/management/values"
        )
        params: dict[str, Any] = {}
        if not cursor.get("next_link"):
            params = {
                "api-version": API_VERSION,
                "$filter": f"eventTimestamp ge '{since}'",
                "$top": min(int(limit), 1000),
            }
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            resp = http.get(url, params=params or None)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("value", [])
        # The Activity Log answers newest first: carry the newest across the
        # walk, and hold `since` while following the nextLink issued for it.
        newest = max(
            [str(r.get("eventTimestamp", "")) for r in records]
            + [str(cursor.get("newest") or since)]
        )
        next_link = payload.get("nextLink")
        if next_link and records:
            held = {"since": since, "newest": newest, "next_link": next_link}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


CONNECTOR = Streams(AzureActivityConnector(), "subscription_id")
