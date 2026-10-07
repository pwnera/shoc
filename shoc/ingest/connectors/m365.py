"""Microsoft 365 connector (ING-1): the Office 365 Management Activity API.

Content arrives in two steps: list the blobs published for a content type, then
fetch each blob. Both calls use the same Azure AD application as Entra ID.

The listing is filtered on when each blob became available, not on the
`CreationTime` of the records inside it, so the cursor is kept on that axis. The
API wants both ends of a window, at most 24 hours apart and no more than 7 days
back, and pages the listing through a `NextPageUri` header. Every call names
the tenant as `PublisherIdentifier`, which Microsoft asks for: without it, the
requests share one quota with every other caller that leaves it out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import OVERLAP, FetchResult, Streams, client, since_default, utc
from shoc.ingest.connectors.msgraph import access_token

API = "https://manage.office.com/api/v1.0"
SCOPE = "https://manage.office.com/.default"
WINDOW = timedelta(hours=24)
OLDEST = timedelta(days=7) - timedelta(hours=1)


class M365Connector:
    source = "m365"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        tenant = secret.get("tenant_id")
        if not tenant:
            raise ConfigError("m365: secret needs tenant_id, client_id and client_secret")
        content_type = settings["content_type"]
        token = access_token(secret, SCOPE)
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        if cursor.get("next_page"):
            # The next-page URI carries the window it was issued for.
            url, params, end = cursor["next_page"], None, str(cursor["end"])
        else:
            now = datetime.now(UTC)
            start = max(utc(since), now - OLDEST)
            stop = min(start + WINDOW, now)
            url = f"{API}/{tenant}/activity/feed/subscriptions/content"
            params = {
                "contentType": content_type,
                "startTime": _stamp(start),
                "endTime": _stamp(stop),
            }
            end = stop.isoformat()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        records: list[dict[str, Any]] = []
        with client(headers) as http:
            # httpx drops a URL's own query when `params` is given, so a URI
            # Microsoft handed back gets the identifier appended instead.
            if params is None:
                listed = http.get(_quota(url, tenant))
            else:
                listed = http.get(url, params={**params, "PublisherIdentifier": tenant})
            listed.raise_for_status()
            for blob in listed.json() or []:
                content = http.get(_quota(blob["contentUri"], tenant))
                content.raise_for_status()
                for record in content.json() or []:
                    record["_content_type"] = content_type
                    records.append(record)
            next_page = listed.headers.get("NextPageUri")
        if next_page:
            held = {"since": since, "end": end, "next_page": next_page}
            return FetchResult(records=records, cursor=held, more=True)
        # A window that closed well before now is backfill: go on to the next one.
        behind = utc(end) < datetime.now(UTC) - OVERLAP
        return FetchResult(records=records, cursor={"since": end}, more=behind)


def _quota(url: str, tenant: str) -> str:
    """A URI Microsoft handed back, with `PublisherIdentifier` unless it has one."""
    if "PublisherIdentifier=" in url:
        return url
    return f"{url}{'&' if '?' in url else '?'}PublisherIdentifier={tenant}"


def _stamp(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")


CONNECTOR = Streams(
    M365Connector(),
    "content_type",
    ("Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General"),
)
