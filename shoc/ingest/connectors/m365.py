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

import httpx

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
        # `since` is when content became available, not an event time (D164).
        since = since_default(cursor, settings, timedelta(0))
        # Blobs a listing named and a call left unread, then the listing's next page.
        pending = list(cursor.get("pending") or [])
        next_page = cursor.get("next_page")
        listing: tuple[str, dict[str, str] | None] | None = None
        gap = ""
        if pending or next_page:
            # The next-page URI carries the window it was issued for. httpx
            # drops a URL's own query when `params` is given, so the URI
            # Microsoft handed back gets the identifier appended instead.
            end = str(cursor["end"])
            if not pending:
                listing = (_quota(str(next_page), tenant), None)
        else:
            now = datetime.now(UTC)
            start = max(utc(since), now - OLDEST)
            if start > utc(since):
                # After an outage of more than a week those days are gone: say
                # so instead of skipping them silently.
                gap = (
                    f"events from {since} to {start.isoformat()} were not read: "
                    "the Management Activity API serves the last 7 days only"
                )
            stop = min(start + WINDOW, now)
            params = {
                "contentType": content_type,
                "startTime": _stamp(start),
                "endTime": _stamp(stop),
                "PublisherIdentifier": tenant,
            }
            listing = (f"{API}/{tenant}/activity/feed/subscriptions/content", params)
            end = stop.isoformat()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        records: list[dict[str, Any]] = []
        with client(headers) as http:
            if listing:
                listed = _list(http, *listing, tenant, content_type)
                pending = [blob["contentUri"] for blob in listed.json() or []]
                next_page = listed.headers.get("NextPageUri")
            # A page can name a day of blobs: the ones past `limit` records wait
            # in the cursor for the next call.
            while pending and len(records) < limit:
                content = http.get(_quota(pending.pop(0), tenant))
                content.raise_for_status()
                for record in content.json() or []:
                    record["_content_type"] = content_type
                    records.append(record)
        if pending or next_page:
            held: dict[str, Any] = {"since": since, "end": end}
            if pending:
                held["pending"] = pending
            if next_page:
                held["next_page"] = next_page
            return FetchResult(records=records, cursor=held, more=True, error=gap)
        # A window that closed well before now is backfill: go on to the next one.
        behind = utc(end) < datetime.now(UTC) - OVERLAP
        return FetchResult(records=records, cursor={"since": end}, more=behind, error=gap)


def _list(
    http: httpx.Client,
    url: str,
    params: dict[str, str] | None,
    tenant: str,
    content_type: str,
) -> httpx.Response:
    """A content listing. Microsoft answers 400 AF20022 for a content type with
    no subscription started, which is every type of a new app registration:
    start it, then list once more. Content is published only from the start on,
    so `backfill_hours` reaches no further back, and the first can take up to
    12 hours to appear. A start answered AF20024 is one already enabled, which
    a listing can still miss for a while after the start."""
    listed = http.get(url, params=params)
    if listed.status_code == 400 and "AF20022" in listed.text:
        started = http.post(
            f"{API}/{tenant}/activity/feed/subscriptions/start",
            params={"contentType": content_type, "PublisherIdentifier": tenant},
        )
        if not (started.status_code == 400 and "AF20024" in started.text):
            started.raise_for_status()
        listed = http.get(url, params=params)
    listed.raise_for_status()
    return listed


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
