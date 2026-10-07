"""Google Workspace connector (ING-1): Admin SDK Reports activities.

Authentication is a signed JWT assertion from a service account with
domain-wide delegation, so the connector impersonates an admin who is allowed to
read the reports.

Google delivers some applications late: OAuth token events can arrive a couple
of hours after they happened. Each read starts that far behind the cursor for
such an application, and what it reads again loads once.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors import googleauth
from shoc.ingest.connectors.base import FetchResult, Streams, client, since_default, utc

REPORTS = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
# Google's documented delivery lag, beyond the run loop's own overlap.
LAG = {"token": timedelta(hours=3)}


def access_token(secret: dict[str, Any], subject: str, client_id: str = "") -> str:
    """Exchange a signed service-account assertion for an access token."""
    if not subject:
        raise ConfigError(
            "google_workspace: settings need admin_email (the admin user to impersonate)"
        )
    if client_id and not secret.get("client_id"):
        secret = {**secret, "client_id": client_id}
    return googleauth.access_token(secret, SCOPE, subject=subject)


def credentials(settings: dict[str, Any], secret: dict[str, Any]) -> list[tuple[str, str]]:
    """shoc's own credential, as Google's token log names it: the service
    account's numeric client id (its Unique ID), and the one scope it uses."""
    known = str(secret.get("client_id") or settings.get("client_id") or "")
    if not known and settings.get("admin_email"):
        token = access_token(secret, str(settings["admin_email"]))
        known = googleauth.client_id(secret, token)
    return [(known, SCOPE)] if known else []


class GoogleWorkspaceConnector:
    source = "google_workspace"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        application = settings["application"]
        token = access_token(
            secret, settings.get("admin_email", ""), str(settings.get("client_id") or "")
        )
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        start = (utc(since) - LAG.get(application, timedelta(0))).isoformat()
        params: dict[str, Any] = {"maxResults": min(int(limit), 1000), "startTime": start}
        if cursor.get("page_token"):
            params["pageToken"] = cursor["page_token"]
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            resp = http.get(f"{REPORTS}/{application}", params=params)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("items", [])
        for record in records:
            record["_application"] = application
        # Reports answer newest first; carry the newest across the walk, and
        # hold startTime while following its pageToken.
        newest = max(
            [str((r.get("id") or {}).get("time", "")) for r in records]
            + [str(cursor.get("newest") or since)]
        )
        page_token = payload.get("nextPageToken")
        if page_token:
            held = {"since": since, "newest": newest, "page_token": page_token}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


CONNECTOR = Streams(GoogleWorkspaceConnector(), "application", ("admin", "login", "token", "drive"))
