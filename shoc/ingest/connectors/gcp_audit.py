"""GCP Cloud Audit Logs connector (ING-1).

Google's route for a SIEM is a log sink into a Pub/Sub topic, read here through
a pull subscription over HTTPS (`subscription`). Each page is acknowledged at
the start of the next read, after the run loop has loaded it; a message
redelivered in between loads once, by its insertId.

Without a subscription it falls back to Cloud Logging `entries.list`, which
needs no setup but which Google caps at 60 calls a minute and says is not meant
for high-volume reads. Admin Activity audit logs are on in every project; Data
Access logs are opt-in there and expensive here, so the default filter leaves
them out.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors import googleauth
from shoc.ingest.connectors.base import FetchResult, client, since_default

ENTRIES = "https://logging.googleapis.com/v2/entries:list"
SCOPE = "https://www.googleapis.com/auth/logging.read"
PUBSUB = "https://pubsub.googleapis.com/v1"
PUBSUB_SCOPE = "https://www.googleapis.com/auth/pubsub"
ACK_DEADLINE = 600  # the most Pub/Sub allows; longer than a poll interval
ADMIN_ACTIVITY = 'logName:"cloudaudit.googleapis.com%2Factivity"'


class GCPAuditConnector:
    source = "gcp_audit"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        if settings.get("subscription"):
            return _pull(str(settings["subscription"]), secret, cursor, limit)
        projects = settings.get("projects") or (
            [settings["project_id"]] if settings.get("project_id") else []
        )
        if not projects:
            raise ConfigError("gcp_audit: settings need project_id (or a list of projects)")
        token = googleauth.access_token(secret, SCOPE)
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        log_filter = settings.get("filter", ADMIN_ACTIVITY)
        body: dict[str, Any] = {
            "resourceNames": [f"projects/{p}" for p in projects],
            "filter": f'{log_filter} AND timestamp > "{since}"',
            "orderBy": "timestamp asc",
            "pageSize": min(int(limit), 1000),
        }
        if cursor.get("page_token"):
            body["pageToken"] = cursor["page_token"]
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            resp = http.post(ENTRIES, json=body)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("entries", [])
        newest = max(
            [str(r.get("timestamp", "")) for r in records] + [str(cursor.get("newest") or since)]
        )
        page_token = payload.get("nextPageToken")
        if page_token:
            # A pageToken is only valid for the filter it came from, so the
            # timestamp bound stays put until the walk is done.
            held = {"since": since, "newest": newest, "page_token": page_token}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


def _pull(
    subscription: str, secret: dict[str, Any], cursor: dict[str, Any], limit: int
) -> FetchResult:
    """One page from the sink's subscription, `projects/<p>/subscriptions/<s>`."""
    token = googleauth.access_token(secret, PUBSUB_SCOPE)
    size = min(int(limit), 1000)
    with client({"Authorization": f"Bearer {token}"}) as http:
        if cursor.get("ack"):
            # An id past its deadline no longer acknowledges anything; its
            # message comes back and loads once, so a refusal here is not fatal.
            http.post(f"{PUBSUB}/{subscription}:acknowledge", json={"ackIds": cursor["ack"]})
        resp = http.post(f"{PUBSUB}/{subscription}:pull", json={"maxMessages": size})
        resp.raise_for_status()
        received = resp.json().get("receivedMessages") or []
        ids = [m["ackId"] for m in received if m.get("ackId")]
        if ids:
            # Long enough to be acknowledged by the next cycle, not redelivered first.
            held = http.post(
                f"{PUBSUB}/{subscription}:modifyAckDeadline",
                json={"ackIds": ids, "ackDeadlineSeconds": ACK_DEADLINE},
            )
            held.raise_for_status()
    records = [
        json.loads(base64.b64decode((m.get("message") or {}).get("data") or b"e30="))
        for m in received
    ]
    return FetchResult(records=records, cursor={"ack": ids}, more=len(received) == size)


CONNECTOR = GCPAuditConnector()
