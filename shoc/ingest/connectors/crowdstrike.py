"""CrowdStrike Falcon connector (ING-1): the Alerts API.

Falcon answers in two steps — query the ids updated after the cursor, then ask
for those entities — and its OAuth token is minted per region, so the cloud goes
in the settings. An alert that changes is read again as a row of its own,
marked `_update` as `updates` says (ING-3).
"""

from __future__ import annotations

from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors import updates
from shoc.ingest.connectors.base import FetchResult, client, client_token, reached, since_default

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}


def base_url(settings: dict[str, Any]) -> str:
    cloud = str(settings.get("cloud", "eu-1"))
    if cloud not in CLOUDS:
        raise ConfigError(f"crowdstrike: unknown cloud '{cloud}' (have: {', '.join(CLOUDS)})")
    return CLOUDS[cloud]


def access_token(base: str, secret: dict[str, Any]) -> str:
    """Falcon OAuth2 token, cached as `client_token` says."""
    client_id = secret.get("client_id")
    client_secret = secret.get("client_secret")
    if not (client_id and client_secret):
        raise ConfigError("crowdstrike: secret needs client_id and client_secret")
    data = {"client_id": client_id, "client_secret": client_secret}
    return client_token(f"{base}/oauth2/token", data, default_ttl=1800)


class CrowdStrikeConnector:
    source = "crowdstrike"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        base = base_url(settings)
        token = access_token(base, secret)
        cursor = updates.upgrade(cursor)
        since = since_default(cursor, settings)
        page = min(int(limit), 1000)
        offset = int(cursor.get("offset", 0))
        # An alert already read that changes mid-walk moves to the end of the
        # sort, and every id after it moves back one place. A later page starts
        # a tenth of a page early, so a moved id is read twice (the second copy
        # is dropped as stored, D150) instead of skipped.
        start = max(0, offset - page // 10)
        held = reached(cursor, since)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        records: list[dict[str, Any]] = []
        with client(headers) as http:
            listed = http.get(
                f"{base}/alerts/queries/alerts/v2",
                params={
                    "filter": f"updated_timestamp:>'{since}'",
                    "sort": "updated_timestamp|asc",
                    "limit": page,
                    "offset": start,
                },
            )
            listed.raise_for_status()
            ids = listed.json().get("resources") or []
            if ids:
                detail = http.post(f"{base}/alerts/entities/alerts/v2", json={"composite_ids": ids})
                detail.raise_for_status()
                records = detail.json().get("resources") or []
        marks = updates.mark(records, [r.get("created_timestamp") for r in records], cursor, since)
        newest = max([str(r.get("updated_timestamp", "")) for r in records] + [held])
        late = str(cursor.get("since") or "")
        # A full page means more to read; offset walks it, and the window only
        # moves once the pages run out, on to what the walk read.
        if len(ids) >= page:
            return FetchResult(
                records=records,
                cursor={
                    **cursor,
                    "start": since,
                    "offset": start + len(ids),
                    "newest": newest,
                    **marks,
                },
                more=True,
                since=late,
            )
        done = {"since": newest, "created": marks["created_newest"]}
        return FetchResult(records=records, cursor=done, more=False, since=late)


CONNECTOR = CrowdStrikeConnector()
