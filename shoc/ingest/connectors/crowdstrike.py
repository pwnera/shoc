"""CrowdStrike Falcon connector (ING-1): the Alerts API.

Falcon answers in two steps — query the ids created after the cursor, then ask
for those entities — and its OAuth token is minted per region, so the cloud goes
in the settings. Records can also be pushed to `/ingest/crowdstrike` (ING-2).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, since_default

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}
_TOKENS: dict[str, tuple[str, float]] = {}


def base_url(settings: dict[str, Any]) -> str:
    cloud = str(settings.get("cloud", "eu-1"))
    if cloud not in CLOUDS:
        raise ConfigError(f"crowdstrike: unknown cloud '{cloud}' (have: {', '.join(CLOUDS)})")
    return CLOUDS[cloud]


def access_token(base: str, secret: dict[str, Any]) -> str:
    """Falcon OAuth2 token, cached until a minute before it expires."""
    client_id = secret.get("client_id")
    client_secret = secret.get("client_secret")
    if not (client_id and client_secret):
        raise ConfigError("crowdstrike: secret needs client_id and client_secret")
    key = f"{base}|{client_id}"
    cached = _TOKENS.get(key)
    if cached and cached[1] > time.time():
        return cached[0]
    with httpx.Client(timeout=30.0) as http:
        resp = http.post(
            f"{base}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
        )
        resp.raise_for_status()
        payload = resp.json()
    token = payload["access_token"]
    _TOKENS[key] = (token, time.time() + int(payload.get("expires_in", 1800)) - 60)
    return token


class CrowdStrikeConnector:
    source = "crowdstrike"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        base = base_url(settings)
        token = access_token(base, secret)
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        page = min(int(limit), 1000)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            listed = http.get(
                f"{base}/alerts/queries/alerts/v2",
                params={
                    "filter": f"created_timestamp:>'{since}'",
                    "sort": "created_timestamp|asc",
                    "limit": page,
                    "offset": int(cursor.get("offset", 0)),
                },
            )
            listed.raise_for_status()
            ids = listed.json().get("resources") or []
            if not ids:
                return FetchResult(records=[], cursor={"since": since}, more=False)
            detail = http.post(f"{base}/alerts/entities/alerts/v2", json={"composite_ids": ids})
            detail.raise_for_status()
            records = detail.json().get("resources") or []
        newest = max([str(r.get("created_timestamp", "")) for r in records] + [since])
        # A full page means more to read; offset walks it, and the window only
        # moves once the pages run out.
        if len(ids) >= page:
            return FetchResult(
                records=records,
                cursor={"since": since, "offset": int(cursor.get("offset", 0)) + len(ids)},
                more=True,
            )
        return FetchResult(records=records, cursor={"since": newest}, more=False)


CONNECTOR = CrowdStrikeConnector()
