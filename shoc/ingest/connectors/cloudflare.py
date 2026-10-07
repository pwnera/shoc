"""Cloudflare account audit-log connector (ING-1): Audit Logs v2.

On every plan, Free included, with 18 months of history behind the API. v2
logs creates, updates and deletes that succeeded; reads and refused requests
are not in it. `action.type` is only create, update or delete, so rules tell
one operation from another by `raw.method` and `raw.uri`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, since_default

API = "https://api.cloudflare.com/client/v4"


def credentials(settings: dict[str, Any], secret: dict[str, Any]) -> list[tuple[str, str]]:
    """shoc's own token, by the id Cloudflare's audit log records it under."""
    token = secret.get("api_token")
    if not token:
        return []
    account = settings.get("account_id")
    paths = [f"{API}/user/tokens/verify"]
    if account:  # an account-owned token verifies under its account
        paths.insert(0, f"{API}/accounts/{account}/tokens/verify")
    with client({"Authorization": f"Bearer {token}"}) as http:
        for path in paths:
            resp = http.get(path)
            if resp.is_success:
                token_id = str((resp.json().get("result") or {}).get("id") or "")
                return [(token_id, "")] if token_id else []
    return []


class CloudflareConnector:
    source = "cloudflare"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        account = settings.get("account_id")
        token = secret.get("api_token")
        if not account or not token:
            raise ConfigError("cloudflare: settings need account_id and the secret needs api_token")
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        # `since` and `before` are both required, and a cursor pages through the
        # window it was issued for, so `before` is held with it.
        before = str(cursor.get("before") or datetime.now(UTC).isoformat())
        params: dict[str, Any] = {
            "since": since,
            "before": before,
            "direction": "asc",
            "limit": min(int(limit), 1000),
        }
        if cursor.get("page"):
            params["cursor"] = cursor["page"]
        with client({"Authorization": f"Bearer {token}"}) as http:
            resp = http.get(f"{API}/accounts/{account}/logs/audit", params=params)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("result") or []
        newest = max(
            [str((r.get("action") or {}).get("time") or "") for r in records]
            + [str(cursor.get("newest") or since)]
        )
        page = (payload.get("result_info") or {}).get("cursor")
        if page and records:
            held = {"since": since, "before": before, "newest": newest, "page": page}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


CONNECTOR = CloudflareConnector()
