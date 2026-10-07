"""Anthropic (Claude API) connector (ING-1): the activity feed, new API keys,
and each key's hourly usage.

Needs an Admin key, which organization admins create; individual accounts have
no Admin API. The Compliance API activity feed is Anthropic's audit log for a
SIEM: sign-ins, key and member changes, with the actor's address. An admin turns
it on in the Console, and an Admin key made before that cannot read it; set
`activity_feed` once it is on. Without it, a key that was not in the list at
the last read is the event. Usage stays either way: a leaked key shows up there.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors import llmusage
from shoc.ingest.connectors.base import FetchResult, client, since_default, utc

API = "https://api.anthropic.com/v1/organizations"
FEED = "https://api.anthropic.com/v1/compliance/activities"
VERSION = "2023-06-01"


def headers(secret: dict[str, Any]) -> dict[str, str]:
    key = secret.get("admin_key")
    if not key:
        raise ConfigError("anthropic: the secret needs admin_key, an Admin API key")
    return {"x-api-key": str(key), "anthropic-version": VERSION}


class AnthropicConnector:
    source = "anthropic"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        hours = int(settings.get("backfill_hours", 24))
        with client(headers(secret)) as http:
            keys = _new_keys(http, cursor.get("keys") or {}, hours)
            usage = llmusage.read(
                http,
                f"{API}/usage_report/messages",
                cursor.get("usage") or {},
                hours,
                "anthropic",
                _usage_query,
            )
            if not settings.get("activity_feed"):
                return llmusage.combine(keys=keys, usage=usage)
            feed = _activities(http, cursor.get("feed") or {}, limit, hours)
        return llmusage.combine(keys=keys, usage=usage, feed=feed)


def _usage_query(start: datetime, end: datetime) -> list[tuple[str, Any]]:
    return [
        ("starting_at", start.isoformat()),
        ("ending_at", end.isoformat()),
        ("bucket_width", "1h"),
        ("group_by[]", "api_key_id"),
        ("limit", int((end - start).total_seconds() // 3600)),
    ]


def _new_keys(http: httpx.Client, cursor: dict[str, Any], hours: int) -> FetchResult:
    """Every key created after the cursor, read from the whole list.

    The list is small and has no creation filter, so it is read to the end each
    time; `since` moves to the newest key seen.
    """
    since = since_default(cursor, hours=hours)
    found: list[dict[str, Any]] = []
    params: dict[str, Any] = {"limit": 1000}
    for _ in range(20):
        resp = http.get(f"{API}/api_keys", params=params)
        resp.raise_for_status()
        body = resp.json()
        found += body.get("data") or []
        if not (body.get("has_more") and body.get("last_id")):
            break
        params["after_id"] = body["last_id"]
    fresh = [k for k in found if k.get("created_at") and utc(k["created_at"]) > utc(since)]
    records = [{**k, "event": "api_key.created", "key_id": k.get("id")} for k in fresh]
    newest = max([str(k["created_at"]) for k in fresh] + [since], key=utc)
    return FetchResult(records=records, cursor={"since": newest})


def _activities(http: httpx.Client, cursor: dict[str, Any], limit: int, hours: int) -> FetchResult:
    """Oldest first, a minute behind now as Anthropic advises; `after_id` pages
    through the window it was issued for."""
    since = since_default(cursor, hours=hours)
    params: dict[str, Any] = {
        "order": "asc",
        "limit": min(int(limit), 1000),
        "created_at.gt": since,
        "created_at.lt": cursor.get("until")
        or (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
    }
    if cursor.get("after"):
        params["after_id"] = cursor["after"]
    resp = http.get(FEED, params=params)
    resp.raise_for_status()
    body = resp.json()
    records = body.get("data") or []
    newest = max([str(r["created_at"]) for r in records if r.get("created_at")] + [since], key=utc)
    if body.get("has_more") and body.get("last_id"):
        held = {"since": since, "until": params["created_at.lt"], "after": body["last_id"]}
        return FetchResult(records=records, cursor=held, more=True)
    # Delivery is at least once and rows dedupe on `id`, so the next window
    # can start at the newest record read.
    return FetchResult(records=records, cursor={"since": newest})


CONNECTOR = AnthropicConnector()
