"""Stripe connector (ING-1): the account's activity log and its payment events.

The activity log says who created, viewed or deleted an API key and whose team
roles changed; it is a public preview, starts on 2026-04-01, keeps six months,
and carries no address. Events are where fraud shows: failed charges, which is
what card testing looks like, and early fraud warnings. Each keeps its own
cursor under one source.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, resume, since_default, utc

API = "https://api.stripe.com"
PREVIEW = "2026-07-29.preview"
EVENT_TYPES = ("charge.failed", "radar.early_fraud_warning.created")
PAGE = 100


class StripeConnector:
    source = "stripe"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        key = secret.get("api_key")
        if not key:
            raise ConfigError("stripe: the secret needs api_key, a restricted key")
        size = max(1, min(int(limit), PAGE))
        hours = int(settings.get("backfill_hours", 24))
        with client({"Authorization": f"Bearer {key}"}) as http:
            logs = _activity(http, cursor.get("logs") or {}, size)
            events = _events(http, cursor.get("events") or {}, size, hours)
        return FetchResult(
            records=logs.records + events.records,
            cursor={"logs": logs.cursor, "events": events.cursor},
            more=logs.more or events.more,
        )


def _activity(http: httpx.Client, cursor: dict[str, Any], size: int) -> FetchResult:
    """Oldest first. The next-page URL is where polling goes on from, and it
    is good for ten days; after that, or when Stripe refuses it, the walk
    starts again from the beginning and what is re-read loads once."""
    url = cursor.get("next") or f"/v2/iam/activity_logs?limit={size}"
    resp = http.get(API + url if url.startswith("/") else url, headers={"Stripe-Version": PREVIEW})
    if resp.status_code == 400 and cursor.get("next"):
        return _activity(http, {}, size)
    resp.raise_for_status()
    body = resp.json()
    records = body.get("data") or []
    return FetchResult(
        records=records,
        cursor={"next": body.get("next_page_url") or url},
        more=len(records) >= size,
    )


def _events(http: httpx.Client, cursor: dict[str, Any], size: int, hours: int) -> FetchResult:
    """Newest first: `since` is held while paging back with `starting_after`."""
    since = since_default(cursor, hours=hours)
    params: list[tuple[str, Any]] = [
        ("created[gt]", int(utc(since).timestamp())),
        ("limit", size),
        *(("types[]", t) for t in EVENT_TYPES),
    ]
    if cursor.get("after"):
        params.append(("starting_after", cursor["after"]))
    resp = http.get(f"{API}/v1/events", params=params)
    resp.raise_for_status()
    body = resp.json()
    records = body.get("data") or []
    newest = max(
        [datetime.fromtimestamp(int(e["created"]), tz=UTC).isoformat() for e in records]
        + [str(cursor.get("newest") or since)],
        key=utc,
    )
    if body.get("has_more") and records:
        held = {"since": since, "newest": newest, "after": records[-1]["id"]}
        return FetchResult(records=records, cursor=held, more=True)
    # The run loop moves only a top-level `since`; this one moves itself.
    return FetchResult(records=records, cursor={"since": resume(since, newest)}, more=False)


CONNECTOR = StripeConnector()
