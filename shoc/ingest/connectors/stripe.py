"""Stripe connector (ING-1): the account's activity log and its payment events.

The activity log says who created, viewed or deleted an API key and whose team
roles changed, and from 2026-10-05 who turned off two-step authentication, SSO
or anomaly detection and whose sign-in factors changed; it is a public preview,
starts on 2026-04-01, keeps six months, and carries no address. Events are
where money shows: failed charges, which is what card testing looks like, early
fraud warnings, and payouts. Each keeps its own cursor under one source.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, since_default, utc

API = "https://api.stripe.com"
PREVIEW = "2026-09-30.preview"
EVENT_TYPES = ("charge.failed", "radar.early_fraud_warning.created", "payout.created")
PAGE = 100
# What stripe_payout_to_new_destination compares a payout's destination with.
PAYOUT_HISTORY = timedelta(days=60)


class StripeConnector:
    source = "stripe"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        key = secret.get("api_key")
        if not key:
            raise ConfigError("stripe: the secret needs api_key, a restricted key")
        size = max(1, min(int(limit), PAGE))
        held = cursor.get("events") or {}
        since = since_default(held, hours=int(settings.get("backfill_hours", 24)))
        with client({"Authorization": f"Bearer {key}"}) as http:
            logs = _activity(http, cursor.get("logs") or {}, size)
            events = _events(http, held, size, since)
            first = not cursor.get("payouts") and any(
                e.get("type") == "payout.created" for e in events.records
            )
            history = _payouts(http, since) if first else []
        return FetchResult(
            records=logs.records + events.records + history,
            cursor={
                "logs": logs.cursor,
                "events": events.cursor,
                "payouts": bool(cursor.get("payouts") or first),
            },
            more=logs.more or events.more,
        )


def _activity(http: httpx.Client, cursor: dict[str, Any], size: int) -> FetchResult:
    """Oldest first. The next-page URL is where polling goes on from, and it
    is good for ten days; after that, when Stripe refuses it, or when it came
    from another preview version, which may have left out action types this
    one returns, the walk starts again from the beginning and what is re-read
    loads once."""
    if cursor.get("version") != PREVIEW:
        cursor = {}
    url = cursor.get("next") or f"/v2/iam/activity_logs?limit={size}"
    resp = http.get(API + url if url.startswith("/") else url, headers={"Stripe-Version": PREVIEW})
    if resp.status_code == 400 and cursor.get("next"):
        return _activity(http, {}, size)
    resp.raise_for_status()
    body = resp.json()
    records = body.get("data") or []
    return FetchResult(
        records=records,
        cursor={"next": body.get("next_page_url") or url, "version": PREVIEW},
        more=len(records) >= size,
    )


def _events(http: httpx.Client, cursor: dict[str, Any], size: int, since: str) -> FetchResult:
    """Newest first: `since` is held while paging back with `starting_after`."""
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
    return FetchResult(records=records, cursor={"since": newest}, more=False)


def _payouts(http: httpx.Client, before: str) -> list[dict[str, Any]]:
    """The payouts of the `PAYOUT_HISTORY` up to where the events stream
    starts, each as the `payout.created` event it had, read once: when the
    first payout event arrives, which also shows the key can read payouts.
    /v1/events keeps 30 days, and a destination is compared with 60. These
    payouts are older than the rule's own history is long, so none of them
    fires (D157)."""
    end = utc(before)
    params: dict[str, Any] = {
        "created[gte]": int((end - PAYOUT_HISTORY).timestamp()),
        "created[lte]": int(end.timestamp()),
        "limit": PAGE,
    }
    found: list[dict[str, Any]] = []
    while True:
        resp = http.get(f"{API}/v1/payouts", params=params)
        resp.raise_for_status()
        body = resp.json()
        found += body.get("data") or []
        if not (body.get("has_more") and found):
            break
        params["starting_after"] = found[-1]["id"]
    return [
        {"id": p["id"], "type": "payout.created", "created": p["created"], "data": {"object": p}}
        for p in found
    ]


CONNECTOR = StripeConnector()
