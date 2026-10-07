"""OpenAI API Platform connector (ING-1): the audit log, and each key's hourly usage.

Needs an Admin key, which only an organization owner can create, with audit
logs read. The audit log starts when an owner turns it on, in the organization's
data controls, and it cannot be turned off from there afterwards; nothing
before that day exists.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors import llmusage
from shoc.ingest.connectors.base import FetchResult, client, resume, since_default, utc

API = "https://api.openai.com/v1/organization"


class OpenAIConnector:
    source = "openai"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        key = secret.get("admin_key")
        if not key:
            raise ConfigError("openai: the secret needs admin_key, an organization Admin key")
        hours = int(settings.get("backfill_hours", 24))
        with client({"Authorization": f"Bearer {key}"}) as http:
            audit = _audit(http, cursor.get("audit") or {}, min(max(int(limit), 1), 100), hours)
            usage = llmusage.read(
                http,
                f"{API}/usage/completions",
                cursor.get("usage") or {},
                hours,
                "openai",
                _usage_query,
            )
        return llmusage.combine(audit=audit, usage=usage)


def _usage_query(start: datetime, end: datetime) -> list[tuple[str, Any]]:
    return [
        ("start_time", int(start.timestamp())),
        ("end_time", int(end.timestamp())),
        ("bucket_width", "1h"),
        ("group_by[]", "api_key_id"),
        ("group_by[]", "project_id"),
        ("limit", int((end - start).total_seconds() // 3600)),
    ]


def _audit(http: httpx.Client, cursor: dict[str, Any], size: int, hours: int) -> FetchResult:
    since = since_default(cursor, hours=hours)
    params: list[tuple[str, Any]] = [
        ("effective_at[gt]", int(utc(since).timestamp())),
        ("limit", size),
    ]
    if cursor.get("after"):
        params.append(("after", cursor["after"]))
    resp = http.get(f"{API}/audit_logs", params=params)
    resp.raise_for_status()
    body = resp.json()
    records = [_entry(e) for e in body.get("data") or []]
    newest = max(
        [datetime.fromtimestamp(int(e["effective_at"]), tz=UTC).isoformat() for e in records]
        + [str(cursor.get("newest") or since)],
        key=utc,
    )
    if body.get("has_more") and body.get("last_id"):
        held = {"since": since, "newest": newest, "after": body["last_id"]}
        return FetchResult(records=records, cursor=held, more=True)
    # The run loop moves only a top-level `since`; this one moves itself.
    return FetchResult(records=records, cursor={"since": resume(since, newest)}, more=False)


def _entry(entry: dict[str, Any]) -> dict[str, Any]:
    """An audit entry keeps its detail under the event type, `api_key.created`,
    whose dot no rule path can reach: it is copied to `details`, and the key
    the event is about, or the key that acted, to `key_id`."""
    kind = str(entry.get("type") or "")
    details = entry.get(kind) or {}
    acted = ((entry.get("actor") or {}).get("api_key") or {}).get("id")
    return {
        **entry,
        "details": details,
        "key_id": details.get("id") if kind.startswith("api_key.") else acted,
    }


CONNECTOR = OpenAIConnector()
