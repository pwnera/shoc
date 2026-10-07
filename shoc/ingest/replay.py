"""Replaying recorded source records (evals, fixtures, the quick start).

A recorded scenario describes *shapes* of events rather than a literal log: a
record may carry `_repeat: 60` to stand for sixty of itself, and it usually has
no timestamp, because a detection window is relative to now. `expand` turns such
a file into concrete records — spread over a recent window, each with a unique
id so the store's dedup does not collapse them.

Records that already carry a timestamp keep it, so a genuine log export replays
unchanged.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any

# Where each source keeps its timestamp and its record id.
# A dotted name is a nested field (`id.time`).
TIME_FIELD = {
    "aws_cloudtrail": "eventTime",
    "okta": "published",
    "github": "@timestamp",
    "stripe": "created",
    "tailscale": "eventTime",
    "google_workspace": "id.time",
    "cloudflare": "action.time",
    "crowdstrike_fdr": "timestamp",
    "defender_hunting": "properties.Timestamp",
    "sentinelone_cloudfunnel": "event.time",
    "sentinelone": "createdAt",
    "cloudflare_logs": "Datetime",
    "aws_guardduty": "updatedAt",
    "gcp_audit": "timestamp",
    "gitlab": "created_at",
    "anthropic": "created_at",
    "openai": "effective_at",
}
# Tailscale entries carry no id; they are keyed by their content, time included.
ID_FIELD = {
    "aws_cloudtrail": "eventID",
    "okta": "uuid",
    "github": "_document_id",
    "cloudflare": "id",
    "stripe": "id",
    "openai": "id",
    "anthropic": "id",
    "google_workspace": "id.uniqueQualifier",
    "crowdstrike_fdr": "id",
    "sentinelone_cloudfunnel": "event.id",
    "sentinelone": "id",
    "aws_guardduty": "id",
    "gcp_audit": "insertId",
    "gitlab": "id",
    # Without these a repeated Entra or Microsoft 365 record kept one id, and
    # five failed sign-ins were stored as one event the rule had counted five.
    "entra": "id",
    "m365": "Id",
}


def get_path(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def set_path(record: dict[str, Any], path: str, value: Any) -> None:
    *parents, leaf = path.split(".")
    node = record
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value


def drop_path(record: dict[str, Any], path: str) -> None:
    *parents, leaf = path.split(".")
    node: Any = record
    for part in parents:
        node = node.get(part) if isinstance(node, dict) else None
    if isinstance(node, dict):
        node.pop(leaf, None)


REPEAT_KEY = "_repeat"
# Days before `now` a record sits, so a scenario can carry a week of history.
DAY_OFFSET_KEY = "_day_offset"


def expand(
    records: list[dict[str, Any]],
    source: str,
    now: datetime | None = None,
    spread_seconds: int = 120,
) -> list[dict[str, Any]]:
    """Expand `_repeat`, stamp unique ids, and place the records just before `now`."""
    now = now or datetime.now(UTC)
    time_field = TIME_FIELD.get(source)
    id_field = ID_FIELD.get(source)
    out: list[dict[str, Any]] = []
    index = 0
    for record in records:
        count = int(record.get(REPEAT_KEY, 1))
        for _ in range(count):
            item = copy.deepcopy(record)
            item.pop(REPEAT_KEY, None)
            days = float(item.pop(DAY_OFFSET_KEY, 0) or 0)
            ts = now - timedelta(days=days, seconds=(index % spread_seconds) + 5)
            if time_field and not get_path(item, time_field):
                set_path(
                    item,
                    time_field,
                    int(ts.timestamp() * 1000) if source == "github" else ts.isoformat(),
                )
            if id_field:
                set_path(item, id_field, f"{get_path(item, id_field) or source}-{index}")
            out.append(item)
            index += 1
    return out


def shift_time(iso: str, seconds: float) -> str:
    """Move a mapped event in time, keeping its distance from its neighbours.

    A public dataset is years old: retention drops it and every detection window
    is relative to now, so a replay has to move it forward. Shifting every event
    by the same offset preserves the spacing, which is what a rate or burst rule
    actually reads.
    """
    return (datetime.fromisoformat(iso) + timedelta(seconds=seconds)).isoformat()


def has_shapes(records: list[dict[str, Any]]) -> bool:
    """True when the file is a recorded scenario rather than a literal log export."""
    return any(REPEAT_KEY in r for r in records)
