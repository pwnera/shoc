"""Alerts a vendor changes in place: Defender, Falcon and SentinelOne (ING-1, ING-3).

Their connectors poll on the update time, so each change to an alert is read as
a row of its own. A row is marked `_update` when its alert was created at or
before `created`, the newest creation time an earlier walk read: the
creation-time poll these connectors ran before would already have read it. The
update cursor cannot stand in for `created`. An older alert changed at 12:00
would push it past a new alert created at 11:59 that the vendor lists at 12:03,
and that alert would never open a finding.

`created` is compared less `OVERLAP`, the stretch a poll re-reads (D164): an
alert created just before `created` that the vendor lists late is new, not an
update. The cost is that a change to an alert created in the last `OVERLAP`
before `created` reads as new too, and can open a second finding.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from shoc.ingest.connectors.base import OVERLAP, utc
from shoc.ingest.ocsf import TRANSFORMS


def upgrade(cursor: dict[str, Any]) -> dict[str, Any]:
    """A cursor written before `created` existed held a creation time in
    `since`, and any page token in it belonged to the creation-time filter:
    a new walk starts from that time."""
    if "created" in cursor or not cursor.get("since"):
        return cursor
    return {"since": cursor["since"], "created": cursor["since"]}


def mark(
    records: list[dict[str, Any]], created: list[Any], cursor: dict[str, Any], since: str
) -> dict[str, str]:
    """Mark the records created at or before the walk's `created` less
    `OVERLAP`, and return the fields to carry: `created`, held while the walk
    pages, and `created_newest`, which becomes `created` once it ends. A
    creation time that does not parse marks nothing, and one ahead of now
    counts as now."""
    held = utc(str(cursor.get("created") or since))
    newest = utc(str(cursor.get("created_newest") or held.isoformat()))
    now = datetime.now(UTC)
    for record, value in zip(records, created, strict=True):
        try:  # None and "" do not parse either
            when = datetime.fromisoformat(TRANSFORMS["iso8601"](value))
        except (TypeError, ValueError, OverflowError):
            continue
        if when <= held - OVERLAP:
            record["_update"] = True
        newest = max(newest, min(when, now))
    return {"created": held.isoformat(), "created_newest": newest.isoformat()}
