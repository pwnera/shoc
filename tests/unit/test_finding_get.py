"""finding.get reads its cited events one row each (DET-3, wh-7)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shoc.capabilities import findings
from shoc.capabilities.registry import Caller, Context
from tests.unit.test_events_query import _Store

T0 = datetime(2026, 10, 1, tzinfo=UTC)


def test_an_alert_updated_in_place_does_not_hide_another_cited_event(monkeypatch):
    row = {
        "finding_uid": "F-1",
        "rule_id": "a_rule",
        "title": "A finding",
        "severity": "high",
        "entity_key": "u",
        "event_count": 2,
        "first_seen": T0,
        "last_seen": T0,
        "event_uids": ["A", "B"],
    }
    monkeypatch.setattr(findings, "fetch_one", lambda *args: row)
    rows = [{"event_uid": "A", "time": T0 + timedelta(minutes=m), "n": m} for m in (1, 2, 3)]
    rows.append({"event_uid": "B", "time": T0, "n": 0})
    ctx = Context(tenant_id="t1", caller=Caller())
    ctx._db, ctx._store = object(), _Store(rows)
    got = findings.get_finding.fn(ctx, findings.FindingRef(finding_uid="F-1"))
    assert [e["event_uid"] for e in got.data.events] == ["A", "B"]
    assert got.data.events[0]["n"] == 3, "the alert's newest row stands for it"
