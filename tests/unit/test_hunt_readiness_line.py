"""The packs sentence of hunt.results and hunt.daily (DET-9)."""

from __future__ import annotations

from shoc.capabilities.hunting import _readiness_line


def test_a_learning_pack_without_a_date_names_no_day():
    """A pack learning on its own selection has no ready_at before its first run."""
    line = _readiness_line([{"state": "learning", "ready_at": None}])
    assert line == "Packs: 1 learning."
    assert "None" not in line


def test_the_soonest_dated_learning_pack_is_named():
    rows = [
        {"state": "learning", "ready_at": None},
        {"state": "learning", "ready_at": "2026-10-20T00:00:00+00:00"},
        {"state": "learning", "ready_at": "2026-10-15T00:00:00+00:00"},
        {"state": "ready", "ready_at": None},
    ]
    assert _readiness_line(rows) == (
        "Packs: 3 learning, 1 ready; the first learning pack is ready on 2026-10-15."
    )
