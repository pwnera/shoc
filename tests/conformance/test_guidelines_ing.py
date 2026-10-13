"""The ingest guidelines that need a store (ING-G5), on every backend reached."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shoc.ingest import batch, ocsf

pytestmark = pytest.mark.postgres


def _uids(store) -> set[str]:
    result = store.query(
        "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id",
        {"tenant_id": store.tenant_id},
    )
    return {str(r["event_uid"]) for r in result.rows}


def test_a_row_the_store_refuses_does_not_refuse_its_batch(store, clean):
    """ING-G5: every EventStore loads the rest of a batch around a row it refuses."""
    mapping = ocsf.load_mapping("okta")
    published = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    rows = [
        row
        for n in range(5)
        for row in mapping.map_records(
            {"uuid": f"ing-g5-{n}", "eventType": "user.session.start", "published": published},
            store.tenant_id,
        )
    ]
    # Past what map_record cleans: a NUL Postgres refuses in text.
    rows[2]["message"] = "bad\x00byte"
    stats = batch.load(store, rows)
    clean_uids = {f"ing-g5-{n}" for n in (0, 1, 3, 4)}
    assert clean_uids <= _uids(store), "the rows around the refused one are stored"
    assert stats.rows + stats.skipped == len(rows), "a row left out is counted, not lost"
