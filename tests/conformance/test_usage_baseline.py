"""A model API key is judged against its own week, not a fixed threshold (ING-1)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from shoc.detect import rules as ruleset
from shoc.detect.engine import run_rule
from shoc.ingest import batch
from tests.support import fixture_rows

pytestmark = pytest.mark.postgres


def _usage(key: str, tokens: int, when) -> dict:
    return {
        "id": f"openai-usage-{key}-{tokens}",
        "event": "usage",
        "key_id": key,
        "api_key_id": key,
        "project_id": "proj_abc",
        "output_tokens": tokens,
        "effective_at": when.isoformat(),
    }


def test_a_key_fires_on_a_band_it_has_not_reached_this_week(store, config, clean, now):
    rule = next(r for r in ruleset.load() if r.id == "openai_api_key_usage_spike")
    day = timedelta(days=1)
    records = [
        {
            "id": "audit-old",
            "type": "project.created",
            "effective_at": (now - 8 * day).isoformat(),
            "actor": {"type": "session", "session": {"user": {"email": "owner@example.com"}}},
        },
        # Both keys ran at ten million an hour two days ago.
        _usage("key_busy", 12_000_000, now - 2 * day),
        _usage("key_hot", 12_000_000, now - 2 * day),
        _usage("key_busy", 15_000_000, now - timedelta(minutes=10)),
        _usage("key_hot", 120_000_000, now - timedelta(minutes=10)),
        _usage("key_new", 1_500_000, now - timedelta(minutes=10)),
    ]
    batch.load(store, fixture_rows(records, "openai", config.tenant_id, now))
    found = run_rule(store, config.tenant_id, rule, now - timedelta(hours=1), now)
    assert sorted(f.entity_key for f in found) == ["key_hot", "key_new"]
