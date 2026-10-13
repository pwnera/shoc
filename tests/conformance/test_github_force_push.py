"""Each kind of force push fires on its own, not only beside a push to main (DET-2)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from shoc.detect import rules as ruleset
from shoc.detect.engine import run_rule
from shoc.ingest import batch
from tests.support import fixture_rows, fixture_source, load_fixture

pytestmark = pytest.mark.postgres

RULE = next(r for r in ruleset.load() if r.id == "github_force_push_to_default_branch")


@pytest.mark.parametrize(
    "record",
    load_fixture(RULE.id, "positive"),
    ids=lambda r: r["_document_id"],
)
def test_every_positive_record_fires_alone(record, store, config, clean, now):
    rows = fixture_rows([record], fixture_source(RULE), config.tenant_id, now)
    batch.load(store, rows)
    findings = run_rule(
        store, config.tenant_id, RULE, now - timedelta(hours=1), now + timedelta(minutes=1)
    )
    assert findings, f"{record['_document_id']} raised nothing"
