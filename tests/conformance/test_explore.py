"""The explorer's queries, run on a real store. Every adapter must agree (STO-1)."""

from __future__ import annotations

import pytest

from shoc.capabilities.events import EventQuery, SummarizeInput
from shoc.capabilities.events import query as events_query
from shoc.capabilities.events import summarize as events_summarize
from shoc.ingest import batch, ocsf
from tests.support import expand

pytestmark = pytest.mark.postgres


def _load(store, tenant, now, records):
    mapping = ocsf.load_mapping("aws_cloudtrail")
    rows = [mapping.map_record(r, tenant) for r in expand(records, "aws_cloudtrail", now)]
    return batch.load(store, rows).rows


def _seed(store, config, now):
    return _load(
        store,
        config.tenant_id,
        now,
        [
            {
                "eventID": "explore-1",
                "eventName": "GetSecretValue",
                "eventSource": "secretsmanager.amazonaws.com",
                "sourceIPAddress": "203.0.113.10",
                "errorCode": "AccessDenied",
                "userIdentity": {"type": "IAMUser", "userName": "deploy-ci"},
                "_repeat": 3,
            },
            {
                "eventID": "explore-2",
                "eventName": "ListBuckets",
                "eventSource": "s3.amazonaws.com",
                "sourceIPAddress": "198.51.100.7",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
                "_repeat": 2,
            },
        ],
    )


def test_a_one_box_query_narrows_by_field(ctx, store, config, clean, now):
    assert _seed(store, config, now) == 5

    page = events_query.fn(ctx, EventQuery(since="-1h", q="actor.user.name=deploy-ci"))
    assert page.data.count == 3
    assert {row["api_operation"] for row in page.data.rows} == {"GetSecretValue"}
    assert page.citations and len(page.citations) == 3

    both = events_query.fn(ctx, EventQuery(since="-1h", q="api.operation~bucket"))
    assert both.data.count == 2

    numeric = events_query.fn(ctx, EventQuery(since="-1h", q="severity_id>=1 alice"))
    assert numeric.data.count == 2


def test_an_unknown_field_is_an_error_not_an_empty_page(ctx, store, config, clean, now):
    from shoc.errors import ValidationError

    _seed(store, config, now)
    with pytest.raises(ValidationError):
        events_query.fn(ctx, EventQuery(since="-1h", q="actor.user.nam=deploy-ci"))


def test_the_whole_original_record_comes_back_when_asked(ctx, store, config, clean, now):
    _seed(store, config, now)
    page = events_query.fn(ctx, EventQuery(since="-1h", include_raw=True, limit=1))
    row = page.data.rows[0]
    assert row["raw"]["eventSource"].endswith("amazonaws.com")
    assert "unmapped" in row

    narrow = events_query.fn(ctx, EventQuery(since="-1h", limit=1))
    assert "raw" not in narrow.data.rows[0]


def test_the_histogram_buckets_the_window(ctx, store, config, clean, now):
    _seed(store, config, now)
    result = events_summarize.fn(ctx, SummarizeInput(since="-1h", by="time"))
    assert result.data.interval == "minute"
    assert result.data.total == 5
    assert sum(group.count for group in result.data.rows) == 5


def test_a_field_summary_ranks_its_values(ctx, store, config, clean, now):
    _seed(store, config, now)
    result = events_summarize.fn(ctx, SummarizeInput(since="-1h", by="actor.user.name", limit=10))
    assert [(g.key, g.count) for g in result.data.rows] == [("deploy-ci", 3), ("alice", 2)]

    filtered = events_summarize.fn(
        ctx, SummarizeInput(since="-1h", by="api.operation", q="status=Failure")
    )
    assert [(g.key, g.count) for g in filtered.data.rows] == [("GetSecretValue", 3)]
