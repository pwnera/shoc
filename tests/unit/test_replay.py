from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shoc.ingest.replay import expand, has_shapes


def test_repeat_expands_into_unique_records():
    out = expand([{"eventName": "GetObject", "_repeat": 5}], "aws_cloudtrail")
    assert len(out) == 5
    assert len({r["eventID"] for r in out}) == 5
    assert all("_repeat" not in r for r in out)


def test_records_are_placed_just_before_now():
    now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
    out = expand([{"eventName": "ListBuckets", "_repeat": 3}], "aws_cloudtrail", now)
    times = [datetime.fromisoformat(r["eventTime"]) for r in out]
    assert all(now - timedelta(minutes=10) < t < now for t in times)


def test_an_existing_timestamp_is_kept():
    out = expand([{"eventName": "X", "eventTime": "2020-01-01T00:00:00+00:00"}], "aws_cloudtrail")
    assert out[0]["eventTime"] == "2020-01-01T00:00:00+00:00"


def test_github_timestamps_are_epoch_milliseconds():
    out = expand([{"action": "repo.access"}], "github")
    assert isinstance(out[0]["@timestamp"], int)


def test_has_shapes_detects_a_recorded_scenario():
    assert has_shapes([{"_repeat": 2}])
    assert not has_shapes([{"eventName": "X"}])
