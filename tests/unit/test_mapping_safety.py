"""What a mapped row holds, whatever the vendor sent (ING-1, ING-3, STO-2, AGT-6)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from shoc.ingest import ocsf
from shoc.ingest.replay import TIME_FIELD, expand, time_paths
from tests.support import FIXTURES


def _storable(row):
    """What Postgres takes: no NUL, and text that encodes as UTF-8."""
    text = json.dumps(row, ensure_ascii=False, default=str)
    text.encode("utf-8")  # a lone surrogate raises here, as it does in psycopg
    return "\x00" not in text and "\\u0000" not in text


def test_nul_and_lone_surrogates_never_reach_the_store():
    record = {
        "id": "fdr-nul",
        "event_simpleName": "ProcessRollup2",
        "UserName": "svc\x00backup",
        "ImageFileName": "\\Device\\HarddiskVolume3\\Temp\\inv\ud800ice.exe",
        "CommandLine": "cmd.exe /c echo \x00",
        "nested": {"key\x00": ["\udc00"]},
    }
    row = ocsf.load_mapping("crowdstrike_fdr").map_record(record, "t1")
    assert _storable(row)
    assert row["actor_user_name"] == "svcbackup"
    assert row["process_file_path"].endswith("inv�ice.exe")
    assert row["raw"]["CommandLine"] == "cmd.exe /c echo "
    assert row["raw"]["nested"] == {"key": ["�"]}
    assert record["UserName"] == "svc\x00backup", "the vendor's record is left as it was"


def test_a_clean_record_maps_unchanged():
    # An astral character is a surrogate pair in UTF-16, never a lone surrogate.
    message = "Sign in \U0001f600"
    record = {"uuid": "u1", "eventType": "user.session.start", "displayMessage": message}
    row = ocsf.load_mapping("okta").map_record(record, "t1")
    assert row["raw"] == record and row["message"] == message


def _okta(published):
    record = {"uuid": "u1", "eventType": "user.session.start", "published": published}
    return ocsf.load_mapping("okta").map_record(record, "t1")


@pytest.mark.parametrize(
    "published",
    [
        "9999-12-31T23:59:59Z",
        "9999-12-31T23:00:00-05:00",
        "1970-01-01T00:00:00Z",
        "not a time",
        "in-three-days",
    ],
)
def test_an_event_time_that_cannot_be_one_becomes_the_ingest_time(published):
    if published == "in-three-days":
        published = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    row = _okta(published)
    assert row["time"] == row["ingested_at"]
    assert row["unmapped"]["_time_original"]
    assert row["raw"]["published"] == published


def test_a_sane_event_time_is_kept():
    row = _okta("2026-09-20T10:00:00Z")
    assert row["time"].startswith("2026-09-20T10:00:00")
    assert "_time_original" not in row["unmapped"]


def test_no_event_time_is_the_ingest_time_with_nothing_to_keep():
    row = ocsf.load_mapping("okta").map_record({"uuid": "u1", "eventType": "x"}, "t1")
    assert row["time"] == row["ingested_at"]
    assert "_time_original" not in row["unmapped"]


def _activity():
    records = json.loads((FIXTURES / "mappings" / "google_workspace.json").read_text())
    return next(r for r in records if len(r.get("events") or []) == 7)


def test_each_event_of_a_workspace_activity_is_its_own_row():
    activity = _activity()
    rows = ocsf.load_mapping("google_workspace").map_records(activity, "t1")
    names = [e["name"] for e in activity["events"]]
    assert [r["api_operation"] for r in rows] == names
    uid = activity["id"]["uniqueQualifier"]
    assert [r["event_uid"] for r in rows] == [uid] + [f"{uid}-{n}" for n in range(1, 7)]
    assert all(len(r["raw"]["events"]) == 1 and r["raw"]["id"] == activity["id"] for r in rows)
    enforce = rows[names.index("ENFORCE_STRONG_AUTHENTICATION")]
    assert enforce["unmapped"]["params"]["NEW_VALUE"] == "true"
    methods = rows[names.index("CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS")]
    assert methods["unmapped"]["params"]["ALLOWED_TWO_STEP_VERIFICATION_METHOD"] == "NO_TELEPHONY"


def test_a_single_event_record_maps_as_before():
    mapping = ocsf.load_mapping("google_workspace")
    record = {"id": {"time": "2026-09-20T10:00:00Z", "uniqueQualifier": "9"}, "events": [{}]}
    assert [r["event_uid"] for r in mapping.map_records(record, "t1")] == ["9"]
    okta = ocsf.load_mapping("okta")
    assert len(okta.map_records({"uuid": "u", "events": [1, 2]}, "t1")) == 1


@pytest.mark.parametrize("source", ocsf.available_sources())
def test_replay_places_every_source_on_a_path_its_mapping_reads(source):
    assert TIME_FIELD.get(source) in time_paths(source), (
        f"{source}: TIME_FIELD must name one of the paths its mapping reads time from"
    )


def test_a_day_offset_moves_an_entra_record_back():
    now = datetime.now(UTC)
    record = expand([{"id": "s1", "_day_offset": 10}], "entra", now)[0]
    row = ocsf.load_mapping("entra").map_record(record, "t1")
    assert datetime.fromisoformat(row["time"]) < now - timedelta(days=9)


def test_a_time_on_any_mapped_path_is_the_records_own():
    out = expand([{"id": "g1", "createdAt": "2026-01-02T00:00:00+00:00"}], "aws_guardduty")
    assert "updatedAt" not in out[0]
