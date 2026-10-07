"""Azure Activity Log categories pick the class, in both serialisations (ING-3)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shoc.ingest import ocsf
from tests.support import FIXTURES

RECORDS = json.loads((FIXTURES / "mappings" / "azure_activity.json").read_text())


def row(category: str) -> dict[str, Any]:
    """The REST-shape record of a category, where `category` is an object."""
    record = next(
        r
        for r in RECORDS
        if isinstance(r.get("category"), dict) and r["category"]["value"] == category
    )
    return ocsf.load_mapping("azure_activity").map_record(record, "t1")


@pytest.mark.parametrize(
    ("category", "class_uid", "activity_id"),
    [
        ("Administrative", 6003, 3),
        ("Policy", 6003, 99),
        ("ServiceHealth", 6003, 99),
        ("Alert", 2004, 3),
        ("Security", 2004, 1),
    ],
)
def test_category_picks_the_class(category, class_uid, activity_id):
    mapped = row(category)
    assert (mapped["class_uid"], mapped["activity_id"]) == (class_uid, activity_id)
    assert mapped["type_uid"] == class_uid * 100 + activity_id


def test_a_defender_for_cloud_alert_keeps_its_severity_and_process():
    mapped = row("Security")
    assert mapped["severity_id"] == 4
    assert mapped["process_pid"] == 6988 and mapped["process_cmd_line"].endswith(".pdf.exe")


def test_the_event_hub_shape_reads_the_same_fields():
    record = next(r for r in RECORDS if r.get("category") == "Administrative")
    mapped = ocsf.load_mapping("azure_activity").map_record(record, "t1")
    assert mapped["actor_user_name"] == "dana@example.com"
    assert mapped["src_endpoint_ip"] == "198.51.100.40"
    assert mapped["status"] == "Success" and mapped["severity_id"] == 3


def test_the_caller_kind_comes_from_the_authorization_evidence():
    record = next(r for r in RECORDS if r.get("category") == "Administrative")
    assert ocsf.load_mapping("azure_activity").map_record(record, "t1")["actor_user_type"] == "User"
