"""A Defender alert's evidence list fills the host, process and file columns (ING-3)."""

from __future__ import annotations

import json

from shoc.ingest import ocsf
from tests.support import FIXTURES

RECORDS = json.loads((FIXTURES / "mappings" / "defender.json").read_text())


def test_each_evidence_type_fills_its_own_columns():
    record = next(r for r in RECORDS if r["category"] == "Impact")
    row = ocsf.load_mapping("defender").map_record(record, "t1")
    assert row["device_hostname"] == "laptop-21.example.org"
    assert row["device_uid"] == row["resource_uid"] == "2222222222222222222222222222222222222222"
    assert row["actor_user_name"] == "jdoe@example.com"
    assert (row["process_name"], row["process_pid"], row["process_parent_name"]) == (
        "invoice.pdf.exe",
        7311,
        "explorer.exe",
    )
    assert row["process_hash_sha256"].startswith("e3b0c442")
    assert row["file_path"] == "README_RESTORE.txt" and row["file_hash_sha256"].startswith(
        "6b86b273"
    )
    assert row["http_request_url"] == "https://files.example.net/payload/invoice.pdf.exe"
    assert row["severity_id"] == 4


def test_service_source_and_defenders_own_verdict_are_read():
    record = next(r for r in RECORDS if r["category"] == "Impact")
    mapping = ocsf.load_mapping("defender")
    assert mapping.map_record(record, "t1")["api_service_name"] == "microsoftDefenderForEndpoint"
    for verdict in ({"classification": "falsePositive"}, {"determination": "securityTesting"}):
        assert mapping.map_record({**record, **verdict}, "t1")["severity_id"] == 1
    legacy = next(r for r in RECORDS if r["category"] == "Execution")
    assert mapping.map_record(legacy, "t1")["api_service_name"] == "defender"
