"""Every shipped mapping is valid, and each one has a fixture that maps cleanly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shoc.ingest import ocsf
from shoc.store import ocsf as layout
from tests.support import FIXTURES

SOURCES = ocsf.available_sources()


def test_every_connector_and_push_source_has_a_mapping():
    from shoc.ingest import connectors

    for source in connectors.available():
        if source != "file":
            assert source in SOURCES, f"{source} has a connector but no OCSF mapping"
    for source in connectors.push_sources():
        assert source in SOURCES, f"{source} accepts pushes but has no OCSF mapping"


@pytest.mark.parametrize("source", SOURCES)
def test_mapping_targets_only_real_columns(source):
    assert ocsf.load_mapping(source).validate() == []


@pytest.mark.parametrize("source", SOURCES)
def test_mapping_has_a_fixture_and_produces_a_usable_row(source):
    path: Path = FIXTURES / "mappings" / f"{source}.json"
    assert path.exists(), f"{source} needs a mapping fixture at {path}"
    records = json.loads(path.read_text())
    mapping = ocsf.load_mapping(source)
    for record in records:
        row = mapping.map_record(record, "t1")
        assert set(row) == set(layout.COLUMN_NAMES)
        assert row["event_uid"] and row["time"]
        assert row["class_uid"] and row["metadata_product"]
        assert row["severity_id"] in (1, 2, 3, 4, 5)
        assert row["raw"] == record


# OCSF 1.3.0's activity enum for every class a mapping writes; 99 is Other in
# all of them.
ACTIVITIES: dict[int, dict[int, str]] = {
    1001: {
        1: "Create",
        2: "Read",
        3: "Update",
        4: "Delete",
        5: "Rename",
        6: "Set Attributes",
        7: "Set Security",
        8: "Get Attributes",
        9: "Get Security",
        10: "Encrypt",
        11: "Decrypt",
        12: "Mount",
        13: "Unmount",
        14: "Open",
    },
    1002: {1: "Load", 2: "Unload"},
    1004: {
        1: "Allocate Page",
        2: "Modify Page",
        3: "Delete Page",
        4: "Buffer Overflow",
        5: "Disable DEP",
        6: "Enable DEP",
        7: "Read",
        8: "Write",
        9: "Map View",
    },
    1005: {1: "Load", 2: "Unload"},
    1006: {1: "Create", 2: "Update", 3: "Delete", 4: "Enable", 5: "Disable", 6: "Start", 7: "End"},
    1007: {1: "Launch", 2: "Terminate", 3: "Open", 4: "Inject", 5: "Set User ID"},
    2002: {1: "Create", 2: "Update", 3: "Close"},
    2004: {1: "Create", 2: "Update", 3: "Close"},
    201001: {
        1: "Create",
        2: "Read",
        3: "Modify",
        4: "Delete",
        5: "Rename",
        6: "Set Security",
        7: "Restore",
        8: "Import",
        9: "Export",
    },
    201002: {1: "Get", 2: "Set", 3: "Modify", 4: "Delete"},
    3001: {
        1: "Create",
        2: "Enable",
        3: "Password Change",
        4: "Password Reset",
        5: "Disable",
        6: "Delete",
        7: "Attach Policy",
        8: "Detach Policy",
        9: "Lock",
        10: "MFA Factor Enable",
        11: "MFA Factor Disable",
    },
    3002: {
        1: "Logon",
        2: "Logoff",
        3: "Authentication Ticket",
        4: "Service Ticket Request",
        5: "Service Ticket Renew",
        6: "Preauth",
    },
    3004: {
        1: "Create",
        2: "Read",
        3: "Update",
        4: "Delete",
        5: "Move",
        6: "Enroll",
        7: "Unenroll",
        8: "Enable",
        9: "Disable",
        10: "Activate",
        11: "Deactivate",
        12: "Suspend",
        13: "Resume",
    },
    3005: {1: "Assign Privileges", 2: "Revoke Privileges"},
    3006: {
        1: "Assign Privileges",
        2: "Revoke Privileges",
        3: "Add User",
        4: "Remove User",
        5: "Delete",
        6: "Create",
    },
    4001: {1: "Open", 2: "Close", 3: "Reset", 4: "Fail", 5: "Refuse", 6: "Traffic", 7: "Listen"},
    4002: {
        1: "Connect",
        2: "Delete",
        3: "Get",
        4: "Head",
        5: "Options",
        6: "Post",
        7: "Put",
        8: "Trace",
    },
    4003: {1: "Query", 2: "Response", 6: "Traffic"},
    4009: {1: "Send", 2: "Receive", 3: "Scan"},
    4011: {1: "Send", 2: "Receive", 3: "Scan"},
    4012: {1: "Send", 2: "Receive", 3: "Scan"},
    5001: {1: "Log", 2: "Collect"},
    5003: {1: "Log", 2: "Collect"},
    5007: {1: "Query"},
    6001: {
        1: "Create",
        2: "Read",
        3: "Update",
        4: "Delete",
        5: "Search",
        6: "Import",
        7: "Export",
        8: "Share",
    },
    6003: {1: "Create", 2: "Read", 3: "Update", 4: "Delete"},
    6005: {1: "Read", 2: "Update", 3: "Connect", 4: "Query", 5: "Write", 6: "Create", 7: "Delete"},
}


def _every_mapped_row():
    """Each mapping fixture and each rule fixture, mapped as ingest would."""
    from datetime import UTC, datetime

    from shoc.detect import rules as ruleset
    from tests.support import fixture_rows, fixture_source

    for source in SOURCES:
        for record in json.loads((FIXTURES / "mappings" / f"{source}.json").read_text()):
            yield source, ocsf.load_mapping(source).map_record(record, "t1")
    now = datetime.now(UTC)
    for rule in ruleset.load():
        for kind in ("positive", "negative"):
            path = FIXTURES / "rules" / rule.id / f"{kind}.json"
            if path.exists():
                for row in fixture_rows(
                    json.loads(path.read_text()), fixture_source(rule), "t1", now
                ):
                    yield rule.id, row


def test_every_mapped_row_is_valid_ocsf_1_3_0():
    """Class, activity, type and category agree, whatever a `derive` changed (ING-3)."""
    bad = []
    for origin, row in _every_mapped_row():
        cls, act = row["class_uid"], row["activity_id"]
        names = {**ACTIVITIES.get(cls, {}), 99: "Other"}
        if cls not in ACTIVITIES or names.get(act) != row["activity_name"]:
            bad.append(f"{origin}: {cls} {row['class_name']} activity {act} {row['activity_name']}")
        if row["type_uid"] != cls * 100 + act or row["category_uid"] != cls % 100000 // 1000:
            bad.append(f"{origin}: type {row['type_uid']}, category {row['category_uid']}")
        if row["metadata_version"] != "1.3.0":
            bad.append(f"{origin}: metadata_version {row['metadata_version']}")
    assert not bad, "\n".join(sorted(set(bad)))


def test_every_mapping_fixture_holds_several_event_kinds():
    """One record per source tested the happy path and nothing else (ING-3)."""
    for source in SOURCES:
        records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
        mapping = ocsf.load_mapping(source)
        kinds = {
            (row["class_uid"], row["activity_id"], row["api_operation"])
            for row in (mapping.map_record(r, "t1") for r in records)
        }
        assert len(records) >= 3 and len(kinds) >= 3, f"{source}: {len(kinds)} kind(s)"


@pytest.mark.parametrize("source", SOURCES)
def test_mapping_extracts_at_least_one_entity(source):
    records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
    mapping = ocsf.load_mapping(source)
    from shoc.detect.engine import entities_of

    for record in records:
        row = mapping.map_record(record, "t1")
        assert entities_of(row), f"{source}: a mapped row with no entity cannot be correlated"
