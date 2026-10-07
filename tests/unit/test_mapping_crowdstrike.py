"""CrowdStrike: the Alerts API, Event Streams records and FDR telemetry (ING-3)."""

from __future__ import annotations

import json

import pytest

from shoc.ingest import ocsf
from tests.support import FIXTURES


def first(rows: list[dict], key) -> dict:
    """The first row of each kind, which is the one the fixture lists first."""
    out: dict = {}
    for row in rows:
        out.setdefault(key(row["raw"]), row)
    return out


def rows(source: str) -> list[dict]:
    mapping = ocsf.load_mapping(source)
    records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
    return [mapping.map_record(r, "t1") for r in records]


def test_an_alerts_api_entity_fills_host_process_and_parent():
    row = next(r for r in rows("crowdstrike") if r["raw"].get("agent_id"))
    assert (row["class_uid"], row["severity_id"]) == (2004, 4)
    assert row["device_hostname"] == row["src_endpoint_domain"] == "laptop-33"
    assert row["device_uid"] == row["resource_uid"] == "5d40e8a1c7b6"
    assert row["process_name"] == "powershell.exe" and row["process_pid"] == 6120
    assert row["process_parent_name"] == "WINWORD.EXE"
    assert row["process_cmd_line"].startswith("powershell.exe -nop")


def test_a_prevented_alert_drops_to_medium_and_identity_alerts_name_their_product():
    mapping = ocsf.load_mapping("crowdstrike")
    base = {
        "composite_id": "ldt:1",
        "type": "ldt",
        "product": "epp",
        "severity": 70,
        "device": {"device_id": "d1", "hostname": "laptop-1"},
    }
    assert mapping.map_record(base, "t1")["severity_id"] == 4
    prevented = {**base, "pattern_disposition_description": "Prevention, process killed."}
    assert mapping.map_record(prevented, "t1")["severity_id"] == 3
    assert mapping.map_record({**prevented, "severity": 90}, "t1")["severity_id"] == 5
    idp = next(r for r in rows("crowdstrike") if r["raw"].get("type", "").startswith("idp-"))
    assert idp["api_service_name"] == "idp"


def test_stream_records_that_are_not_findings_get_their_own_class():
    by_type = first(rows("crowdstrike"), lambda raw: (raw.get("metadata") or {}).get("eventType"))
    assert by_type["AuthActivityAuditEvent"]["class_uid"] == 3002
    assert by_type["UserActivityAuditEvent"]["class_uid"] == 6003
    firewall = by_type["FirewallMatchEvent"]
    assert (firewall["class_uid"], firewall["activity_id"], firewall["severity_id"]) == (4001, 5, 1)
    assert firewall["process_name"] == "ssh" and firewall["dst_endpoint_port"] == 22
    assert by_type["Vertex"]["class_uid"] == 1007
    assert by_type["EppDetectionSummaryEvent"]["class_uid"] == 2004


def test_an_on_demand_scan_names_a_file_and_no_process():
    row = next(r for r in rows("crowdstrike") if (r["raw"].get("event") or {}).get("Type") == "ods")
    assert row["process_name"] is None and row["file_path"].endswith("testfile.vmx")


@pytest.mark.parametrize(
    ("name", "class_uid", "activity_id"),
    [
        ("ProcessRollup2", 1007, 1),
        ("EndOfProcess", 1007, 2),
        ("DnsRequest", 4003, 1),
        ("NetworkReceiveAcceptIP4", 4001, 1),
        ("UserLogonFailed2", 3002, 1),
        ("UserAccountAddedToGroup", 3006, 3),
        ("NewExecutableWritten", 1001, 1),
        ("ScheduledTaskRegistered", 1006, 1),
        ("AsepValueUpdate", 201002, 2),
        ("ClassifiedModuleLoad", 1005, 1),
        ("SensorHeartbeat", 1007, 99),
    ],
)
def test_fdr_classes_follow_event_simple_name(name, class_uid, activity_id):
    row = next(r for r in rows("crowdstrike_fdr") if r["raw"].get("event_simpleName") == name)
    assert (row["class_uid"], row["activity_id"]) == (class_uid, activity_id)
    assert row["type_uid"] == class_uid * 100 + activity_id
    assert row["severity_id"] == 1 and row["device_uid"]


def test_fdr_rows_carry_the_columns_a_hunt_pivots_on():
    fdr = first(rows("crowdstrike_fdr"), lambda raw: raw["event_simpleName"])
    process = fdr["ProcessRollup2"]
    assert process["process_name"] == "rundll32.exe"
    assert process["process_parent_name"] == "setup.exe" and process["process_pid"] == 17600
    assert process["process_file_path"].endswith("\\Windows\\System32\\rundll32.exe")
    assert process["file_path"] is None
    assert fdr["DnsRequest"]["dns_query_hostname"] == "roaming.example.org"
    assert fdr["DnsRequest"]["dst_endpoint_domain"] is None
    connect = fdr["NetworkConnectIP4"]
    assert connect["dst_endpoint_port"] == 443 and connect["dst_endpoint_ip"]
    logon = fdr["UserLogonFailed2"]
    assert logon["status"] == "Failure" and logon["src_endpoint_ip"] == "198.51.100.78"
    assert logon["dst_endpoint_ip"] is None
    module = fdr["ClassifiedModuleLoad"]
    assert module["process_name"] == "rundll32.exe" and module["process_hash_sha256"] is None
    assert fdr["NewExecutableWritten"]["file_path"].endswith("WebView2Loader.dll")
    assert fdr["UserLogon"]["time"].startswith("2023-06-23T08:")
    admins = [r for r in rows("crowdstrike_fdr") if r["raw"].get("GroupRid") == "00000220"]
    assert admins and admins[0]["class_uid"] == 3006 and admins[0]["resource_uid"]
