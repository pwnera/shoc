"""SentinelOne: threats, unified alerts, console activities and Cloud Funnel telemetry (ING-3)."""

from __future__ import annotations

import json

import pytest

from shoc.ingest import ocsf
from tests.support import FIXTURES


def rows(source: str) -> list[dict]:
    mapping = ocsf.load_mapping(source)
    records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
    return [mapping.map_record(r, "t1") for r in records]


def test_a_threat_names_its_file_host_and_the_process_that_launched_it():
    row = next(r for r in rows("sentinelone") if r["event_uid"] == "1373834705420286869")
    assert (row["class_uid"], row["severity_id"]) == (2004, 3), "mitigated: one band down"
    assert row["device_hostname"] == row["src_endpoint_domain"] == "host05.example.com"
    assert row["device_uid"] == "5e4482b45d134ae8bf4901cb52b65e88"
    assert row["resource_uid"] == "1088377752722254024", "the console's agent id, for actions"
    assert row["file_path"].endswith("OfficeTimeline.exe") and row["process_name"] is None
    assert row["process_parent_name"] == "chrome.exe"


def test_an_identity_alert_about_an_account_has_no_host():
    row = next(r for r in rows("sentinelone") if r["message"] == "Compromised Password Detected")
    assert row["class_uid"] == 2004 and row["device_hostname"] is None
    assert (row["resource_type"], row["actor_user_name"]) == ("user", "name_test")


def test_console_activities_are_never_findings():
    by_type = {
        r["raw"]["activityType"]: r for r in rows("sentinelone") if "activityType" in r["raw"]
    }
    assert all(r["class_uid"] != 2004 and r["severity_id"] == 1 for r in by_type.values())
    assert by_type[27]["class_uid"] == 3002 and by_type[27]["src_endpoint_ip"] == "192.0.2.30"
    assert (by_type[25]["class_uid"], by_type[25]["activity_id"]) == (3001, 6)
    assert by_type[25]["actor_user_name"] == "Jean Dupont", "who deleted, not who was deleted"
    assert (by_type[3016]["class_uid"], by_type[3016]["activity_id"]) == (6003, 4)
    assert (by_type[5232]["class_uid"], by_type[5232]["activity_id"]) == (4001, 5)
    assert by_type[3608]["process_name"] == "ExampleAppHost_old.exe"


@pytest.mark.parametrize(
    ("event_type", "class_uid", "activity_id"),
    [
        ("Process Creation", 1007, 1),
        ("DuplicateProcessHandle", 1007, 3),
        ("Command Script", 1007, 99),
        ("Behavioral Indicators", 1007, 99),
        ("File Rename", 1001, 5),
        ("ModuleLoad", 1005, 1),
        ("Driver Load", 1002, 1),
        ("Task Register", 1006, 1),
        ("Registry Key Create", 201001, 1),
        ("Registry Value Modified", 201002, 3),
        ("IP Connect", 4001, 1),
        ("DNS Resolved", 4003, 6),
        ("GET", 4002, 3),
        ("Logout", 3002, 2),
    ],
)
def test_cloud_funnel_event_types_get_their_class(event_type, class_uid, activity_id):
    row = next(
        r for r in rows("sentinelone_cloudfunnel") if r["raw"]["event"]["type"] == event_type
    )
    assert (row["class_uid"], row["activity_id"], row["severity_id"]) == (class_uid, activity_id, 1)
    assert row["device_hostname"] and row["device_uid"]


def test_cloud_funnel_rows_name_the_agent_and_the_process_image():
    cf = rows("sentinelone_cloudfunnel")
    started = next(
        r for r in cf if r["raw"]["event"]["type"] == "Process Creation" and r["raw"].get("src")
    )
    assert (started["resource_type"], started["resource_uid"]) == ("host", started["device_uid"])
    assert started["process_file_path"] == started["raw"]["tgt"]["process"]["image"]["path"]
    key = next(r for r in cf if r["raw"]["event"]["category"] == "registry")
    assert key["resource_type"] == "registry key" and key["resource_uid"] != key["device_uid"]


def test_cloud_funnel_process_parent_is_set_only_for_a_started_process():
    cf = rows("sentinelone_cloudfunnel")
    started = next(
        r for r in cf if r["raw"]["event"]["type"] == "Process Creation" and r["raw"].get("src")
    )
    assert (started["process_name"], started["process_parent_name"]) == (
        started["raw"]["tgt"]["process"]["name"],
        started["raw"]["src"]["process"]["name"],
    )
    opened = next(r for r in cf if r["raw"]["event"]["category"] == "cross_process")
    assert opened["process_name"] == "chrome.exe" and opened["process_parent_name"] is None


def test_cloud_funnel_windows_logons_and_failures():
    cf = rows("sentinelone_cloudfunnel")
    by_id = {r["api_operation"]: r for r in cf if r["raw"].get("winEventLog")}
    assert (by_id["4769"]["class_uid"], by_id["4769"]["activity_id"]) == (3002, 4)
    assert by_id["4624"]["status"] == "Success" and by_id["4648"]["actor_user_name"] == "user1"
    failed = next(r for r in cf if r["message"] == "Unknown user name or bad password.")
    assert (failed["class_uid"], failed["status"]) == (3002, "Failure")
