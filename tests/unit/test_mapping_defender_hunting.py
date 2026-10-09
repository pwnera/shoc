"""Defender Advanced Hunting rows: the columns that move between tables (ING-3).

Most tables name the acting process InitiatingProcess* and the file FileName.
DeviceProcessEvents, DeviceLogonEvents and inbound connections read the other
way round, which only the derive rules know.
"""

from __future__ import annotations

from typing import Any

from shoc.ingest import ocsf


def row(table: str, **properties: Any) -> dict[str, Any]:
    record = {
        "time": "2026-09-20T10:00:01Z",
        "tenantId": "11111111-1111-1111-1111-111111111111",
        "operationName": "Publish",
        "category": f"AdvancedHunting-{table}",
        "properties": {"Timestamp": "2026-09-20T10:00:00Z", **properties},
    }
    return ocsf.load_mapping("defender_hunting").map_record(record, "t1")


ACTOR = {
    "InitiatingProcessFileName": "cmd.exe",
    "InitiatingProcessCommandLine": "cmd.exe /c run.bat",
    "InitiatingProcessSHA256": "a" * 64,
    "InitiatingProcessId": "4100",
    "InitiatingProcessParentFileName": "explorer.exe",
}


def test_a_started_process_is_the_process_and_its_initiator_the_parent():
    r = row(
        "DeviceProcessEvents",
        ActionType="ProcessCreated",
        FileName="powershell.exe",
        DeviceId="dev-1",
        FolderPath="C:\\Windows\\System32\\powershell.exe",
        SHA256="b" * 64,
        ProcessCommandLine="powershell -enc AAAA",
        ProcessId="4200",
        **ACTOR,
    )
    assert (r["class_uid"], r["type_uid"], r["severity_id"]) == (1007, 100701, 1)
    assert r["process_name"] == "powershell.exe"
    assert r["process_cmd_line"] == "powershell -enc AAAA"
    assert r["process_hash_sha256"] == "b" * 64
    assert r["process_pid"] == 4200
    assert r["process_parent_name"] == "cmd.exe"
    assert r["process_file_path"] == "C:\\Windows\\System32\\powershell.exe"
    assert r["file_path"] is None and r["file_hash_sha256"] is None
    assert (r["resource_type"], r["resource_uid"]) == ("host", "dev-1")


def test_a_file_event_keeps_the_file_apart_from_the_process_that_wrote_it():
    r = row(
        "DeviceFileEvents",
        ActionType="FileCreated",
        FileName="run.dll",
        FolderPath="C:\\Temp\\run.dll",
        SHA256="b" * 64,
        **ACTOR,
    )
    assert (r["class_uid"], r["activity_id"]) == (1001, 1)
    assert r["file_path"] == "C:\\Temp\\run.dll" and r["file_hash_sha256"] == "b" * 64
    assert r["process_name"] == "cmd.exe" and r["process_hash_sha256"] == "a" * 64
    assert r["process_parent_name"] == "explorer.exe"


def test_an_inbound_connection_starts_at_the_remote_end():
    r = row(
        "DeviceNetworkEvents",
        ActionType="InboundConnectionAccepted",
        LocalIP="10.0.0.5",
        LocalPort=3389,
        RemoteIP="203.0.113.7",
        RemotePort=51000,
    )
    assert r["class_uid"] == 4001
    assert (r["src_endpoint_ip"], r["src_endpoint_port"]) == ("203.0.113.7", 51000)
    assert (r["dst_endpoint_ip"], r["dst_endpoint_port"]) == ("10.0.0.5", 3389)
    out = row(
        "DeviceNetworkEvents",
        ActionType="ConnectionSuccess",
        LocalIP="10.0.0.5",
        RemoteIP="203.0.113.7",
    )
    assert (out["src_endpoint_ip"], out["dst_endpoint_ip"], out["status"]) == (
        "10.0.0.5",
        "203.0.113.7",
        "Success",
    )


def test_a_device_logon_comes_from_the_remote_ip():
    r = row(
        "DeviceLogonEvents",
        ActionType="LogonFailed",
        AccountName="admin",
        RemoteIP="203.0.113.9",
        RemoteDeviceName="workstation-02",
        InitiatingProcessId="0",
    )
    assert (r["class_uid"], r["status"]) == (3002, "Failure")
    assert r["src_endpoint_ip"] == "203.0.113.9" and r["dst_endpoint_ip"] is None
    assert r["src_endpoint_domain"] == "workstation-02"
    assert r["actor_user_name"] == "admin"
    assert r["process_pid"] is None


def test_device_events_are_classed_by_action_type():
    assert row("DeviceEvents", ActionType="NtAllocateVirtualMemoryApiCall")["class_uid"] == 1004
    assert row("DeviceEvents", ActionType="ScheduledTaskCreated")["type_uid"] == 100601
    assert row("DeviceEvents", ActionType="UsbDriveMounted")["type_uid"] == 100112
    assert row("DeviceEvents", ActionType="PowerShellCommand")["type_uid"] == 100799


def test_only_a_dns_query_fills_the_query_name():
    dns = row("IdentityQueryEvents", ActionType="DNS query", QueryTarget="host.example.com")
    assert (dns["class_uid"], dns["dns_query_hostname"]) == (4003, "host.example.com")
    ldap = row("IdentityQueryEvents", ActionType="LDAP query", QueryTarget="All users")
    assert (ldap["class_uid"], ldap["dns_query_hostname"]) == (6003, None)


def test_an_inspected_dns_row_names_the_query_and_the_client_that_asked():
    asked = row(
        "DeviceNetworkEvents",
        ActionType="DnsConnectionInspected",
        LocalIP="192.0.2.15",
        RemoteIP="192.0.2.1",
        AdditionalFields={"direction": "Out", "query": "k3j4h5.oast.fun", "qtype_name": "A"},
    )
    assert (asked["class_uid"], asked["dns_query_hostname"]) == (4003, "k3j4h5.oast.fun")
    assert (asked["src_endpoint_ip"], asked["dst_endpoint_ip"]) == ("192.0.2.15", "192.0.2.1")
    served = row(
        "DeviceNetworkEvents",
        ActionType="DnsConnectionInspected",
        LocalIP="192.0.2.53",
        RemoteIP="192.0.2.15",
        AdditionalFields={"direction": "In", "query": "k3j4h5.oast.fun", "qtype_name": "A"},
    )
    assert (served["src_endpoint_ip"], served["dst_endpoint_ip"]) == ("192.0.2.15", "192.0.2.53")


def test_email_tables_use_the_ocsf_1_3_classes():
    assert row("EmailEvents", EmailDirection="Inbound")["type_uid"] == 400902
    assert row("EmailAttachmentInfo")["class_uid"] == 4011
    assert row("EmailUrlInfo", Url="https://example.com/a")["class_uid"] == 4012
    click = row("UrlClickEvents", ActionType="ClickBlocked", Url="https://example.com/a")
    assert (click["class_uid"], click["status"], click["http_request_url"]) == (
        4002,
        "Failure",
        "https://example.com/a",
    )


def test_only_alert_tables_are_findings():
    assert row("AlertInfo", Severity="High", AlertId="da1")["class_uid"] == 2004
    assert row("AlertInfo", Severity="High", AlertId="da1")["severity_id"] == 4
    assert row("CloudAppEvents", ActionType="FileDownloaded")["severity_id"] == 1
