"""Cloudflare mappings where the class or outcome is a choice (ING-3)."""

from __future__ import annotations

import json

from shoc.ingest import ocsf
from tests.support import FIXTURES


def rows(source: str) -> list[dict]:
    mapping = ocsf.load_mapping(source)
    records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
    return [mapping.map_record(r, "t1") for r in records]


def by_dataset(dataset: str) -> list[dict]:
    return [r for r in rows("cloudflare_logs") if r["raw"].get("_dataset") == dataset]


def test_logpush_audit_export_maps_like_the_api():
    pushed = [r for r in rows("cloudflare") if "ActionType" in r["raw"]]
    created, updated, v2 = pushed
    assert (created["activity_name"], created["api_operation"]) == (
        "Create",
        "gateway_create_location",
    )
    assert created["actor_user_name"] == "john.doe@example.org"
    assert created["cloud_account_uid"] == "1d1e650b3385b95db72bba7cfb1287e9"
    assert updated["activity_name"] == "Update" and updated["status"] == "Success"
    assert v2["event_uid"] == "8d7e5f9a-1b2c-4d3e-a4f5-0b1c2d3e4f56"
    assert v2["time"].startswith("2026-09-29T15:57:41")


def test_a_failed_logpush_audit_action_is_a_failure():
    mapping = ocsf.load_mapping("cloudflare")
    row = mapping.map_record({"ID": "x", "ActionType": "delete", "ActionResult": False}, "t1")
    assert (row["activity_name"], row["status"], row["severity_id"]) == ("Delete", "Failure", 2)


def test_logpush_nanosecond_timestamps_are_read():
    (request,) = by_dataset("http_requests")
    assert request["time"].startswith("2022-07-20T01:47:51.671")


def test_firewall_block_is_http_activity_at_severity_one():
    (event,) = by_dataset("firewall_events")
    assert (event["class_uid"], event["status"], event["severity_id"]) == (4002, "block", 1)
    assert event["dst_endpoint_domain"] == "www.example.com"
    assert event["http_request_url"] is None, "Logpush has no field with the whole URL"


def test_gateway_antivirus_block_raises_severity_and_names_the_file():
    blocked, allowed = by_dataset("gateway_http")
    assert blocked["severity_id"] == 3 and allowed["severity_id"] == 1
    assert blocked["file_path"] == "mimikatz_trunk.zip"
    assert blocked["http_request_url"].startswith("https://downloads.example.net/")


def test_dns_query_name_is_not_a_destination():
    for row in by_dataset("dns_logs") + by_dataset("gateway_dns"):
        assert row["class_uid"] == 4003 and row["dns_query_hostname"]
        assert row["dst_endpoint_domain"] is None


def test_access_login_is_authentication_and_a_denial_fails():
    _, login = by_dataset("access_requests")
    assert (login["class_uid"], login["activity_name"], login["status"]) == (
        3002,
        "Logon",
        "Success",
    )
    mapping = ocsf.load_mapping("cloudflare_logs")
    denied = mapping.map_record({**login["raw"], "Allowed": False}, "t1")
    assert (denied["status"], denied["severity_id"]) == ("Failure", 2)


def test_pushed_audit_rows_carry_the_audit_product():
    (audit,) = by_dataset("audit_logs")
    assert (audit["class_uid"], audit["metadata_product"]) == (6003, "Cloudflare Audit Log")


def test_a_created_token_is_named_by_the_id_in_the_response():
    record = {
        "id": "cf-1",
        "action": {"time": "2026-10-01T10:00:00Z", "type": "create", "description": "create token"},
        "actor": {"email": "admin@example.com", "ip_address": "203.0.113.10"},
        "account": {"id": "acc-1"},
        "resource": {"product": "api_tokens", "response": {"id": "token-123"}},
    }
    row = ocsf.load_mapping("cloudflare").map_record(record, "t1")
    assert row["resource_uid"] == "token-123"
