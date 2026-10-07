"""Entra ID sign-ins of every kind are Authentication; audits take an IAM class (ING-3)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shoc.ingest import ocsf
from tests.support import FIXTURES

RECORDS = json.loads((FIXTURES / "mappings" / "entra.json").read_text())


def row(key: str) -> dict[str, Any]:
    record = next(r for r in RECORDS if key in (r.get("activityDisplayName"), r.get("_stream")))
    return ocsf.load_mapping("entra").map_record(record, "t1")


@pytest.mark.parametrize(
    ("stream", "actor_type"),
    [
        ("nonInteractiveSignIns", "Member"),
        ("servicePrincipalSignIns", "ServicePrincipal"),
        ("managedIdentitySignIns", "ManagedIdentity"),
    ],
)
def test_every_sign_in_kind_is_a_logon(stream, actor_type):
    mapped = row(stream)
    assert (mapped["class_uid"], mapped["type_uid"]) == (3002, 300201)
    assert mapped["actor_user_type"] == actor_type
    assert mapped["actor_user_name"]


@pytest.mark.parametrize(
    ("activity", "class_uid", "activity_id"),
    [
        ("Update user", 3001, 99),
        ("Remove member from group", 3006, 4),
        ("Remove member from role (PIM activation expired)", 3005, 2),
        ("Consent to application", 3005, 1),
        ("Add app role assignment grant to user", 3005, 1),
        ("Recover device local administrator password", 3004, 2),
        ("Delete device", 3004, 4),
        ("Update conditional access policy", 3004, 99),
    ],
)
def test_directory_audit_class_follows_category_and_activity(activity, class_uid, activity_id):
    mapped = row(activity)
    assert (mapped["class_uid"], mapped["activity_id"]) == (class_uid, activity_id)
    assert mapped["type_uid"] == class_uid * 100 + activity_id


def test_an_audit_target_user_is_named_by_upn():
    assert row("Add app role assignment grant to user")["resource_uid"] == "target.one@example.com"
    assert row("Add member to group")["resource_uid"] == "bob@example.com"


def by_id(uid: str) -> dict[str, Any]:
    record = next(r for r in RECORDS if r["id"] == uid)
    return ocsf.load_mapping("entra").map_record(record, "t1")


def test_a_beta_interactive_sign_in_keeps_what_phishing_shows_in():
    """The interactive stream reads beta, which v1.0 leaves these fields out of (E1)."""
    mapped = by_id("aaaaaaaa-1111-4111-8111-111111111111")
    assert (mapped["class_uid"], mapped["actor_user_type"]) == (3002, "Member")
    assert mapped["http_user_agent"].startswith("Mozilla/5.0")
    assert mapped["src_endpoint_asn"] == "64500"
    assert mapped["raw"]["authenticationProtocol"] == "deviceCode"


@pytest.mark.parametrize(
    ("uid", "severity_id"),
    [
        ("6a5874ca-abcd-4d82-9d82-5ad39bd71600", 4),  # riskDetections, riskLevel high
        ("d1d4a5d4-a5d4-41d4-84a5-d4d1d4a5d4d1", 4),  # riskyUsers, confirmedCompromised
    ],
)
def test_identity_protection_risk_is_a_detection_finding(uid, severity_id):
    mapped = by_id(uid)
    assert (mapped["class_uid"], mapped["severity_id"]) == (2004, severity_id)
    assert mapped["actor_user_name"] == "john.doe@example.com"
    assert mapped["time"].startswith("2026-09-20")


def test_an_audit_user_agent_comes_from_additional_details():
    mapped = by_id("Directory_000000-000000000-000000-0000000")
    assert mapped["http_user_agent"] == "O365AdminPortal"
