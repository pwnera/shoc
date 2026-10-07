"""GitHub's organisation webhook as a push source, for plans with no audit-log API (ING-2)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any
from urllib.parse import urlencode

import pytest

from shoc.api import ingest
from shoc.errors import Denied, ValidationError
from shoc.ingest import ocsf
from shoc.ingest.connectors.github import from_webhook

# A version-1 UUID, as GitHub hands out: made at 2014-04-24T01:47:52Z.
DELIVERY = "72d3162e-cb52-11e3-8bc7-4c9367dc0958"


def headers(event: str, **more: str) -> dict[str, str]:
    return {
        "x-github-event": event,
        "x-github-delivery": DELIVERY,
        "content-type": "application/json",
        **more,
    }


def publicized() -> dict:
    return {
        "action": "publicized",
        "repository": {"full_name": "acme/payments", "private": False},
        "organization": {"login": "acme"},
        "sender": {"login": "mallory", "id": 4242},
    }


def test_a_webhook_reads_as_the_audit_log_event_the_rules_know():
    (record,) = from_webhook(headers("repository"), json.dumps(publicized()).encode())
    row = ocsf.load_mapping("github").map_record(record, "t1")
    assert row["api_operation"] == "repo.access"  # github_repo_made_public
    assert row["actor_user_name"] == "mallory" and row["actor_user_uid"] == "4242"
    assert row["resource_uid"] == "acme/payments" and row["cloud_account_uid"] == "acme"
    assert row["event_uid"] == f"github-webhook-{DELIVERY}"
    assert row["time"].startswith("2014-04-24T01:47:52")
    assert record["webhook"] == {
        "event": "repository",
        "action": "publicized",
        "delivery": DELIVERY,
    }
    assert record["repository"]["private"] is False, "the whole payload is kept"


@pytest.mark.parametrize(
    ("event", "action", "expected"),
    [
        ("dependabot_alert", "created", "dependabot_alert.created"),
        ("release", "published", "release.published"),
        # `team.added_to_repository` already reads as `team.add_repository`.
        ("team_add", "", "team_add"),
    ],
)
def test_an_event_with_no_audit_log_twin_keeps_its_own_name(event, action, expected):
    body = {"action": action, "organization": {"login": "acme"}, "sender": {"login": "a"}}
    (record,) = from_webhook(headers(event), json.dumps(body).encode())
    assert record["action"] == expected


@pytest.mark.parametrize(
    ("event", "action", "expected"),
    [
        ("team", "added_to_repository", "team.add_repository"),
        ("membership", "added", "team.add_member"),
        ("repository_ruleset", "edited", "repository_ruleset.update"),
        ("personal_access_token_request", "approved", "personal_access_token.access_granted"),
        ("org_block", "unblocked", "org.unblock_user"),
    ],
)
def test_team_ruleset_and_token_events_read_as_their_audit_log_actions(event, action, expected):
    body = {"action": action, "organization": {"login": "acme"}, "sender": {"login": "a"}}
    (record,) = from_webhook(headers(event), json.dumps(body).encode())
    assert record["action"] == expected


def security_change(feature: str, status: str) -> dict:
    was = "enabled" if status == "disabled" else "disabled"
    return {
        "changes": {"from": {"security_and_analysis": {feature: {"status": was}}}},
        "repository": {
            "full_name": "acme/payments",
            "security_and_analysis": {feature: {"status": status}},
        },
        "organization": {"login": "acme"},
        "sender": {"login": "mallory", "id": 4242},
    }


def test_switching_off_push_protection_reads_as_its_audit_log_action():
    body = security_change("secret_scanning_push_protection", "disabled")
    (record,) = from_webhook(headers("security_and_analysis"), json.dumps(body).encode())
    assert record["action"] == "repository_secret_scanning_push_protection.disable"
    body = security_change("secret_scanning", "enabled")
    (record,) = from_webhook(headers("security_and_analysis"), json.dumps(body).encode())
    assert record["action"] == "repository_secret_scanning.enable"
    (record,) = from_webhook(headers("security_and_analysis"), b'{"sender": {"login": "a"}}')
    assert record["action"] == "security_and_analysis"


def test_a_field_the_payload_lacks_is_left_out_not_null():
    """events.ingest refuses a null, and an organisation event names no repository."""
    body = {
        "action": "member_added",
        "organization": {"login": "acme"},
        "sender": {"login": "mallory", "id": 1},
    }
    (record,) = from_webhook(headers("organization"), json.dumps(body).encode())
    assert record["action"] == "org.add_member" and "repo" not in record
    assert None not in record.values()
    # A push names a null base_ref when no branch was merged in.
    body = {"ref": "refs/heads/main", "base_ref": None, "sender": {"login": "a"}}
    (record,) = from_webhook(headers("push"), json.dumps(body).encode())
    assert "base_ref" not in record and None not in record.values()


def test_the_form_encoded_default_is_read_too():
    body = urlencode({"payload": json.dumps(publicized())}).encode()
    form = headers("repository", **{"content-type": "application/x-www-form-urlencoded"})
    assert from_webhook(form, body)[0]["action"] == "repo.access"


def test_a_ping_loads_nothing_and_a_delivery_needs_its_headers():
    assert from_webhook(headers("ping"), b'{"zen": "Keep it logically awesome."}') == []
    with pytest.raises(ValidationError):
        from_webhook({"x-github-event": "repository"}, b"{}")


# `push_key` is replaced in these tests, so no connection is ever used.
NO_DB: Any = None


def github_signature(key: str, body: bytes) -> str:
    return "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def test_only_a_delivery_signed_with_the_push_key_is_accepted(monkeypatch):
    monkeypatch.setattr(ingest, "push_key", lambda *a: "shoc_push_k")
    body = b'{"action": "publicized"}'
    ingest.verify_github(NO_DB, "t1", "m", body, github_signature("shoc_push_k", body))
    with pytest.raises(Denied, match="does not match"):
        ingest.verify_github(NO_DB, "t1", "m", body, github_signature("other", body))
    with pytest.raises(Denied, match="does not match"):
        ingest.verify_github(NO_DB, "t1", "m", body + b" ", github_signature("shoc_push_k", body))


def test_without_a_push_key_nothing_is_accepted(monkeypatch):
    """GitHub sends no bearer token, so an unsigned source would be open to anyone."""
    monkeypatch.setattr(ingest, "push_key", lambda *a: None)
    with pytest.raises(Denied, match="push-key"):
        ingest.verify_github(NO_DB, "t1", "m", b"{}", github_signature("", b"{}"))


def test_a_second_organisation_is_checked_against_its_own_key(monkeypatch):
    keys = {"github": "shoc_push_a", "github:acme": "shoc_push_b"}
    monkeypatch.setattr(ingest, "push_key", lambda conn, tenant, source, master: keys[source])
    body = b"{}"
    ingest.verify_github(
        NO_DB, "t1", "m", body, github_signature("shoc_push_b", body), "github:acme"
    )
    with pytest.raises(Denied, match="does not match"):
        ingest.verify_github(
            NO_DB, "t1", "m", body, github_signature("shoc_push_a", body), "github:acme"
        )
