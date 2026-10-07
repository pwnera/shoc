"""Okta events whose class depends on more than the event-type prefix (ING-3)."""

from __future__ import annotations

import pytest

from shoc.ingest import ocsf


def _row(event_type, result="SUCCESS"):
    record = {"uuid": "u", "eventType": event_type, "outcome": {"result": result}}
    return ocsf.load_mapping("okta").map_record(record, "t1")


@pytest.mark.parametrize(
    ("event_type", "class_uid"),
    [
        ("policy.evaluate_sign_on", 3002),
        ("system.push.send_factor_verify_push", 3002),
        ("policy.lifecycle.update", 3004),
        ("user.account.privilege.grant", 3005),
        ("iam.resourceset.bindings.add", 3005),
        ("application.policy.sign_on.update", 3004),
        ("application.policy.sign_on.rule.delete", 3004),
        ("group.user_membership.add", 3006),
        ("user.mfa.factor.deactivate", 3001),
        ("security.threat.detected", 2004),
    ],
)
def test_event_type_picks_the_class(event_type, class_uid):
    assert _row(event_type)["class_uid"] == class_uid


def test_a_rejected_push_is_a_failed_sign_in_step():
    row = _row("user.mfa.okta_verify.deny_push")
    assert (row["class_uid"], row["status"]) == (3002, "Failure")


def test_a_custom_role_binding_is_a_privilege_grant():
    row = _row("iam.resourceset.bindings.add")
    assert (row["activity_name"], row["severity_id"]) == ("Assign Privileges", 3)
