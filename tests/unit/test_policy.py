"""The autonomy policy decides; nothing else does (RSP-3, decision D8)."""

from __future__ import annotations

import pytest
import yaml

from shoc.cases.policy import Policy
from shoc.errors import ConfigError

SHIPPED = Policy.load()


def test_the_shipped_policy_is_valid_and_conservative():
    assert SHIPPED.version >= 1
    assert SHIPPED.defaults["autonomy"] == "L2", "the default must be: ask a human"
    assert SHIPPED.defaults["dry_run"] is True, "a new install must change nothing"
    assert SHIPPED.principals["external_agent"] == "L0"
    assert SHIPPED.principals["human"] == "L2"


def test_every_automatic_action_is_reversible():
    for name, rule in SHIPPED.actions.items():
        if rule.get("autonomy") == "L1":
            assert rule.get("reversible"), f"{name} runs automatically but cannot be undone"


def test_every_policy_action_exists_and_every_action_is_in_the_policy():
    from shoc.actions import available

    actions = set(available())
    assert set(SHIPPED.actions) <= actions, "the policy names an action that does not exist"
    assert actions <= set(SHIPPED.actions), "an action exists that the policy never mentions"


def test_an_irreversible_l1_action_is_rejected_at_load(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump({"version": 1, "actions": {"x.y": {"autonomy": "L1", "reversible": False}}})
    )
    with pytest.raises(ConfigError, match="not reversible"):
        Policy.from_file(path)


def _decide(**kw):
    base = {
        "principal_kind": "agent",
        "target_kind": "key",
        "target": "AKIAEXAMPLE",
        "confidence": 0.95,
        "severity": "critical",
        "has_citations": True,
    }
    return SHIPPED.decide(kw.pop("action", "aws.disable_access_key"), **{**base, **kw})


def test_a_confident_reversible_action_runs_automatically():
    decision = _decide()
    assert decision.allowed and decision.autonomy == "L1" and not decision.needs_approval


def test_low_confidence_falls_back_to_a_human():
    decision = _decide(confidence=0.4)
    assert decision.needs_approval and "confidence" in decision.reason


def test_a_target_the_evidence_never_showed_falls_back_to_a_human():
    """RFC 0020: a log line can name a target; it cannot make a cited event show it."""
    decision = _decide(grounded=False)
    assert decision.needs_approval and "does not appear in the evidence" in decision.reason
    assert not _decide().needs_approval, "a grounded target is still automatic"


def test_low_severity_falls_back_to_a_human():
    decision = _decide(severity="low")
    assert decision.needs_approval and "severity" in decision.reason


def test_an_uncited_case_gets_no_action_at_all():
    decision = _decide(has_citations=False)
    assert not decision.allowed and "cites no events" in decision.reason


def test_a_protected_target_is_never_automatic():
    decision = SHIPPED.decide(
        "okta.revoke_sessions",
        principal_kind="agent",
        target_kind="user",
        target="root-admin@acme.com",
        confidence=0.99,
        severity="critical",
    )
    assert decision.needs_approval and "protected" in decision.reason


def test_an_external_agent_can_never_act():
    """Its ceiling is L0, which takes no action: not an L2 a human could approve."""
    decision = _decide(principal_kind="external_agent")
    assert not decision.allowed and decision.autonomy == "L0"


def test_an_l0_action_is_refused_whoever_proposes_it(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "principals": {"human": "L2", "agent": "L1"},
                "actions": {"x.notify_only": {"autonomy": "L0", "reversible": True}},
            }
        )
    )
    policy = Policy.from_file(path)
    for kind in ("human", "agent", "service"):
        decision = policy.decide(
            "x.notify_only", principal_kind=kind, confidence=1.0, severity="critical"
        )
        assert not decision.allowed and decision.autonomy == "L0", kind
        assert "notify-only" in decision.reason


def test_an_l2_action_always_needs_a_human_however_confident():
    decision = SHIPPED.decide(
        "okta.suspend_user",
        principal_kind="agent",
        target_kind="user",
        target="jane@acme.com",
        confidence=1.0,
        severity="critical",
    )
    assert decision.allowed and decision.needs_approval


def test_the_automatic_action_budget_per_case_is_enforced():
    decision = _decide(auto_actions_so_far=5)
    assert decision.needs_approval and "already ran" in decision.reason


def test_an_unknown_action_is_refused():
    decision = SHIPPED.decide("rm.minus_rf", principal_kind="human")
    assert not decision.allowed and "not in the policy" in decision.reason
