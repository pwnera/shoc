"""A playbook step acts on the entity its findings name (RSP-2, RFC 0026).

Each scenario here puts two users on one case, and two keys or two device ids
with them. The alphabetically first value of each kind, which `{{ entity.X }}`
renders, is the wrong target in every one of them: the account a spray failed
on, the WARP device Gateway reported, the IAM user mistaken for a role.
"""

from __future__ import annotations

import pytest

from evals.run import SCENARIOS, load_scenario
from shoc.capabilities.registry import call
from shoc.cases import playbooks
from shoc.db.pool import fetch_all, fetch_one
from tests.support import malicious_case

pytestmark = pytest.mark.postgres

TARGETED = sorted(
    p.name
    for p in SCENARIOS.iterdir()
    if p.is_dir() and load_scenario(p)[0].get("playbook_targets")
)


def _kinds(conn, tenant_id: str, case_uid: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in fetch_all(
        conn,
        "SELECT entity FROM shoc.case_entities WHERE tenant_id = %s AND case_uid = %s",
        (tenant_id, case_uid),
    ):
        kind, _, value = str(row["entity"]).partition(":")
        out.setdefault(kind, []).append(value)
    return out


def test_the_targeting_scenarios_are_there():
    assert {
        "okta_spray_one_sign_in",
        "endpoint_alert_two_users",
        "aws_session_key_two_users",
    } <= set(TARGETED)


@pytest.mark.parametrize("name", TARGETED)
def test_each_step_acts_on_what_its_findings_name(name, ctx, config, store, clean):
    expected, _ = load_scenario(SCENARIOS / name)
    case = malicious_case(ctx.db, config.tenant_id, name)
    kinds = _kinds(ctx.db, config.tenant_id, case)
    assert len(kinds.get("user", [])) >= 2, f"{name} must put two users on one case: {kinds}"

    for book, steps in expected["playbook_targets"].items():
        run = call("playbook.run", ctx, {"playbook_id": book, "case_uid": case, "dry_run": True})
        by_name = {s["name"]: s for s in playbooks.steps_of(ctx.db, run.data.run_uid)}
        for step, want in steps.items():
            assert step in by_name, f"{book} has no step '{step}'"
            uid = by_name[step]["action_uid"]
            assert uid, f"{book} '{step}' proposed nothing: {by_name[step]['result']}"
            action = fetch_one(
                ctx.db, "SELECT params FROM shoc.actions WHERE action_uid = %s", (uid,)
            )
            assert action
            for param, value in want.items():
                assert action["params"][param] == value, f"{book} '{step}' {param}"


def test_the_first_user_of_a_spray_case_is_not_the_one_who_signed_in(ctx, config, store, clean):
    """The case this RFC started from: `{{ entity.user }}` named adam, who never got in."""
    case = malicious_case(ctx.db, config.tenant_id, "okta_spray_one_sign_in")
    assert playbooks.entities_of_case(ctx.db, config.tenant_id, case)["user"] == "adam@example.com"
    rules, platforms = playbooks.scoped_entities(ctx.db, config.tenant_id, case)
    assert rules["okta_sign_in_after_attack_from_address"]["user"] == "mia@example.com"
    assert platforms["okta"]["ip"] == "203.0.113.77"


def test_the_edr_device_is_not_the_first_device_on_the_case(ctx, config, store, clean):
    endpoint = malicious_case(ctx.db, config.tenant_id, "endpoint_alert_two_users")
    kinds = _kinds(ctx.db, config.tenant_id, endpoint)
    assert "file_hash" in kinds and "device" in kinds
    _rules, platforms = playbooks.scoped_entities(ctx.db, config.tenant_id, endpoint)
    # The WARP device sorts first; the EDR's is the one isolation takes.
    assert playbooks.entities_of_case(ctx.db, config.tenant_id, endpoint)["device"].startswith(
        "0b7e"
    )
    assert platforms["edr"]["device"] == "5e4482b45d134ae8bf4901cb52b65e88"


def test_a_step_reading_a_rule_its_playbook_does_not_answer_is_refused():
    from shoc.errors import ConfigError

    with pytest.raises(ConfigError, match="a rule it does not answer"):
        playbooks.Playbook.from_dict(
            {
                "id": "typo",
                "title": "A misspelt rule",
                "rules": ["okta_sign_in_after_attack_from_address"],
                "steps": [
                    {
                        "name": "revoke",
                        "action": "okta.revoke_sessions",
                        "params": {"user": "{{ rule.okta_sign_in_after_atack.user }}"},
                    }
                ],
            }
        )
