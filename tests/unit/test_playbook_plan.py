"""A playbook step acts on every value of its rule-scoped target, an action on
every one of its parameters, and a run knows what it acted on (RSP-2, RSP-4,
RFC 0026)."""

from __future__ import annotations

from shoc.actions import get
from shoc.cases import playbooks
from shoc.cases.actions import make_uid, target_key

BOOK = playbooks.Playbook.from_dict(
    {
        "id": "contain_keys",
        "title": "Contain the keys",
        "rules": ["x"],
        "steps": [
            {
                "name": "page",
                "action": "notify.page",
                "params": {"summary": "keys {{ rule.x.key }} on {{ case.title }}"},
            },
            {
                "name": "disable the key",
                "action": "aws.disable_access_key",
                "params": {"access_key_id": "{{ rule.x.key }}"},
            },
        ],
    }
)


def context(*keys: str, title: str = "leaked key") -> dict:
    return {
        "case": {"title": title},
        "entity": {"key": keys[0]},
        "rule": {"x": {"key": keys[0]}},
        "each": {"entity": {"key": list(keys)}, "rule": {"x": {"key": list(keys)}}},
    }


def test_a_target_with_two_values_is_a_step_for_each():
    ctx = context("AKIAEXAMPLEONE000001", "AKIAEXAMPLETWO000002")
    steps = playbooks.plan(BOOK, ctx)
    assert steps == [
        {"step": 0},
        {"step": 1, "bind": {"rule.x.key": "AKIAEXAMPLEONE000001"}},
        {"step": 1, "bind": {"rule.x.key": "AKIAEXAMPLETWO000002"}},
    ]
    second = playbooks.render(BOOK.steps[1].params, ctx, steps[2]["bind"])
    assert second == {"access_key_id": "AKIAEXAMPLETWO000002"}


def test_a_page_names_every_value_and_a_plain_render_the_first():
    ctx = context("AKIAEXAMPLEONE000001", "AKIAEXAMPLETWO000002")
    page = playbooks.render(BOOK.steps[0].params, ctx, joined=True)
    assert page["summary"] == "keys AKIAEXAMPLEONE000001, AKIAEXAMPLETWO000002 on leaked key"
    assert playbooks.render(BOOK.steps[1].params, ctx) == {"access_key_id": "AKIAEXAMPLEONE000001"}


def test_more_values_than_the_cap_is_one_ambiguous_step():
    keys = [f"AKIAEXAMPLE{n:09d}" for n in range(playbooks.FAN_OUT_AT_MOST + 1)]
    steps = playbooks.plan(BOOK, context(*keys))
    assert len(steps) == 2 and "11 values" in steps[1]["ambiguous"]


def test_a_case_wide_placeholder_still_names_its_first_value_alone():
    """`entity.key` holds every key linked to the case, the CI key next to the
    leaked one; only a rule's or a platform's values fan out (RFC 0026)."""
    book = playbooks.Playbook.from_dict(
        {
            "id": "disable_first",
            "title": "Disable the case's key",
            "rules": ["x"],
            "steps": [
                {
                    "name": "disable the key",
                    "action": "aws.disable_access_key",
                    "params": {"access_key_id": "{{ entity.key }}"},
                }
            ],
        }
    )
    two = context("AKIAEXAMPLEONE000001", "AKIAEXAMPLETWO000002")
    assert playbooks.plan(book, two) == [{"step": 0}]
    assert playbooks.render(book.steps[0].params, two) == {"access_key_id": "AKIAEXAMPLEONE000001"}
    assert playbooks.targets(book, two) == playbooks.targets(book, context("AKIAEXAMPLEONE000001"))


def test_a_run_started_before_values_were_kept_plans_as_it_did():
    old = {"case": {"title": "t"}, "rule": {"x": {"key": "AKIAEXAMPLEONE000001"}}}
    assert playbooks.plan(BOOK, old) == [{"step": 0}, {"step": 1}]
    assert playbooks.targets(BOOK, old) == playbooks.targets(BOOK, context("AKIAEXAMPLEONE000001"))


def test_a_second_key_changes_what_the_run_acts_on_and_a_new_title_does_not():
    one = playbooks.targets(BOOK, context("AKIAEXAMPLEONE000001"))
    assert one == playbooks.targets(BOOK, context("AKIAEXAMPLEONE000001", title="renamed"))
    assert one != playbooks.targets(BOOK, context("AKIAEXAMPLEONE000001", "AKIAEXAMPLETWO000002"))


def test_an_action_id_covers_every_required_parameter():
    detach = get("aws.detach_user_policy")
    admin = {"user_name": "eve", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}
    iam = {"user_name": "eve", "policy_arn": "arn:aws:iam::aws:policy/IAMFullAccess"}
    assert make_uid("t", detach.type, target_key(detach, admin), "C") != make_uid(
        "t", detach.type, target_key(detach, iam), "C"
    )


def test_a_one_parameter_action_keeps_the_id_it_always_had():
    revoke = get("okta.revoke_sessions")
    params = {"user": "jane@example.com"}
    assert target_key(revoke, params) == "jane@example.com"
    assert make_uid("t", revoke.type, target_key(revoke, params), "C") == make_uid(
        "t", revoke.type, "jane@example.com", "C"
    )


def test_a_parameter_that_only_locates_the_object_is_not_part_of_its_id():
    """The user a key belongs to is found later or named differently; the key is one action."""
    disable = get("aws.disable_access_key")
    key = "AKIAEXAMPLEONE000001"
    assert target_key(disable, {"access_key_id": key, "user_name": "deploy-ci"}) == key
