"""What a role is offered as tools (AGT-10, AGT-14, D22). No database, no model."""

from __future__ import annotations

from shoc.agents import roles, tools
from shoc.api.mcp import EXTERNAL_AGENT
from shoc.capabilities.registry import Caller


def test_a_role_is_offered_reads_and_only_the_writes_its_spec_names():
    for role in roles.ALL.values():
        for cap in tools.allowed(role.tools, role.name):
            assert tools.is_read(cap) or cap.name in tools.WRITES.get(role.name, ()), (
                f"{role.name} is offered {cap.name}, a write its spec does not name"
            )


# A role's other turn, with its own list: the Hunter's backlog (RFC 0032).
OTHER_TURNS = {"Hunter": roles.HUNTER_PACK_TOOLS}


def test_every_named_write_is_on_its_roles_list():
    for name, writes in tools.WRITES.items():
        assert set(writes) <= set(roles.ALL[name].tools) | set(OTHER_TURNS.get(name, ())), name


def test_hunter_triage_writes_nothing_and_its_backlog_turn_only_merges():
    assert all(tools.is_read(c) for c in tools.allowed(roles.HUNTER.tools, "Hunter"))
    backlog = tools.allowed(roles.HUNTER_PACK_TOOLS, "Hunter")
    assert {c.name for c in backlog if not tools.is_read(c)} == {"hunt.merge"}


def test_a_role_without_the_name_gets_no_writes():
    offered = {c.name for c in tools.allowed(roles.COMMANDER.tools)}
    assert "action.propose" not in offered and "posture.exposure" in offered


def test_reads_that_used_to_write_by_default_no_longer_do():
    from shoc.capabilities.detection import BacklogInput
    from shoc.capabilities.posture import PostureInput

    assert PostureInput().refresh is False
    assert BacklogInput().run is False


def test_a_question_cannot_hand_the_commander_a_proposal():
    """Work done for a caller offers each role only what that caller may call."""
    asked = {c.name for c in tools.allowed(roles.COMMANDER.tools, "IR Commander", EXTERNAL_AGENT)}
    assert "action.propose" not in asked
    reader = Caller(kind="human", id="r", scopes=("*:read",))
    assert "action.propose" not in {
        c.name for c in tools.allowed(roles.COMMANDER.tools, "IR Commander", reader)
    }
    admin = Caller(kind="human", id="a", scopes=("*",))
    assert "action.propose" in {
        c.name for c in tools.allowed(roles.COMMANDER.tools, "IR Commander", admin)
    }


def test_the_commander_note_lists_its_checks_one_per_line() -> None:
    from types import SimpleNamespace

    from shoc.agents.loop import _response_note

    note = _response_note(
        SimpleNamespace(
            containment_note="Disable the key.",
            page_human=True,
            page_condition="cannot_contain",
            verify=["no new calls from the key", "the key reads Inactive"],
            verify_clean_for_minutes=60,
        )
    )
    assert note == (
        "Disable the key.\n\nPaging a human (cannot_contain).\n\n"
        "Verified by, clean for 60 minutes:\n- no new calls from the key\n- the key reads Inactive"
    )
