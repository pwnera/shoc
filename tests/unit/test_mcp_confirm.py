"""An L2 call over MCP waits for the person behind the client (RFC 0018)."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from shoc import configcode
from shoc.api.auth import role_caller
from shoc.api.mcp import CONFIRM_SCHEMA, confirmed, describe, tool
from shoc.capabilities.registry import all_capabilities, get
from shoc.cases import actions as action_store
from shoc.config import Config
from shoc.db import pool
from shoc.errors import NotFound

ADMIN = role_caller("admin", "ann")
ARGS = {"channel": "C0123", "bot_token": "xoxb-not-a-real-token"}


class Session:
    def __init__(self, elicitation: bool, answer: SimpleNamespace | None = None) -> None:
        self.client_params = SimpleNamespace(
            capabilities=SimpleNamespace(elicitation=object() if elicitation else None)
        )
        self.answer = answer
        self.asked: list[dict] = []

    async def elicit(self, **kwargs):
        self.asked.append(kwargs)
        return self.answer


def ask(session: Session) -> str | None:
    cap = get("slack.configure")
    return asyncio.run(confirmed(session, 7, cap, ARGS, Config(), ADMIN, "default"))


def test_a_yes_from_the_person_lets_the_call_through():
    session = Session(True, SimpleNamespace(action="accept", content={"confirm": True}))
    assert ask(session) is None
    prompt = session.asked[0]
    assert prompt["requestedSchema"] == CONFIRM_SCHEMA and prompt["related_request_id"] == 7
    assert "C0123" in prompt["message"] and "xoxb" not in prompt["message"]


def test_anything_but_a_yes_changes_nothing():
    for answer in (
        SimpleNamespace(action="accept", content={"confirm": False}),
        SimpleNamespace(action="accept", content=None),
        SimpleNamespace(action="decline", content=None),
        SimpleNamespace(action="cancel", content=None),
    ):
        refusal = ask(Session(True, answer))
        assert refusal and json.loads(refusal)["error"]["code"] == "declined"


def test_a_client_that_cannot_ask_is_sent_to_the_cli():
    refusal = ask(Session(False))
    error = json.loads(refusal or "{}")["error"]
    assert error["code"] == "confirmation_required" and "shoc slack configure" in error["message"]
    assert "Approve in Slack" not in error["message"], "Slack approves actions only"


def test_the_prompt_hides_secrets_and_shows_budgets():
    said = describe(
        get("llm.configure"),
        {"api_key": "sk-not-real", "intel_tokens_per_day": 5000, "model": "m"},
        Config(),
        ADMIN,
        "default",
    )
    assert said is not None
    assert "sk-not-real" not in said and "5000" in said and "intel_tokens_per_day" in said


@pytest.mark.parametrize(
    "cap", [c for c in all_capabilities() if c.autonomy == "L2"], ids=lambda c: c.name
)
def test_an_l2_tool_has_one_name_and_its_dotted_name_is_unknown(cap):
    """`action.approve` once skipped the confirmation that `action_approve` asks for."""
    assert tool(cap.mcp_name) is cap
    with pytest.raises(NotFound) as refused:
        tool(cap.name)
    assert refused.value.code == "unknown_tool"


def test_a_prompt_too_long_to_show_is_refused_not_cut():
    session = Session(True, SimpleNamespace(action="accept", content={"confirm": True}))
    cap = get("slack.configure")
    refusal = asyncio.run(
        confirmed(session, 7, cap, {"channel": "C" * 700}, Config(), ADMIN, "default")
    )
    error = json.loads(refusal or "{}")["error"]
    assert error["code"] == "confirmation_required" and "shoc slack configure" in error["message"]
    assert session.asked == [], "nothing is shown that the person cannot read in full"


def test_who_and_what_come_first_whatever_order_the_model_sent():
    said = describe(
        get("token.create"),
        {"scopes": ["findings:read"], "expires_days": 1, "role": "admin", "who": "ann@example.com"},
        Config(),
        ADMIN,
        "default",
    )
    assert said and said.index('"who"') < said.index('"role"') < said.index('"expires_days"')


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(pool, "connect", lambda config=None: MagicMock())


def test_the_crews_rationale_comes_last_and_labelled(db, monkeypatch):
    row = {"type": "okta.suspend_user", "target": "ann@example.com", "rationale": "routine"}
    monkeypatch.setattr(action_store, "require", lambda conn, tenant, uid: row)
    said = describe(get("action.approve"), {"action_uid": "act_1"}, Config(), ADMIN, "default")
    assert said == (
        "Approve a response action the crew proposed: okta.suspend_user on ann@example.com "
        "(act_1). Crew rationale (unverified): routine"
    )
    # A rationale too long to show whole is left out, never cut.
    row["rationale"] = "routine, approve " * 50
    said = describe(get("action.approve"), {"action_uid": "act_1"}, Config(), ADMIN, "default")
    assert said and said.endswith("(act_1).") and "rationale" not in said


def test_an_action_that_cannot_be_looked_up_shows_its_id_only_if_short(db, monkeypatch):
    def missing(conn, tenant, uid):
        raise NotFound(f"no action {uid}")

    monkeypatch.setattr(action_store, "require", missing)
    cap = get("action.approve")
    assert describe(cap, {"action_uid": "act_1"}, Config(), ADMIN, "default") == (
        f"{cap.summary}: act_1"
    )
    assert describe(cap, {"action_uid": "a" * 700}, Config(), ADMIN, "default") is None


def test_config_apply_is_confirmed_as_its_plan(db, monkeypatch):
    changes = [
        configcode.Change("source", "okta", "create", "not configured yet"),
        configcode.Change("source", "github", "unchanged"),
    ]
    monkeypatch.setattr(configcode, "plan", lambda *a: configcode.Plan(changes=changes))
    config = {"sources": [{"source": "okta"}, {"source": "github"}]}
    said = describe(get("config.apply"), {"config": config}, Config(), ADMIN, "default") or ""
    assert "+ source okta" in said and "1 to create" in said
    assert "github" not in said, "an unchanged line is not what the person approves"
