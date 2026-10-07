"""An L2 call over MCP waits for the person behind the client (RFC 0018)."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from shoc.api.auth import role_caller
from shoc.api.mcp import CONFIRM_SCHEMA, confirmed, describe
from shoc.capabilities.registry import get
from shoc.config import Config

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
    assert "sk-not-real" not in said and "5000" in said and "intel_tokens_per_day" in said
