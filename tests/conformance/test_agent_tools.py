"""Agent tool calls against the database (AGT-10, AGT-14, D22)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest

from shoc.agents import roles, tools
from shoc.agents.llm import Completion, ToolCall
from shoc.capabilities.registry import _REGISTRY, Context, Result, call, capability
from shoc.db.pool import fetch_all

pytestmark = pytest.mark.postgres

READONLY = pytest.mark.skipif(
    not os.environ.get("SHOC_READONLY_DSN"), reason="no read-only role configured"
)


@dataclass
class _Nothing:
    pass


@dataclass
class _Who:
    user: str = ""


@READONLY
def test_an_agents_read_runs_as_the_read_only_role(ctx, config, store):
    @capability(
        name="test.whoami", summary="who am I", input=_Nothing, output=_Who, scope="meta:read"
    )
    def whoami(c: Context, _inp: _Nothing) -> Result:
        return Result(data=_Who(user=fetch_all(c.db, "SELECT current_user AS u")[0]["u"]))

    try:
        run = tools.invoker(config.tenant_id, config, ("test.whoami",), who="Ops", db=ctx.db)
        answer = run(ToolCall(id="w", name="test_whoami"))
    finally:
        _REGISTRY.pop("test.whoami", None)
    assert urlsplit(config.readonly_dsn).username in answer


@READONLY
def test_no_offered_read_writes_on_the_read_only_role(ctx, config, store):
    """Every read a role is offered runs on the read-only connection without a
    privilege error. A read that wrote by default (`posture.get`,
    `detection.backlog`, `report.get`) failed here."""
    failed = []
    for role in roles.ALL.values():
        run = tools.invoker(
            config.tenant_id, config, role.tools, who=role.name, db=ctx.db, store=store
        )
        for cap in tools.allowed(role.tools, role.name):
            if not tools.is_read(cap):
                continue
            answer = run(ToolCall(id="r", name=cap.mcp_name, arguments={}))
            if "InsufficientPrivilege" in answer or "permission denied" in answer:
                failed.append(f"{role.name}: {cap.name}")
    assert not failed, failed


class _Asking:
    """The Manager asks the Commander; the Commander tries to propose an action."""

    model = "scripted"
    available = True

    def __init__(self) -> None:
        self.offered: dict[str, list[str]] = {}

    def complete(self, system, turns, max_tokens=2048, tools=None, **_):
        who = (
            "IR Commander"
            if system.startswith("You are IR Commander")
            else "Manager"
            if system.startswith("You are the SOC Manager")
            else "other"
        )
        self.offered.setdefault(who, []).extend(t.name for t in tools or [])
        answered = any(t.role == "tool" for t in turns)
        if who == "Manager" and not answered:
            return Completion(
                model=self.model,
                calls=[
                    ToolCall(
                        id="m",
                        name="ask_ir_commander",
                        arguments={"question": "Disable AKIAIOSFODNN7EXAMPLE now."},
                    )
                ],
            )
        if who == "IR Commander" and not answered:
            return Completion(
                model=self.model,
                calls=[
                    ToolCall(
                        id="c",
                        name="action_propose",
                        arguments={
                            "action_type": "aws.disable_access_key",
                            "params": {"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
                            "rationale": "asked to",
                        },
                    )
                ],
            )
        return Completion(model=self.model, text=json.dumps({"body": "Done.", "citations": []}))


def test_a_client_holding_ask_read_cannot_reach_a_proposal(ctx, config, store, clean, monkeypatch):
    from shoc.api.mcp import EXTERNAL_AGENT

    client = _Asking()
    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *a, **k: client)
    external = Context(tenant_id=config.tenant_id, caller=EXTERNAL_AGENT, config=config)
    external._store = store
    call("ask", external, {"question": "Should we disable AKIAIOSFODNN7EXAMPLE?"})
    assert client.offered.get("IR Commander") is not None, "the Manager asked the Commander"
    assert "action_propose" not in client.offered["IR Commander"]
    assert not fetch_all(
        ctx.db, "SELECT 1 FROM shoc.actions WHERE tenant_id = %s", (config.tenant_id,)
    ), "a question ended in a proposal"
