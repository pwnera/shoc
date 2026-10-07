"""Permissions are decided in one place: the registry's `Capability.check`.

A capability declares the principals that may call it. Every other list of who
may do what has to agree with that declaration, or one of the two is a lie.
"""

from __future__ import annotations

import pytest

from shoc.agents.roles import ALL
from shoc.api.mcp import EXTERNAL_AGENT, tool_definitions
from shoc.capabilities.registry import Caller, all_capabilities, load

CAPABILITIES = all_capabilities()


@pytest.mark.parametrize("cap", CAPABILITIES, ids=lambda c: c.name)
def test_mcp_scopes_and_declared_principals_agree(cap):
    declared = "external_agent" in cap.principals
    granted = EXTERNAL_AGENT.allows(cap.scope) and cap.autonomy != "L2"
    assert declared == granted, (
        f"{cap.name} {'declares' if declared else 'does not declare'} external_agent "
        f"but the MCP scopes {'do' if granted else 'do not'} carry '{cap.scope}'"
    )


def test_the_mcp_tool_list_is_what_the_registry_permits():
    listed = {t["name"] for t in tool_definitions(EXTERNAL_AGENT)}
    assert listed == {c.mcp_name for c in CAPABILITIES if c.permits(EXTERNAL_AGENT)}


@pytest.mark.parametrize("role", ALL.values(), ids=lambda r: r.name)
def test_every_tool_a_role_is_given_is_one_an_agent_may_call(role):
    registered = load()
    for name in role.tools:
        cap = registered.get(name)
        if cap is None:  # a role may name a capability that is not built yet
            continue
        agent = Caller(kind="agent", id=f"agent:{role.name}", scopes=(cap.scope,))
        assert cap.permits(agent), f"{role.name} is offered {name} and the registry refuses it"
