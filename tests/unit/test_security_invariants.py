"""Properties the whole registry must hold, whatever anyone adds later.

These are the rules a reviewer would otherwise have to check by hand on every
pull request: what may write, what must be audited, what only a human may do,
and what may come back out in a response.
"""

from __future__ import annotations

import dataclasses

import pytest

from shoc.api.mcp import EXTERNAL_AGENT, tool_definitions
from shoc.capabilities.registry import all_capabilities

CAPABILITIES = all_capabilities()
WRITE_TAGS = {"write", "ingest", "approval"}

# The capabilities that hand a secret back exactly once, on purpose: you cannot
# use a signing key or a token you have never seen. Each says so in its summary.
SECRET_RETURNING = {
    "source.push_key",
    "stream.subscribe",
    "token.create",
    "user.invite",
    "user.reset",
}


@pytest.mark.parametrize("cap", CAPABILITIES, ids=lambda c: c.name)
def test_anything_that_writes_is_audited(cap):
    writes = bool(WRITE_TAGS & set(cap.tags)) or cap.scope.endswith((":write", ":approve"))
    if writes:
        assert cap.audit, f"{cap.name} writes but is not audited"


@pytest.mark.parametrize("cap", CAPABILITIES, ids=lambda c: c.name)
def test_l2_capabilities_are_human_only(cap):
    if cap.autonomy == "L2":
        assert cap.principals == ("human",), f"{cap.name} is L2 but not human-only"


@pytest.mark.parametrize("cap", CAPABILITIES, ids=lambda c: c.name)
def test_every_capability_has_a_scoped_name_and_a_summary(cap):
    area, _, verb = cap.scope.partition(":")
    assert area and verb, f"{cap.name}: scope must be area:verb"
    assert cap.summary and cap.summary[0].isupper()
    assert not cap.summary.endswith("."), "summaries read as a phrase, not a sentence"


@pytest.mark.parametrize("cap", CAPABILITIES, ids=lambda c: c.name)
def test_no_capability_returns_a_secret_by_accident(cap):
    if not dataclasses.is_dataclass(cap.output):
        return
    # "tokens" is a model's token count, not a credential; match credential
    # names precisely rather than any word containing "token".
    credential_words = ("secret", "password", "private_key", "api_key", "credential")
    credential_names = {"token", "bot_token", "access_token", "push_key", "signing_secret"}
    suspicious = {
        f.name
        for f in dataclasses.fields(cap.output)
        if f.name.lower() in credential_names
        or any(word in f.name.lower() for word in credential_words)
    }
    if suspicious:
        assert cap.name in SECRET_RETURNING, (
            f"{cap.name} returns {suspicious}; if that is deliberate, add it to "
            "SECRET_RETURNING and say so in the summary"
        )


def test_the_secret_returning_capabilities_are_human_only_and_audited():
    by_name = {c.name: c for c in CAPABILITIES}
    for name in SECRET_RETURNING:
        cap = by_name[name]
        assert cap.principals == ("human",), f"{name} hands out a secret to a non-human"
        assert cap.audit


# What an outside assistant may tell the crew. The crew reads all of it as data:
# facts and openspace messages, and intel it hands in or withdraws (RFC 0016),
# whose indicators are capped below every action floor.
EXTERNAL_AGENT_WRITES = {
    "memory_add_fact",
    "openspace_post",
    "intel_add",
    "intel_remove",
    "intel_digest",
    "intel_refresh",
}


def test_an_external_agent_writes_only_what_it_may_tell_the_crew():
    tools = {t["name"] for t in tool_definitions(EXTERNAL_AGENT)}
    by_mcp = {c.mcp_name: c for c in CAPABILITIES}
    for name in tools - EXTERNAL_AGENT_WRITES:
        cap = by_mcp[name]
        assert cap.scope.endswith((":read", ":run")), f"{name} is not read-only"
    for name in tools:
        assert by_mcp[name].autonomy == "L0"
    assert "ask" in tools and "finding_list" in tools, "it can still do its job"


def test_an_external_agent_may_post_to_an_openspace_but_not_act():
    by_name = {c.name: c for c in CAPABILITIES}
    assert "external_agent" in by_name["openspace.post"].principals
    for name in ("action.approve", "action.run", "credential.configure", "config.apply"):
        assert "external_agent" not in by_name[name].principals, f"{name} is reachable over MCP"


def test_every_action_capability_that_changes_something_is_audited():
    changing = {
        "action.propose",
        "action.approve",
        "action.reject",
        "action.run",
        "action.undo",
        "credential.configure",
    }
    by_name = {c.name: c for c in CAPABILITIES}
    for name in changing:
        assert by_name[name].audit, f"{name} is not audited"
    assert not by_name["action.list"].audit, "reading the list is not an event worth auditing"


def test_the_registry_has_no_duplicate_surfaces():
    assert len({c.rest_path for c in CAPABILITIES}) == len(CAPABILITIES)
    assert len({c.mcp_name for c in CAPABILITIES}) == len(CAPABILITIES)
    assert len({" ".join(c.cli_words) for c in CAPABILITIES}) == len(CAPABILITIES)


def test_the_autonomy_ladder_is_only_ever_declared_by_the_policy_or_the_registry():
    """No capability may be L1: L1 is a property of an *action*, not of a call."""
    for cap in CAPABILITIES:
        assert cap.autonomy in ("L0", "L2"), (
            f"{cap.name} is {cap.autonomy}; capabilities are L0 or L2, and actions carry L1"
        )


def test_the_mcp_role_is_the_only_way_to_exceed_external_agent():
    """SHOC_MCP_ROLE names the person driving a stdio client (RFC 0018).

    Anything but the exact name of a role leaves the client an external agent,
    and the old SHOC_MCP_PRINCIPAL grants nothing.
    """
    import os
    from unittest import mock

    from shoc.api.auth import ROLES
    from shoc.api.mcp import caller_from_env

    for value in (
        "",
        "external_agent",
        "agent",
        "service",
        "human",
        "ADMIN",
        "admin ",
        "Operator",
        "1",
        "true",
    ):
        with mock.patch.dict(os.environ, {"SHOC_MCP_ROLE": value}, clear=False):
            assert caller_from_env().kind == "external_agent", f"{value!r} must not grant more"
    with mock.patch.dict(os.environ, {"SHOC_MCP_PRINCIPAL": "human"}, clear=False):
        os.environ.pop("SHOC_MCP_ROLE", None)
        assert caller_from_env().kind == "external_agent"
    for role in ROLES:
        with mock.patch.dict(os.environ, {"SHOC_MCP_ROLE": role, "SHOC_MCP_USER": "ann"}):
            caller = caller_from_env()
            assert caller.kind == "human" and caller.id == "ann" and caller.scopes == ROLES[role]


CONFIGURE = {
    "source.configure",
    "source.remove",
    "source.push_key",
    "source.onboard",
    "source.sync",
    "mapping.write",
    "credential.configure",
    "credential.check",
    "intel.configure",
    "config.apply",
    "slack.configure",
}
RESPOND = {"action.approve", "action.reject", "action.run", "action.undo"}


def test_roles_split_configuring_from_responding():
    """RFC 0018: the deployer configures and never acts; the operator acts and never configures."""
    from shoc.api.auth import ROLES
    from shoc.capabilities.registry import Caller

    def reach(role: str) -> set[str]:
        caller = Caller(kind="human", id="t", scopes=ROLES[role])
        return {c.name for c in CAPABILITIES if c.permits(caller)}

    assert reach("admin") >= CONFIGURE | RESPOND
    assert reach("deployer") >= CONFIGURE and not reach("deployer") & RESPOND
    assert reach("operator") >= RESPOND and not reach("operator") & CONFIGURE
    reader = reach("reader")
    assert not reader & (CONFIGURE | RESPOND)
    assert all("write" not in c.tags for c in CAPABILITIES if c.name in reader)


def test_only_an_admin_issues_or_revokes_tokens():
    """RFC 0019: a token is a role, so issuing one is above every role but admin."""
    from shoc.api.auth import ROLES
    from shoc.capabilities.registry import Caller

    by_name = {c.name: c for c in CAPABILITIES}
    for name in ("token.create", "token.revoke"):
        cap = by_name[name]
        assert cap.autonomy == "L2" and cap.audit and cap.principals == ("human",)
        for role, scopes in ROLES.items():
            assert cap.permits(Caller(kind="human", id="t", scopes=scopes)) == (role == "admin")


def test_only_an_admin_manages_people_and_sso():
    """RFC 0028: inviting someone or pointing sign-in at a provider is a role, so admin only."""
    from shoc.api.auth import ROLES
    from shoc.capabilities.registry import Caller

    by_name = {c.name: c for c in CAPABILITIES}
    for name in ("user.invite", "user.reset", "user.update", "sso.configure"):
        cap = by_name[name]
        assert cap.scope in ("users:write", "sso:write")
        assert cap.autonomy == "L2" and cap.audit and cap.principals == ("human",)
        for role, scopes in ROLES.items():
            assert cap.permits(Caller(kind="human", id="t", scopes=scopes)) == (role == "admin")
