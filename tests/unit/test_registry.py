from __future__ import annotations

import pytest

from shoc.capabilities.registry import Caller, Context, all_capabilities, get
from shoc.errors import Denied


def test_every_capability_declares_a_scope_and_schemas():
    caps = all_capabilities()
    assert len(caps) >= 10
    for cap in caps:
        assert cap.scope and ":" in cap.scope
        assert cap.input_schema()["type"] == "object"
        assert cap.rest_path.startswith("/v1/")
        assert cap.mcp_name.isidentifier()


def test_rest_paths_and_mcp_names_are_unique():
    caps = all_capabilities()
    assert len({c.rest_path for c in caps}) == len(caps)
    assert len({c.mcp_name for c in caps}) == len(caps)


def test_scope_check_blocks_a_caller_without_the_scope():
    cap = get("events.query")
    ctx = Context(tenant_id="t", caller=Caller(kind="human", id="u", scopes=("findings:read",)))
    with pytest.raises(Denied, match="lacks scope"):
        cap.invoke(ctx, {})


def test_principal_check_blocks_an_agent_from_a_human_only_capability():
    cap = get("source.configure")
    ctx = Context(tenant_id="t", caller=Caller(kind="agent", id="crew", scopes=("*",)))
    with pytest.raises(Denied, match="principal"):
        cap.invoke(ctx, {"source": "okta"})


def test_area_wildcard_scope_is_accepted():
    caller = Caller(kind="agent", id="worker", scopes=("events:*",))
    assert caller.allows("events:read")
    assert not caller.allows("findings:read")
