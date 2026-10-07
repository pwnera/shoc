"""`shoc mcp` over stdio, as a desktop client starts it (API-1, API-2)."""

from __future__ import annotations

import json
import os
import sys

import anyio
import pytest

from shoc.cases.engine import publish

pytestmark = pytest.mark.postgres


def test_a_client_lists_tools_and_calls_one_over_stdio(ctx, config, clean):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    publish(ctx.db, config.tenant_id, "case.opened", "C-stdio", {})
    env = {
        **os.environ,
        "SHOC_DSN": config.dsn,
        "SHOC_TENANT": config.tenant_id,
        "SHOC_MASTER_KEY": config.master_key,
        "SHOC_MCP_ROLE": "",
    }
    server = StdioServerParameters(command=sys.executable, args=["-m", "shoc", "mcp"], env=env)

    async def session() -> tuple[set[str], dict]:
        with anyio.fail_after(60):
            async with stdio_client(server) as (read, write), ClientSession(read, write) as s:
                await s.initialize()
                tools = {t.name for t in (await s.list_tools()).tools}
                result = await s.call_tool("stream_tail", {"types": ["case.opened"]})
                return tools, json.loads(result.content[0].text)  # type: ignore[union-attr]

    tools, answer = anyio.run(session)
    assert "stream_tail" in tools
    assert "config_apply" not in tools, "an external agent is not offered what it may not call"
    assert [e["subject"] for e in answer["data"]["events"]] == ["C-stdio"]
    assert answer["summary"]
