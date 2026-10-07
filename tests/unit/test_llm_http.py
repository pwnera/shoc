"""What the LLM clients actually send and read (AGT-5)."""

from __future__ import annotations

import json

import httpx
import pytest

from shoc.agents.llm import (
    AnthropicClient,
    OpenAICompatibleClient,
    OpenAIResponsesClient,
    ToolCall,
    ToolSpec,
    Turn,
)
from shoc.errors import ConfigError


def recorder(monkeypatch, body: dict, status: int = 200) -> list[httpx.Request]:
    """Make every client the code opens use a mock transport, and keep the requests."""
    seen: list[httpx.Request] = []
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": transport}))
    return seen


ANTHROPIC_REPLY = {
    "model": "claude-sonnet-5",
    "content": [{"type": "text", "text": '{"verdict": "malicious"}'}],
    "usage": {"input_tokens": 1200, "output_tokens": 80},
}

OPENAI_REPLY = {
    "model": "gpt-4o-mini",
    "choices": [{"message": {"role": "assistant", "content": "hello"}}],
    "usage": {"prompt_tokens": 90, "completion_tokens": 10},
}


def test_the_anthropic_client_sends_the_system_prompt_separately(monkeypatch):
    seen = recorder(monkeypatch, ANTHROPIC_REPLY)
    client = AnthropicClient("key", "claude-sonnet-5")
    completion = client.complete("you are Investigator", [Turn("user", "what happened?")], 1024)

    body = json.loads(seen[0].content)
    assert body["system"] == "you are Investigator"
    assert body["messages"] == [{"role": "user", "content": "what happened?"}]
    assert body["max_tokens"] == 1024
    assert seen[0].headers["x-api-key"] == "key"
    assert seen[0].headers["anthropic-version"] == "2023-06-01"
    assert completion.text == '{"verdict": "malicious"}'
    assert completion.tokens_in == 1200 and completion.tokens_out == 80


def test_the_openai_client_puts_the_system_prompt_in_the_messages(monkeypatch):
    seen = recorder(monkeypatch, OPENAI_REPLY)
    client = OpenAICompatibleClient("key", "gpt-4o-mini", "http://localhost:11434/v1")
    completion = client.complete("you are Reporter", [Turn("user", "summarise")], 256)

    body = json.loads(seen[0].content)
    assert body["messages"][0] == {"role": "system", "content": "you are Reporter"}
    assert str(seen[0].url) == "http://localhost:11434/v1/chat/completions"
    assert seen[0].headers["authorization"] == "Bearer key"
    assert completion.text == "hello" and completion.tokens == 100


RESPONSES_REPLY = {
    "model": "deepseek-v4-1-flash",
    "output": [
        {"type": "reasoning", "summary": [{"type": "summary_text", "text": "thinking"}]},
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "checking"}],
        },
        {
            "type": "function_call",
            "call_id": "call_1",
            "name": "lookup_ip",
            "arguments": '{"ip": "192.0.2.10"}',
        },
    ],
    "usage": {"input_tokens": 300, "output_tokens": 90},
}


def test_the_responses_client_speaks_the_responses_api(monkeypatch):
    seen = recorder(monkeypatch, RESPONSES_REPLY)
    client = OpenAIResponsesClient("key", "deepseek-v4-1-flash", "https://api.kie.ai/openai/v1")
    history = [
        Turn("user", "who owns 192.0.2.10?"),
        Turn("assistant", "", calls=[ToolCall("call_0", "whois", {"ip": "192.0.2.10"})]),
        Turn("tool", '{"owner": "TEST-NET-1"}', call_id="call_0"),
    ]
    tool = ToolSpec("lookup_ip", "Look up an IP", {"type": "object"})
    completion = client.complete("you are Investigator", history, 512, [tool])

    body = json.loads(seen[0].content)
    assert str(seen[0].url) == "https://api.kie.ai/openai/v1/responses"
    assert body["instructions"] == "you are Investigator"
    assert body["max_output_tokens"] == 512
    assert body["input"] == [
        {"role": "user", "content": "who owns 192.0.2.10?"},
        {
            "type": "function_call",
            "call_id": "call_0",
            "name": "whois",
            "arguments": '{"ip": "192.0.2.10"}',
        },
        {"type": "function_call_output", "call_id": "call_0", "output": '{"owner": "TEST-NET-1"}'},
    ]
    assert body["tools"] == [
        {
            "type": "function",
            "name": "lookup_ip",
            "description": "Look up an IP",
            "parameters": {"type": "object"},
        }
    ]
    assert completion.text == "checking"
    assert completion.calls == [ToolCall("call_1", "lookup_ip", {"ip": "192.0.2.10"})]
    assert completion.tokens_in == 300 and completion.tokens_out == 90


def test_a_responses_gateway_error_says_what_went_wrong(monkeypatch):
    recorder(monkeypatch, {"code": 422, "msg": "The model is not supported", "data": None})
    with pytest.raises(ConfigError, match="not supported"):
        OpenAIResponsesClient("key", "x", "https://api.kie.ai/openai/v1").complete(
            "s", [Turn("user", "x")]
        )


def test_a_local_endpoint_needs_no_key(monkeypatch):
    seen = recorder(monkeypatch, OPENAI_REPLY)
    OpenAICompatibleClient("", "llama3", "http://ollama:11434/v1").complete(
        "s", [Turn("user", "x")]
    )
    assert "authorization" not in seen[0].headers


def test_an_http_error_reaches_the_caller(monkeypatch):
    recorder(monkeypatch, {"error": "overloaded"}, status=529)
    with pytest.raises(httpx.HTTPStatusError):
        AnthropicClient("key").complete("s", [Turn("user", "x")])


def test_anthropic_needs_an_api_key():
    with pytest.raises(ConfigError, match="SHOC_LLM_API_KEY"):
        AnthropicClient("")


def test_the_default_models_are_current():
    from shoc.agents.llm import DEFAULT_MODELS

    assert DEFAULT_MODELS["anthropic"].startswith("claude-")
    assert AnthropicClient("k").model == DEFAULT_MODELS["anthropic"]


def test_the_anthropic_client_caches_the_prefix_and_holds_output_to_a_schema(monkeypatch):
    seen = recorder(
        monkeypatch,
        {
            **ANTHROPIC_REPLY,
            "usage": {
                "input_tokens": 100,
                "output_tokens": 80,
                "cache_read_input_tokens": 900,
                "cache_creation_input_tokens": 200,
            },
        },
    )
    schema = {
        "type": "object",
        "title": "V",
        "properties": {"verdict": {"type": "string"}},
        "additionalProperties": False,
    }
    completion = AnthropicClient("key", "claude-sonnet-5").complete(
        "s", [Turn("user", "x")], 1024, schema=schema
    )
    body = json.loads(seen[0].content)
    assert body["cache_control"] == {"type": "ephemeral"}
    fmt = body["output_config"]["format"]
    assert fmt["type"] == "json_schema" and fmt["schema"]["required"] == ["verdict"]
    assert completion.tokens_in == 1200, "cached tokens were still read"
    assert "fallbacks" not in body, "claude-sonnet-5 takes no server-side fallback"


def test_a_model_that_declines_fails_loudly(monkeypatch):
    from shoc.errors import UpstreamError

    recorder(
        monkeypatch,
        {
            "model": "claude-opus-5-5",
            "content": [],
            "stop_reason": "refusal",
            "stop_details": {"type": "refusal", "category": "cyber"},
            "usage": {"input_tokens": 10, "output_tokens": 0},
        },
    )
    with pytest.raises(UpstreamError, match="cyber"):
        AnthropicClient("key", "claude-opus-5-5").complete("s", [Turn("user", "x")])


def test_a_model_with_a_fallback_asks_for_it_on_the_anthropic_api_only(monkeypatch):
    seen = recorder(monkeypatch, ANTHROPIC_REPLY)
    AnthropicClient("key", "claude-opus-5-5").complete("s", [Turn("user", "x")])
    AnthropicClient("key", "claude-opus-5-5", "https://gateway.example").complete(
        "s", [Turn("user", "x")]
    )
    first, second = (json.loads(r.content) for r in seen)
    assert first["fallbacks"] == "default"
    assert seen[0].headers["anthropic-beta"] == "server-side-fallback-2026-07-01"
    assert "fallbacks" not in second, "a gateway may not know the field"
