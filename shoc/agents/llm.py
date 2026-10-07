"""Two thin LLM clients, plus a scripted one for tests and offline runs (AGT-5).

Decision D11: no LLM framework. Anthropic and any OpenAI-compatible endpoint
(vLLM, Ollama, Databricks model serving, OpenRouter) cover what our users have,
and both are one `httpx` call. Structured output is enforced here rather than
trusted: we ask for JSON, parse leniently, validate against the caller's
dataclass, and retry once with the validation error before giving up.
"""

from __future__ import annotations

import copy
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from shoc.errors import ConfigError, UpstreamError
from shoc.jsonschema import coerce_dataclass, dataclass_schema

# A turn with room to think and a 16k-token answer can take minutes; a two-minute
# read timeout turned slow answers into outages.
TIMEOUT = httpx.Timeout(600.0, connect=10.0)

# Sensible defaults per provider; override with SHOC_LLM_MODEL.
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5", "openai": "gpt-4o-mini"}

# Models whose safety classifiers can decline a request, and which accept the
# API's own fallback. A SOC reads attack traffic all day, so a declined case is
# a real outcome here, and on an unattended install it is a case nobody works.
FALLBACK_MODELS = frozenset(
    {
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-sonnet-5-5",
    }
)
ANTHROPIC_API = "https://api.anthropic.com"

# Statuses a gateway answers when the provider is busy or slow, not wrong: rate
# limits, overload and Cloudflare's 524 "origin timed out". Three of those in a
# row left a case as needs_human with nothing wrong in it, so they are retried.
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 520, 522, 524, 529})
RETRY_DELAYS = (2.0, 10.0)


def _post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    """POST and decode, retrying a busy or timed-out provider with backoff."""
    for delay in (*RETRY_DELAYS, None):
        try:
            with httpx.Client(timeout=TIMEOUT) as http:
                resp = http.post(url, json=payload, headers=headers)
            if resp.status_code not in RETRY_STATUSES or delay is None:
                resp.raise_for_status()
                return resp.json()
        except httpx.TransportError:
            if delay is None:
                raise
        time.sleep(delay)
    raise AssertionError("unreachable")


@dataclass
class ToolSpec:
    """One capability an agent may call while it is thinking."""

    name: str
    description: str
    schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCall:
    """An agent asking for one of them."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class Completion:
    text: str = ""
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    calls: list[ToolCall] = field(default_factory=list)
    # The tools this turn actually used, so the openspace can say what an agent
    # checked before it spoke. An answer nobody can see the working for is the
    # thing this whole file exists to avoid.
    lookups: list[str] = field(default_factory=list)
    # What those tools answered. An action's target has to be something the case
    # showed the agent: an event it cites, or a platform read it made (RFC 0020).
    seen: list[str] = field(default_factory=list)

    @property
    def tokens(self) -> int:
        return self.tokens_in + self.tokens_out

    def plus(self, other: Completion) -> Completion:
        """The two calls as one bill. A conversation costs what its turns cost."""
        return Completion(
            text=other.text,
            model=other.model or self.model,
            tokens_in=self.tokens_in + other.tokens_in,
            tokens_out=self.tokens_out + other.tokens_out,
            calls=other.calls,
            lookups=self.lookups + other.lookups,
            seen=self.seen + other.seen,
        )


@dataclass
class Turn:
    role: str  # "user", "assistant" or "tool"
    content: str = ""
    calls: list[ToolCall] = field(default_factory=list)  # what an assistant asked for
    call_id: str = ""  # role == "tool": the call this answers


class LLMClient(Protocol):
    model: str

    def complete(
        self,
        system: str,
        turns: list[Turn],
        max_tokens: int = 2048,
        tools: list[ToolSpec] | None = None,
    ) -> Completion: ...


def strict_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """The schema as the Anthropic API constrains output to it, or None.

    Every property becomes required, because the API caps how many optional ones
    a request may carry and a dataclass default is only a fallback here anyway;
    `title` goes because nothing reads it. A free-form map cannot be constrained,
    so a schema with one is sent without the constraint and parsed as before.
    """
    if schema.get("type") == "object":
        if schema.get("additionalProperties", False) is not False:
            return None
        props = {}
        for name, sub in (schema.get("properties") or {}).items():
            strict = strict_schema(sub)
            if strict is None:
                return None
            props[name] = strict
        out = {k: v for k, v in schema.items() if k != "title"}
        return {**out, "properties": props, "required": list(props)}
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        items = strict_schema(schema["items"])
        return None if items is None else {**schema, "items": items}
    if "anyOf" in schema:
        options = [strict_schema(o) for o in schema["anyOf"]]
        return None if None in options else {**schema, "anyOf": options}
    return schema if schema else None


class NoLLM:
    """The default. Agent turns are skipped, and cases say so instead of guessing."""

    model = "none"
    available = False

    def complete(
        self,
        system: str,
        turns: list[Turn],
        max_tokens: int = 2048,
        tools: list[ToolSpec] | None = None,
    ) -> Completion:
        raise ConfigError(
            "no LLM is configured; set SHOC_LLM_PROVIDER (anthropic or openai) "
            "with SHOC_LLM_API_KEY, or run detections without the crew"
        )


def _arguments(raw: Any) -> dict[str, Any]:
    """A function call's arguments, whether they arrive as JSON text or a dict."""
    if isinstance(raw, dict):
        return raw
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _anthropic_messages(turns: list[Turn]) -> list[dict[str, Any]]:
    """Turns as Anthropic messages, with tool results folded into user turns.

    Anthropic carries a tool result in a user message, and consecutive results
    have to share one: two user messages in a row for two answers is a protocol
    error, not a style choice.
    """
    out: list[dict[str, Any]] = []
    for turn in turns:
        if turn.role == "tool":
            block = {
                "type": "tool_result",
                "tool_use_id": turn.call_id,
                "content": turn.content,
            }
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
            continue
        if turn.role == "assistant" and turn.calls:
            blocks: list[dict[str, Any]] = (
                [{"type": "text", "text": turn.content}] if turn.content.strip() else []
            )
            blocks += [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                for c in turn.calls
            ]
            out.append({"role": "assistant", "content": blocks})
            continue
        out.append({"role": turn.role, "content": turn.content})
    return out


def _openai_messages(turns: list[Turn]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for turn in turns:
        if turn.role == "tool":
            out.append({"role": "tool", "tool_call_id": turn.call_id, "content": turn.content})
            continue
        if turn.role == "assistant" and turn.calls:
            out.append(
                {
                    # An empty string, never null. OpenAI accepts both for a turn
                    # that is only tool calls; a gateway in front of it may not,
                    # and `{"code": 400, "msg": "Message content is null"}` looks
                    # exactly like a model outage from the other end of it.
                    "role": "assistant",
                    "content": turn.content,
                    "tool_calls": [
                        {
                            "id": c.id,
                            "type": "function",
                            "function": {
                                "name": c.name,
                                "arguments": json.dumps(c.arguments),
                            },
                        }
                        for c in turn.calls
                    ],
                }
            )
            continue
        out.append({"role": turn.role, "content": turn.content})
    return out


class AnthropicClient:
    available = True
    # Takes `schema=` and constrains its answer to it (structured outputs).
    structured = True

    def __init__(self, api_key: str, model: str = "", base_url: str = "") -> None:
        if not api_key:
            raise ConfigError("SHOC_LLM_API_KEY is required for the anthropic provider")
        self.api_key = api_key
        self.model = model or DEFAULT_MODELS["anthropic"]
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")

    def complete(
        self,
        system: str,
        turns: list[Turn],
        max_tokens: int = 2048,
        tools: list[ToolSpec] | None = None,
        schema: dict[str, Any] | None = None,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": _anthropic_messages(turns),
            # The role prompt, the tools and the dossier are resent on every step
            # of a tool loop; caching the prefix makes the second step onward
            # cost a tenth of the first.
            "cache_control": {"type": "ephemeral"},
        }
        if tools:
            payload["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.schema}
                for t in tools
            ]
        strict = strict_schema(schema) if schema else None
        if strict:
            payload["output_config"] = {"format": {"type": "json_schema", "schema": strict}}
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        if self.model in FALLBACK_MODELS and self.base_url == ANTHROPIC_API:
            payload["fallbacks"] = "default"
            headers["anthropic-beta"] = "server-side-fallback-2026-07-01"
        data = _post(f"{self.base_url}/v1/messages", payload, headers)
        if data.get("stop_reason") == "refusal":
            detail = data.get("stop_details") or {}
            raise UpstreamError(
                f"{data.get('model', self.model)} declined the request "
                f"({detail.get('category') or 'no category'}): the case is left for "
                "the sweep rather than answered without the model"
            )
        blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        usage = data.get("usage", {})
        return Completion(
            text=text,
            model=data.get("model", self.model),
            # Cached tokens are still tokens this call read; a budget counted
            # without them would let a long tool loop look free.
            tokens_in=int(usage.get("input_tokens", 0))
            + int(usage.get("cache_creation_input_tokens", 0) or 0)
            + int(usage.get("cache_read_input_tokens", 0) or 0),
            tokens_out=int(usage.get("output_tokens", 0)),
            calls=[
                ToolCall(str(b.get("id", "")), str(b.get("name", "")), b.get("input") or {})
                for b in blocks
                if b.get("type") == "tool_use"
            ],
        )


class OpenAICompatibleClient:
    """Anything that speaks /v1/chat/completions: vLLM, Ollama, Databricks, OpenAI."""

    available = True

    def __init__(self, api_key: str, model: str = "", base_url: str = "") -> None:
        self.api_key = api_key
        self.model = model or DEFAULT_MODELS["openai"]
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")

    def complete(
        self,
        system: str,
        turns: list[Turn],
        max_tokens: int = 2048,
        tools: list[ToolSpec] | None = None,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, *_openai_messages(turns)],
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.schema,
                    },
                }
                for t in tools
            ]
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        data = _post(f"{self.base_url}/chat/completions", payload, headers)
        # Gateways in front of several providers often answer 200 with an error
        # envelope instead of an HTTP status. Say what went wrong here, or the
        # crew reports "the model did not return JSON" for a bad model name.
        if "choices" not in data:
            reason = data.get("msg") or (data.get("error") or {}).get("message") or str(data)[:200]
            raise ConfigError(f"{self.base_url} returned no completion: {reason}")
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage", {})
        message = choice.get("message") or {}
        return Completion(
            text=message.get("content") or "",
            model=data.get("model", self.model),
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
            calls=[
                ToolCall(
                    str(c.get("id", "")),
                    str((c.get("function") or {}).get("name", "")),
                    _arguments((c.get("function") or {}).get("arguments")),
                )
                for c in (message.get("tool_calls") or [])
            ],
        )


def _responses_input(turns: list[Turn]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for turn in turns:
        if turn.role == "tool":
            out.append(
                {"type": "function_call_output", "call_id": turn.call_id, "output": turn.content}
            )
            continue
        if turn.content or not turn.calls:
            out.append({"role": turn.role, "content": turn.content})
        out.extend(
            {
                "type": "function_call",
                "call_id": c.id,
                "name": c.name,
                "arguments": json.dumps(c.arguments),
            }
            for c in turn.calls
        )
    return out


class OpenAIResponsesClient(OpenAICompatibleClient):
    """An endpoint that speaks /v1/responses only, as Kie does for some models (D73)."""

    def complete(
        self,
        system: str,
        turns: list[Turn],
        max_tokens: int = 2048,
        tools: list[ToolSpec] | None = None,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "instructions": system,
            "max_output_tokens": max_tokens,
            "input": _responses_input(turns),
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.schema,
                }
                for t in tools
            ]
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        data = _post(f"{self.base_url}/responses", payload, headers)
        if "output" not in data:
            reason = data.get("msg") or (data.get("error") or {}).get("message") or str(data)[:200]
            raise ConfigError(f"{self.base_url} returned no response: {reason}")
        items = data.get("output") or []
        usage = data.get("usage") or {}
        return Completion(
            text="".join(
                part.get("text", "")
                for item in items
                if item.get("type") == "message"
                for part in item.get("content") or []
                if part.get("type") == "output_text"
            ),
            model=data.get("model", self.model),
            tokens_in=int(usage.get("input_tokens", 0)),
            tokens_out=int(usage.get("output_tokens", 0)),
            calls=[
                ToolCall(
                    str(i.get("call_id", "")),
                    str(i.get("name", "")),
                    _arguments(i.get("arguments")),
                )
                for i in items
                if i.get("type") == "function_call"
            ],
        )


@dataclass
class ScriptedClient:
    """A deterministic stand-in: replies are chosen by a substring of the prompt.

    Used by the eval harness and the tests so the crew's plumbing — rounds,
    citations, budgets, verdicts — can be exercised without a model, and so a
    regression in that plumbing cannot hide behind model variance.
    """

    replies: dict[str, str] = field(default_factory=dict)
    default: str = "{}"
    model: str = "scripted"
    available: bool = True
    calls: list[str] = field(default_factory=list)
    # Tools this stand-in asks for the first time it is offered any, so the
    # conversation loop — call, answer, answer again — is exercised without a
    # model. After that it answers with `replies`, like any other turn.
    wants: list[ToolCall] = field(default_factory=list)
    asked: list[ToolCall] = field(default_factory=list)

    def complete(
        self,
        system: str,
        turns: list[Turn],
        max_tokens: int = 2048,
        tools: list[ToolSpec] | None = None,
    ) -> Completion:
        prompt = "\n".join(t.content for t in turns)
        self.calls.append(prompt)
        if tools and self.wants and not self.asked:
            self.asked = list(self.wants)
            return Completion(
                model=self.model, tokens_in=100, tokens_out=50, calls=list(self.wants)
            )
        for needle, reply in self.replies.items():
            if needle.lower() in prompt.lower() or needle.lower() in system.lower():
                return Completion(text=reply, model=self.model, tokens_in=100, tokens_out=50)
        return Completion(text=self.default, model=self.model, tokens_in=100, tokens_out=50)


def for_hint(client: LLMClient, hint: str, config: Any = None) -> LLMClient:
    """The same client on the cheaper model, for a role whose work is narrow.

    Each role says whether it needs judgement or volume (`Role.model_hint`).
    With SHOC_LLM_MODEL_CHEAP set, a "cheap" role runs on that model; without
    it, every role runs on the one model, as before.
    """
    cheap = str(getattr(client, "cheap_model", "") or getattr(config, "llm_model_cheap", "") or "")
    if hint != "cheap" or not cheap or cheap == getattr(client, "model", ""):
        return client
    other = copy.copy(client)
    other.model = cheap
    return other


STORED_FIELDS = ("provider", "model", "model_cheap", "base_url")

# What the crew may spend, stored beside the model by `llm.configure`, with the
# value used when none is stored (OPS-1, DET-9). A day's spend over
# `spend_usd_per_day` is an Ops alert (0 = no alert); `hunt_tokens_per_day` is
# the ceiling of the Hunter's daily triage turn; `intel_reports_per_day` and
# `intel_tokens_per_day` cap what CTI reads in a day (RFC 0029).
BUDGETS: dict[str, float] = {
    "spend_usd_per_day": 0.0,
    "hunt_tokens_per_day": 200_000,
    "intel_reports_per_day": 5,
    "intel_tokens_per_day": 100_000,
}


def budget(conn: Any, tenant_id: str, name: str) -> float:
    """One of `BUDGETS`, as stored for the tenant or its default."""
    from shoc.db.pool import fetch_one

    row = fetch_one(
        conn,
        "SELECT settings->>%s AS value FROM shoc.connector_config WHERE tenant_id=%s AND source='llm'",
        (name, tenant_id),
    )
    return float(row["value"]) if row and row["value"] else BUDGETS[name]


def stored(config: Any, conn: Any = None, tenant_id: str = "") -> Any:
    """The config with the tenant's `llm.configure` row laid over it (RFC 0007).

    Field by field, stored wins; a field never stored keeps SHOC_LLM_*. With no
    connection or no row, the config comes back unchanged.
    """
    from dataclasses import replace

    from shoc.config import Config
    from shoc.db.pool import fetch_one
    from shoc.db.secrets import open_secret

    cfg = config or Config.load()
    if conn is None:
        return cfg
    row = fetch_one(
        conn,
        "SELECT settings, secret FROM shoc.connector_config WHERE tenant_id=%s AND source='llm'",
        (tenant_id or cfg.tenant_id,),
    )
    if not row:
        return cfg
    settings = dict(row["settings"] or {})
    over = {f"llm_{k}": settings[k] for k in STORED_FIELDS if settings.get(k)}
    key = (
        open_secret(
            cfg.master_key, row["secret"], tenant_id or cfg.tenant_id, "connector_config", "llm"
        ).get("api_key")
        if row["secret"]
        else ""
    )
    if key:
        over["llm_api_key"] = key
    return replace(cfg, **over)


def from_config(config: Any = None, conn: Any = None, tenant_id: str = "") -> LLMClient:
    cfg = stored(config, conn, tenant_id)
    provider = (cfg.llm_provider or "none").lower()
    if provider in ("none", "", "off"):
        return NoLLM()
    if provider == "anthropic":
        client: Any = AnthropicClient(cfg.llm_api_key, cfg.llm_model, cfg.llm_base_url)
    elif provider in ("openai", "openai-compatible", "compatible"):
        client = OpenAICompatibleClient(cfg.llm_api_key, cfg.llm_model, cfg.llm_base_url)
    elif provider == "openai-responses":
        client = OpenAIResponsesClient(cfg.llm_api_key, cfg.llm_model, cfg.llm_base_url)
    else:
        raise ConfigError(
            f"unknown LLM provider '{provider}' (use anthropic, openai, openai-responses or none)"
        )
    # `for_hint` reads this, so a stored cheap model reaches every role.
    client.cheap_model = cfg.llm_model_cheap
    return client


# -- structured output ------------------------------------------------------
_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def extract_json(text: str) -> Any:
    """Pull a JSON value out of a model's reply, fenced or not.

    `raw_decode` reads the first complete value and ignores what follows it, so
    a model that adds a sentence with a brace after its JSON is still read.
    """
    candidate = text.strip()
    match = _JSON_BLOCK.search(candidate)
    if match:
        candidate = match.group(1)
    starts = [i for i in (candidate.find("{"), candidate.find("[")) if i >= 0]
    try:
        return json.JSONDecoder().raw_decode(candidate[min(starts, default=0) :])[0]
    except json.JSONDecodeError as exc:
        raise ValueError(f"the model did not return JSON: {exc}") from exc


# How many lookups one agent turn may make before it has to answer. A pivot is
# what an investigation is, but an agent that can keep asking will, and every
# call is a model call as well as a query.
MAX_TOOL_STEPS = 6
# A step can ask for many lookups at once, so steps alone did not bound a turn:
# Investigators ran nineteen queries in six steps and spent the case's budget
# before the Challenger spoke. This many in all, then it answers.
MAX_TOOL_CALLS = 12
# Every step re-sends the whole conversation, so the answers of earlier steps
# were most of what a long turn cost. Those older than the latest step are shown
# this short; the agent can ask again, and what they returned stays citable
# (`Completion.seen` keeps every answer whole).
OLD_ANSWER = 1_500


def _complete(
    client: LLMClient,
    system: str,
    turns: list[Turn],
    max_tokens: int,
    tools: list[ToolSpec] | None,
    schema: dict[str, Any] | None,
) -> Completion:
    """One call, with the output schema for a client that can be held to it."""
    if schema is not None and getattr(client, "structured", False):
        return client.complete(system, turns, max_tokens, tools, schema=schema)  # type: ignore[call-arg]
    return client.complete(system, turns, max_tokens, tools)


def _shorten(turns: list[Turn]) -> None:
    """Show the lookup answers older than the latest step as OLD_ANSWER characters."""
    latest = max((i for i, t in enumerate(turns) if t.role == "assistant"), default=-1)
    for turn in turns[:latest]:
        # Already shortened answers end in the note, inside this margin.
        if turn.role != "tool" or len(turn.content) <= OLD_ANSWER + 200:
            continue
        cut = turn.content[:OLD_ANSWER]
        if turn.content.startswith("<untrusted-data"):
            cut += "\n</untrusted-data>"
        turn.content = (
            f"{cut}\n[An earlier answer, shortened from {len(turn.content)} characters. "
            "Look it up again if you need the rest.]"
        )


def _converse(
    client: LLMClient,
    system: str,
    turns: list[Turn],
    max_tokens: int,
    tools: list[ToolSpec] | None,
    invoke: Any,
    max_steps: int,
    schema: dict[str, Any] | None = None,
    token_budget: int = 0,
    outside: Any = None,
    max_calls: int = MAX_TOOL_CALLS,
) -> Completion:
    """Talk until the agent stops asking for things, or runs out of lookups.

    The agent gets the last word either way: when the lookups, or the tokens
    of `token_budget`, are spent it is told so and asked for its answer,
    rather than being cut off mid-thought with nothing to record. `outside`
    returns what was spent elsewhere on this turn's behalf — the colleagues
    it asked — which counts against the same budget.
    """
    bill = Completion(model=getattr(client, "model", ""))
    if not (tools and invoke):
        return bill.plus(_complete(client, system, turns, max_tokens, None, schema))
    calls = 0
    for _ in range(max(1, max_steps)):
        if token_budget and bill.tokens + (outside() if outside else 0) >= token_budget:
            break
        _shorten(turns)
        completion = _complete(client, system, turns, max_tokens, tools, schema)
        bill = bill.plus(completion)
        if not completion.calls:
            return bill
        turns.append(Turn("assistant", completion.text, calls=completion.calls))
        before = outside() if outside else 0
        for call in completion.calls:
            # Once the calls of this step have spent the budget, the rest wait: one
            # step that asked three colleagues ran a case past its budget before
            # the Commander. The lookups it asked for before crossing still run.
            now = outside() if outside else 0
            spent = token_budget and now > before and bill.tokens + now >= token_budget
            if calls >= max_calls or spent:
                # Every call needs an answer, or the next request is refused.
                turns.append(
                    Turn("tool", "Not run: this turn's lookups are spent.", call_id=call.id)
                )
                continue
            calls += 1
            bill.lookups.append(call.name)
            answer = invoke(call)
            bill.seen.append(answer)
            turns.append(Turn("tool", answer, call_id=call.id))
        if calls >= max_calls or (
            token_budget and bill.tokens + (outside() if outside else 0) >= token_budget
        ):
            break
    _shorten(turns)
    turns.append(
        Turn(
            "user",
            "You have used every lookup this case pays for. Do not call another "
            "tool. Answer now from what you have, and say in your reasoning what "
            "you could not check.",
        )
    )
    # The tools stay declared: a history that holds tool calls is refused by the
    # Anthropic API without them. A call made anyway is simply not run.
    return bill.plus(_complete(client, system, turns, max_tokens, tools, schema))


def complete_typed(
    client: LLMClient,
    system: str,
    prompt: str,
    schema_type: type,
    max_tokens: int = 2048,
    tools: list[ToolSpec] | None = None,
    invoke: Any = None,
    max_steps: int = MAX_TOOL_STEPS,
    token_budget: int = 0,
    outside: Any = None,
    max_calls: int = MAX_TOOL_CALLS,
) -> tuple[Any, Completion]:
    """Ask for JSON matching `schema_type`, validate it, and retry once on failure.

    With `tools` and `invoke`, the agent may look things up before it answers:
    it is handed the capabilities its role is allowed to call, the answers come
    back as data, and only then is the typed reply parsed. Without them this is
    the single round trip it always was. Past `token_budget` tokens it looks
    nothing more up.
    """
    schema = dataclass_schema(schema_type)
    instruction = (
        f"{prompt}\n\n"
        + (
            "Look up whatever you need first, with the tools you have. Then reply"
            if tools
            else "Reply"
        )
        + " with JSON only — no prose, no code fence — matching this schema:\n"
        f"{json.dumps(schema, indent=2)}"
    )
    turns = [Turn("user", instruction)]
    completion = _converse(
        client,
        system,
        turns,
        max_tokens,
        tools,
        invoke,
        max_steps,
        schema,
        token_budget,
        outside,
        max_calls,
    )
    try:
        # A field the schema does not have is dropped, not fatal: the schema is
        # what reaches the openspace, and a model without structured output
        # sometimes adds one ("unchecked") and lost the whole case over it.
        return coerce_dataclass(
            schema_type, extract_json(completion.text), strict=False
        ), completion
    except Exception as exc:  # one retry with the error, then give up
        retry = _complete(
            client,
            system,
            [
                *turns,
                Turn("assistant", completion.text[:2000]),
                Turn("user", f"That was not valid: {exc}. Reply with JSON only."),
            ],
            max_tokens,
            tools,
            schema,
        )
        merged = completion.plus(retry)
        return coerce_dataclass(schema_type, extract_json(retry.text), strict=False), merged
