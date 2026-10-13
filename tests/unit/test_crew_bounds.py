"""What bounds a crew turn and a crew close, without a database (AGT-1, AGT-2, AGT-5)."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx
import pytest

from shoc.agents import llm
from shoc.agents.checks import Confidence
from shoc.agents.llm import (
    AnthropicClient,
    Completion,
    ToolCall,
    ToolSpec,
    Turn,
    _anthropic_messages,
    complete_typed,
)
from shoc.jsonschema import field as f


@dataclass
class Verdict:
    verdict: str = f("needs_human", doc="the verdict")


# -- a benign close stands on the measured number (D77) ---------------------
def test_a_benign_close_needs_the_checks_behind_it():
    settled = Confidence(value=0.9, agree=3, reads=3, supported=1, checked=1)
    assert settled.unsettled() == ""
    assert "1 of 3" in Confidence(value=0.3, agree=1, reads=3, supported=1, checked=1).unsettled()
    assert "2 of 4" in Confidence(value=0.5, agree=2, reads=4, supported=1, checked=1).unsettled()
    assert "under" in Confidence(value=0.4, agree=3, reads=3, supported=2, checked=5).unsettled()
    assert Confidence(value=0.0, agree=3, reads=3, check_failed=True).unsettled()
    assert Confidence(value=0.0, agree=3, reads=3, checked=0).unsettled(), "no claim, no close"


# -- a turn stops at the run's time, not only its tokens (AGT-1) -------------
class _Curious:
    """Asks for a lookup on every step until told to answer."""

    model = "curious"

    def complete(self, system, turns, max_tokens=2048, tools=None):
        told = "Do not call another tool" in turns[-1].content
        return Completion(
            text='{"verdict": "benign_expected"}' if told else "",
            calls=[] if told else [ToolCall(f"c{len(turns)}", "events_query", {})],
            model="curious",
            tokens_in=10,
            tokens_out=5,
        )


SPEC = [ToolSpec("events_query", "search events", {"type": "object"})]


@pytest.mark.parametrize("deadline, lookups", [(0.0, 6), (-1.0, 0)])
def test_a_turn_past_its_deadline_looks_nothing_up_and_still_answers(deadline, lookups):
    served: list[str] = []
    value, _ = complete_typed(
        _Curious(),
        "system",
        "decide",
        Verdict,
        tools=SPEC,
        invoke=lambda call: served.append(call.name) or "rows",
        max_steps=6,
        deadline=time.time() + deadline if deadline else 0.0,
    )
    assert len(served) == lookups
    assert value.verdict == "benign_expected"


def test_an_invalid_answer_past_the_deadline_is_still_asked_for_once_more():
    """A re-raise counted as the provider failing and lost the turn's work."""

    class ProseThenJSON:
        model = "prose"
        calls = 0

        def complete(self, system, turns, max_tokens=2048, tools=None):
            ProseThenJSON.calls += 1
            first = ProseThenJSON.calls == 1
            text = "I think it is fine." if first else '{"verdict": "benign_expected"}'
            return Completion(text=text, model="prose")

    value, _ = complete_typed(ProseThenJSON(), "s", "p", Verdict, deadline=time.time() - 1)
    assert value.verdict == "benign_expected"
    assert ProseThenJSON.calls == 2, "one retry, no more"


# -- the retry after an invalid answer (AGT-5) -------------------------------
def test_the_retry_never_sends_an_empty_assistant_turn():
    """Anthropic answers 400 to one, so the retry meant to save a turn lost the case."""

    class SilentThenRight:
        model = "silent"

        def __init__(self) -> None:
            self.turns: list[list[Turn]] = []

        def complete(self, system, turns, max_tokens=2048, tools=None):
            self.turns.append(list(turns))
            text = "" if len(self.turns) == 1 else '{"verdict": "malicious"}'
            return Completion(text=text, model="silent")

    client = SilentThenRight()
    value, _ = complete_typed(client, "s", "p", Verdict)
    assert value.verdict == "malicious" and len(client.turns) == 2
    sent = _anthropic_messages(client.turns[1])
    assert all(m["content"] for m in sent), "every message carries content"


# -- one model call is bounded in time (AGT-5, OPS-1) ------------------------
def _transport(monkeypatch, handler) -> list[httpx.Request]:
    seen: list[httpx.Request] = []
    real_client = httpx.Client

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(recording)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": transport}))
    monkeypatch.setattr(llm.time, "sleep", lambda _: None)
    return seen


def test_a_read_that_timed_out_is_not_tried_again(monkeypatch):
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("no answer", request=request)

    seen = _transport(monkeypatch, slow)
    with pytest.raises(httpx.ReadTimeout):
        AnthropicClient("key").complete("s", [Turn("user", "x")])
    assert len(seen) == 1, "it already waited as long as one answer may take"


def test_a_busy_provider_is_retried_only_within_the_calls_time(monkeypatch):
    seen = _transport(monkeypatch, lambda request: httpx.Response(529, json={}))
    with pytest.raises(httpx.HTTPStatusError):
        AnthropicClient("key").complete("s", [Turn("user", "x")])
    assert len(seen) == 3, "three tries while there is time for them"
    seen.clear()
    monkeypatch.setattr(llm, "CALL_SECONDS", 5.0)
    with pytest.raises(httpx.HTTPStatusError):
        AnthropicClient("key").complete("s", [Turn("user", "x")])
    assert len(seen) == 2, "no try that the 10 s wait would push past the call's time"
