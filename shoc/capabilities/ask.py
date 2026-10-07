"""`ask` and `search`: a plain-language question in, an answer out (API-1, principle 2).

`search` never calls a model: it turns the question into typed capability calls
and answers from what they return, always with citations.

`ask` is the conversation. With a model configured, the question and the turns
before it go to the SOC Manager, which answers by calling the colleague who
knows (RFC 0015). An answer about a case, or about a key, an address, an account
or a finding the question names, cites the events behind it; one about the
deployment itself needs none (D135). Without a model, or when an answer that
needs events has none that survive the store, `ask` answers as `search` does,
and `intent` says which of the two answered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.jsonschema import field as f

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FINDING = re.compile(r"\bF-[0-9a-f]{8,}\b", re.IGNORECASE)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# At word edges, so the apostrophes in "what's" and "it's" do not quote what lies between.
QUOTED = re.compile(r"(?<!\w)[\"']([^\"']{2,64})[\"'](?!\w)")
KEY = re.compile(r"\bAKIA[0-9A-Z]{8,}\b")


@dataclass
class Query:
    """Search findings and events for what a question names. No model is called."""

    question: str = f(doc="A plain-language question or identifier, e.g. 'AKIA…' or an IP")
    since: str = f("-7d", doc="How far back to look")
    limit: int = f(25, doc="Maximum rows per section")


@dataclass
class Question:
    """Ask the crew something. An answer about a case, key, address, account or finding cites the events behind it."""

    question: str = f(doc="A plain-language question, e.g. 'what happened with AKIA…?'")
    since: str = f("-7d", doc="How far back to look")
    limit: int = f(25, doc="Maximum rows per section")
    history: list[dict[str, str]] = f(
        factory=list,
        doc="Earlier turns of this conversation, oldest first: {role: operator|manager, text}",
    )


@dataclass
class Answer:
    question: str = ""
    intent: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    needs_human: bool = False
    consulted: list[str] = field(default_factory=list)


def entities_in(question: str) -> list[str]:
    """Pull the identifiers worth pivoting on. The question is data, never an instruction."""
    found = (
        KEY.findall(question)
        + IP.findall(question)
        + EMAIL.findall(question)
        + FINDING.findall(question)
    )
    for m in QUOTED.findall(question):
        if m not in found:
            found.append(m)
    seen: list[str] = []
    for item in found:
        if item not in seen:
            seen.append(item)
    return seen


@capability(
    name="ask",
    summary="Ask the crew a question, in a conversation, and get a cited answer",
    input=Question,
    output=Answer,
    scope="ask:read",
    # Audited: the Manager answers by calling the crew, which reads more than the
    # caller's scopes do (RFC 0015).
    audit=True,
    tags=("ask", "read"),
)
def ask(ctx: Context, inp: Question) -> Result:
    reply = _managed(ctx, inp.question, inp.history)
    if reply is None:
        return search.fn(ctx, Query(question=inp.question, since=inp.since, limit=inp.limit))
    return Result(
        data=Answer(
            question=inp.question,
            intent="manager",
            entities=entities_in(inp.question),
            consulted=reply.consulted,
        ),
        summary=reply.answer,
        citations=reply.citations,
    )


@capability(
    name="search",
    summary="Search findings and events for what a question names, without a model",
    input=Query,
    output=Answer,
    scope="ask:read",
    tags=("ask", "read"),
)
def search(ctx: Context, inp: Query) -> Result:
    from shoc.capabilities.events import EventQuery
    from shoc.capabilities.events import query as events_query
    from shoc.capabilities.findings import FindingFilter, FindingRef, get_finding, list_findings

    entities = entities_in(inp.question)
    citations: list[str] = []
    events: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    parts: list[str] = []

    finding_ids = [e for e in entities if FINDING.fullmatch(e)]
    if finding_ids:
        detail = get_finding.fn(ctx, FindingRef(finding_uid=finding_ids[0]))
        return Result(
            data=Answer(
                question=inp.question,
                intent="finding.get",
                findings=[detail.data.finding],
                events=detail.data.events,
                entities=entities,
            ),
            summary=detail.summary,
            citations=detail.citations,
        )

    recent = list_findings.fn(ctx, FindingFilter(since=inp.since, limit=inp.limit))
    findings = recent.data.rows
    citations += recent.citations
    parts.append(f"{len(findings)} finding(s) since {inp.since}")

    pivots = [e for e in entities if not FINDING.fullmatch(e)]
    for value in pivots[:3]:
        for field_name in ("actor", "src_ip", "contains"):
            kwargs: dict[str, Any] = {"since": inp.since, "limit": inp.limit}
            if field_name == "src_ip" and not IP.fullmatch(value):
                continue
            if field_name == "actor" and IP.fullmatch(value):
                continue
            kwargs[field_name] = value
            page = events_query.fn(ctx, EventQuery(**kwargs))
            if page.data.count:
                events.extend(page.data.rows)
                citations += page.citations
                parts.append(f"{page.data.count} event(s) for {value} ({field_name})")
                break

    if pivots:
        entity_findings = []
        for value in pivots[:3]:
            hits = list_findings.fn(
                ctx, FindingFilter(entity=value, since=inp.since, limit=inp.limit)
            )
            entity_findings += hits.data.rows
            citations += hits.citations
        if entity_findings:
            findings = entity_findings + [fnd for fnd in findings if fnd not in entity_findings]

    needs_human = not citations
    summary = "; ".join(parts) + "."
    if needs_human:
        summary = (
            "No evidence found for that question in the window, so this needs a human. "
            "Try a wider `since`, or check whether the relevant source is configured."
        )
    return Result(
        data=Answer(
            question=inp.question,
            intent="search",
            findings=findings[: inp.limit],
            events=events[: inp.limit],
            entities=entities,
            needs_human=needs_human,
        ),
        summary=summary,
        citations=_dedup(citations)[:100],
    )


def _managed(ctx: Context, question: str, history: list[dict[str, str]]) -> Any:
    """The Manager's answer, or None when there is no model or no evidence for it."""
    from shoc.agents import manager

    try:
        return manager.answer(
            ctx.db, ctx.store, ctx.tenant_id, question, ctx.config, history, ctx.caller
        )
    except Exception:  # the query path below is always there
        return None


def _dedup(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen)
