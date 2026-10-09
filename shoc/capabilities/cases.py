"""Case and openspace capabilities (RSP-1, AGT-1, AGT-2, AGT-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from shoc.agents import memory as memory_store
from shoc.agents.openspace import Message, post, transcript
from shoc.capabilities.registry import Context, Result, capability
from shoc.cases import engine
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class CaseFilter:
    state: str = f(
        "", doc="triage, analysis, containment, eradication, recovery, post_incident or closed"
    )
    verdict: str = f(
        "",
        doc="malicious, suspicious, benign_expected, false_positive, needs_human or unknown",
    )
    limit: int = f(25, doc="Maximum rows, capped at 200")
    unacknowledged: bool = f(
        False,
        doc="Only cases closed without their containment that nobody has acknowledged",
    )


@dataclass
class CasePage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="case.list",
    summary="List cases, newest first",
    input=CaseFilter,
    output=CasePage,
    scope="cases:read",
    tags=("cases", "read"),
)
def list_cases(ctx: Context, inp: CaseFilter) -> Result:
    rows = engine.recent(
        ctx.db, ctx.tenant_id, max(1, min(inp.limit, 200)), inp.state, inp.unacknowledged
    )
    if inp.verdict:
        rows = [r for r in rows if r["verdict"] == inp.verdict]
    open_count = sum(1 for r in rows if r["state"] != "closed")
    return Result(
        data=CasePage(rows=[to_json(r) for r in rows], count=len(rows)),
        summary=f"{len(rows)} case(s), {open_count} still open.",
        citations=[r["case_uid"] for r in rows],
    )


@dataclass
class CaseRef:
    case_uid: str = f(doc="Case identifier, e.g. CASE-1a2b…")


@dataclass
class CaseDetail:
    case: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    openspace: list[dict[str, Any]] = field(default_factory=list)
    # `openspace` holds the newest 200 messages; this is how many the case has.
    openspace_total: int = 0
    # What this case is about, by kind: the same map a playbook renders
    # `{{ entity.key }}` from. A client proposing an action needs the values,
    # not just the one in the title.
    entities: dict[str, Any] = field(default_factory=dict)


@capability(
    name="case.get",
    summary="Get one case with its findings and the openspace transcript",
    input=CaseRef,
    output=CaseDetail,
    scope="cases:read",
    tags=("cases", "read"),
)
def get_case(ctx: Context, inp: CaseRef) -> Result:
    from shoc.db.pool import fetch_all, fetch_one

    case = engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
    # A loud case can carry hundreds of findings; show the worst 50 and say how
    # many there are in total.
    findings = fetch_all(
        ctx.db,
        """SELECT finding_uid, rule_id, title, severity, event_count, first_seen,
                  last_seen, event_uids, attack
           FROM shoc.findings WHERE tenant_id = %s AND finding_uid = ANY(%s)
           ORDER BY
             array_position(ARRAY['critical','high','medium','low','informational'], severity),
             last_seen DESC
           LIMIT 50""",
        (ctx.tenant_id, list(case["finding_uids"] or [])),
    )
    findings_total = len(case["finding_uids"] or [])
    from shoc.cases.playbooks import entities_of_case

    openspace = transcript(ctx.db, ctx.tenant_id, inp.case_uid)
    openspace_total = (
        fetch_one(
            ctx.db,
            "SELECT count(*) AS n FROM shoc.openspace_messages WHERE tenant_id = %s AND case_uid = %s",
            (ctx.tenant_id, inp.case_uid),
        )
        or {}
    ).get("n", 0)
    entities = entities_of_case(ctx.db, ctx.tenant_id, inp.case_uid)
    citations = [u for m in openspace for u in (m["cited_event_uids"] or [])]
    citations += [u for fnd in findings for u in (fnd["event_uids"] or [])]
    return Result(
        data=CaseDetail(
            case=to_json(case),
            findings=[to_json(r) for r in findings],
            openspace=[to_json(m) for m in openspace],
            openspace_total=openspace_total,
            entities=to_json(entities),
        ),
        summary=(
            f"{case['severity'].upper()} · {case['title']} · state {case['state']} · "
            f"verdict {case['verdict']} ({case['confidence']:.2f}) · "
            f"{findings_total} finding(s), {openspace_total} openspace message(s)"
            + (f", the latest {len(openspace)} shown." if openspace_total > len(openspace) else ".")
        ),
        citations=list(dict.fromkeys(citations))[:100],
    )


@dataclass
class StateChange:
    case_uid: str = f(doc="The case to move")
    state: Literal[
        "triage", "analysis", "containment", "eradication", "recovery", "post_incident", "closed"
    ] = f("analysis", doc="The NIST 800-61 state to move to")
    note: str = f("", doc="Why — kept in the audit log and the stream")


@dataclass
class CaseState:
    case_uid: str = ""
    state: str = ""
    verdict: str = ""


@capability(
    name="case.set_state",
    summary="Move a case to another state in the incident-response process",
    input=StateChange,
    output=CaseState,
    scope="cases:transition",
    principals=("human", "agent"),
    audit=True,
    tags=("cases", "write"),
)
def set_state(ctx: Context, inp: StateChange) -> Result:
    by = "human" if ctx.caller.kind == "human" else "crew"
    row = engine.transition(ctx.db, ctx.tenant_id, inp.case_uid, inp.state, inp.note, by=by)
    if inp.state == "closed" and by == "human":
        _reject_pending(ctx, inp.case_uid, inp.note or "the case was closed by a person")
    return Result(
        data=CaseState(case_uid=inp.case_uid, state=row["state"], verdict=row["verdict"]),
        summary=f"{inp.case_uid} is now in {row['state']}.",
        citations=[inp.case_uid],
    )


def _reject_pending(ctx: Context, case_uid: str, why: str) -> int:
    """A person who closes a case answers what was waiting on it."""
    from shoc.cases import actions

    return actions.reject_pending(
        ctx.db,
        ctx.tenant_id,
        case_uid,
        f"{ctx.caller.kind}:{ctx.caller.id}",
        f"case closed: {why}",
    )


@dataclass
class CloseInput:
    case_uid: str = f(doc="The case to close")
    disposition: Literal["malicious", "suspicious", "benign_expected", "false_positive"] = f(
        "benign_expected",
        doc="malicious or suspicious: it was an attack; benign_expected: real activity "
        "that is normal here, the rule was right to fire; false_positive: the rule "
        "should not have fired on this",
    )
    reason: str = f("", doc="Why, in a sentence or two. The crew reads it on the next case")
    remember_days: int = f(
        90, doc="How long the crew remembers this closure for the same rule and resource"
    )


@dataclass
class CloseResult:
    case_uid: str = ""
    state: str = ""
    verdict: str = ""
    rejected_actions: int = 0
    routed: list[dict[str, Any]] = field(default_factory=list)
    memory_id: str = ""


@capability(
    name="case.close",
    summary="Close a case with your disposition: the crew stops, and what it means is routed",
    input=CloseInput,
    output=CloseResult,
    scope="cases:transition",
    principals=("human",),
    # A person's disposition is final for the crew and can change rules, so
    # an assistant asks its person before sending it (D65).
    autonomy="L2",
    audit=True,
    tags=("cases", "write"),
)
def close_case(ctx: Context, inp: CloseInput) -> Result:
    """Close a case as a person, with a disposition that carries authority.

    The verdict cites the case's own events, pending proposals are rejected, the
    closure is routed as a person's, and a memory fact is written about the rule
    and the resource for a limited time. It is never a fact about a person in
    general, and never a suppression of one: a hijacked chat account must not be
    able to make its owner invisible.
    """
    from datetime import UTC, datetime, timedelta

    from shoc.cases import routing
    from shoc.db.pool import execute, fetch_all
    from shoc.errors import ValidationError

    reason = " ".join(inp.reason.split())
    if not reason:
        raise ValidationError("say why: the reason is what the crew learns from")
    case = engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
    findings = fetch_all(
        ctx.db,
        """SELECT rule_id, entity_key AS resource, first_seen, last_seen, event_uids
           FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s""",
        (ctx.tenant_id, inp.case_uid),
    )
    citations = list(dict.fromkeys(u for r in findings for u in (r["event_uids"] or [])))[:200]
    rejected = _reject_pending(ctx, inp.case_uid, reason)
    engine.set_verdict(
        ctx.db,
        ctx.tenant_id,
        inp.case_uid,
        inp.disposition,
        1.0,
        f"Closed by {ctx.caller.id}: {reason}",
        citations,
    )
    execute(
        ctx.db,
        "UPDATE shoc.cases SET disposition_reason = %s WHERE tenant_id = %s AND case_uid = %s",
        (reason[:2000], ctx.tenant_id, inp.case_uid),
    )
    row = case
    if case["state"] != "closed":
        row = engine.transition(ctx.db, ctx.tenant_id, inp.case_uid, "closed", reason, by="human")
    else:
        execute(
            ctx.db,
            "UPDATE shoc.cases SET closed_by = 'human' WHERE tenant_id = %s AND case_uid = %s",
            (ctx.tenant_id, inp.case_uid),
        )
    routed = routing.route(
        ctx.db,
        ctx.tenant_id,
        engine.require(ctx.db, ctx.tenant_id, inp.case_uid),
        inp.disposition,
        summary=reason,
        by=f"human:{ctx.caller.id}",
        closer="human",
    )
    memory_id = ""
    if inp.disposition in ("benign_expected", "false_positive") and findings:
        rules = sorted({str(r["rule_id"]) for r in findings})
        resources = sorted({str(r["resource"]) for r in findings if r["resource"]})
        start = min(r["first_seen"] for r in findings)
        end = max(r["last_seen"] for r in findings)
        days = max(1, min(int(inp.remember_days or 90), 365))
        memory_id = memory_store.add(
            ctx.db,
            ctx.tenant_id,
            f"{', '.join(rules)} on {', '.join(resources[:5]) or 'this resource'} between "
            f"{start:%Y-%m-%d %H:%M} and {end:%Y-%m-%d %H:%M} UTC was {inp.disposition}, "
            f"said {ctx.caller.id}: {reason}",
            subject=f"{rules[0]}:{resources[0] if resources else ''}",
            kind="correction",
            source="human",
            expires_at=datetime.now(UTC) + timedelta(days=days),
        )
    return Result(
        data=CloseResult(
            case_uid=inp.case_uid,
            state=row.get("state", "closed"),
            verdict=inp.disposition,
            rejected_actions=rejected,
            routed=[e.to_json() for e in routed.entries],
            memory_id=memory_id,
        ),
        summary=(
            f"{inp.case_uid} closed as {inp.disposition}."
            + (f" {rejected} pending action(s) rejected." if rejected else "")
        ),
        citations=[inp.case_uid, *citations[:20]],
    )


@dataclass
class Acknowledged:
    case_uid: str = ""
    acknowledged_at: str = ""


@capability(
    name="case.acknowledge",
    summary="Acknowledge a case closed without its containment, so it stops asking for you",
    input=CaseRef,
    output=Acknowledged,
    scope="cases:transition",
    principals=("human",),
    # It takes a warning off the inbox and the exception report, which is what
    # a log line written at an assistant would want, so an assistant asks (D65).
    autonomy="L2",
    audit=True,
    tags=("cases", "write"),
)
def acknowledge(ctx: Context, inp: CaseRef) -> Result:
    """Say a person has seen that this case closed without its containment (D152).

    Only the actions that expired before now are covered: one that expires
    later puts the case back in front of a person.
    """
    from shoc.db.pool import fetch_one

    engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
    row = fetch_one(
        ctx.db,
        """UPDATE shoc.cases SET acknowledged_at = now(), acknowledged_by = %s
           WHERE tenant_id = %s AND case_uid = %s RETURNING acknowledged_at""",
        (f"{ctx.caller.kind}:{ctx.caller.id}", ctx.tenant_id, inp.case_uid),
    )
    at = row["acknowledged_at"].isoformat() if row else ""
    return Result(
        data=Acknowledged(case_uid=inp.case_uid, acknowledged_at=at),
        summary=f"{inp.case_uid} acknowledged.",
        citations=[inp.case_uid],
    )


@dataclass
class InvestigateInput:
    case_uid: str = f(doc="The case the crew should discuss")
    max_rounds: int = f(0, doc="Override the severity-based round budget (0 keeps it)")


@dataclass
class InvestigateReport:
    case_uid: str = ""
    verdict: str = "unknown"
    confidence: float = 0.0
    state: str = ""
    rounds: int = 0
    messages: int = 0
    tokens: int = 0
    model: str = ""
    peer_calls: int = 0
    stopped_because: str = ""
    errors: list[str] = field(default_factory=list)
    routed: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="case.investigate",
    summary="Run the crew on a case and record a cited verdict",
    input=InvestigateInput,
    output=InvestigateReport,
    scope="cases:investigate",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("cases", "agents"),
)
def investigate(ctx: Context, inp: InvestigateInput) -> Result:
    from shoc.agents.loop import run_case
    from shoc.agents.openspace import Budget

    case = engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
    # Without an explicit cap the crew budgets from what the case turns out to
    # contain, which it cannot do if a budget is decided out here from severity
    # alone (`Budget.for_case`).
    budget = None
    if inp.max_rounds:
        budget = Budget.for_severity(case["severity"])
        budget.max_rounds = max(1, inp.max_rounds)
    report = run_case(
        ctx.db, ctx.store, ctx.tenant_id, inp.case_uid, budget=budget, config=ctx.config
    )
    openspace = transcript(ctx.db, ctx.tenant_id, inp.case_uid)
    citations = [u for m in openspace for u in (m["cited_event_uids"] or [])]
    return Result(
        data=InvestigateReport(
            case_uid=report.case_uid,
            verdict=report.verdict,
            confidence=report.confidence,
            state=report.state,
            rounds=report.rounds,
            messages=report.messages,
            tokens=report.tokens,
            model=report.model,
            peer_calls=report.peer_calls,
            stopped_because=report.stopped_because,
            errors=report.errors,
            routed=report.routed,
            actions=report.actions,
        ),
        summary=(
            f"{inp.case_uid}: {report.verdict} ({report.confidence:.2f}) after "
            f"{report.rounds} round(s), {report.tokens} tokens — {report.stopped_because}."
            + (
                " Routed to " + ", ".join(sorted({r["routed_to"] for r in report.routed})) + "."
                if report.routed
                else ""
            )
        ),
        citations=list(dict.fromkeys(citations))[:100],
    )


@dataclass
class OpenspacePost:
    case_uid: str = f(doc="The openspace to post into")
    body: str = f(doc="What you want the openspace to know")
    kind: Literal[
        "observation",
        "hypothesis",
        "evidence",
        "challenge",
        "concede",
        "proposal",
        "decision",
        "inject",
        "request",
        "answer",
        "interject",
    ] = f("inject", doc="Message kind; 'inject' is how a human adds a fact from above")
    to: str = f("", doc="The agent a 'request' is for, or the one an 'answer' replies to")
    citations: list[str] = f(doc="event_uid values that back this message", factory=list)
    round: int = f(0, doc="Round to post into (0 continues the current one)")


@dataclass
class OpenspaceMessage:
    msg_id: int = 0
    round: int = 0
    agent: str = ""
    kind: str = ""
    to: str = ""
    citations: list[str] = field(default_factory=list)


@capability(
    name="openspace.post",
    summary="Post a message into an openspace: a fact, a challenge, a question for one agent",
    input=OpenspacePost,
    output=OpenspaceMessage,
    scope="cases:write",
    principals=("human", "agent", "external_agent"),
    audit=True,
    tags=("cases", "agents"),
)
def openspace_post(ctx: Context, inp: OpenspacePost) -> Result:
    case = engine.require(ctx.db, ctx.tenant_id, inp.case_uid)
    row = post(
        ctx.db,
        ctx.store,
        ctx.tenant_id,
        inp.case_uid,
        Message(
            agent=f"{ctx.caller.kind}:{ctx.caller.id}",
            kind=inp.kind,
            body=inp.body,
            to=inp.to,
            citations=inp.citations,
            principal=ctx.caller.kind,
            round=inp.round or max(1, int(case["rounds"] or 1)),
        ),
    )
    return Result(
        data=OpenspaceMessage(
            msg_id=row["msg_id"],
            round=row["round"],
            agent=row["agent"],
            kind=row["kind"],
            to=row.get("to_agent") or "",
            citations=list(row["cited_event_uids"] or []),
        ),
        summary=f"Posted a {inp.kind} into {inp.case_uid} (round {row['round']}).",
        citations=list(row["cited_event_uids"] or []),
    )


@dataclass
class MemoryFact:
    body: str = f(doc="The fact, in one sentence, e.g. 'The VPN pool is 10.8.0.0/16'")
    subject: str = f("", doc="What it is about — a user, an IP range, a system")
    kind: Literal["semantic", "episodic", "correction"] = f("semantic", doc="Kind of memory")
    expires_at: str = f("", doc="ISO-8601 timestamp after which this stops being true")


@dataclass
class MemoryRef:
    memory_id: str = ""


@capability(
    name="memory.add_fact",
    summary="Tell the crew something about this company that logs cannot show",
    input=MemoryFact,
    output=MemoryRef,
    scope="memory:write",
    principals=("human", "agent", "external_agent"),
    audit=True,
    tags=("memory", "write"),
)
def add_fact(ctx: Context, inp: MemoryFact) -> Result:
    from datetime import datetime

    expires = (
        datetime.fromisoformat(inp.expires_at.replace("Z", "+00:00")) if inp.expires_at else None
    )
    memory_id = memory_store.add(
        ctx.db, ctx.tenant_id, inp.body, inp.subject, inp.kind, ctx.caller.kind, expires
    )
    return Result(
        data=MemoryRef(memory_id=memory_id),
        summary=f"Remembered: {inp.body}",
        citations=[memory_id],
    )


@dataclass
class MemoryQuery:
    query: str = f("", doc="Words to search for; empty returns the most recent facts")
    limit: int = f(10, doc="Maximum rows")


@dataclass
class MemoryPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="memory.search",
    summary="Search what the crew knows about this company",
    input=MemoryQuery,
    output=MemoryPage,
    scope="memory:read",
    tags=("memory", "read"),
)
def search_memory(ctx: Context, inp: MemoryQuery) -> Result:
    rows = memory_store.search(ctx.db, ctx.tenant_id, inp.query, max(1, min(inp.limit, 100)))
    return Result(
        data=MemoryPage(rows=[to_json(r) for r in rows], count=len(rows)),
        summary=f"{len(rows)} remembered fact(s).",
        citations=[r["memory_id"] for r in rows],
    )
