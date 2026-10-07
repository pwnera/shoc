"""The openspace: a blackboard in one table (AGT-1, RFC 0003, RFC 0010).

The openspace is the record of a case, not what drives it (RFC 0012): the
loop posts each role's turn here, in the order it was produced. Claims must
carry evidence: a hypothesis, a piece of evidence or a decision without event
UIDs that actually exist in the store is refused, and the caller has to
downgrade it. A run's budget is rounds, tokens and wall time (`Budget`); the
loop reads what a run spent with `spend`, and running out stops the run and
hands the case to a person (AGT-1).

Two kinds of message are addressed rather than broadcast. A role that calls a
peer while it is thinking leaves a `request` naming the peer and an `answer`
naming the caller, so the record says who asked what.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.cases import engine
from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.errors import ValidationError
from shoc.store import ocsf as layout
from shoc.store.base import EventStore

KINDS = (
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
)

# Kinds that are for one named agent rather than for the openspace at large.
ADDRESSED = ("request", "answer")

# Kinds that make a claim about what happened, and therefore need evidence.
MUST_CITE = ("hypothesis", "evidence", "decision")


@dataclass
class Budget:
    """What one run of the crew on a case may spend before it has to conclude.

    Running out stops the run and hands the case to a person (AGT-1). The
    figures are per run, and sized for what a run costs: every turn of the
    Investigator re-reads the dossier on each of its six lookups, so the 12k
    tokens a low case used to get were spent before the Challenger spoke.
    """

    max_rounds: int = 2
    max_tokens: int = 200_000
    max_seconds: int = 600

    @classmethod
    def for_severity(cls, severity: str) -> Budget:
        return {
            "informational": cls(1, 60_000, 300),
            "low": cls(1, 100_000, 420),
            "medium": cls(2, 200_000, 600),
            "high": cls(3, 300_000, 900),
            "critical": cls(5, 500_000, 1200),
        }.get(severity, cls())

    @classmethod
    def for_case(cls, severity: str, observables: int = 0, reports: int = 0) -> Budget:
        """What this case may spend, from what it holds and not only its label.

        Severity is a guess made by a rule before anybody looked. What the
        evidence actually contains is better information: a medium case with a
        hash that appears in a report we have read is worth a debate, and the
        same severity with one login and nothing to research is not. Severity
        sets the floor; evidence raises it.
        """
        budget = cls.for_severity(severity)
        if reports:
            budget.max_rounds += 1
            budget.max_tokens += 60_000
            budget.max_seconds += 180
        elif observables >= 3:
            budget.max_rounds = max(budget.max_rounds, 2)
            budget.max_tokens += 30_000
            budget.max_seconds += 120
        return budget


@dataclass
class Message:
    agent: str
    kind: str
    body: str
    to: str = ""  # the agent a request is for, or the one an answer replies to
    citations: list[str] = field(default_factory=list)
    confidence: float | None = None
    tokens: int = 0
    model: str = ""
    principal: str = "agent"
    round: int = 1


@dataclass
class Evidence:
    """The events one piece of work may cite (SEC-2, principle 6).

    Its own events (a case's findings, a hunt's tuple), and whatever a lookup
    returned while the agent worked: the tool answers are kept as text, and an
    event counts when its id is in one of them. An event that exists elsewhere
    in the tenant and that nothing showed the agent proves nothing here.
    """

    uids: set[str] = field(default_factory=set)
    seen: list[str] = field(default_factory=list)

    def __contains__(self, uid: object) -> bool:
        return uid in self.uids or any(str(uid) in text for text in self.seen)


def validate_citations(
    store: EventStore | None, tenant_id: str, uids: list[str], evidence: Any = None
) -> list[str]:
    """Return the subset of event UIDs that really exist. Hallucinated ones vanish.

    With `evidence`, an event also has to be in it.
    """
    wanted = [u for u in dict.fromkeys(uids) if u and (evidence is None or u in evidence)][:200]
    if not wanted or store is None:
        return []  # nothing claimed, or nothing to check it against
    placeholders = ", ".join(f":u{i}" for i in range(len(wanted)))
    params: dict[str, Any] = {f"u{i}": u for i, u in enumerate(wanted)}
    params["tenant_id"] = tenant_id
    rows = store.query(
        # DISTINCT: one event id loaded twice (a replay, another tenant's test
        # data) used to take two of the limit's rows and push a real one out.
        f"SELECT DISTINCT event_uid FROM {layout.EVENTS_TABLE} "
        f"WHERE tenant_id = :tenant_id AND event_uid IN ({placeholders})",
        params,
        limit=len(wanted),
    ).rows
    found = {str(r["event_uid"]) for r in rows}
    return [u for u in wanted if u in found]


def _collapse_repeat(
    conn: Conn, tenant_id: str, case_uid: str, message: Message
) -> dict[str, Any] | None:
    """Count an identical re-post instead of appending it.

    A crew run that cannot reach its model says exactly the same thing every
    time it is retried. Five tries an hour, on a case nobody has closed, is a
    transcript that grows for as long as the outage lasts and never says
    anything new. The first message stays; the rest become a number on it.

    Only the newest message is compared, so a genuine exchange that returns to
    the same point is still recorded — this collapses repetition, not agreement.
    A message that cost tokens is never collapsed: models are charged for, and
    spend has to stay countable even when a model says the same thing twice.
    """
    if message.tokens:
        return None
    latest = fetch_one(
        conn,
        """SELECT msg_id, round, agent, kind, body, cited_event_uids, confidence,
                  to_agent, created_at, principal
           FROM shoc.openspace_messages
           WHERE tenant_id = %s AND case_uid = %s
           ORDER BY msg_id DESC LIMIT 1""",
        (tenant_id, case_uid),
    )
    if not latest:
        return None
    same = (
        latest["agent"] == message.agent
        and latest["kind"] == message.kind
        and latest["body"] == message.body
        and (latest["principal"] or "") == (message.principal or "")
    )
    if not same:
        return None
    return fetch_one(
        conn,
        """UPDATE shoc.openspace_messages
           SET repeats = repeats + 1, last_repeat_at = now()
           WHERE tenant_id = %s AND msg_id = %s
           RETURNING msg_id, round, agent, kind, body, cited_event_uids, confidence,
                     to_agent, created_at, repeats""",
        (tenant_id, latest["msg_id"]),
    )


def post(
    conn: Conn,
    store: EventStore | None,
    tenant_id: str,
    case_uid: str,
    message: Message,
) -> dict[str, Any]:
    """Append one message to an openspace, after checking its kind and its evidence."""
    if message.kind not in KINDS:
        raise ValidationError(f"unknown openspace message kind '{message.kind}'")
    if not message.body.strip():
        raise ValidationError("an openspace message needs a body")
    if message.kind in ADDRESSED and not message.to.strip():
        raise ValidationError(f"a '{message.kind}' message must name the agent it is for")
    engine.require(conn, tenant_id, case_uid)
    citations = validate_citations(store, tenant_id, message.citations)
    if message.kind in MUST_CITE and not citations:
        raise ValidationError(
            f"a '{message.kind}' message must cite at least one event that exists; "
            "post it as an 'observation' or a 'challenge' instead"
        )
    repeated = _collapse_repeat(conn, tenant_id, case_uid, message)
    if repeated is not None:
        return repeated
    row = fetch_one(
        conn,
        """INSERT INTO shoc.openspace_messages
             (tenant_id, case_uid, round, agent, principal, kind, body,
              cited_event_uids, confidence, tokens, model, to_agent)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           RETURNING msg_id, round, agent, kind, body, cited_event_uids, confidence,
                     to_agent, created_at""",
        (
            tenant_id,
            case_uid,
            max(1, message.round),
            message.agent,
            message.principal,
            message.kind,
            message.body,
            citations,
            message.confidence,
            message.tokens,
            message.model or None,
            message.to.strip(),
        ),
    )
    execute(
        conn,
        """UPDATE shoc.cases
           SET rounds = GREATEST(rounds, %s), tokens_used = tokens_used + %s, updated_at = now()
           WHERE tenant_id = %s AND case_uid = %s""",
        (max(1, message.round), message.tokens, tenant_id, case_uid),
    )
    engine.publish(
        conn,
        tenant_id,
        "openspace.message",
        case_uid,
        {
            "agent": message.agent,
            "principal": message.principal,
            "kind": message.kind,
            "to": message.to.strip(),
            "round": message.round,
            "citations": citations[:20],
        },
    )
    execute(conn, "SELECT pg_notify(%s, %s)", ("shoc_openspace", f"{tenant_id}:{case_uid}"))
    return row or {}


def transcript(conn: Conn, tenant_id: str, case_uid: str, limit: int = 200) -> list[dict[str, Any]]:
    """The newest `limit` messages, oldest first.

    It used to return the first `limit`, so a case that ran past 200 messages
    lost the end of its discussion, the decision included.
    """
    return fetch_all(
        conn,
        """SELECT * FROM (
             SELECT msg_id, round, agent, principal, kind, body, cited_event_uids,
                    confidence, tokens, model, to_agent, created_at, repeats, last_repeat_at
             FROM shoc.openspace_messages
             WHERE tenant_id = %s AND case_uid = %s
             ORDER BY msg_id DESC LIMIT %s
           ) newest ORDER BY msg_id""",
        (tenant_id, case_uid, limit),
    )


@dataclass
class Spend:
    rounds: int = 0
    tokens: int = 0
    seconds: float = 0.0

    def exceeds(self, budget: Budget) -> str:
        if self.rounds >= budget.max_rounds:
            return f"round budget reached ({budget.max_rounds})"
        if self.tokens >= budget.max_tokens:
            return f"token budget reached ({budget.max_tokens})"
        if self.seconds >= budget.max_seconds:
            return f"time budget reached ({budget.max_seconds}s)"
        return ""
