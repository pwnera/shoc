"""Review before a containment action (RSP-6, RFC 0004, RFC 0012).

Research says what an address *is*. It cannot say what blocking it will cost this
particular company — that the address is the payment provider's webhook source,
or the office wifi, or the CEO's hotel. So before a blocking action runs
automatically, somebody answers for it against the evidence the question actually
needs: the graph neighbourhood of the target, and what the company has told us
about it.

RFC 0012 deleted the Operator, and the review is now the **IR Commander's** own,
answering two questions about its proposal: who else this touches, and whether
this is the smallest action that would do. A role reviewing its own work is
weaker than a role reviewing somebody else's, which is why the blast radius has
to be cited and why the guard below runs first and cannot be argued with.

**A deterministic guard runs before any model.** If more than
`MAX_SHARED_PRINCIPALS` distinct principals have been seen behind the target, the
action escalates without a model being asked at all: shared infrastructure is
arithmetic, and the component that can take the company offline should not be
reachable by persuasion.

A review can only ever make an action harder to take. It approves only when
every reviewer approves and nobody raises an objection; anything else — one
objection, a reviewer that could not be reached, a lookup that failed, no model
configured — is an escalation to L2, where a human decides with the objections
attached. A review never approves on a human's behalf and never raises an
action's autonomy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.agents import ops, roles, safety
from shoc.agents.llm import LLMClient, NoLLM, complete_typed, from_config
from shoc.agents.openspace import Message, post
from shoc.db.pool import Conn, fetch_all

REVIEWERS = (roles.COMMANDER,)

# More than this many distinct users, hosts or accounts behind the target in the
# window and the action escalates with no model involved. The number is a
# judgement — it stands between an automatic block and the company's own office
# address — and it is deliberately low.
MAX_SHARED_PRINCIPALS = 3

# How far back the graph is asked about the target. Longer than the action's own
# TTL, because "who used this" is a question about habit, not about today.
SHARED_WINDOW_DAYS = 30


@dataclass
class Opinion:
    """One reviewer's answer."""

    reviewer: str = ""
    approve: bool = False
    blast_radius: str = ""
    objections: list[str] = field(default_factory=list)
    safer_alternative: str = ""
    reached: bool = True
    error: str = ""


@dataclass
class Context:
    """What the reviewer is shown about the target, and whether it could see it."""

    principals: list[str] = field(default_factory=list)
    neighbours: list[dict[str, Any]] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    seen: bool = False  # the graph answered at all
    error: str = ""

    @property
    def shared(self) -> bool:
        """Arithmetic, not judgement: too many people are behind this target."""
        return len(self.principals) > MAX_SHARED_PRINCIPALS

    def to_json(self) -> dict[str, Any]:
        return {
            "principals": self.principals,
            "principal_count": len(self.principals),
            "neighbours": self.neighbours,
            "facts": self.facts,
            "seen": self.seen,
            "shared": self.shared,
            "error": self.error,
        }


@dataclass
class Review:
    """What the crew said about a proposed action."""

    done: bool = False
    approved: bool = False
    reviewers: list[Opinion] = field(default_factory=list)
    objections: list[str] = field(default_factory=list)
    blast_radius: str = ""
    safer_alternative: str = ""
    reason: str = ""
    tokens: int = 0
    model: str = "none"
    context: Context = field(default_factory=Context)

    def to_json(self) -> dict[str, Any]:
        return {
            "done": self.done,
            "context": self.context.to_json(),
            "approved": self.approved,
            "reason": self.reason,
            "objections": self.objections,
            "blast_radius": self.blast_radius,
            "safer_alternative": self.safer_alternative,
            "model": self.model,
            "tokens": self.tokens,
            "reviewers": [
                {
                    "reviewer": o.reviewer,
                    "approve": o.approve,
                    "reached": o.reached,
                    "blast_radius": o.blast_radius,
                    "objections": o.objections,
                    "safer_alternative": o.safer_alternative,
                    "error": o.error,
                }
                for o in self.reviewers
            ],
        }


def case_citations(conn: Conn, tenant_id: str, case_uid: str, limit: int = 20) -> list[str]:
    rows = fetch_all(
        conn,
        """SELECT unnest(event_uids) AS event_uid FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s LIMIT %s""",
        (tenant_id, case_uid, limit),
    )
    return [str(r["event_uid"]) for r in rows]


def gather_context(conn: Conn, tenant_id: str, target_kind: str, target: str) -> Context:
    """Who and what is behind this target, from the graph and from memory.

    A reviewer that cannot see this is guessing, so a failure here is recorded
    rather than swallowed: `seen` stays false and the review refuses.
    """
    from shoc.agents import graph, memory

    out = Context()
    if not target:
        out.error = "the action names no target"
        return out
    node_id = f"{target_kind}:{target}"
    try:
        walk = graph.neighbours(conn, tenant_id, node_id, hops=1, limit=100)
        out.seen = True
        out.neighbours = [
            {"node": n["node_id"], "kind": n["kind"], "label": n["label"], "events": n["events"]}
            for n in walk.nodes
            if n["node_id"] != node_id
        ]
        # A principal is something that acts: a user, a key, a host or an
        # account. Another address next to this one is not somebody losing
        # access, so counting it would escalate every busy target.
        out.principals = sorted(
            {
                str(n["node"])
                for n in out.neighbours
                if n["kind"] in ("user", "key", "account", "host", "resource")
            }
        )
        out.facts = [str(m["body"]) for m in memory.search(conn, tenant_id, target, limit=8)]
    except Exception as exc:
        out.seen = False
        out.error = f"{type(exc).__name__}: {exc}"
    return out


def _brief(
    action_type: str,
    plan: str,
    target_kind: str,
    target: str,
    rationale: str,
    case: dict[str, Any],
    research: Any,
    context: Context | None = None,
    citations: list[str] | None = None,
) -> str:
    """What every reviewer is shown. Research is a third party's words, so it is quoted."""
    lines = [
        "A containment action is about to run automatically, without a human.",
        "Review it before it does.",
        "",
        f"Action:    {action_type}",
        # The target, the plan and the rationale were written by a model that
        # read the logs, and a case title can carry a log value (SEC-2).
        safety.quote(
            "proposal",
            {
                "plan": plan,
                "target": f"{target_kind}:{target}",
                "proposed_because": rationale or "no rationale was given",
            },
        ),
    ]
    if case:
        lines += [
            "",
            safety.quote(
                "case",
                {
                    "case_uid": case.get("case_uid", ""),
                    "title": case.get("title", ""),
                    "severity": case.get("severity", "?"),
                    "confidence": round(float(case.get("confidence", 0.0)), 2),
                    "state": case.get("state", "?"),
                },
            ),
        ]
    if research is not None:
        lines += [
            "",
            "Research on the target, gathered from public sources:",
            safety.quote("intel_research", research.to_json()),
        ]
    if context is not None:
        lines += [
            "",
            f"Who and what has been seen behind this target in the last "
            f"{SHARED_WINDOW_DAYS} days ({len(context.principals)} distinct principal(s)):",
            safety.quote("world_graph", context.to_json()),
        ]
        if context.facts:
            lines += [
                "",
                "What this company has told us about it:",
                safety.quote("tenant-memory", context.facts),
            ]
        elif context.seen:
            lines += ["", "This company has told us nothing about this target."]
    if citations:
        # A blast radius that counts somebody cites the events it counted them
        # from, and these are the ones a review may cite.
        lines += [
            "",
            "The events behind this case, which your answer cites:",
            safety.quote("case-events", citations),
        ]
    lines += [
        "",
        "Answer for this action only. Approve it only if you would run it right now,",
        "on a live production network, with nobody watching. If it would cut off",
        "people or services that are not using a compromised credential — an office,",
        "a shared address, other users — say so in blast_radius and do not approve.",
        "A credential the attacker holds is cut off together with whatever of ours",
        "also uses it: that is the cost of containing it, not a reason to wait. If a",
        "narrower action would do, or one that stops the attacker where this does",
        "not, name it in safer_alternative and do not approve this one.",
    ]
    return "\n".join(lines)


def _named(alternative: str) -> bool:
    return alternative.strip().strip(".").lower() not in ("", "none", "n/a", "no", "nothing")


def _cites(blast: Any, answer: Any, allowed: list[str]) -> bool:
    cited = [str(c) for c in [*(blast.citations or []), *(answer.citations or [])]]
    return bool(set(cited) & set(allowed)) if allowed else bool(cited)


def _radius(blast: Any) -> str:
    """The blast radius as one sentence, or empty when it was not answered.

    It is a typed object now (RFC 0012) rather than a sentence, because "who else
    is behind this" is a count and a count can be checked. An unanswered count is
    an empty string here, and an empty string refuses the action.
    """
    if blast is None:
        return ""
    counted = getattr(blast, "principals", None)
    # Not `or -1`: zero principals behind the target is the best possible answer —
    # the attacker and nobody else — and treating it as unreadable refused exactly
    # the actions that are safest to take.
    principals = -1 if counted is None else int(counted)
    if principals < 0:
        return ""
    bits = [f"{principals} principal(s) behind the target"]
    for label, value in (
        ("shared infrastructure", getattr(blast, "shared_infrastructure", "")),
        ("already declared as", getattr(blast, "declared_as", "")),
        ("the company loses", getattr(blast, "company_loses", "")),
    ):
        if str(value or "").strip():
            bits.append(f"{label}: {str(value).strip()}")
    return "; ".join(bits)


def review_action(
    conn: Conn,
    store: Any,
    tenant_id: str,
    *,
    action_type: str,
    plan: str,
    target_kind: str,
    target: str,
    rationale: str = "",
    case: dict[str, Any] | None = None,
    research: Any = None,
    config: Any = None,
    client: LLMClient | None = None,
    context: Context | None = None,
) -> Review:
    """Convene the review. Failure to review is an escalation, never an approval.

    `context` is what the reviewer is shown about the target; leaving it unset
    reads it from the graph and from memory, which is what production does.
    """
    from shoc.config import Config

    cfg = config or Config.load()
    case = case or {}
    case_uid = str(case.get("case_uid") or "")
    out = Review()
    out.context = (
        context if context is not None else gather_context(conn, tenant_id, target_kind, target)
    )

    # The deterministic guard, before any model. Shared infrastructure and a
    # blind reviewer are both arithmetic, and neither should be arguable.
    guard = _guard(out.context, target)
    if guard:
        out.done = True
        out.objections = guard
        out.reason = "; ".join(guard)
        if case_uid:
            # No role decided this, so no role is credited with it: the guard is
            # arithmetic, and attributing it to an agent invited an argument.
            _say(
                conn,
                store,
                tenant_id,
                case_uid,
                "shoc",
                "observation",
                f"{action_type} on {target} was not reviewed automatically: " + out.reason,
            )
        return out

    client = client or from_config(cfg, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        out.reason = (
            "no model is configured, so the crew could not review this action; "
            "a human approves it instead"
        )
        return out
    out.model = getattr(client, "model", "none")

    citations = case_citations(conn, tenant_id, case_uid) if case_uid else []
    brief = _brief(
        action_type, plan, target_kind, target, rationale, case, research, out.context, citations
    )

    if case_uid:
        _say(
            conn,
            store,
            tenant_id,
            case_uid,
            "IR Commander",
            "proposal",
            f"Proposing {action_type} on {target_kind}:{target}. {plan}",
        )
        if research is not None:
            _say(
                conn,
                store,
                tenant_id,
                case_uid,
                "CTI",
                "evidence" if citations else "observation",
                f"Research on {target}: {research.summary}",
                citations,
            )

    for role in REVIEWERS:
        opinion = Opinion(reviewer=role.name)
        try:
            answer, usage = complete_typed(
                client,
                safety.system_prompt(role.prompt),
                brief,
                roles.ReviewOutput,
                cfg.llm_max_tokens,
            )
            ops.charge(conn, tenant_id, usage)
            out.tokens += usage.tokens
            opinion.approve = bool(answer.approve)
            opinion.blast_radius = _radius(answer.blast_radius)
            opinion.objections = [str(o) for o in (answer.objections or []) if str(o).strip()]
            # An uncertain blast radius is a refusal, and "I could not count the
            # principals" is uncertain. The prompt says so; this enforces it.
            if not opinion.blast_radius:
                opinion.approve = False
                opinion.objections.append("the blast radius was not answered, which is a refusal")
            # A count of somebody behind the target is a claim about our events,
            # so it cites them (D45). Zero has nothing to cite. In a case, the
            # citation has to be one of the case's events it was shown: the brief
            # used to show none, so a review either refused or cited ids nothing
            # checked.
            elif (
                (blast := answer.blast_radius) is not None
                and int(blast.principals) > 0
                and not _cites(blast, answer, citations)
            ):
                opinion.approve = False
                opinion.objections.append("the blast radius cites no events, which is a refusal")
            opinion.safer_alternative = str(answer.safer_alternative or "")
            # "Is this the smallest action that would do" is half the review. A
            # reviewer that names a better one has answered no, whatever it set
            # `approve` to: a block approved beside "disable the key instead".
            if opinion.approve and _named(opinion.safer_alternative):
                opinion.approve = False
                opinion.objections.append(
                    f"a better action would do: {opinion.safer_alternative.strip()}"
                )
            if case_uid:
                _say(
                    conn,
                    store,
                    tenant_id,
                    case_uid,
                    role.name,
                    "challenge",
                    _opinion_body(opinion, action_type, target),
                    [str(c) for c in (answer.citations or [])] or citations,
                )
        except Exception as exc:
            opinion.reached = False
            opinion.error = f"{type(exc).__name__}: {exc}"
        out.reviewers.append(opinion)

    out.done = True
    unreachable = [o.reviewer for o in out.reviewers if not o.reached]
    out.objections = [f"{o.reviewer}: {text}" for o in out.reviewers for text in o.objections]
    out.blast_radius = "; ".join(
        f"{o.reviewer}: {o.blast_radius}" for o in out.reviewers if o.blast_radius.strip()
    )
    out.safer_alternative = next(
        (o.safer_alternative for o in out.reviewers if o.safer_alternative.strip()), ""
    )
    refused = [o.reviewer for o in out.reviewers if o.reached and not o.approve]

    if unreachable:
        out.reason = f"{', '.join(unreachable)} could not be reached for review"
    elif refused:
        out.reason = f"{', '.join(refused)} did not approve: " + (
            "; ".join(out.objections) or "no reason given"
        )
    elif out.objections:
        out.reason = "the reviewers approved but raised: " + "; ".join(out.objections)
    else:
        out.approved = True
        out.reason = f"{', '.join(o.reviewer for o in out.reviewers)} reviewed and approved"
    return out


def _guard(context: Context, target: str) -> list[str]:
    """What escalates an action without asking a model (RFC 0006).

    Two answers are arithmetic. A target that several principals share is
    infrastructure, whoever else is also using it right now; and a reviewer that
    could not see the graph cannot argue blast radius at all, so it must not be
    asked to try. Both escalate to a human rather than blocking anything.
    """
    if not context.seen:
        return [
            f"the graph could not be read for {target or 'this target'}"
            + (f" ({context.error})" if context.error else "")
            + ", and blast radius cannot be argued without it"
        ]
    if context.shared:
        names = ", ".join(context.principals[:5])
        more = f" and {len(context.principals) - 5} more" if len(context.principals) > 5 else ""
        return [
            f"{len(context.principals)} distinct principals have been seen behind "
            f"{target} ({names}{more}); that is shared infrastructure, and blocking it "
            f"would cut off more than the attacker"
        ]
    return []


def _opinion_body(opinion: Opinion, action_type: str, target: str) -> str:
    verb = "approves" if opinion.approve else "does not approve"
    parts = [f"{opinion.reviewer} {verb} {action_type} on {target}."]
    if opinion.blast_radius:
        parts.append(f"Blast radius: {opinion.blast_radius}")
    if opinion.objections:
        parts.append("Objections: " + "; ".join(opinion.objections))
    if opinion.safer_alternative:
        parts.append(f"Narrower option: {opinion.safer_alternative}")
    return " ".join(parts)


def _say(
    conn: Conn,
    store: Any,
    tenant_id: str,
    case_uid: str,
    agent: str,
    kind: str,
    body: str,
    citations: list[str] | None = None,
) -> None:
    """Write the review into the openspace. An openspace that refuses the message is not fatal."""
    import contextlib

    with contextlib.suppress(Exception):
        post(
            conn,
            store,
            tenant_id,
            case_uid,
            Message(agent=agent, kind=kind, body=body, citations=citations or []),
        )
