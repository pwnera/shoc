"""The agent loop: one case, worked to a verdict nobody has to read (AGT-1, AGT-2).

The shape of a case is fixed in code, not asked of a model:

  Investigator   builds the timeline from the alerting source out, reaches a
                 disposition and sets the severity, calling CTI and the Surveyor
                 while it thinks
  Challenger     argues whichever side the verdict did not, once
  Investigator   answers what survived
  IR Commander   proposes the response when there is one, and owns the outcome

There is no Orchestrator and there are no rounds to converge (RFC 0012). A role
that needs something another role knows **calls it** — `ask_cti`,
`ask_surveyor` — and the answer comes back inside its own turn instead of being
scheduled. The `request` and `answer` messages are still written, because the
openspace is the record of what was asked; it is no longer the mechanism.

The case is closed by whoever held it last: the Investigator when nothing needed
doing, the Commander when something did. An exhausted budget still produces a
decision, never silence, and without an LLM the deterministic parts run and the
case is handed to a human with the evidence attached.

Whatever the case concludes, the closure is routed: `benign_expected` becomes an
expiring suppression and a note in memory, `false_positive` becomes a detection
defect, and the rest goes to the Commander. See `shoc/cases/routing.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from shoc.agents import checks, observables, roles, safety, tools
from shoc.agents.dossier import (
    MAX_DOSSIER_FINDINGS,
    build_dossier,
    finding_count,
)
from shoc.agents.dossier import (
    findings as case_findings,
)
from shoc.agents.llm import (
    MAX_TOOL_CALLS,
    MAX_TOOL_STEPS,
    Completion,
    LLMClient,
    NoLLM,
    complete_typed,
    for_hint,
)
from shoc.agents.openspace import (
    Budget,
    Evidence,
    Message,
    Spend,
    post,
    transcript,
    validate_citations,
)
from shoc.cases import credentials, engine
from shoc.db.pool import Conn, fetch_all
from shoc.errors import ShocError
from shoc.store.base import EventStore

# What asking colleagues may cost. Every peer call is a model call, and rounds
# used to bound a case by construction, so this ceiling is the whole replacement:
# a case spends no more than this many peer calls however much there is to ask.
MAX_PEER_CALLS = 6

# What the loop asks CTI when the case's own evidence calls for it (AGT-11). The
# values are in the dossier CTI reads, quoted as data, so none is repeated here.
CTI_BY_EVIDENCE = (
    "The observables and reports in this case's dossier: what is known about them? "
    "Look up the ones worth looking up."
)


class BudgetExhausted(Exception):
    """This run has spent its token or time budget, and stops where it is (AGT-1)."""


def _exhausted(report: RunReport, budget: Budget, started: datetime) -> str:
    """Which of this run's token and time budgets is spent, or "".

    Counted from what this run spent, not from the case's whole life: a case
    worked before would otherwise arrive over budget. Rounds are not counted
    here; a round is a step of the loop, not a cost.
    """
    seconds = (datetime.now(UTC) - started).total_seconds()
    return Spend(tokens=report.tokens, seconds=seconds).exceeds(budget)


def _within(report: RunReport, budget: Budget, started: datetime) -> None:
    if reason := _exhausted(report, budget, started):
        raise BudgetExhausted(reason)


@dataclass
class RunReport:
    case_uid: str
    rounds: int = 0
    messages: int = 0
    tokens: int = 0
    verdict: str = "unknown"
    confidence: float = 0.0
    state: str = "triage"
    severity: str = ""
    stopped_because: str = ""
    model: str = ""
    peer_calls: int = 0
    errors: list[str] = field(default_factory=list)
    routed: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _Peers:
    """Roles a role may call while it is thinking (RFC 0012).

    A peer call runs that role with its own principal and its own capability
    list, never the caller's, so this is not a way to borrow scopes. It costs a
    model call, so the case holds a ceiling and refuses once it is spent, and the
    exchange is written to the openspace as a `request` and an `answer` because
    the record of who asked what is worth keeping even though nothing schedules
    it any more.
    """

    conn: Conn
    store: EventStore
    tenant_id: str
    case_uid: str
    report: RunReport
    client: LLMClient
    config: Any
    dossier: str
    budget: Budget
    started: datetime
    round_no: int = 1
    asked: set[tuple[str, str, str]] = field(default_factory=set)
    # Whose request this work answers, when it answers one (`ask`): every peer
    # is offered only what that caller may call itself (AGT-10, AGT-14).
    on_behalf: Any = None

    def ask_for(self, caller: str) -> Any:
        """A callable the caller's tool loop uses to put a question to a peer."""

        def ask(name: str, question: str) -> str:
            return self._ask(caller, name, question)

        return ask

    def _spent(self) -> bool:
        if self.report.peer_calls >= MAX_PEER_CALLS:
            return True
        # Tokens and time this run spent; rounds bound the case's own turns, and
        # counting them here refused every peer call on a low or resumed case.
        return bool(_exhausted(self.report, self.budget, self.started))

    def _ask(self, caller: str, name: str, question: str) -> str:
        role = roles.peer(caller, name)
        if role is None:
            allowed = ", ".join(roles.PEERS.get(caller, ())) or "nobody"
            return f"You cannot ask {name}. You may ask: {allowed}."
        if self._spent():
            return (
                f"{role.name} cannot be asked: this case has spent what it may on "
                "asking colleagues. Answer from what you have."
            )
        key = (caller, role.name, question)
        if key in self.asked:
            return f"You already asked {role.name} that, and the answer has not changed."
        self.asked.add(key)
        self.report.peer_calls += 1
        if self.case_uid:
            _post(
                self.conn,
                self.store,
                self.tenant_id,
                self.case_uid,
                self.report,
                Message(
                    agent=caller,
                    kind="request",
                    to=role.name,
                    body=question,
                    round=self.round_no,
                ),
            )
        try:
            answer, usage = _ask(
                self.client,
                role,
                f"{self.dossier}\n\n{caller} is asking you:\n"
                f"{safety.quote('question', question)}\n"
                "Answer it from the evidence in front of you, in three sentences at "
                "most. Look up what you need first. If you do not know, say that "
                "instead of guessing.",
                role.answers,
                self.config,
                self.conn,
                self.tenant_id,
                self.store,
                # A peer asks its own peers under the same ceiling (AGT-9).
                ask=self.ask_for(role.name),
                on_behalf=self.on_behalf,
                # A colleague answers one question in three sentences: a short
                # turn, not an investigation of its own.
                budget=_turn(self.report, self.budget, 0.1),
                max_steps=3,
                max_calls=6,
            )
        except Exception as exc:  # a peer failing must not lose the case
            reason = f"{role.name}: {type(exc).__name__}: {exc}"
            self.report.errors.append(reason)
            _charge_failure(
                self.conn, self.tenant_id, getattr(self.client, "model", "none"), reason
            )
            self._audit(caller, role.name, question, error=reason)
            return f"{role.name} could not be reached. Answer without them, and say so."
        _charge(self.conn, self.tenant_id, usage)
        body, cites, confidence = _answer(answer)
        self._audit(caller, role.name, question, body)
        if not body:
            return f"{role.name} has nothing to add."
        if not self.case_uid:
            # A question asked outside any case, through `ask` or a scheduled
            # turn, has no openspace; the audit row above is its record.
            self.report.tokens += usage.tokens
            return safety.quote(f"{role.name} answers", body)
        _post(
            self.conn,
            self.store,
            self.tenant_id,
            self.case_uid,
            self.report,
            Message(
                agent=role.name,
                kind="answer",
                to=caller,
                body=_said(body, usage),
                citations=validate_citations(self.store, self.tenant_id, cites),
                confidence=confidence,
                tokens=usage.tokens,
                model=usage.model,
                round=self.round_no,
            ),
        )
        return safety.quote(f"{role.name} answers", body)

    def _audit(
        self, caller: str, peer: str, question: str, answer: str = "", error: str | None = None
    ) -> None:
        """Every peer call goes in the audit chain, in a case or not (AGT-9, RFC 0012)."""
        from shoc.db import audit

        audit.append(
            # The same principal id the role's tool calls are audited under.
            self.conn,
            self.tenant_id,
            "agent",
            f"agent:{caller}",
            tools.peer_specs((peer,))[0].name,
            audit.hash_payload({"case_uid": self.case_uid, "to": peer, "question": question}),
            None if error else audit.hash_payload({"answer": answer}),
            error,
        )


def _answer(answer: Any) -> tuple[str, list[str], float]:
    """One peer's reply as a sentence, whatever schema its role answers in.

    A peer keeps its own contract rather than being flattened into free text: CTI
    owes a provenance on every claim, and the Surveyor owes what it knows an
    address from. A `body` field would have quietly dropped both.
    """
    cites = [str(c) for c in (getattr(answer, "citations", None) or [])]
    confidence = float(getattr(answer, "confidence", 0.5) or 0.5)

    body = str(getattr(answer, "body", "") or "").strip()
    if body:  # RemarkOutput: the plain answer
        return ("" if getattr(answer, "speak", True) is False else body), cites, confidence

    known = getattr(answer, "known", None)
    if known is not None:  # CtiOpinionOutput
        bits = [f"{k.says} [{k.provenance}]" for k in known if str(k.says).strip()]
        if getattr(answer, "attribution", ""):
            bits.append(f"Attribution: {answer.attribution}. It does not change what to do next.")
        if getattr(answer, "what_usually_follows", None):
            bits.append("Usually followed by: " + "; ".join(answer.what_usually_follows[:3]) + ".")
        if getattr(answer, "queue_read", None):
            bits.append("Queued for reading: " + "; ".join(answer.queue_read[:3]) + ".")
        return (" ".join(bits) or "Nothing has been published on any of this."), cites, confidence

    if hasattr(answer, "what_it_is"):  # AssetAnswer
        what = str(answer.what_it_is or "").strip() or "unknown"
        ours = "ours" if answer.is_ours else "not ours"
        counted = getattr(answer, "principals", None)
        count = (
            f"{int(counted)} principal(s) behind it"
            if counted is not None and int(counted) >= 0
            else "the graph could not be read"
        )
        return (
            f"{answer.target}: {ours} — {what} (known from {answer.source}); {count}.",
            cites,
            confidence,
        )
    return "", cites, confidence


def _observation(case: dict[str, Any], findings: list[dict[str, Any]], total: int = 0) -> str:
    shown = findings[:10]
    bits = [
        f"{f['title']} ({f['rule_id']}, {f['event_count']} event(s) "
        f"{f['first_seen']:%H:%M}-{f['last_seen']:%H:%M} UTC)"
        for f in shown
    ]
    total = total or len(findings)
    tail = f" and {total - len(shown)} more" if total > len(shown) else ""
    return (
        f"{total} detection(s) fired for {case['entity_key'] or 'this tenant'}: "
        + "; ".join(bits)
        + tail
        + "."
    )


def run_case(
    conn: Conn,
    store: EventStore,
    tenant_id: str,
    case_uid: str,
    client: LLMClient | None = None,
    budget: Budget | None = None,
    config: Any = None,
) -> RunReport:
    """Work one case to a verdict, within its budget."""
    from shoc.agents.llm import from_config

    case = engine.require(conn, tenant_id, case_uid)
    if case["state"] == "closed":
        # A job queued before the case closed is not a reason to reopen the
        # argument: a person's close is final, and so is the crew's own.
        return RunReport(
            case_uid=case_uid,
            state="closed",
            verdict=str(case["verdict"]),
            confidence=float(case["confidence"]),
            stopped_because="the case is closed",
        )
    client = client or from_config(config, conn, tenant_id)
    budget = budget or Budget.for_severity(case["severity"])
    started = datetime.now(UTC)
    report = RunReport(
        case_uid=case_uid, state=case["state"], model=getattr(client, "model", "none")
    )
    findings = case_findings(conn, tenant_id, case, MAX_DOSSIER_FINDINGS)
    if not findings:
        # Its findings are gone (retention, or a merge). Left open, the sweep
        # re-queues it every cycle and nothing is ever said.
        report.stopped_because = "the case has no findings"
        import contextlib

        with contextlib.suppress(ShocError):
            report.state = engine.transition(
                conn, tenant_id, case_uid, "closed", "its findings no longer exist"
            )["state"]
        return report

    # A case the crew has worked before is continued, not restarted: what matters
    # on the way back in is the difference, not the same detections read out again.
    prior = transcript(conn, tenant_id, case_uid)
    opening = max((int(m["round"]) for m in prior), default=0) + 1
    cited = [u for f in findings for u in (f["event_uids"] or [])][:20]
    # What a verdict may cite: the case's own events, what the crew cited here
    # before, and what its lookups return during this run (SEC-2). An event
    # elsewhere in the tenant proves nothing about this case.
    evidence = Evidence(
        {u for f in case_findings(conn, tenant_id, case) for u in (f["event_uids"] or [])}
        | {u for m in prior for u in (m.get("cited_event_uids") or [])}
    )
    changed = _changed(conn, tenant_id, case, prior) if prior else ""
    # Sentinel has no seat in the openspace (RFC 0012), so the case opens with a
    # statement of fact that no model wrote. It exists because silence is the one
    # outcome this loop may not produce: with no LLM, this is all a human gets.
    _post(
        conn,
        store,
        tenant_id,
        case_uid,
        report,
        Message(
            agent="shoc",
            kind="observation",
            body=changed or _observation(case, findings, finding_count(conn, tenant_id, case)),
            citations=cited,
            round=opening,
        ),
    )

    cap = case.get("token_cap")
    if cap and int(case.get("tokens_used") or 0) >= int(cap):
        # A case only a hunt opened has a lifetime ceiling: past it, a person
        # reads what the crew already gathered rather than the crew reading again.
        engine.set_verdict(
            conn,
            tenant_id,
            case_uid,
            "needs_human",
            0.0,
            f"This hunt case has used its {cap} tokens; what the crew found is attached.",
            cited,
        )
        report.verdict, report.stopped_because = "needs_human", "the case's token ceiling"
        report.routed = _route(conn, tenant_id, case, "needs_human", report)
        return report

    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        engine.set_verdict(
            conn,
            tenant_id,
            case_uid,
            "needs_human",
            0.0,
            "No LLM is configured, so the crew did not run. The detections and their "
            "evidence are attached for a human.",
            cited,
        )
        report.verdict, report.stopped_because = "needs_human", "no LLM configured"
        report.rounds = 1
        report.routed = _route(conn, tenant_id, case, "needs_human", report)
        return report

    dossier = build_dossier(conn, store, tenant_id, case)
    # Every role reads the earlier discussion and what brought the crew back,
    # not only the Investigator (AGT-12).
    resumed = _so_far(prior) + (
        f"\n\nWhat brought the crew back:\n{safety.quote('what-changed', changed)}"
        if changed
        else ""
    )
    dossier.text += resumed + _people_said(prior)
    verdict, confidence, citations = "needs_human", 0.0, cited
    investigation: Any = None
    challenge: Any = None
    broke = False
    exhausted = ""
    round_no = opening
    peers = _Peers(
        conn,
        store,
        tenant_id,
        case_uid,
        report,
        client,
        config,
        dossier.text,
        budget,
        started,
        round_no,
    )

    try:
        investigation, usage = _ask(
            client,
            roles.INVESTIGATOR,
            f"{dossier.text}{_rejoin(prior)}\n\nBuild the timeline from the source "
            "that alerted outward, then give your disposition. Set the severity this "
            "case deserves, say in scope what else the same indicators touch, and "
            "record what you looked for and did not find. Ask CTI and the Surveyor "
            "rather than inferring what they know.",
            roles.InvestigatorOutput,
            config,
            conn,
            tenant_id,
            store,
            ask=peers.ask_for("Investigator"),
            budget=_turn(report, budget, 0.35),
        )
        _charge(conn, tenant_id, usage)
        evidence.seen += usage.seen
        verdict, confidence = investigation.verdict, investigation.confidence
        # Where the Investigator stood before anybody argued with it. Asked "are
        # you sure?", a model changes its answer often enough that a flip is a
        # disagreement to count, not a correction to adopt silently.
        earlier: list[str] = []
        # An agent's citations are checked against the store, and never quietly
        # replaced by someone else's: a verdict stands on its own evidence.
        citations = validate_citations(store, tenant_id, _cited(investigation), evidence)
        said = _with_scope(investigation)
        case, budget = _resevere(
            conn,
            store,
            tenant_id,
            case,
            report,
            investigation,
            dossier,
            budget,
            round_no,
            evidence,
        )
        peers.budget = budget
        _post(
            conn,
            store,
            tenant_id,
            case_uid,
            report,
            Message(
                agent="Investigator",
                kind="hypothesis",
                body=_said(said, usage),
                citations=citations,
                confidence=confidence,
                tokens=usage.tokens,
                model=usage.model,
                round=round_no,
            ),
            fallback_kind="observation",
        )
        _within(report, budget, started)

        # The evidence calls CTI when the Investigator did not (AGT-11, D41):
        # something researchable in the events, or a report that describes them.
        # What it says is in front of the Challenger and the answer to it.
        if observables.worth_asking(dossier.observables, dossier.reports) and not any(
            asked == "CTI" for _, asked, _ in peers.asked
        ):
            heard = peers.ask_for("Investigator")("CTI", CTI_BY_EVIDENCE)
            dossier.text += f"\n\nCTI, asked because of what the evidence contains:\n{heard}"

        # The Challenger runs on every case, once, and argues whichever side the
        # verdict did not. It used to be gated on severity, so most cases — the
        # mediums — never heard an ordinary explanation at all; and it only ever
        # argued benign, so a wrong `benign_expected` was never contested by
        # anything.
        round_no += 1
        peers.round_no = round_no
        challenge, usage = _ask(
            client,
            roles.CHALLENGER,
            _against(verdict, dossier.text),
            roles.ChallengerOutput,
            config,
            conn,
            tenant_id,
            store,
            budget=_turn(report, budget, 0.12),
        )
        _charge(conn, tenant_id, usage)
        body = (
            challenge.strongest
            or "; ".join(challenge.explanations)
            or "Nothing survives the evidence."
        )
        _post(
            conn,
            store,
            tenant_id,
            case_uid,
            report,
            Message(
                agent="Challenger",
                kind="concede" if challenge.concede else "challenge",
                body=_said(
                    f"[arguing {challenge.arguing}, grounded in {challenge.grounded_in}] {body}",
                    usage,
                ),
                citations=validate_citations(store, tenant_id, challenge.citations),
                tokens=usage.tokens,
                model=usage.model,
                round=round_no,
            ),
        )
        # An objection must be answered, not obeyed: the Investigator rules it out
        # with cited evidence, or revises. It may not close over it in silence,
        # and that holds for an argument that rests on nothing as well (AGT-2):
        # the budget was checked before the Challenger spoke, so the answer is
        # paid for, and a verdict never stands over an unanswered objection.
        if not challenge.concede:
            earlier = [verdict]
            round_no += 1
            peers.round_no = round_no
            investigation, usage = _ask(
                client,
                roles.INVESTIGATOR,
                f"{dossier.text}\n\nThe Challenger is arguing {challenge.arguing}. Its "
                "argument and what would rule it out are its own words, written after "
                "reading the same logs:\n"
                + safety.quote(
                    "challenge",
                    {
                        "argument": body,
                        "would_rule_out": list(challenge.would_rule_out),
                    },
                )
                + "\n"
                "Rule it out with cited evidence, including a query that comes back "
                "empty, or revise your verdict. You may not close over it in silence.",
                roles.InvestigatorOutput,
                config,
                conn,
                tenant_id,
                store,
                ask=peers.ask_for("Investigator"),
                budget=_turn(report, budget, 0.15),
            )
            _charge(conn, tenant_id, usage)
            evidence.seen += usage.seen
            verdict, confidence = investigation.verdict, investigation.confidence
            # A revised verdict stands on its own citations or becomes
            # `needs_human`; it never inherits round 1's (principle 6).
            citations = validate_citations(store, tenant_id, _cited(investigation), evidence)
            said = _with_scope(investigation)
            case, budget = _resevere(
                conn,
                store,
                tenant_id,
                case,
                report,
                investigation,
                dossier,
                budget,
                round_no,
                evidence,
            )
            peers.budget = budget
            _post(
                conn,
                store,
                tenant_id,
                case_uid,
                report,
                Message(
                    agent="Investigator",
                    kind="evidence",
                    body=_said(said, usage),
                    citations=citations,
                    confidence=confidence,
                    tokens=usage.tokens,
                    model=usage.model,
                    round=round_no,
                ),
                fallback_kind="observation",
            )

        # The confidence the policy reads is measured, not asked for (RFC 0020):
        # independent reads agreeing, and each claim shown by its own events.
        measured = checks.derive(
            client, store, tenant_id, dossier.text, investigation, earlier, config
        )
        _charge(conn, tenant_id, measured.usage)
        report.tokens += measured.usage.tokens
        confidence = measured.value
        _post(
            conn,
            store,
            tenant_id,
            case_uid,
            report,
            Message(
                agent="shoc",
                kind="observation",
                body=measured.note(verdict),
                citations=citations,
                round=round_no,
            ),
        )

        # The disposition is recorded before the response is proposed, because the
        # policy decides an action's autonomy partly from the case's own
        # confidence. Recording it afterwards meant every proposal was judged
        # against `confidence = 0.0`, so every L1 action the policy would have
        # allowed was downgraded to "a human approves" — on a product whose human
        # does not look at it most days.
        # Activity that has not stopped calls for a response only while the
        # verdict leaves room for an attack. Benign activity keeps going: an
        # integration refreshing its token every hour is still active, and the
        # Commander sent there proposed revoking shoc's own credential.
        benign = verdict in ("benign_expected", "false_positive")
        responds = verdict in ("malicious", "suspicious") or (
            bool(getattr(investigation, "still_active", False)) and not benign
        )
        if engine.require(conn, tenant_id, case_uid)["state"] == "closed":
            # Somebody closed it while the crew was talking. Their close stands.
            report.stopped_because = "the case was closed while the crew worked"
            report.state, report.verdict = (
                "closed",
                str(engine.require(conn, tenant_id, case_uid)["verdict"]),
            )
            report.rounds = round_no
            return report
        if responds:
            _within(report, budget, started)
            interim = engine.set_verdict(
                conn,
                tenant_id,
                case_uid,
                verdict,
                confidence,
                investigation.reasoning,
                citations,
            )
            verdict = interim.get("verdict", verdict)
            confidence = float(interim.get("confidence", confidence))

            round_no += 1
            peers.round_no = round_no
            command, usage = _ask(
                client,
                roles.COMMANDER,
                f"{_brief(conn, tenant_id, case, dossier, investigation, measured, resumed)}\n\n"
                f"Verdict: {verdict} ({confidence:.2f}). The Investigator's reasoning, "
                "written after reading the logs:\n"
                f"{safety.quote('reasoning', investigation.reasoning)}\n"
                f"{'The activity has not stopped. ' if getattr(investigation, 'still_active', False) else ''}"
                "Collect the evidence containment would destroy first, then propose "
                "the response. Ask the Surveyor for the blast radius of every target "
                "and cite it; an action whose blast radius you cannot answer does "
                "not run. Every L2 names its fallback and its window.\n\n"
                f"{_catalogue(config, credentials.Scope.of(conn, tenant_id, case_uid, config))}",
                roles.CommanderOutput,
                config,
                conn,
                tenant_id,
                store,
                ask=peers.ask_for("IR Commander"),
                budget=_turn(report, budget, 0.15),
            )
            _charge(conn, tenant_id, usage)
            # A page is asked for with `page_condition`, through the Manager's
            # gate (RFC 0015). Proposed as an action it was a second way to wake
            # somebody, and the Commander used it as "collect from a human".
            ordered = _ordered(
                [p for p in command.proposals if not str(p.action).startswith("notify.")]
            )[:5]
            evidence = _evidence(conn, store, tenant_id, case, dossier, citations, usage)
            report.actions = _propose(
                conn,
                tenant_id,
                case_uid,
                ordered,
                config,
                grounded=[
                    all(_grounded(str(v), evidence) for v in [p.target, *p.params.values()])
                    for p in ordered
                ],
            )
            for proposal, taken in zip(ordered, report.actions, strict=False):
                _post(
                    conn,
                    store,
                    tenant_id,
                    case_uid,
                    report,
                    Message(
                        agent="IR Commander",
                        kind="proposal",
                        body=json.dumps(_proposal_json(proposal, taken)),
                        tokens=usage.tokens,
                        model=usage.model,
                        round=round_no,
                    ),
                )
            _page(conn, tenant_id, case_uid, command, citations)
            _post(
                conn,
                store,
                tenant_id,
                case_uid,
                report,
                Message(
                    agent="IR Commander",
                    kind="decision",
                    body=_response_note(command),
                    citations=citations,
                    confidence=confidence,
                    tokens=usage.tokens,
                    model=usage.model,
                    round=round_no,
                ),
                fallback_kind="observation",
            )
            next_state = "containment"
            if command.ready_to_close:
                open_items = _unverified(conn, store, tenant_id, case_uid, command)
                if open_items:
                    _post(
                        conn,
                        store,
                        tenant_id,
                        case_uid,
                        report,
                        Message(
                            agent="IR Commander",
                            kind="observation",
                            body="Not closing yet: " + "; ".join(open_items),
                            round=round_no,
                        ),
                    )
                else:
                    next_state = "closed"
        else:
            # Nothing to respond to, so the Investigator closes its own case. There
            # is no shift lead to adjourn a meeting that is not happening.
            _post(
                conn,
                store,
                tenant_id,
                case_uid,
                report,
                Message(
                    agent="Investigator",
                    kind="decision",
                    body=f"Closing as {verdict} ({confidence:.2f}): {investigation.reasoning}",
                    citations=citations,
                    confidence=confidence,
                    round=round_no,
                ),
                fallback_kind="observation",
            )
            # A benign verdict closes, whether or not the activity goes on; an
            # open one closes when the Investigator says so. A case left in
            # analysis is a case the sweep sends the crew back to.
            next_state = (
                "closed" if benign or getattr(investigation, "ready_to_close", True) else "analysis"
            )
    except BudgetExhausted as exc:
        # Out of tokens or time is a decision, never a silent stop (RFC 0003): a
        # person decides, with what the crew found so far attached (AGT-1).
        exhausted = str(exc)
        verdict, confidence, next_state = "needs_human", 0.0, ""
        report.stopped_because = f"budget: {exhausted}"
        seconds = int((datetime.now(UTC) - started).total_seconds())
        _post(
            conn,
            store,
            tenant_id,
            case_uid,
            report,
            Message(
                agent="shoc",
                kind="decision",
                body=f"The crew stopped here: {exhausted}, after {report.tokens} tokens and "
                f"{seconds}s. A person decides; what the crew found is above.",
                citations=citations or cited,
                round=round_no,
            ),
            fallback_kind="observation",
        )
        engine.publish(
            conn,
            tenant_id,
            "case.budget_exhausted",
            case_uid,
            {
                "reason": exhausted,
                "tokens": report.tokens,
                "seconds": seconds,
                "severity": case.get("severity"),
            },
        )
    # A case that broke down keeps the state it is in: `triage` is not reachable
    # from `analysis`, so asking for it only added a second, meaningless error to
    # every failed run.
    except Exception as exc:  # a model failure must not lose the case
        _broke_down(conn, store, tenant_id, case_uid, report, client, exc, cited)
        broke = True
        # What the Investigator concluded is kept, at confidence 0 (D42 as
        # amended by D77): the next reader starts from it, the policy acts on
        # none of it, and nothing is routed from a run that did not finish.
        if investigation is None:
            verdict = "needs_human"
        confidence, next_state = 0.0, ""

    if engine.require(conn, tenant_id, case_uid)["state"] == "closed":
        report.stopped_because = (
            report.stopped_because or "the case was closed while the crew worked"
        )
        report.state = "closed"
        return report
    reasoning = getattr(investigation, "reasoning", "") or ""
    if exhausted:
        reasoning = f"The crew stopped at its budget ({exhausted}). {reasoning}".strip()
    case_row = engine.set_verdict(
        conn,
        tenant_id,
        case_uid,
        verdict,
        confidence,
        reasoning,
        citations,
    )
    report.verdict = case_row.get("verdict", verdict)
    # Every disposition goes somewhere: a suppression, a detection defect, the
    # Commander or a person. The verdict that was actually recorded is the one
    # that routes — an uncited verdict was downgraded and owes a human, not a
    # suppression — and a benign one routes only once the case closes on it.
    if broke:
        report.routed = _route(conn, tenant_id, case_row or case, "needs_human", report, reasoning)
    elif next_state == "closed" or report.verdict in ("needs_human", "malicious", "suspicious"):
        report.routed = _route(conn, tenant_id, case_row or case, report.verdict, report, reasoning)
    if not broke and next_state == "closed" and report.verdict == "benign_expected":
        # The Challenger's draft is stored only when the benign side won, and
        # only words the closure's own row: its rule and entity, its week.
        _suppression(conn, tenant_id, case_uid, challenge, report)
    report.confidence = case_row.get("confidence", confidence)
    if next_state and next_state != case_row.get("state"):
        try:
            case_row = engine.transition(
                conn, tenant_id, case_uid, next_state, "crew decision", by="crew"
            )
        except ShocError as exc:
            report.errors.append(str(exc))
    report.state = case_row.get("state", report.state)
    report.severity = report.severity or str(case.get("severity") or "")
    report.rounds = round_no
    if report.tokens:
        # Only when somebody actually spoke: a run that could not reach a model
        # has to stay eligible for the sweep, or a flaky gateway retires the case.
        _worked(conn, tenant_id, case_uid, started)
    report.stopped_because = report.stopped_because or "converged"
    return report


def _against(verdict: str, dossier: str) -> str:
    """Tell the Challenger which side to argue. It is never told to argue both."""
    if verdict in ("malicious", "suspicious"):
        side = (
            "You are arguing benign. Find the ordinary explanation the "
            "Investigator has to rule out."
        )
    else:
        side = (
            "You are arguing attack. The Investigator says this is ordinary; say "
            "what would look exactly like this and not be. A wrong benign verdict "
            "is the failure nobody ever notices."
        )
    # The verdict and nothing else: an argument built against the Investigator's
    # prose is an argument about its wording, and the evidence is right there.
    return (
        f"{dossier}\n\nThe verdict on the table is {verdict}.\n{side}\n"
        "Say what your explanation rests on, and set concede when nothing on your "
        "side survives."
    )


def _cited(investigation: Any) -> list[str]:
    """Every event the Investigator pointed at, from its claims as well as its list.

    Citations used to be one bag at the end of a verdict, which is evidence of
    nothing in particular. Per-claim citations are the contract now, and the
    verdict's own list is whatever the model also offered wholesale.
    """
    out = list(getattr(investigation, "citations", None) or [])
    for claim in getattr(investigation, "claims", None) or []:
        out.extend(getattr(claim, "citations", None) or [])
    seen: dict[str, None] = {}
    for uid in out:
        if str(uid).strip():
            seen.setdefault(str(uid).strip(), None)
    return list(seen)


def _ordered(proposals: list[Any]) -> list[Any]:
    """Collection first, then short-term, then long-term.

    The Commander is told to order them and mostly does, but the ordering is what
    decides whether the process tree still exists when somebody wants it, so it is
    not left to a prompt.
    """
    rank = {"collect": 0, "short_term": 1, "long_term": 2}
    return sorted(
        proposals, key=lambda p: rank.get(str(getattr(p, "stage", "") or "short_term"), 1)
    )


def _proposal_json(proposal: Any, taken: dict[str, Any]) -> dict[str, Any]:
    blast = getattr(proposal, "blast_radius", None)
    return {
        "action": proposal.action,
        "target": proposal.target,
        "stage": getattr(proposal, "stage", "short_term"),
        "autonomy": taken.get("autonomy") or proposal.autonomy,
        "reversible": proposal.reversible,
        "rationale": proposal.rationale,
        "blast_radius": {
            "principals": getattr(blast, "principals", -1),
            "shared_infrastructure": getattr(blast, "shared_infrastructure", ""),
            "declared_as": getattr(blast, "declared_as", ""),
            "company_loses": getattr(blast, "company_loses", ""),
        }
        if blast is not None
        else None,
        "fallback": getattr(proposal, "fallback", ""),
        "fallback_after_minutes": getattr(proposal, "fallback_after_minutes", 0),
        "destroys_evidence": getattr(proposal, "destroys_evidence", ""),
        "action_uid": taken.get("action_uid", ""),
        "state": taken.get("state") or taken.get("error", "not recorded"),
    }


def _page(conn: Conn, tenant_id: str, case_uid: str, command: Any, citations: list[str]) -> None:
    """The Commander asks the Manager to wake somebody; it does not page itself.

    The Manager's gate decides with a query whether a page goes out, and folds
    this into any page already sent for the same incident (RFC 0015).
    """
    if not command.page_human:
        return
    from shoc.agents import manager

    manager.tell(
        conn,
        tenant_id,
        "IR Commander",
        "page",
        command.containment_note.strip() or "The Commander asked for a person.",
        case_uid=case_uid,
        condition=command.page_condition,
        citations=citations,
    )


def _response_note(command: Any) -> str:
    """What the Commander decided, including how it will know the response worked."""
    bits = [command.containment_note.strip() or "Response proposed."]
    if command.page_human:
        bits.append(f"Paging a human ({command.page_condition or 'no condition named'}).")
    if command.verify:
        # A list the console sets as one, not one run-on line.
        bits.append(
            f"Verified by, clean for {command.verify_clean_for_minutes} minutes:\n"
            + "\n".join(f"- {check}" for check in command.verify[:4])
        )
    return "\n\n".join(bits)


def _suppression(
    conn: Conn, tenant_id: str, case_uid: str, challenge: Any, report: RunReport
) -> None:
    """Record the suppression the Challenger drafted when it won on "normal here".

    The role that knows why the activity is benign is the one that should describe
    the exclusion, and nothing else in the loop knows the fields. It is a draft: a
    human or the Detection Engineer merges it, and it carries a TTL because
    nothing is suppressed for ever.
    """
    from shoc.cases import routing

    draft = getattr(challenge, "suppression", None)
    if challenge is None or getattr(challenge, "repair", "") != "suppression" or draft is None:
        return
    if not draft.rule_id.strip() or not draft.entity.strip():
        report.errors.append("Challenger: suppression draft with no rule or no entity, ignored")
        return
    from shoc.cases import own

    raised = {
        (str(p["rule_id"]), own.bare(str(p["entity_key"] or "")))
        for p in routing._pairs(conn, tenant_id, case_uid)
        if routing._detection(str(p["rule_id"]))
    }
    if (draft.rule_id.strip(), own.bare(draft.entity)) not in raised:
        report.errors.append(
            f"Challenger: suppression draft for {draft.rule_id.strip()} and "
            f"{draft.entity.strip()[:80]}, which this case did not raise, ignored"
        )
        return
    try:
        routing.suppress_draft(
            conn,
            tenant_id,
            case_uid,
            rule_id=draft.rule_id.strip(),
            entity=draft.entity.strip(),
            reason=draft.because.strip(),
            ttl_days=draft.ttl_days,
        )
    except Exception as exc:
        report.errors.append(f"Challenger: suppression draft not recorded: {exc}")


def _broke_down(
    conn: Conn,
    store: EventStore,
    tenant_id: str,
    case_uid: str,
    report: RunReport,
    client: LLMClient,
    exc: Exception,
    cited: list[str],
) -> None:
    """Say in the openspace that the crew could not work, and count the failure.

    A model that cannot be reached used to leave the case exactly as Sentinel had
    left it: a critical case in `analysis` with nobody's name on it and no reason
    anywhere. Silence is the one outcome this loop is not allowed to produce.
    """
    reason = f"{type(exc).__name__}: {exc}"
    report.errors.append(reason)
    report.stopped_because = report.stopped_because or "the crew could not reach a model"
    _charge_failure(conn, tenant_id, getattr(client, "model", "none"), reason)
    _post(
        conn,
        store,
        tenant_id,
        case_uid,
        report,
        Message(
            agent="shoc",
            kind="observation",
            body=f"The crew stopped without a verdict: {reason[:400]} "
            "The detections and their evidence are attached for a human.",
            citations=cited,
            principal="agent",
            round=1,
        ),
    )


def _charge_failure(conn: Conn, tenant_id: str, model: str, reason: str) -> None:
    """Record a model call that did not come back, so `ops.alerts` can see it."""
    import contextlib

    from shoc.agents.ops import record_failure

    with contextlib.suppress(Exception):
        record_failure(conn, tenant_id, model, reason)


def _worked(conn: Conn, tenant_id: str, case_uid: str, started: datetime) -> None:
    """Mark when the crew last did anything here (017).

    The sweep asks what has happened to a case since this moment. Without it the
    only question that could be asked was "has anybody ever spoken here", which
    is true once and then never again.

    The crew read the transcript and the findings when the run started. A human
    message or a finding that arrived while it was talking was never read, so
    the mark stops just before the first of them and the sweep comes back.
    """
    import contextlib

    from shoc.db.pool import execute

    with contextlib.suppress(Exception):
        execute(
            conn,
            """UPDATE shoc.cases c SET worked_at = coalesce((
                   SELECT min(t) - interval '1 microsecond' FROM (
                       SELECT created_at AS t FROM shoc.openspace_messages m
                       WHERE m.tenant_id = c.tenant_id AND m.case_uid = c.case_uid
                         AND (m.kind = 'inject' OR m.principal = 'human')
                         AND m.created_at > %s
                       UNION ALL
                       SELECT created_at FROM shoc.findings f
                       WHERE f.tenant_id = c.tenant_id AND f.case_uid = c.case_uid
                         AND f.created_at > %s) unread), now())
               WHERE tenant_id = %s AND case_uid = %s""",
            (started, started, tenant_id, case_uid),
        )


def _changed(conn: Conn, tenant_id: str, case: dict[str, Any], prior: list[dict[str, Any]]) -> str:
    """What has happened to this case since the crew last looked at it.

    Reading the same detections out a second time is how a resumed case looked
    exactly like a restarted one. What matters on the way back in is the
    difference: a new detection, an action that finished and how (AGT-12), a
    proposal a person turned down and why, or
    somebody telling the crew that the human it was waiting for is not coming.
    """
    since = case.get("worked_at")
    parts: list[str] = []
    new = (
        fetch_all(
            conn,
            """SELECT title, rule_id, event_count FROM shoc.findings
               WHERE tenant_id = %s AND case_uid = %s AND created_at > %s
               ORDER BY created_at DESC LIMIT 10""",
            (tenant_id, case["case_uid"], since),
        )
        if since
        else []
    )
    if new:
        parts.append(
            f"{len(new)} new detection(s) since the crew last looked at this case: "
            + "; ".join(f"{f['title']} ({f['rule_id']}, {f['event_count']} event(s))" for f in new)
            + "."
        )
    # The same actions the sweep counts as a reason to come back (`worker.NEEDS_ATTENTION`).
    ended = (
        fetch_all(
            conn,
            """SELECT action_uid, type, target, state, error, result->>'detail' AS detail
               FROM shoc.actions
               WHERE tenant_id = %s AND case_uid = %s AND updated_at > %s
                 AND (state IN ('done', 'failed', 'rolled_back')
                      OR (state = 'rejected' AND approved_by LIKE 'human:%%'))
                 AND type NOT LIKE 'notify.%%'
               ORDER BY updated_at LIMIT 10""",
            (tenant_id, case["case_uid"], since),
        )
        if since
        else []
    )
    if ended:
        parts.append(
            "Finished since the crew last looked: "
            + "; ".join(
                f"{a['type']} on {a['target'] or 'no target'} ({a['action_uid']}) "
                + ("was rejected by a human" if a["state"] == "rejected" else f"ended {a['state']}")
                + (f": {str(a['error'] or a['detail'])[:200]}" if a["error"] or a["detail"] else "")
                for a in ended
            )
            + "."
        )
    if parts:
        return " ".join(parts)
    latest = next(
        (m for m in reversed(prior) if m["kind"] in ("inject", "answer", "proposal")), None
    )
    why = f" What brought us back: {str(latest['body'])[:300]}" if latest else ""
    return (
        f"No new detections have fired for {case['entity_key'] or 'this tenant'} since "
        f"the crew last looked, and the case is still open.{why}"
    )


def _people_said(prior: list[dict[str, Any]]) -> str:
    """What people wrote into the case, for every role, marked for what it is.

    The operator's "it's me" used to reach only the Investigator's first prompt,
    as one transcript line among twenty-five. Every role sees it now, in its own
    section. It raises the benign explanation; it cannot settle it alone,
    because a chat account an attacker holds can say the same thing. Only a
    person's disposition and memory facts carry that authority.
    """
    said = [
        {"said_by": str(m["agent"]), "at": str(m["created_at"])[:19], "text": str(m["body"])[:1000]}
        for m in prior
        if m.get("principal") == "human" or m.get("kind") == "inject"
    ][-10:]
    if not said:
        return ""
    return (
        "\n\nWhat people wrote into this case. Each is unverified: weigh it, check "
        "it against the events, and do not treat it as proof on its own:\n"
        + safety.quote("people-said", said)
    )


def _so_far(prior: list[dict[str, Any]]) -> str:
    """The discussion a case is resuming, for every role that works it (AGT-12).

    Only the Investigator used to see it, so the Challenger argued again what
    it had already lost and the Commander proposed what had already run. The
    bodies quote logs and people, so they are data (SEC-2).
    """
    if not prior:
        return ""
    # Every message here was written by a model or a person who read the logs.
    said = [
        {
            "round": m["round"],
            "agent": str(m["agent"]),
            "kind": str(m["kind"]),
            "said": str(m["body"])[:500],
        }
        for m in prior[-25:]
    ]
    return "\n\nThis case has been worked before. What was said, oldest first:\n" + safety.quote(
        "discussion", said
    )


def _rejoin(prior: list[dict[str, Any]]) -> str:
    """What the Investigator owes a case it has worked before."""
    if not prior:
        return ""
    return (
        "\n\nDo not repeat the earlier discussion. Say what has changed, and revise "
        "your disposition if the new evidence or what you have been told changes it."
    )


def _said(body: str, usage: Completion) -> str:
    """What an agent said, and what it checked before saying it.

    An answer whose working nobody can see is the thing this crew exists to
    avoid, and "the Investigator queried nothing" is exactly what a reader of a
    thin verdict needs to know.
    """
    note = tools.describe(usage.lookups)
    return f"{body} [{note}]" if note else body


def _resevere(
    conn: Conn,
    store: EventStore,
    tenant_id: str,
    case: dict[str, Any],
    report: RunReport,
    investigation: Any,
    dossier: Any,
    budget: Budget,
    round_no: int,
    evidence: Evidence | None = None,
) -> tuple[dict[str, Any], Budget]:
    """Apply the Investigator's severity, if it moved one.

    A severity that changes is not bookkeeping: it is what the budget allows for
    the rest of the discussion, what floor an automatic action has to clear, and
    whether the one technical person in the company gets woken. So it is applied
    now rather than at the end, said out loud in the openspace, and the budget is
    recomputed around it.
    """
    from shoc.errors import ShocError

    wanted = str(getattr(investigation, "severity", "") or "").strip().lower()
    was = str(case.get("severity") or "")
    if not wanted or wanted == was:
        return case, budget
    reason = str(getattr(investigation, "severity_reason", "") or "").strip()
    if not reason:
        report.errors.append("Investigator: severity change with no reason, ignored")
        return case, budget
    try:
        case = engine.set_severity(conn, tenant_id, case["case_uid"], wanted, reason)
    except ShocError as exc:
        report.errors.append(f"Investigator: {exc}")
        return case, budget
    report.severity = wanted
    _post(
        conn,
        store,
        tenant_id,
        case["case_uid"],
        report,
        Message(
            agent="Investigator",
            kind="observation",
            body=f"Severity moved from {was} to {wanted}: {reason}",
            citations=validate_citations(store, tenant_id, investigation.citations, evidence),
            round=round_no,
        ),
    )
    return case, Budget.for_case(wanted, len(dossier.observables), len(dossier.reports))


def _catalogue(config: Any, scope: Any) -> str:
    """The actions that answer the case, for the Commander's prompt.

    A proposal is only worth making if something can run it. The Commander used
    to name actions from memory and produced `okta.revoke_sessions` for an
    action then called `idp.revoke_sessions`, so the list is put in front of it.
    """
    from shoc.cases.actions import catalogue

    try:
        available = [
            a for a in catalogue(config, scope=scope) if not str(a["action"]).startswith("notify.")
        ]
    except Exception:  # no catalogue is better than no response
        return ""
    return (
        "These are the only actions that exist, with what the policy does with "
        "each one. Use the exact name; an action you invent cannot be run, and a "
        "name that is nearly right is a name that is wrong:\n" + json.dumps(available, indent=2)
    )


def _propose(
    conn: Conn,
    tenant_id: str,
    case_uid: str,
    proposals: list[Any],
    config: Any,
    grounded: list[bool] | None = None,
) -> list[dict[str, Any]]:
    """Put the Commander's proposals to the policy, and queue what it allows.

    The crew proposes; the policy decides. An L1 action it allows is queued and
    runs without a human, an L2 waits for one, and a proposal naming an action
    that does not exist says so in the openspace instead of disappearing.
    """
    from shoc.cases.actions import CrewProposal, from_crew

    try:
        taken = from_crew(
            conn,
            tenant_id,
            case_uid,
            [
                CrewProposal(
                    p.action,
                    p.target,
                    p.rationale,
                    grounded=ok,
                    params=dict(getattr(p, "params", None) or {}),
                    fallback=str(getattr(p, "fallback", "") or ""),
                    window_minutes=int(getattr(p, "fallback_after_minutes", 0) or 0),
                    blast_radius=_blast(getattr(p, "blast_radius", None)),
                )
                for p, ok in zip(proposals, grounded or [True] * len(proposals), strict=False)
            ],
            config=config,
        )
    except Exception as exc:
        return [{"error": f"{type(exc).__name__}: {exc}"}] * len(proposals)
    return [t.to_json() for t in taken]


def _blast(blast: Any) -> dict[str, Any]:
    """The Commander's blast radius for the policy (D45). Unanswered is {}, which refuses."""
    if blast is None:
        return {}
    return {
        "principals": getattr(blast, "principals", -1),
        "shared_infrastructure": getattr(blast, "shared_infrastructure", ""),
        "citations": list(getattr(blast, "citations", None) or []),
    }


def _unverified(
    conn: Conn, store: EventStore, tenant_id: str, case_uid: str, command: Any
) -> list[str]:
    """What still stands between the Commander's `ready_to_close` and a closed case.

    Every approved action has to have run, and every `verify` search has to find
    nothing over the window the Commander named. A search that cannot run has
    verified nothing, so it keeps the case open too.
    """
    from shoc.capabilities.events import EventQuery, build_query

    out = [
        f"{r['type']} on {r['target']} has not run yet"
        for r in fetch_all(
            conn,
            """SELECT type, target FROM shoc.actions WHERE tenant_id = %s AND case_uid = %s
                 AND state IN ('approved', 'running')""",
            (tenant_id, case_uid),
        )
    ]
    minutes = max(1, int(getattr(command, "verify_clean_for_minutes", 60) or 60))
    for search in [str(q).strip() for q in command.verify[:6] if str(q).strip()]:
        try:
            sql, params, limit = build_query(
                EventQuery(q=search, since=f"-{minutes}m", limit=1), tenant_id
            )
            if store.query(sql, params, limit).rows:
                out.append(f"'{search}' still finds events in the last {minutes} minutes")
        except Exception as exc:
            out.append(f"'{search}' could not run ({type(exc).__name__})")
    return out


def _brief(
    conn: Conn,
    tenant_id: str,
    case: dict[str, Any],
    dossier: Any,
    investigation: Any,
    measured: checks.Confidence,
    resumed: str = "",
) -> str:
    """What the Commander decides from: what was established, not the raw logs.

    The role that picks an action's target is the one an injected log line most
    wants to reach, so it reads the claims that survived their check, the case's
    entities and its indicators (context minimisation, RFC 0020). The logs stay
    with the roles that read them; a peer it asks still has the whole dossier.
    """
    struck = set(measured.struck)
    established = [
        {"says": c.says, "citations": list(c.citations or [])}
        for c in (getattr(investigation, "claims", None) or [])
        if c.says not in struck
    ]
    return (
        "\n".join(
            [
                "Case under discussion:",
                safety.quote(
                    "case",
                    {
                        "case_uid": case["case_uid"],
                        "entity": case.get("entity_key"),
                        "severity": case.get("severity"),
                        "attack": list(case.get("attack") or []),
                        "entities": _entities(conn, tenant_id, case["case_uid"]),
                        "scope": list(getattr(investigation, "scope", None) or []),
                        "still_active": bool(getattr(investigation, "still_active", False)),
                    },
                ),
                "",
                "What the Investigator established, each claim shown by the events it cites:",
                safety.quote("established", established),
                "",
                "What the evidence contains that an action could target:",
                safety.quote("observables", [o.to_json() for o in dossier.observables]),
            ]
        )
        + resumed
        + _people_said(transcript(conn, tenant_id, case["case_uid"]))
    )


def _entities(conn: Conn, tenant_id: str, case_uid: str) -> list[str]:
    import contextlib

    with contextlib.suppress(Exception):
        return [
            str(r["entity"])
            for r in fetch_all(
                conn,
                "SELECT entity FROM shoc.case_entities WHERE tenant_id = %s AND case_uid = %s",
                (tenant_id, case_uid),
            )
        ]
    return []


def _evidence(
    conn: Conn,
    store: EventStore,
    tenant_id: str,
    case: dict[str, Any],
    dossier: Any,
    citations: list[str],
    usage: Completion,
) -> str:
    """Everything an action's target may be drawn from, as one lowercase text."""
    import contextlib

    from shoc.agents.dossier import _events

    events: list[dict[str, Any]] = []
    with contextlib.suppress(Exception):
        events = _events(store, tenant_id, citations)
    parts = [
        str(case.get("entity_key") or ""),
        *_entities(conn, tenant_id, case["case_uid"]),
        *(json.dumps(o.to_json(), default=str) for o in dossier.observables),
        *(json.dumps(e, default=str) for e in events),
        # What the platform itself answered: the id of the inbox rule to delete
        # is in a lookup, not in any log.
        *usage.seen,
    ]
    return "\n".join(parts).lower()


def _grounded(target: str, evidence: str) -> bool:
    """Whether an action's target is something the case actually showed.

    An injected line can name an address or an account; it cannot put that name
    into the events a verified claim cites. A target found nowhere in the case
    still gets proposed, and waits for a person with a deadline instead of
    running on its own.
    """
    wanted = target.strip().lower()
    return bool(wanted) and wanted in evidence


def _with_scope(investigation: Any) -> str:
    """The reasoning, plus how far the activity spread — an unscoped verdict is half one."""
    scope = [str(e) for e in (getattr(investigation, "scope", None) or []) if str(e).strip()]
    body = investigation.reasoning
    if scope:
        body += " Scope: " + ", ".join(scope[:10]) + "."
    return body


def _route(
    conn: Conn,
    tenant_id: str,
    case: dict[str, Any],
    verdict: str,
    report: RunReport,
    summary: str = "",
) -> list[dict[str, Any]]:
    """Hand the closure on. A routing failure must not lose the verdict itself."""
    from shoc.cases import routing

    try:
        return [
            e.to_json()
            for e in routing.route(conn, tenant_id, case, verdict, summary=summary).entries
        ]
    except Exception as exc:
        report.errors.append(f"routing: {type(exc).__name__}: {exc}")
        return []


def _ask(
    client: LLMClient,
    role: roles.Role,
    prompt: str,
    schema: type,
    config: Any,
    conn: Conn | None = None,
    tenant_id: str = "",
    store: EventStore | None = None,
    ask: Any = None,
    on_behalf: Any = None,
    budget: tuple[int, Any] = (0, None),
    max_steps: int = MAX_TOOL_STEPS,
    max_calls: int = MAX_TOOL_CALLS,
) -> tuple[Any, Completion]:
    """One agent turn, with whatever this role is allowed to look up and ask.

    Given a connection and a tenant, the role's capabilities are offered as
    tools and it can pivot: widen the window, check the address against last
    month, ask what else the account touched. Given `ask`, the roles it declared
    as peers are offered the same way, so a question to a colleague costs a tool
    call rather than a scheduled turn. Without either — a unit test, a caller that
    has no database — it answers from the prompt, as it always did. Given
    `on_behalf`, only the tools that caller may call are offered. `budget` is
    what the turn may spend and what it has spent outside itself (`_turn`).
    """
    from shoc.config import Config

    cfg = config or Config.load()
    lookups = (
        tools.specs(role.tools, role.name, on_behalf) if (role.tools and conn is not None) else None
    )
    peers = role.peers if (ask is not None and conn is not None) else ()
    offered = [*(lookups or []), *tools.peer_specs(peers)]
    run = (
        tools.invoker(
            tenant_id,
            cfg,
            role.tools,
            who=role.name,
            db=conn,
            store=store,
            peers=peers,
            ask=ask,
            on_behalf=on_behalf,
        )
        if offered
        else None
    )
    return complete_typed(
        for_hint(client, role.model_hint, cfg),
        safety.system_prompt(role.prompt),
        prompt,
        schema,
        cfg.llm_max_tokens,
        tools=offered or None,
        invoke=run,
        max_steps=max_steps,
        token_budget=budget[0],
        outside=budget[1],
        max_calls=max_calls,
    )


def _turn(report: RunReport, budget: Budget, share: float) -> tuple[int, Any]:
    """What one turn may spend, its peers included: a share of the run's budget,
    and never more than is left of it.

    A turn that reaches it stops looking things up and answers. Without it the
    first turn of a busy case spent the whole run and the case went to a person
    with the Investigator's conclusion thrown away.
    """
    start = report.tokens
    allowed = min(int(budget.max_tokens * share), budget.max_tokens - start)
    return max(1, allowed), lambda: report.tokens - start


def _charge(conn: Conn, tenant_id: str, usage: Completion) -> None:
    """Record what a model call cost, so `health.cost` can answer for it (OPS-1)."""
    import contextlib

    from shoc.agents.ops import record_spend

    # Accounting must never break an investigation.
    with contextlib.suppress(Exception):
        record_spend(conn, tenant_id, usage.model, usage.tokens_in, usage.tokens_out)


def _post(
    conn: Conn,
    store: EventStore,
    tenant_id: str,
    case_uid: str,
    report: RunReport,
    message: Message,
    fallback_kind: str = "",
) -> None:
    """Post a message; if it fails its evidence check, downgrade it rather than lose it."""
    from shoc.errors import ValidationError

    try:
        post(conn, store, tenant_id, case_uid, message)
    except ValidationError as exc:
        if not fallback_kind:
            report.errors.append(str(exc))
            return
        report.errors.append(f"{message.agent}: {exc}")
        message.body = f"[uncited, downgraded] {message.body}"
        message.kind = fallback_kind
        message.citations = []
        post(conn, store, tenant_id, case_uid, message)
    report.messages += 1
    report.tokens += message.tokens
