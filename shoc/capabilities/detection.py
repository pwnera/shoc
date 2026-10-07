"""Rule and detection capabilities (DET-1, DET-2, DET-3, AGT-3).

The rules themselves, and the Detection Engineer's queue around them: the
backlog every detection idea arrives on, the human decision on each one, and the
suppressions that must never outlive their reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from shoc.capabilities.registry import Context, Result, capability
from shoc.detect import rules as ruleset
from shoc.detect.compiler import compile_rule
from shoc.detect.engine import ADHOC_LIMIT, match_indicators, run_all, run_rule
from shoc.errors import ConfigError, Denied, NotFound
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class RuleFilter:
    severity: str = f("", doc="Only rules of this severity")
    product: str = f("", doc="Only rules whose logsource product matches")
    contains: str = f("", doc="Substring matched against id, title and description")


@dataclass
class RuleList:
    rules: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="rule.list",
    summary="List the detection rules this deployment runs",
    input=RuleFilter,
    output=RuleList,
    scope="rules:read",
    tags=("detection", "read"),
)
def list_rules(ctx: Context, inp: RuleFilter) -> Result:
    rules = ruleset.load(ctx.config, ctx.db, ctx.tenant_id)
    if inp.severity:
        rules = [r for r in rules if r.severity == inp.severity.lower()]
    if inp.product:
        rules = [r for r in rules if r.logsource.get("product", "") == inp.product]
    if inp.contains:
        needle = inp.contains.lower()
        rules = [
            r
            for r in rules
            if needle in r.id.lower()
            or needle in r.title.lower()
            or needle in r.description.lower()
        ]
    data = [r.to_json() for r in rules]
    return Result(
        data=RuleList(rules=data, count=len(data)),
        summary=f"{len(data)} rule(s) loaded.",
    )


@dataclass
class RuleRef:
    rule_id: str = f(doc="Rule id, as listed by rule.list")
    since: str = f("-24h", doc="Window to evaluate, relative or ISO-8601")


@dataclass
class RulePreview:
    rule: dict[str, Any] = field(default_factory=dict)
    canonical_sql: str = ""
    dialect_sql: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="rule.test",
    summary="Run one rule over a window and show what it would find, writing nothing",
    input=RuleRef,
    output=RulePreview,
    scope="rules:read",
    tags=("detection", "read"),
)
def test_rule(ctx: Context, inp: RuleRef) -> Result:
    from shoc.capabilities.events import parse_since
    from shoc.store.sql import translate

    rule = next(
        (r for r in ruleset.load(ctx.config, ctx.db, ctx.tenant_id) if r.id == inp.rule_id), None
    )
    if rule is None:
        raise NotFound(f"no rule '{inp.rule_id}'")
    compiled = compile_rule(rule)
    canonical = compiled.agg_sql or compiled.select_sql
    start = parse_since(inp.since)
    now = datetime.now(UTC)
    findings = run_rule(ctx.store, ctx.tenant_id, rule, start, now)
    citations = [uid for fnd in findings for uid in fnd.event_uids][:50]
    return Result(
        data=RulePreview(
            rule=rule.to_json(),
            canonical_sql=canonical,
            dialect_sql=translate(canonical, ctx.store.dialect),
            findings=[to_json(fnd) for fnd in findings[:ADHOC_LIMIT]],
        ),
        summary=f"{rule.id} would raise {len(findings)} finding(s) since {inp.since}.",
        citations=citations,
    )


@dataclass
class DetectRun:
    rule_id: str = f("", doc="Run only this rule; empty runs every rule")
    lookback: str = f(
        "",
        doc="Evaluate events from this far back, e.g. 24h (default: what was ingested since the last cycle)",
    )
    open_cases: bool = f(True, doc="Group the new findings into cases (RSP-1)")


@dataclass
class DetectReport:
    rules_run: int = 0
    findings_new: int = 0
    findings_updated: int = 0
    ioc_matches: int = 0
    cases_opened: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


@capability(
    name="detect.run",
    summary="Run a detection cycle now and write the findings",
    input=DetectRun,
    output=DetectReport,
    scope="detection:run",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("detection", "write"),
)
def run_detection(ctx: Context, inp: DetectRun) -> Result:
    rules = ruleset.load(ctx.config, ctx.db, ctx.tenant_id)
    if inp.rule_id:
        rules = [r for r in rules if r.id == inp.rule_id]
        if not rules:
            raise NotFound(f"no rule '{inp.rule_id}'")
    lookback = ruleset.parse_timeframe(inp.lookback) if inp.lookback else None
    stats = run_all(ctx.db, ctx.store, ctx.tenant_id, rules, lookback_seconds=lookback)
    ioc_findings = _match_indicators(ctx, lookback)
    cases = _open_cases(ctx) if inp.open_cases else []
    return Result(
        data=DetectReport(
            rules_run=stats.rules_run,
            findings_new=stats.findings_new,
            findings_updated=stats.findings_updated,
            ioc_matches=len(ioc_findings),
            cases_opened=cases,
            errors=stats.errors,
        ),
        summary=(
            f"Ran {stats.rules_run} rule(s): {stats.findings_new} new and "
            f"{stats.findings_updated} updated finding(s), {len(ioc_findings)} indicator match(es), "
            f"{len(cases)} case(s) opened, {len(stats.errors)} error(s)."
        ),
        citations=cases,
    )


def _match_indicators(ctx: Context, lookback: int | None) -> list[str]:
    """Check what the cycle read against known indicators (DET-4)."""
    try:
        return match_indicators(ctx.db, ctx.store, ctx.tenant_id, lookback)
    except Exception:  # intel is an enrichment; it must never fail a detection cycle
        return []


def _open_cases(ctx: Context) -> list[str]:
    """Group findings that belong to no case yet into cases, by entity (RSP-1).

    With a model, Sentinel then reshapes what the grouping touched (D43).
    """
    from shoc.agents import sentinel
    from shoc.agents.llm import NoLLM, from_config
    from shoc.cases import engine as case_engine
    from shoc.db.pool import fetch_all

    unassigned = fetch_all(
        ctx.db,
        """SELECT finding_uid, rule_id, title, severity, status, entity_key, entities,
                  last_seen, attack, case_uid, event_uids
           FROM shoc.findings
           WHERE tenant_id = %s AND case_uid IS NULL AND NOT (evidence ? 'intake')
           ORDER BY last_seen""",
        (ctx.tenant_id,),
    )
    touched = case_engine.open_for_findings(ctx.db, ctx.tenant_id, unassigned, ctx.store)
    try:
        client = from_config(ctx.config, ctx.db, ctx.tenant_id) if touched else None
    except ConfigError:  # a model misconfigured must not stop detection
        client = None
    if client is None or isinstance(client, NoLLM) or not getattr(client, "available", True):
        return touched
    return sentinel.shape(ctx.db, ctx.store, ctx.tenant_id, touched, client, ctx.config)


# -- the Detection Engineer's backlog (AGT-3, docs/agent-specs.md §11) -------
@dataclass
class BacklogInput:
    run: bool = f(False, doc="Sweep the intakes into the backlog first (needs detection:run)")
    state: str = f("open", doc="open, accepted, rejected or done. Empty lists every state")
    limit: int = f(100, doc="How many items to return")


@dataclass
class BacklogPage:
    items: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    by_intake: dict[str, int] = field(default_factory=dict)
    not_observable: int = 0


@capability(
    name="detection.backlog",
    summary="Every idea for a detection change, ranked, with where it came from",
    input=BacklogInput,
    output=BacklogPage,
    scope="detection:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("detection", "backlog"),
)
def backlog(ctx: Context, inp: BacklogInput) -> Result:
    from shoc.agents import detection_engineer as engineer

    # A read by default (AGT-10): sweeping the intakes writes backlog items.
    if inp.run:
        if not ctx.caller.allows("detection:run"):
            raise Denied(
                "detection.backlog: run sweeps the intakes and needs scope 'detection:run'"
            )
        engineer.intake(ctx.db, ctx.tenant_id, ctx.config)
    rows = engineer.backlog(ctx.db, ctx.tenant_id, inp.state, max(1, min(inp.limit, 500)))
    by_intake: dict[str, int] = {}
    for row in rows:
        by_intake[str(row["intake"])] = by_intake.get(str(row["intake"]), 0) + 1
    blind = [r for r in rows if r["observability"] == "none"]
    items = [to_json(r) for r in rows]
    # An item that names techniques says what this deployment holds about them (D133).
    named = [
        [e["technique"]] if e.get("technique") else list(e.get("attack") or [])
        for e in (i["evidence"] or {} for i in items)
    ]
    if any(named):
        from shoc.detect import context as near

        here = near.here(ctx.db, ctx.tenant_id, ctx.config)
        for item, codes in zip(items, named, strict=True):
            if codes:
                item["context"] = near.about(
                    here, codes, report_uid=str(item["evidence"].get("report_uid") or "")
                )
    return Result(
        data=BacklogPage(
            items=items,
            count=len(rows),
            by_intake=by_intake,
            not_observable=len(blind),
        ),
        summary=(
            f"{len(rows)} {inp.state or 'listed'} detection item(s)"
            + (": " if rows else ".")
            + ", ".join(f"{n} from {src}" for src, n in sorted(by_intake.items()))
            + (
                f". {len(blind)} need data we do not ingest — those are source gaps, "
                "not detections anybody can write."
                if blind
                else "."
            )
        ),
        citations=[str(r["item_uid"]) for r in rows],
    )


@dataclass
class BacklogDecision:
    item_uid: str = f(doc="The backlog item to decide on")
    state: Literal["rejected", "done", "open"] = f(
        "rejected", doc="rejected or done to end it, open to put it back in the queue"
    )
    reason: str = f(
        "", doc="Why: required to end it, and shown on the item. Optional when reopening"
    )


@dataclass
class BacklogState:
    item_uid: str = ""
    state: str = ""


@capability(
    name="detection.decide",
    summary="End a detection backlog item, or put it back in the queue",
    input=BacklogDecision,
    output=BacklogState,
    scope="detection:write",
    principals=("human",),
    audit=True,
    tags=("detection", "backlog"),
)
def decide_backlog(ctx: Context, inp: BacklogDecision) -> Result:
    from shoc.agents import detection_engineer as engineer

    row = engineer.decide_item(
        ctx.db, ctx.tenant_id, inp.item_uid, inp.state, f"human:{ctx.caller.id}", inp.reason
    )
    return Result(
        data=BacklogState(item_uid=inp.item_uid, state=row["state"]),
        summary=f"{inp.item_uid} marked {row['state']}.",
        citations=[inp.item_uid],
    )


@dataclass
class BacklogProposal:
    title: str = f(doc="What a rule should catch, in a line")
    product: str = f(
        "",
        doc="The product whose events it reads, as a rule's logsource.product (okta, aws). "
        "The item waits as a source gap until a connected source delivers it",
    )
    logic: str = f("", doc="What to look for: fields, values, a threshold and the window")
    false_positives: str = f(
        "", doc="Legitimate activity that looks the same; it becomes the negative fixture"
    )
    event_uids: list[str] = f(
        doc="Events that show it, from events.query; they seed the positive fixture",
        factory=list,
    )
    why: str = f("", doc="The report, case or change that raised it")
    attack: list[str] = f(doc="ATT&CK technique ids, e.g. T1562.008", factory=list)


@dataclass
class BacklogRef:
    item_uid: str = ""


@capability(
    name="detection.propose",
    summary="Put a rule idea on the detection backlog, for detection.merge to answer",
    input=BacklogProposal,
    output=BacklogRef,
    scope="detection:write",
    principals=("human", "agent"),
    audit=True,
    tags=("detection", "backlog", "write"),
)
def propose(ctx: Context, inp: BacklogProposal) -> Result:
    from shoc.agents import detection_engineer as engineer
    from shoc.errors import ValidationError

    title = inp.title.strip()[:300]
    if not title:
        raise ValidationError("title is required")
    attack = [str(t).strip().upper()[:20] for t in inp.attack[:10] if str(t).strip()]
    product = inp.product.strip().lower()[:40]
    evidence: dict[str, Any] = {"attack": attack, "by": f"{ctx.caller.kind}:{ctx.caller.id}"}
    evidence |= {
        k: v
        for k, v in {
            "product": product,
            "logic": inp.logic.strip()[:2000],
            "false_positives": inp.false_positives.strip()[:2000],
            "event_uids": [str(u).strip()[:80] for u in inp.event_uids[:20] if str(u).strip()],
        }.items()
        if v
    }
    observability = "unknown"
    if product:
        observability = "have" if product in engineer._delivering(ctx.db, ctx.tenant_id) else "none"
        if observability == "none":
            evidence["waiting_for"] = [product]
    uid = engineer.add(
        ctx.db,
        ctx.tenant_id,
        engineer.BacklogItem(
            item_uid=engineer.item_uid(ctx.tenant_id, "human", title.lower()),
            kind="coverage",
            intake="human",
            title=title,
            reason=inp.why.strip()[:1000],
            # The default 3: a person's idea goes ahead of the sweep's coverage gaps (4).
            observability=observability,
            evidence=evidence,
        ),
    )
    return Result(
        data=BacklogRef(item_uid=uid),
        summary=f"On the detection backlog: {title[:120]}."
        + (f" It waits for {product} to be connected." if observability == "none" else ""),
        citations=[uid],
    )


@dataclass
class SuppressionInput:
    review: bool = f(False, doc="Expire what has run out before listing")
    rule_id: str = f("", doc="Only suppressions for this rule")


@dataclass
class SuppressionPage:
    suppressions: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    expired: int = 0


@capability(
    name="suppression.list",
    summary="What is currently suppressed, why, and when it comes back",
    input=SuppressionInput,
    output=SuppressionPage,
    scope="detection:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("detection", "suppression"),
)
def suppressions(ctx: Context, inp: SuppressionInput) -> Result:
    from shoc.cases import routing

    expired = routing.expire_suppressions(ctx.db, ctx.tenant_id) if inp.review else 0
    rows = routing.active_suppressions(ctx.db, ctx.tenant_id, inp.rule_id)
    return Result(
        data=SuppressionPage(
            suppressions=[to_json(r) for r in rows],
            count=len(rows),
            expired=expired,
        ),
        summary=(
            f"{len(rows)} active suppression(s); {expired} expired just now. Each lasts a "
            "week at most and names the case that justified it."
        ),
        citations=[str(r["suppression_uid"]) for r in rows],
    )


# -- the Detection Engineer merging its own work (D48) -----------------------
@dataclass
class BacktestInput:
    rule: dict[str, Any] = f(
        doc="The rule, in the YAML shape of content/rules, as JSON", factory=dict
    )
    rule_id: str = f("", doc="Or an existing rule, by id")
    days: int = f(7, doc="How much history to replay, 1 to 30 days")


@dataclass
class BacktestReport:
    rule_id: str = ""
    days: int = 0
    findings: int = 0
    ceiling: int = 0
    top_entities: dict[str, int] = field(default_factory=dict)
    sample: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="rule.backtest",
    summary="Replay a rule over our own history and count what it would have raised",
    input=BacktestInput,
    output=BacktestReport,
    scope="rules:read",
    tags=("detection", "read"),
)
def backtest_rule(ctx: Context, inp: BacktestInput) -> Result:
    from shoc.agents import detection_engineer as engineer
    from shoc.errors import ConfigError, ValidationError

    try:
        rule = (
            ruleset.from_dict(inp.rule)
            if inp.rule
            else next(
                r for r in ruleset.load(ctx.config, ctx.db, ctx.tenant_id) if r.id == inp.rule_id
            )
        )
    except StopIteration as exc:
        raise NotFound(f"no rule '{inp.rule_id}'") from exc
    except (ConfigError, KeyError, TypeError, ValueError) as exc:
        raise ValidationError(f"the rule does not parse: {exc}") from exc
    days = min(30, max(1, inp.days))
    found = engineer.backtest(ctx.store, ctx.tenant_id, rule, days)
    entities: dict[str, int] = {}
    for fnd in found:
        entities[fnd.entity_key] = entities.get(fnd.entity_key, 0) + 1
    top = dict(sorted(entities.items(), key=lambda kv: -kv[1])[:5])
    ceiling = engineer.volume_ceiling(days) - 1
    return Result(
        data=BacktestReport(
            rule_id=rule.id,
            days=days,
            findings=len(found),
            ceiling=ceiling,
            top_entities=top,
            sample=[to_json(fnd) for fnd in found[:3]],
        ),
        summary=f"{rule.id} would have raised {len(found)} finding(s) in {days} days "
        f"(merge ceiling {ceiling}).",
        citations=[uid for fnd in found[:3] for uid in fnd.event_uids][:20],
    )


@dataclass
class MergeInput:
    item_uid: str = f(
        "",
        doc="The open backlog item this answers; it is closed on merge. A person adding a "
        "new rule may leave it out: the merge records an item of its own. Narrowing a "
        "shipped rule always names one, dry run included",
    )
    narrows: str = f("", doc="A shipped rule to narrow. With it, give `exclude` and not `rule`")
    exclude: list[dict[str, Any]] = f(
        doc="Alternatives to exclude from the shipped rule. Each holds one exact "
        "src_endpoint.ip, exactly one of actor.user.uid, resource.uid or "
        "actor.session.uid, and optionally api.operation, api.service.name or "
        "cloud.account.uid. Exact values only",
        factory=list,
    )
    hide_events: list[str] = f(
        doc="For an item from a benign closure: the event_uids the narrowing must stop "
        "matching, at least three on two days",
        factory=list,
    )
    rule: dict[str, Any] = f(
        doc="A new rule: id, title, description, severity, attack, logsource.product, "
        "detection (selections and condition; timeframe, group_by and count inside it for "
        "a count) and entity, as in content/rules; rule.list shows real ones. A shipped id "
        "is refused: narrow it instead",
        factory=dict,
    )
    playbook_id: str = f(
        "",
        doc="The existing playbook that answers it, as playbook.list names it; it must act on "
        "the rule's product",
    )
    ads: dict[str, str] = f(
        doc="goal, categorization, strategy, technical_context, blind_spots, "
        "false_positives, validation, priority, and response, which defaults to the playbook",
        factory=dict,
    )
    fixtures: dict[str, Any] = f(
        doc="{source, positive: [raw records], negative: [raw records]}: records as that "
        "source sends them, without timestamps; events.query with include_raw returns real "
        "ones in `raw`",
        factory=dict,
    )
    backtest_days: int = f(7, doc="History the backtest replays, 1 to 30 days")
    reason: str = f("", doc="One sentence on why this change, now")
    dry_run: bool = f(
        False, doc="Run the whole gate and write nothing. A new rule then needs no item_uid"
    )


@dataclass
class MergeReport:
    rule_id: str = ""
    narrows: bool = False
    playbook_id: str = ""
    backtest: dict[str, int] = field(default_factory=dict)
    # The backlog item the merge answered, or recorded for a person's new rule.
    item_uid: str = ""
    dry_run: bool = False


@capability(
    name="detection.merge",
    summary="Narrow a shipped rule or add a new one, behind the gate that replays stored evidence",
    input=MergeInput,
    output=MergeReport,
    scope="detection:merge",
    principals=("human", "agent"),
    audit=True,
    tags=("detection", "write"),
)
def merge_rule(ctx: Context, inp: MergeInput) -> Result:
    from shoc.agents import detection_engineer as engineer

    who = f"{ctx.caller.kind}:{ctx.caller.id}"
    spec = to_json(inp) | {"by_hand": ctx.caller.kind == "human"}
    out = engineer.merge(ctx.db, ctx.store, ctx.tenant_id, ctx.config, spec, who)
    found = out["backtest"]["findings"]
    if inp.dry_run:
        summary = f"{out['rule_id']} passes the gate; nothing merged. " + (
            f"{found} event(s) in 30 days would stop matching."
            if out["narrows"]
            else f"{found} finding(s) in the last {out['backtest']['days']} days."
        )
    elif out["narrows"]:
        summary = f"{out['rule_id']} narrowed: {found} event(s) in 30 days no longer match."
    else:
        summary = (
            f"{out['rule_id']} merged, answered by {out['playbook_id']}; "
            f"{found} finding(s) in the last {out['backtest']['days']} days."
        )
    return Result(
        data=MergeReport(**out, dry_run=inp.dry_run),
        summary=summary,
        citations=[c for c in (out["rule_id"], out["item_uid"]) if c],
    )


@dataclass
class RevertInput:
    rule_id: str = f(doc="A rule merged here. A rule shipped in content/ is out of reach")
    reason: str = f(doc="Why: the volume or the false-positive ratio")


@dataclass
class RevertReport:
    rule_id: str = ""
    state: str = ""


@capability(
    name="detection.revert",
    summary="Take back a merged rule; the shipped rule it narrowed, if any, returns",
    input=RevertInput,
    output=RevertReport,
    scope="detection:merge",
    principals=("human", "agent"),
    audit=True,
    tags=("detection", "write"),
)
def revert_rule(ctx: Context, inp: RevertInput) -> Result:
    from shoc.agents import detection_engineer as engineer

    who = f"{ctx.caller.kind}:{ctx.caller.id}"
    out = engineer.revert(ctx.db, ctx.tenant_id, inp.rule_id, inp.reason, who)
    return Result(
        data=RevertReport(**out),
        summary=f"{inp.rule_id} reverted.",
        citations=[inp.rule_id],
    )


@dataclass
class WorkInput:
    limit: int = f(6, doc="How many backlog items to work, 1 to 20")


@dataclass
class WorkReport:
    worked: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    reasoning: str = ""
    tokens: int = 0
    why: str = ""


@capability(
    name="detection.work",
    summary="The Detection Engineer works the top of the backlog to an end",
    input=WorkInput,
    output=WorkReport,
    scope="detection:work",
    principals=("human", "service", "agent"),
    audit=True,
    tags=("detection", "write"),
)
def work_backlog(ctx: Context, inp: WorkInput) -> Result:
    from shoc.agents import detection_engineer as engineer

    out = engineer.work(
        ctx.db, ctx.store, ctx.tenant_id, ctx.config, limit=min(20, max(1, inp.limit))
    )
    report = WorkReport(**out)
    return Result(
        data=report,
        summary=(
            f"Detection Engineer worked {report.worked} item(s): "
            + (
                ", ".join(f"{n} {k}" for k, n in sorted(report.outcomes.items()))
                or report.why
                or "no outcome"
            )
            + "."
        ),
    )
