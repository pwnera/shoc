"""Behavioural hunting (DET-8, DET-9, DET-11, RFC 0005, RFC 0022).

The daily cycle, one pack on demand, what the runs concluded, and the backlog
every hunt starts on. Indicator search stays where it was, in `intel.py`, as the
narrow question it is.

Nothing here lets a caller supply a query: `hunt.pack` names a pack, and a pack
is content with fixtures. The Hunter may add one for an item on its backlog
(`hunt.merge`, RFC 0032), behind a gate that runs its fixtures and its query
before anything is kept. Triage still decides only whether a row is boring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.agents import hunter
from shoc.capabilities.detection import BacklogDecision, BacklogState
from shoc.capabilities.registry import Context, Result, capability
from shoc.errors import NotFound, ValidationError
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class DailyInput:
    limit: int = f(
        0,
        doc="Run at most this many due packs (0 = every due pack). The day's budget is "
        "the triage ceiling set with llm.configure (hunt_tokens_per_day)",
    )


@dataclass
class DailyOut:
    chosen: list[dict[str, Any]] = field(default_factory=list)
    runs: list[dict[str, Any]] = field(default_factory=list)
    outcomes: dict[str, int] = field(default_factory=dict)
    readiness: list[dict[str, Any]] = field(default_factory=list)
    tokens: int = 0


@capability(
    name="hunt.daily",
    summary="Run today's behavioural hunts, chosen by what intel and incidents say",
    input=DailyInput,
    output=DailyOut,
    scope="hunts:work",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("hunt", "daily"),
)
def daily(ctx: Context, inp: DailyInput) -> Result:
    report = hunter.daily(ctx.db, ctx.store, ctx.tenant_id, ctx.config, limit=max(0, inp.limit))
    outcomes = report.outcomes
    return Result(
        data=DailyOut(**report.to_json()),
        summary=(
            f"{len(report.runs)} hunt(s) ran: "
            + (
                ", ".join(f"{n} {name}" for name, n in sorted(outcomes.items()))
                if outcomes
                else "none were due"
            )
            + ". "
            + _readiness_line(report.readiness)
        ),
        citations=[r["run_uid"] for r in report.runs],
    )


def _readiness_line(rows: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["state"]] = counts.get(row["state"], 0) + 1
    learning = [r for r in rows if r["state"] == "learning"]
    line = ", ".join(f"{n} {state.replace('_', ' ')}" for state, n in sorted(counts.items()))
    if learning:
        soonest = min(str(r["ready_at"])[:10] for r in learning)
        line += f"; the first learning pack is ready on {soonest}"
    return f"Packs: {line}." if line else ""


@dataclass
class PackInput:
    pack_id: str = f(doc="A pack, as hunt.results lists it")


@dataclass
class PackOut:
    run_uid: str = ""
    pack_id: str = ""
    outcome: str = ""
    rows: int = 0
    triage: str = ""
    finding_uid: str = ""
    case_uid: str = ""
    error: str = ""
    hypothesis: str = ""
    ruled_out: list[str] = field(default_factory=list)
    unseen: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="hunt.pack",
    summary="Run one hunt pack now, and say what came back",
    input=PackInput,
    output=PackOut,
    scope="hunts:work",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("hunt", "pack"),
)
def pack(ctx: Context, inp: PackInput) -> Result:
    from shoc.detect import hunts

    found = next(
        (p for p in hunts.load(ctx.config, ctx.db, ctx.tenant_id) if p.id == inp.pack_id), None
    )
    if found is None:
        raise NotFound(f"no hunt pack '{inp.pack_id}'")
    run = hunter.run_pack(ctx.db, ctx.store, ctx.tenant_id, found, config=ctx.config)
    return Result(
        data=PackOut(
            run_uid=run.run_uid,
            pack_id=run.pack_id,
            outcome=run.outcome,
            rows=run.rows,
            triage=run.triage,
            finding_uid=run.finding_uid,
            case_uid=run.case_uid,
            error=run.error,
            hypothesis=found.hypothesis,
            ruled_out=run.ruled_out,
            unseen=run.unseen,
            observations=[
                {
                    "tuple": t["values"],
                    "events": t["events"],
                    "verdict": t.get("verdict", ""),
                    "why": t.get("why", ""),
                    "citations": t["event_uids"][:20],
                }
                for t in run.tuples[:50]
            ],
        ),
        summary=(
            f"{found.id}: {run.outcome}, {run.rows} row(s). "
            + (run.triage or run.error or found.triage)
        ),
        citations=[u for t in run.tuples for u in t["event_uids"]][:100],
    )


@dataclass
class ResultsInput:
    pack_id: str = f("", doc="Only this pack")
    days: int = f(7, doc="How far back to look")
    limit: int = f(100, doc="How many runs to return")


@dataclass
class ResultsOut:
    runs: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    metrics: dict[str, Any] = field(default_factory=dict)
    # Per pack: ready, learning until a date, stale, or not applicable here.
    readiness: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="hunt.results",
    summary="What the hunts have concluded, and the measures that count",
    input=ResultsInput,
    output=ResultsOut,
    scope="hunts:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("hunt", "read"),
)
def results(ctx: Context, inp: ResultsInput) -> Result:
    rows = hunter.results(
        ctx.db, ctx.tenant_id, inp.pack_id, max(1, inp.days), max(1, min(inp.limit, 500))
    )
    from shoc.detect import hunts

    measures = hunter.metrics(ctx.db, ctx.tenant_id, max(1, inp.days))
    # The logic rides here and not in hunt.daily's report: a reader opens one pack.
    ready = [
        {**hunter.readiness(ctx.db, ctx.tenant_id, p).to_json(), "logic": p.logic()}
        for p in hunts.load(ctx.config, ctx.db, ctx.tenant_id)
        if not inp.pack_id or p.id == inp.pack_id
    ]
    return Result(
        data=ResultsOut(
            runs=[to_json(r) for r in rows],
            count=len(rows),
            metrics=measures,
            readiness=ready,
        ),
        summary=(
            f"{len(rows)} hunt run(s) in {inp.days} day(s) across "
            f"{measures['packs_hunted']} pack(s): "
            + ", ".join(f"{n} {name}" for name, n in sorted(measures["by_outcome"].items()))
            + f". {measures['detections_proposed']} detection(s) proposed from hunting, "
            f"{measures['gaps_open']} gap(s) still open. " + _readiness_line(ready)
        ),
        citations=[str(r["run_uid"]) for r in rows],
    )


@dataclass
class HuntBacklogInput:
    state: str = f("open", doc="open, packed, rejected or done. Empty lists every state")
    limit: int = f(100, doc="How many items to return")


@dataclass
class HuntBacklogPage:
    items: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="hunt.backlog",
    summary="Hypotheses waiting for a pack, with why each was raised and how each ended",
    input=HuntBacklogInput,
    output=HuntBacklogPage,
    scope="hunts:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("hunt", "backlog"),
)
def backlog(ctx: Context, inp: HuntBacklogInput) -> Result:
    rows = hunter.backlog(ctx.db, ctx.tenant_id, inp.state, max(1, min(inp.limit, 500)))
    triggers: dict[str, int] = {}
    for row in rows:
        triggers[str(row["trigger"])] = triggers.get(str(row["trigger"]), 0) + 1
    items = [to_json(r) for r in rows]
    # What this deployment holds about the techniques it tests, and whether we
    # receive the logs that would show it (D133).
    wanted = [i for i in items if i["attack"] or (i["evidence"] or {}).get("seen_in")]
    if wanted:
        from shoc.detect import context as near

        here = near.here(ctx.db, ctx.tenant_id, ctx.config)
        for item in wanted:
            evidence = item["evidence"] or {}
            item["context"] = near.about(
                here,
                item["attack"],
                seen_in=evidence.get("seen_in"),
                report_uid=str(evidence.get("report_uid") or ""),
                every_report=False,
            )
    return Result(
        data=HuntBacklogPage(items=items, count=len(rows)),
        summary=(
            f"{len(rows)} hunt(s) on the backlog"
            + (
                ": " + ", ".join(f"{n} from {src}" for src, n in sorted(triggers.items())) + "."
                if triggers
                else "."
            )
        ),
        citations=[str(r["item_uid"]) for r in rows],
    )


@capability(
    name="hunt.decide",
    summary="End a hunt backlog item, or put it back in the queue",
    input=BacklogDecision,
    output=BacklogState,
    scope="hunts:work",
    principals=("human",),
    audit=True,
    tags=("hunt", "backlog"),
)
def decide(ctx: Context, inp: BacklogDecision) -> Result:
    """As detection.decide: a person's word on an item, with its reason (DET-8, D132)."""
    hunter.decide_item(
        ctx.db, ctx.tenant_id, inp.item_uid, inp.state, f"human:{ctx.caller.id}", inp.reason
    )
    return Result(
        data=BacklogState(item_uid=inp.item_uid, state=inp.state),
        summary=f"{inp.item_uid} marked {inp.state}.",
        citations=[inp.item_uid],
    )


@dataclass
class HuntBacklogAdd:
    title: str = f(doc="What to hunt for, in a line")
    hypothesis: str = f("", doc="What an adversary would be doing here, and why it would show")
    would_confirm: str = f("", doc="What in our data would confirm it")
    data_needed: str = f("", doc="Which sources and fields it reads")
    why_now: str = f("", doc="The report, case or change that raised it")
    attack: list[str] = f(doc="ATT&CK technique ids, e.g. T1078", factory=list)


@dataclass
class HuntBacklogRef:
    item_uid: str = ""


@capability(
    name="hunt.propose",
    summary="Hand the Hunter a hypothesis to test: a report described it, nothing checks for it",
    input=HuntBacklogAdd,
    output=HuntBacklogRef,
    scope="hunts:work",
    principals=("human", "agent"),
    audit=True,
    tags=("hunt", "backlog", "write"),
)
def backlog_add(ctx: Context, inp: HuntBacklogAdd) -> Result:
    if not inp.title.strip():
        raise ValidationError("title is required")
    uid = hunter.add_to_backlog(
        ctx.db,
        ctx.tenant_id,
        trigger=f"{ctx.caller.kind}:{ctx.caller.id}",
        title=inp.title.strip()[:300],
        hypothesis=inp.hypothesis[:2000],
        would_confirm=inp.would_confirm[:1000],
        data_needed=inp.data_needed[:500],
        why_now=inp.why_now[:1000],
        attack=[str(t).upper()[:20] for t in inp.attack[:10]],
    )
    return Result(
        data=HuntBacklogRef(item_uid=uid),
        summary=f"On the hunt backlog: {inp.title.strip()[:120]}.",
        citations=[uid],
    )


@dataclass
class HuntMergeInput:
    item_uid: str = f(
        "",
        doc="The open hunt backlog item this pack answers. A person may leave it out: the "
        "merge records an item of its own",
    )
    pack: dict[str, Any] = f(
        doc="The pack: id, title, hypothesis, attack, logsource.product, detection, "
        "baseline (first_seen: [fields] or rare: {by, among, seen_by_fewer_than}, and "
        "lookback), window, pivot and triage, as in content/hunts; hunt.results shows each "
        "pack's logic. A shipped id is refused, and an id merged here is refused until "
        "hunt.revert takes it back",
        factory=dict,
    )
    fixtures: dict[str, Any] = f(
        doc="{source, surfaced: [raw records], baseline: [raw records]}: records as that "
        "source sends them, without timestamps; events.query with include_raw returns real "
        "ones in `raw`. The pack must return surfaced once baseline came first",
        factory=dict,
    )
    reason: str = f("", doc="One sentence on why this pack, now")
    dry_run: bool = f(False, doc="Run the whole gate and write nothing; item_uid is optional")


@dataclass
class HuntMergeReport:
    pack_id: str = ""
    item_uid: str = ""
    checked: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False


@capability(
    name="hunt.merge",
    summary="Add a hunt pack for a backlog item, behind a gate that runs its fixtures and its query",
    input=HuntMergeInput,
    output=HuntMergeReport,
    scope="hunts:merge",
    principals=("human", "agent"),
    audit=True,
    tags=("hunt", "write"),
)
def merge(ctx: Context, inp: HuntMergeInput) -> Result:
    who = f"{ctx.caller.kind}:{ctx.caller.id}"
    spec = to_json(inp) | {"by_hand": ctx.caller.kind == "human"}
    out = hunter.merge_pack(ctx.db, ctx.store, ctx.tenant_id, ctx.config, spec, who)
    return Result(
        data=HuntMergeReport(**out, dry_run=inp.dry_run),
        summary=f"Hunt pack {out['pack_id']} passes the gate; nothing merged."
        if inp.dry_run
        else f"Hunt pack {out['pack_id']} merged; it runs with the others from the next cycle.",
        citations=[c for c in (out["pack_id"], out["item_uid"]) if c],
    )


@dataclass
class HuntRevertInput:
    pack_id: str = f(doc="A pack hunt.merge added")
    reason: str = f(doc="Why it goes")


@dataclass
class HuntRevertReport:
    pack_id: str = ""
    state: str = ""


@capability(
    name="hunt.revert",
    summary="Take back a merged hunt pack; it stops running",
    input=HuntRevertInput,
    output=HuntRevertReport,
    scope="hunts:merge",
    principals=("human", "agent"),
    audit=True,
    tags=("hunt", "write"),
)
def revert(ctx: Context, inp: HuntRevertInput) -> Result:
    who = f"{ctx.caller.kind}:{ctx.caller.id}"
    out = hunter.revert_pack(ctx.db, ctx.tenant_id, inp.pack_id, inp.reason, who)
    return Result(
        data=HuntRevertReport(**out), summary=f"{inp.pack_id} reverted.", citations=[inp.pack_id]
    )


@dataclass
class HuntWorkInput:
    limit: int = f(hunter.ITEMS_PER_DAY, doc="How many open items to work, priority first, 1 to 20")


@dataclass
class HuntWorkReport:
    worked: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    reasoning: str = ""
    tokens: int = 0
    why: str = ""


@capability(
    name="hunt.work",
    summary="The Hunter works the top of its backlog: a pack for each item, or why not",
    input=HuntWorkInput,
    output=HuntWorkReport,
    scope="hunts:work",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("hunt", "backlog"),
)
def work(ctx: Context, inp: HuntWorkInput) -> Result:
    out = hunter.work_backlog(
        ctx.db, ctx.store, ctx.tenant_id, ctx.config, limit=max(1, min(inp.limit, 20))
    )
    outcomes = out["outcomes"]
    return Result(
        data=HuntWorkReport(**out),
        summary=(
            f"{out['worked']} hunt backlog item(s) worked"
            + (
                ": " + ", ".join(f"{n} {k}" for k, n in sorted(outcomes.items())) + "."
                if outcomes
                else "."
            )
            + (f" {out['why']}." if out.get("why") else "")
        ),
    )
