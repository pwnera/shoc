"""Operations, reporting, tuning and the world graph (OPS-1, AGT-3, AGT-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from shoc.agents import graph as world
from shoc.agents import hunter, ops, reporter
from shoc.capabilities.registry import Context, Result, capability
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class Empty:
    pass


@dataclass
class HealthDetail:
    sources: list[dict[str, Any]] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    ok: bool = True


@capability(
    name="health.sources",
    summary="Which log sources are fresh, late or failing",
    input=Empty,
    output=HealthDetail,
    scope="health:read",
    tags=("ops", "read"),
)
def sources(ctx: Context, inp: Empty) -> Result:
    rows = [to_json(s.__dict__) for s in ops.source_health(ctx.db, ctx.tenant_id)]
    late = [r["source"] for r in rows if r["stale"] or r["error"]]
    return Result(
        data=HealthDetail(sources=rows, ok=not late),
        summary=(
            f"{len(rows)} source(s); "
            + (f"{len(late)} need attention: {', '.join(late)}." if late else "all fresh.")
        ),
    )


@dataclass
class RulePage:
    """Each rule measured from its cases' verdicts (D77). `silent_reason` is one of
    not_ingested, field_empty:<field>, value_absent:<value> or quiet."""

    rules: list[dict[str, Any]] = field(default_factory=list)
    ok: bool = True


@dataclass
class RuleHealthFilter:
    only: Literal["all", "noisy", "silent", "failing"] = f("all", doc="Narrow the list")


@capability(
    name="health.rules",
    summary="Which rules are noisy, silent or failing",
    input=RuleHealthFilter,
    output=RulePage,
    scope="health:read",
    tags=("ops", "read"),
)
def rules(ctx: Context, inp: RuleHealthFilter) -> Result:
    health = ops.rule_health(
        ctx.db,
        ctx.tenant_id,
        config=ctx.config,
        store=ctx.store if inp.only in ("all", "silent") else None,
    )
    if inp.only == "noisy":
        health = [h for h in health if h.noisy]
    elif inp.only == "silent":
        health = [h for h in health if h.silent]
    elif inp.only == "failing":
        health = [h for h in health if h.error]
    rows = [to_json(h.__dict__) for h in health]
    noisy = sum(1 for h in health if h.noisy)
    failing = sum(1 for h in health if h.error)
    dead = sum(1 for h in health if h.silent_reason and h.silent_reason != "quiet")
    return Result(
        data=RulePage(rules=rows, ok=not failing),
        summary=(
            f"{len(rows)} rule(s) tracked: {noisy} noisy, {failing} failing"
            + (f", {dead} silent because they cannot fire here" if dead else "")
            + "."
        ),
    )


@dataclass
class CostWindow:
    days: int = f(30, doc="How many days of spend to add up")


@dataclass
class CostReport:
    spend: dict[str, Any] = field(default_factory=dict)
    volume: dict[str, Any] = field(default_factory=dict)


@capability(
    name="health.cost",
    summary="What this deployment is costing: events stored and LLM spend",
    input=CostWindow,
    output=CostReport,
    scope="health:read",
    tags=("ops", "read"),
)
def cost(ctx: Context, inp: CostWindow) -> Result:
    money = ops.spend(ctx.db, ctx.tenant_id, inp.days)
    events = ops.volume(ctx.db, ctx.store, ctx.tenant_id, min(inp.days, 30))
    return Result(
        data=CostReport(spend=to_json(money), volume=to_json(events)),
        summary=(
            f"${money['usd_total']:.2f} of LLM spend over {inp.days} day(s) "
            f"({money['tokens']} tokens); {events['events']} event(s) stored in the "
            f"last {events['days']} day(s)."
        ),
    )


@dataclass
class AlertBudget:
    budget_usd_per_day: float = f(
        0.0, doc="Warn when today's LLM spend passes this (0 = the budget set with llm.configure)"
    )


@dataclass
class AlertList:
    alerts: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="ops.alerts",
    summary="What the Ops role would raise right now: stale sources, noisy rules, stuck approvals",
    input=AlertBudget,
    output=AlertList,
    scope="health:read",
    tags=("ops", "read"),
)
def alerts(ctx: Context, inp: AlertBudget) -> Result:
    from shoc.agents.llm import budget

    limit = inp.budget_usd_per_day or budget(ctx.db, ctx.tenant_id, "spend_usd_per_day")
    found = ops.alerts(ctx.db, ctx.tenant_id, limit, ctx.store)
    rows = [a.to_json() for a in found]
    return Result(
        data=AlertList(alerts=rows, count=len(rows)),
        summary=(
            "Nothing to report; the pipeline is healthy."
            if not rows
            else f"{len(rows)} alert(s): "
            + "; ".join(f"{a['kind']} {a['subject']}" for a in rows[:5])
        ),
        citations=[a["subject"] for a in rows],
    )


@dataclass
class ReportInput:
    # The 12-hour shift report is no longer sent (D58); `shift` stays buildable
    # for the console's last-12-hours view.
    kind: Literal["shift", "weekly", "exec", "exception"] = f(
        "weekly", doc="Which report to build. `exception` lists the decisions that need a person"
    )
    narrate: bool = f(False, doc="Add a short written summary (needs an LLM)")


@dataclass
class ReportOutput:
    report_uid: str = ""
    kind: str = ""
    period_start: str = ""
    period_end: str = ""
    summary: str = ""
    narrative: str = ""
    body: dict[str, Any] = field(default_factory=dict)


@capability(
    name="report.get",
    summary="Build the shift, weekly, executive or exception report",
    input=ReportInput,
    output=ReportOutput,
    scope="reports:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("ops", "report"),
)
def get_report(ctx: Context, inp: ReportInput) -> Result:
    report = reporter.build(ctx.db, ctx.store, ctx.tenant_id, inp.kind, config=ctx.config)
    narrative = ""
    if inp.narrate:
        from shoc.agents.llm import from_config

        client = from_config(ctx.config, ctx.db, ctx.tenant_id)
        narrative = reporter.narrate(report, client, ctx.config, ctx.db, ctx.tenant_id)
    # A read keeps nothing. The console builds one on every view, and a saved
    # exception report marks its decisions as told (D52). `report.send` keeps
    # what it sends (AGT-14).
    return Result(
        data=ReportOutput(
            report_uid=report.report_uid,
            kind=report.kind,
            period_start=report.period_start.isoformat(),
            period_end=report.period_end.isoformat(),
            summary=report.summary,
            narrative=narrative,
            body=to_json(report.body),
        ),
        summary=(report.summary + (" " + narrative if narrative else "")).strip(),
        citations=report.citations,
    )


@dataclass
class GraphRefresh:
    days: int = f(30, doc="How much history to rebuild the graph from")


@dataclass
class GraphStatsOut:
    nodes: int = 0
    edges: int = 0
    events_read: int = 0
    window_days: int = 0
    truncated: bool = False
    limit: int = 0


@capability(
    name="graph.refresh",
    summary="Rebuild the world graph from recent events",
    input=GraphRefresh,
    output=GraphStatsOut,
    scope="graph:write",
    principals=("human", "agent", "service"),
    audit=True,
    tags=("graph", "write"),
)
def refresh_graph(ctx: Context, inp: GraphRefresh) -> Result:
    stats = world.refresh(ctx.db, ctx.store, ctx.tenant_id, inp.days)
    return Result(
        data=GraphStatsOut(**stats.__dict__),
        summary=(
            f"World graph: {stats.nodes} node(s) and {stats.edges} edge(s) from "
            f"{stats.events_read} event(s) over {stats.window_days} day(s)."
            + (
                f" Cut at the newest {stats.limit} events: older activity in the window "
                "is not in the graph."
                if stats.truncated
                else ""
            )
        ),
    )


@dataclass
class GraphQuery:
    node: str = f(doc="A node id like user:jane@acme.com, or just the value")
    hops: int = f(2, doc="How far to walk, capped at three")


@dataclass
class GraphView:
    root: str = ""
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    hops: int = 1


@capability(
    name="graph.neighbours",
    summary="What this user, key, address or resource is connected to",
    input=GraphQuery,
    output=GraphView,
    scope="graph:read",
    tags=("graph", "read"),
)
def neighbours(ctx: Context, inp: GraphQuery) -> Result:
    from shoc.db.pool import fetch_one

    node = inp.node
    if ":" not in node:
        row = fetch_one(
            ctx.db,
            "SELECT node_id FROM shoc.graph_nodes WHERE tenant_id=%s AND label=%s "
            "ORDER BY events DESC LIMIT 1",
            (ctx.tenant_id, node),
        )
        node = row["node_id"] if row else node
    hood = world.neighbours(ctx.db, ctx.tenant_id, node, inp.hops)
    kinds: dict[str, int] = {}
    for item in hood.nodes:
        kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
    breakdown = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) or "nothing"
    return Result(
        data=GraphView(
            root=hood.root,
            nodes=[to_json(n) for n in hood.nodes],
            edges=[to_json(e) for e in hood.edges],
            hops=hood.hops,
        ),
        summary=f"{node} is connected to {breakdown} within {hood.hops} hop(s).",
        citations=[n["node_id"] for n in hood.nodes],
    )


@dataclass
class HuntSuggestInput:
    limit: int = f(10, doc="How many suggestions to return")


@dataclass
class HuntSuggestions:
    suggestions: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="hunt.suggest",
    summary="What the Hunter thinks is worth looking for this week, and why",
    input=HuntSuggestInput,
    output=HuntSuggestions,
    scope="hunts:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("ops", "hunt"),
)
def suggest(ctx: Context, inp: HuntSuggestInput) -> Result:
    found = hunter.suggest(ctx.db, ctx.tenant_id, inp.limit)
    rows = [s.to_json() for s in found]
    return Result(
        data=HuntSuggestions(suggestions=rows, count=len(rows)),
        summary=(
            f"{len(rows)} hunt(s) worth running"
            + (": " + "; ".join(f"{s['value']} — {s['reason']}" for s in rows[:3]) if rows else ".")
        ),
        citations=[s["value"] for s in rows],
    )


# -- source quality and the metric set (OPS-1, docs/agent-specs.md §12) -----
@dataclass
class QualityInput:
    days: int = f(30, doc="The window to score over")


@dataclass
class QualityOut:
    sources: list[dict[str, Any]] = field(default_factory=list)
    worst: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    ok: bool = True


@capability(
    name="health.quality",
    summary="How good the data is, not just whether it is arriving",
    input=QualityInput,
    output=QualityOut,
    scope="health:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("ops", "health"),
)
def quality(ctx: Context, inp: QualityInput) -> Result:
    scored = ops.source_quality(ctx.db, ctx.store, ctx.tenant_id, max(1, inp.days))
    rows = [q.to_json() for q in scored]
    notes = [n for q in rows for n in q["notes"]]
    return Result(
        data=QualityOut(
            sources=rows,
            worst=rows[0] if rows else {},
            notes=notes,
            ok=not notes,
        ),
        summary=(
            f"{len(rows)} source(s) scored on completeness, retention, timeliness and "
            f"field fidelity"
            + (
                f". Worst is {rows[0]['product']} at {rows[0]['score']}: {notes[0]}"
                if notes
                else ". Nothing is arriving late, thin or half-empty."
            )
        ),
        citations=[str(r["product"]) for r in rows],
    )


@dataclass
class MetricsInput:
    days: int = f(30, doc="The window to measure over")


@dataclass
class MetricsOut:
    days: int = 0
    by_incident_type: dict[str, Any] = field(default_factory=dict)
    dispositions: dict[str, int] = field(default_factory=dict)
    false_positive_rate: float | None = None
    false_positives_by_rule: list[dict[str, Any]] = field(default_factory=list)
    spend_usd: float = 0.0


@capability(
    name="metrics.get",
    summary="MTTD and MTTR per incident type, false positives, and what it cost",
    input=MetricsInput,
    output=MetricsOut,
    scope="health:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("ops", "metrics"),
)
def metrics(ctx: Context, inp: MetricsInput) -> Result:
    measured = ops.metrics(ctx.db, ctx.tenant_id, max(1, inp.days))
    by_type = measured["by_incident_type"]
    worst = max(
        (k for k in by_type if by_type[k]["mttr_minutes"] is not None),
        key=lambda k: by_type[k]["mttr_minutes"],
        default="",
    )
    return Result(
        data=MetricsOut(**measured),
        summary=(
            f"{len(by_type)} incident type(s) over {measured['days']} day(s)"
            + (
                f". Slowest to close: {worst} at {by_type[worst]['mttr_minutes']:.0f} minutes"
                if worst
                else ". Nothing has closed yet, so there is no MTTR to report"
            )
            + (
                f". False-positive rate {measured['false_positive_rate']:.0%}."
                if measured["false_positive_rate"] is not None
                else "."
            )
            + " Measured per type, because an aggregate hides everything."
        ),
        citations=sorted(by_type),
    )


@dataclass
class MetricsText:
    text: str = ""


@capability(
    name="metrics.export",
    summary="Findings, jobs and source age in the Prometheus text format, as /metrics serves them",
    input=Empty,
    output=MetricsText,
    scope="health:read",
    principals=("human", "agent", "external_agent", "service"),
    tags=("ops", "metrics"),
)
def export_metrics(ctx: Context, _inp: Empty) -> Result:
    """Written by hand (D6: no client library), for the caller's tenant only (SEC-1)."""
    from shoc.db.pool import fetch_all

    tenant = ctx.tenant_id
    findings = fetch_all(
        ctx.db,
        "SELECT severity, count(*) AS n FROM shoc.findings WHERE tenant_id = %s GROUP BY severity",
        (tenant,),
    )
    jobs = fetch_all(
        ctx.db,
        "SELECT state, count(*) AS n FROM shoc.jobs WHERE tenant_id = %s GROUP BY state",
        (tenant,),
    )
    sources = fetch_all(
        ctx.db,
        """SELECT source, EXTRACT(EPOCH FROM (now() - coalesce(last_ok_at, now()))) AS age
           FROM shoc.connector_state WHERE tenant_id = %s""",
        (tenant,),
    )
    lines = ["# HELP shoc_findings Findings by severity", "# TYPE shoc_findings gauge"]
    lines += [
        f'shoc_findings{{tenant="{tenant}",severity="{r["severity"]}"}} {r["n"]}' for r in findings
    ]
    lines += ["# HELP shoc_jobs Jobs by state", "# TYPE shoc_jobs gauge"]
    lines += [f'shoc_jobs{{state="{r["state"]}"}} {r["n"]}' for r in jobs]
    lines += [
        "# HELP shoc_source_age_seconds Seconds since a source last succeeded",
        "# TYPE shoc_source_age_seconds gauge",
    ]
    lines += [
        f'shoc_source_age_seconds{{tenant="{tenant}",source="{r["source"]}"}} {int(r["age"] or 0)}'
        for r in sources
    ]
    return Result(
        data=MetricsText(text="\n".join(lines) + "\n"), summary=f"{len(lines)} metric line(s)"
    )
