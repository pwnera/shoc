"""Score the roles a replayed case does not reach, one probe at a time (AGT-6).

`evals.run` replays an attack and scores the case: Sentinel, the Investigator,
the Challenger, the claim check, CTI and the Surveyor as colleagues, the IR
Commander and the Manager's answers. The rest of the crew works on other
inputs — a dark source, a renamed vendor field, a threat report, an action
waiting for review — and `python -m evals.roles` puts each probe in
`evals/probes/<role>.yaml` to the configured model and scores what the role
decided, never its wording:

  ops         which sources a retry is queued for, and what each diagnosis names
  integrator  whether the field it moves maps the renamed vendor field back
  cti         the indicators a report yields, typed, and the ones it must not
  review      whether the IR Commander approves an action, given who is behind
              the target and what the company wrote down about it
  checks      whether the claim checker finds a claim shown by its own events
  surveyor    whether an address or credential is the company's own, and how
              it knows
  manager     whether the page it writes is one the gate sends, rather than the
              template, and names what the operator has to act on
  reporter    whether the Manager's reading of a report uses only its figures

Each probe runs in its own tenant. With `--repeat k` a probe passes only when
every run does, as in `evals.run`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

PROBES = Path(__file__).parent / "probes"
# A figure as a reading writes it, "33,271" included.
NUMBER = re.compile(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?")


@dataclass
class ProbeReport:
    role: str = ""
    probe: str = ""
    problems: list[str] = field(default_factory=list)
    tokens: int = 0
    # What the role returned, to read when the probe fails.
    said: Any = None
    passed: bool = False

    def line(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"{status} {self.role}/{self.probe}" + (
            f" — {'; '.join(self.problems)}" if self.problems else ""
        )


def _context(tenant_id: str) -> Any:
    from evals.run import DOCUMENTATION_ADDRESSES, _provision
    from shoc.capabilities.registry import Caller, Context, call
    from shoc.config import Config

    cfg = Config.load()
    cfg.tenant_id = tenant_id
    ctx = Context(tenant_id=tenant_id, caller=Caller(kind="human", id="evals"), config=cfg)
    _provision(ctx, cfg)
    call("memory.add_fact", ctx, {"body": DOCUMENTATION_ADDRESSES})
    return ctx


def _client(ctx: Any) -> Any:
    from shoc.agents.llm import from_config

    return from_config(ctx.config, ctx.db, ctx.tenant_id)


# -- the roles ------------------------------------------------------------------
def ops(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from shoc.agents import ops as role
    from shoc.db.pool import execute, fetch_one

    for source in probe["sources"]:
        execute(
            ctx.db,
            """INSERT INTO shoc.connector_state (tenant_id, source, cursor, last_run_at,
                                                 last_ok_at, last_error)
               VALUES (%s, %s, '{}', now(), now() - %s * interval '1 hour', %s)""",
            (ctx.tenant_id, source["source"], source.get("dark_hours", 30), source["error"]),
        )
    said = role.review(ctx.db, ctx.store, ctx.tenant_id, ctx.config, _client(ctx))
    if not said.get("read"):
        return [f"Ops did not read the sources: {said.get('why')}"], said
    expect = probe["expect"]
    out = []
    if sorted(said["retried"]) != sorted(expect.get("retry") or []):
        out.append(f"retried {said['retried']}, expected {expect.get('retry') or []}")
    for source, pattern in (expect.get("names") or {}).items():
        row = fetch_one(
            ctx.db,
            "SELECT diagnosis FROM shoc.connector_state WHERE tenant_id = %s AND source = %s",
            (ctx.tenant_id, source),
        )
        diagnosis = str((row or {}).get("diagnosis") or "")
        said.setdefault("diagnoses", {})[source] = diagnosis
        if not re.search(pattern, diagnosis, re.IGNORECASE):
            out.append(f"{source}: the diagnosis does not name /{pattern}/")
    return out, said


def integrator(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from shoc.agents import integrator as role
    from shoc.capabilities.registry import call
    from shoc.ingest import ocsf
    from shoc.ingest.connectors.base import write_state
    from shoc.ingest.replay import expand

    source = probe["source"]
    records = expand(probe["records"], source, datetime.now(UTC))
    call("events.ingest", ctx, {"source": source, "records": records})
    write_state(ctx.db, ctx.tenant_id, source, {}, len(records), None)
    said = role.repair(ctx.db, ctx.store, ctx.tenant_id, ctx.config, source, _client(ctx))
    mapped = ocsf.for_tenant(ctx.db, ctx.tenant_id, source).map_record(records[0], ctx.tenant_id)
    out = [
        f"{column} maps to {mapped.get(column)!r}, expected {value!r}"
        for column, value in probe["expect"]["maps"].items()
        if str(mapped.get(column)) != str(value)
    ]
    return out, said


def cti(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from shoc.capabilities.registry import call

    said = call(
        "intel.digest",
        ctx,
        {"text": probe["report"], "title": probe["id"], "retro_hunt": False},
    ).data
    expect = probe["expect"]
    got = {(str(i.get("type")), str(i.get("value")).lower()) for i in said.indicators}
    out = []
    for item in expect.get("indicators") or []:
        kind, value = item.split(":", 1)
        if (kind, value.lower()) not in got:
            out.append(f"missing {kind}:{value}")
    for value in expect.get("not_indicators") or []:
        if any(v == str(value).lower() for _, v in got):
            out.append(f"took {value} for an indicator")
    techniques = {str(t.get("id") or "") for t in said.techniques}
    for technique in expect.get("techniques") or []:
        if not any(t.startswith(technique) for t in techniques):
            out.append(f"missing technique {technique}")
    if "keep" in expect and said.kept != expect["keep"]:
        out.append(f"kept={said.kept}, expected {expect['keep']}")
    return out, asdict(said)


def review(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from evals.run import SCENARIOS, load_scenario
    from shoc.capabilities.registry import call
    from shoc.cases import engine
    from shoc.cases import review as role
    from shoc.ingest.replay import expand

    # The case the action was proposed in, replayed from a scenario: the review
    # cites the case's events for who is behind the target.
    case: dict[str, Any] = {}
    if probe.get("scenario"):
        _, events = load_scenario(SCENARIOS / probe["scenario"])
        for source, batch in events.items():
            records = expand(batch, source, spread_seconds=300)
            call("events.ingest", ctx, {"source": source, "records": records})
        opened = call("detect.run", ctx, {"lookback": "1h"}).data.cases_opened
        case = (engine.get(ctx.db, ctx.tenant_id, opened[0]) or {}) if opened else {}
        if not case:
            return [f"{probe['scenario']} opened no case to review in"], None
    target = probe["target"]
    seen = role.Context(
        principals=list(target.get("principals") or []),
        neighbours=list(target.get("neighbours") or []),
        facts=list(target.get("facts") or []),
        seen=True,
    )
    said = role.review_action(
        ctx.db,
        ctx.store,
        ctx.tenant_id,
        action_type=probe["action"],
        plan=probe["plan"],
        target_kind=target["kind"],
        target=target["value"],
        rationale=probe.get("rationale", ""),
        case=case,
        config=ctx.config,
        client=_client(ctx),
        context=seen,
    )
    out = []
    if said.approved != probe["expect"]["approve"]:
        out.append(f"approved={said.approved}, expected {probe['expect']['approve']}")
    if not said.reviewers or not all(o.reached for o in said.reviewers):
        out.append(f"the review did not run: {said.reason}")
    return out, said.to_json()


def checks(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from shoc.agents import checks as role
    from shoc.agents.roles import Claim
    from shoc.capabilities.registry import call
    from shoc.ingest import ocsf
    from shoc.ingest.replay import expand

    source = probe["source"]
    records = expand(probe["records"], source, datetime.now(UTC))
    call("events.ingest", ctx, {"source": source, "records": records})
    mapping = ocsf.load_mapping(source)
    uids = [mapping.map_record(r, ctx.tenant_id)["event_uid"] for r in records]
    claims = [
        Claim(says=c["says"], citations=[uids[i] for i in c["cites"]]) for c in probe["claims"]
    ]
    shown, usage = role.check_claims(_client(ctx), ctx.store, ctx.tenant_id, claims, ctx.config)
    out = [
        f"claim {i} ({c['says'][:60]}): judged {ok}, expected {c['shown']}"
        for i, (c, ok) in enumerate(zip(probe["claims"], shown, strict=True))
        if ok is not c["shown"]
    ]
    return out, {"shown": shown, "tokens": usage.tokens}


def surveyor(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from shoc.agents import loop, roles
    from shoc.capabilities.registry import call
    from shoc.cases import own
    from shoc.ingest.replay import expand

    for fact in probe.get("memory") or []:
        call("memory.add_fact", ctx, {"body": fact})
    for item in probe.get("own") or []:
        own.register(
            ctx.db,
            ctx.tenant_id,
            item["kind"],
            item["value"],
            source=item.get("source", ""),
            by="evals",
        )
    for source, records in (probe.get("events") or {}).items():
        call("events.ingest", ctx, {"source": source, "records": expand(records, source)})
    answer, usage = loop._ask(
        _client(ctx),
        roles.SURVEYOR,
        f"The Investigator is asking you:\n{probe['question']}\nAnswer it in three "
        "sentences at most. Look up what you need first.",
        roles.AssetAnswer,
        ctx.config,
        ctx.db,
        ctx.tenant_id,
        ctx.store,
    )
    expect = probe["expect"]
    out = []
    if answer.is_ours != expect["is_ours"]:
        out.append(f"is_ours={answer.is_ours}, expected {expect['is_ours']}")
    if "source" in expect and answer.source != expect["source"]:
        out.append(f"source={answer.source}, expected {expect['source']}")
    return out, {**asdict(answer), "tokens": usage.tokens}


def manager(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from shoc.agents import manager as role

    rows = [
        {
            "notice_uid": f"N{i}",
            "group_key": probe["id"],
            "case_uid": n.get("case", ""),
            "citations": n.get("citations") or [],
            "source": n["from"],
            "condition": n["condition"],
            "severity": n["severity"],
            "body": n["said"],
        }
        for i, n in enumerate(probe["notices"])
    ]
    said = role.word(ctx.db, ctx.tenant_id, rows, ctx.config)
    out = []
    if said == role.template(rows):
        out.append("the model's page was refused, so the template went out")
    for pattern in probe["expect"].get("names") or []:
        if not re.search(pattern, said, re.IGNORECASE):
            out.append(f"the page does not name /{pattern}/")
    return out, said


def reporter(ctx: Any, probe: dict[str, Any]) -> tuple[list[str], Any]:
    from evals.run import SCENARIOS, load_scenario
    from shoc.agents import reporter as role
    from shoc.capabilities.registry import call
    from shoc.ingest.replay import expand

    _, events = load_scenario(SCENARIOS / probe["scenario"])
    for source, batch in events.items():
        records = expand(batch, source, spread_seconds=300)
        call("events.ingest", ctx, {"source": source, "records": records})
    call("detect.run", ctx, {"lookback": "1h"})
    report = role.build(ctx.db, ctx.store, ctx.tenant_id, probe["kind"], config=ctx.config)
    reading = role.narrate(report, _client(ctx), ctx.config, ctx.db, ctx.tenant_id)
    figures = {_figure(n) for n in NUMBER.findall(json.dumps(report.body, default=str))}
    out = [] if reading else ["the Manager wrote no reading"]
    # A model may narrate, never count (D47): every figure comes from the report,
    # whether it writes 0 as "0" or "$0.00".
    out += [
        f"{n} is not a figure in the report"
        for n in sorted(set(NUMBER.findall(reading)))
        if _figure(n) not in figures
    ]
    return out, {"reading": reading, "body": report.body}


def _figure(text: str) -> float:
    return float(text.replace(",", ""))


ROLES = {f.__name__: f for f in (ops, integrator, cti, review, checks, surveyor, manager, reporter)}


# -- the run ----------------------------------------------------------------------
def load(names: list[str] | None = None) -> list[tuple[str, dict[str, Any]]]:
    """(role, probe) for every probe, or the roles and `role/probe` ids named."""
    out = []
    for path in sorted(PROBES.glob("*.yaml")):
        spec = yaml.safe_load(path.read_text())
        for probe in spec["probes"]:
            pid = f"{spec['role']}/{probe['id']}"
            if not names or spec["role"] in names or pid in names:
                out.append((spec["role"], probe))
    return out


def run_probe(role: str, probe: dict[str, Any]) -> ProbeReport:
    from shoc.db.pool import fetch_one

    ctx = _context(f"eval{uuid.uuid4().hex[:8]}")
    report = ProbeReport(role=role, probe=probe["id"])
    try:
        report.problems, report.said = ROLES[role](ctx, probe)
    except Exception as exc:  # a probe that crashes is a failed probe, not a crashed run
        report.problems = [f"{type(exc).__name__}: {exc}"]
    spend = fetch_one(
        ctx.db,
        "SELECT coalesce(sum(tokens_in + tokens_out), 0) AS n FROM shoc.llm_spend "
        "WHERE tenant_id = %s",
        (ctx.tenant_id,),
    )
    report.tokens = int((spend or {}).get("n") or 0)
    report.passed = not report.problems
    return report


def run_all(
    names: list[str] | None = None, repeat: int = 1
) -> tuple[list[ProbeReport], dict[str, Any]]:
    reports: list[ProbeReport] = []
    runs: list[ProbeReport] = []
    for role, probe in load(names):
        tries = [run_probe(role, probe) for _ in range(max(1, repeat))]
        runs += tries
        failed = [t for t in tries if not t.passed]
        report = failed[0] if failed else tries[-1]
        report.passed = not failed
        reports.append(report)
    by_role: dict[str, list[int]] = {}
    for r in runs:
        by_role.setdefault(r.role, [0, 0])
        by_role[r.role][0] += int(r.passed)
        by_role[r.role][1] += 1
    summary = {
        "probes": len(reports),
        "passed": sum(1 for r in reports if r.passed),
        "runs_passed_by_role": {k: f"{a}/{n}" for k, (a, n) in sorted(by_role.items())},
        "repeat": max(1, repeat),
        "tokens": sum(r.tokens for r in runs),
        "run_at": datetime.now(UTC).isoformat(),
    }
    return reports, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals.roles", description=(__doc__ or "").splitlines()[0]
    )
    parser.add_argument("names", nargs="*", help="Roles or role/probe ids (default: all)")
    parser.add_argument("--repeat", type=int, default=1, help="Runs per probe; all must pass")
    parser.add_argument("--json", dest="json_out", help="Write the full report to this path")
    args = parser.parse_args(argv)
    reports, summary = run_all(args.names or None, args.repeat)
    for report in reports:
        print(report.line())
    print(json.dumps(summary, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                {"summary": summary, "probes": [asdict(r) for r in reports]}, indent=2, default=str
            )
        )
    return 0 if summary["passed"] == summary["probes"] else 1


if __name__ == "__main__":
    sys.exit(main())
