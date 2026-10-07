"""Turn a case a person closed into a scenario the crew is scored on (AGT-6).

    python -m evals.capture CASE-… --out ~/shoc-evals

A person's disposition is the best label the crew will ever get, and a case
it got wrong is the scenario most worth replaying. This writes the case's
events, as the vendor sent them, and an `expected.yaml` holding that
disposition and the rules that fired. `python -m evals.run --scenarios DIR`
replays the directory like the public set.

These are a company's own logs. They stay in a private directory: a scenario
goes into `evals/scenarios/` only after every address, name and id in it has
been replaced with documentation values and fake ones.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml


def capture(ctx: Any, case_uid: str, out: Path, verdict: str = "") -> Path:
    """Write `out/<case>/` from the case's findings and their events."""
    from shoc.agents import ops
    from shoc.capabilities.events import EventQuery, build_query
    from shoc.cases import engine
    from shoc.db.pool import fetch_all
    from shoc.errors import ValidationError
    from shoc.ingest import ocsf
    from shoc.ingest.replay import TIME_FIELD, set_path

    case = engine.require(ctx.db, ctx.tenant_id, case_uid)
    verdict = verdict or (str(case["verdict"]) if case.get("closed_by") == "human" else "")
    if not verdict:
        raise ValidationError(
            f"{case_uid} was not closed by a person; pass --verdict with the right answer"
        )
    findings = fetch_all(
        ctx.db,
        "SELECT rule_id, event_uids FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
        (ctx.tenant_id, case_uid),
    )
    uids = list(dict.fromkeys(u for f in findings for u in f["event_uids"] or []))[:500]
    sql, params, limit = build_query(
        EventQuery(event_uids=uids, limit=len(uids), include_raw=True), ctx.tenant_id
    )
    by_product = {ops.product_of(s): s for s in ocsf.available_sources()}
    events: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for row in ctx.store.query(sql, params, limit).rows:
        source = by_product.get(str(row.get("metadata_product")), "")
        raw = row.get("raw")
        raw = json.loads(raw) if isinstance(raw, str) else raw
        if not source or not isinstance(raw, dict):
            continue
        # The replay places each record just before it runs, newest first, so the
        # vendor's own time is taken off and the order kept.
        if TIME_FIELD.get(source):
            set_path(raw, TIME_FIELD[source], None)
        events.setdefault(source, []).append((str(row.get("time")), raw))
    if not events:
        raise ValidationError(f"{case_uid} has no events this install can replay")
    target = out / case_uid.lower()
    target.mkdir(parents=True, exist_ok=True)
    (target / "events.json").write_text(
        json.dumps(
            {
                s: [r for _, r in sorted(rows, key=lambda x: x[0], reverse=True)]
                for s, rows in events.items()
            },
            indent=2,
            default=str,
        )
    )
    expected = {
        "id": case_uid.lower(),
        "title": str(case.get("title") or case_uid),
        "description": f"Captured from {case_uid}, closed as {verdict}"
        + (f": {case['disposition_reason']}" if case.get("disposition_reason") else "."),
        "source": next(iter(events)),
        "entity": str(case.get("entity_key") or ""),
        "expected_rules": sorted({str(f["rule_id"]) for f in findings}),
        "expected_verdict": verdict,
    }
    (target / "expected.yaml").write_text(
        "# Captured from a real case: private until every value is replaced.\n"
        + yaml.safe_dump(expected, sort_keys=False, allow_unicode=True)
    )
    return target


def main(argv: list[str] | None = None) -> int:
    from shoc.capabilities.registry import Caller, Context
    from shoc.config import Config

    parser = argparse.ArgumentParser(
        prog="evals.capture", description=(__doc__ or "").splitlines()[0]
    )
    parser.add_argument("case_uid")
    parser.add_argument("--out", required=True, help="A private directory for the scenario")
    parser.add_argument(
        "--verdict", default="", help="The right disposition, if no person closed it"
    )
    args = parser.parse_args(argv)
    cfg = Config.load()
    ctx = Context(tenant_id=cfg.tenant_id, caller=Caller(kind="human", id="evals"), config=cfg)
    print(capture(ctx, args.case_uid, Path(args.out).expanduser(), args.verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
