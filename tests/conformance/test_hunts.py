"""Hunt packs and the daily cycle (DET-8, DET-9, DET-11, RFC 0022).

Every pack surfaces its own fixture and is silenced by its baseline, on every
backend. Around that: a pack runs only on data that can answer it, its window
follows ingestion so nothing is lost, an explanation counts only on a basis code
can check, and a hunt raises a finding rather than opening a case.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path

import pytest

from shoc.agents import hunter
from shoc.agents.llm import Completion, NoLLM
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all
from shoc.detect import hunts
from shoc.ingest import batch
from shoc.store import ocsf as layout
from tests.support import fixture_rows, fixture_source

pytestmark = pytest.mark.postgres

PACKS = hunts.load()
FIXTURES = Path("tests/fixtures/hunts")
FIRST = next(p for p in PACKS if p.id == "aws_identity_first_api_call")


def _source(pack) -> str:
    return fixture_source(pack)


def _ingest(store, tenant: str, pack, kind: str, when) -> int:
    path = FIXTURES / pack.id / f"{kind}.json"
    rows = fixture_rows(json.loads(path.read_text()), _source(pack), tenant, when)
    batch.load(store, rows)
    return len(rows)


def _connect(ctx, config, pack, started_days_ago: int = 60, name: str = "") -> str:
    """A connected source sending the pack's product, whose data starts back then."""
    products = layout.products_for(
        pack.logsource.get("product", ""), pack.logsource.get("service", "")
    )
    source = name or _source(pack)
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, settings) VALUES (%s,%s,'{}')
           ON CONFLICT DO NOTHING""",
        (config.tenant_id, source),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products, first_event_at)
           VALUES (%s,%s,%s, now() - %s * interval '1 day')
           ON CONFLICT (tenant_id, source) DO UPDATE SET products = EXCLUDED.products,
               first_event_at = EXCLUDED.first_event_at, last_loaded_at = now()""",
        (config.tenant_id, source, list(products), started_days_ago),
    )
    return source


def _mark_hunted(ctx, config, pack) -> None:
    """As if the pack's last window ended now: what is loaded next is the new window."""
    execute(
        ctx.db,
        """INSERT INTO shoc.hunt_packs (tenant_id, pack_id, ingested_through, last_run_at)
           VALUES (%s,%s,now(), now() - interval '2 days')
           ON CONFLICT (tenant_id, pack_id) DO UPDATE SET ingested_through = now(),
               last_run_at = now() - interval '2 days'""",
        (config.tenant_id, pack.id),
    )


class Hunter:
    """A stand-in Hunter that answers every tuple it is shown the same way."""

    model = "scripted"
    available = True

    def __init__(self, outcome: str, basis: str = "none", ref: str = "", cite: bool = True):
        self.outcome, self.basis, self.ref, self.cite = outcome, basis, ref, cite
        self.prompts: list[str] = []

    def complete(self, system, turns, max_tokens=2048, tools=None):
        prompt = "\n".join(t.content for t in turns)
        self.prompts.append(prompt)
        tuples = sorted(set(re.findall(r"(?:TUP|OBS)-[0-9a-f]{16,20}", prompt)))
        events = re.findall(r'"event_uids": \[\s*"([^"]+)"', prompt)
        verdicts = [
            {
                "tuple_id": t,
                "outcome": self.outcome,
                "basis": self.basis,
                "basis_ref": self.ref,
                "missing": "who owns deploy-ci",
                "reasoning": "scripted",
                "citations": events[:1] if self.cite else [],
            }
            for t in tuples
        ]
        return Completion(
            text=json.dumps({"ruled_out": ["a deploy"], "verdicts": verdicts, "reasoning": "r"}),
            model=self.model,
            tokens_in=100,
            tokens_out=50,
        )


# -- the packs themselves ---------------------------------------------------
def test_there_are_packs_at_all():
    assert PACKS, "a Hunter with no packs is a cron entry with opinions"


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.id)
def test_every_pack_has_a_hypothesis_and_a_triage_question(pack):
    assert len(pack.hypothesis) > 40
    assert len(pack.triage) > 20
    assert pack.pivot and pack.attack


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.id)
def test_every_pack_has_fixtures(pack):
    for kind in ("surfaced", "baseline"):
        assert (FIXTURES / pack.id / f"{kind}.json").exists(), (
            f"{pack.id} has no {kind} fixture; a pack ships with fixtures like a rule"
        )


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.id)
def test_a_pack_surfaces_its_own_fixture(pack, ctx, store, config, clean, now):
    _connect(ctx, config, pack)
    _ingest(store, config.tenant_id, pack, "surfaced", now)
    run = hunter.run_pack(ctx.db, store, config.tenant_id, pack, client=NoLLM(), config=config)
    assert run.rows > 0, f"{pack.id} did not surface the behaviour it exists to find: {run.error}"
    assert all(t["event_uids"] for t in run.tuples), "a tuple carries every event behind it"


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.id)
def test_a_baseline_silences_a_pack(pack, ctx, store, config, clean, now):
    """`first_seen` is silenced by history ingested earlier; `rare` by the population.

    A floor (`seen_by_at_least` alone) only rises with more events, so nothing
    silences what it surfaced: its baseline is the normal shape, which must stay
    quiet on its own.
    """
    _connect(ctx, config, pack)
    when = now - timedelta(days=10) if pack.baseline.kind == "first_seen" else now
    floor_only = pack.baseline.seen_by_at_least and not pack.baseline.seen_by_fewer_than
    if not floor_only:
        _ingest(store, config.tenant_id, pack, "baseline", when)
    _mark_hunted(ctx, config, pack)
    _ingest(store, config.tenant_id, pack, "baseline" if floor_only else "surfaced", now)
    run = hunter.run_pack(ctx.db, store, config.tenant_id, pack, client=NoLLM(), config=config)
    assert run.rows == 0, f"{pack.id} surfaced rows the baseline explains: {run.tuples[:2]}"
    assert run.outcome == "clear"


def test_a_failed_call_does_not_make_the_successful_one_familiar(ctx, store, config, clean, now):
    """A denied call is not use, so it does not make the tuple familiar."""
    _connect(ctx, config, FIRST)
    surfaced = json.loads((FIXTURES / FIRST.id / "surfaced.json").read_text())
    failed = [
        {**r, "eventID": f"{r['eventID']}-denied", "errorCode": "AccessDenied"} for r in surfaced
    ]
    batch.load(
        store, fixture_rows(failed, "aws_cloudtrail", config.tenant_id, now - timedelta(days=10))
    )
    _mark_hunted(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.rows == len(surfaced)


# -- readiness: only data that can answer the question -------------------------
def test_a_pack_with_no_source_is_not_applicable_and_records_no_run(ctx, store, config, clean, now):
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)  # a replay, not a source
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.outcome == "not_applicable"
    assert not hunter.results(ctx.db, config.tenant_id), (
        "a pack on data nobody sends is not 'clear': nothing was hunted"
    )


def test_a_new_source_is_learning_until_its_baseline_is_long_enough(ctx, store, config, clean):
    _connect(ctx, config, FIRST, started_days_ago=2)
    ready = hunter.readiness(ctx.db, config.tenant_id, FIRST)
    assert ready.state == "learning"
    assert (
        ready.ready_at and (ready.ready_at - ready.ready_at.now(ready.ready_at.tzinfo)).days >= 26
    )
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.outcome == "learning" and not hunter.results(ctx.db, config.tenant_id)


def test_a_stale_source_is_a_gap_with_its_reason(ctx, store, config, clean):
    """A gap is raised with source health, and a ready pack falling back wakes the
    operator with the source's own coverage page, not the weekly (DET-11)."""
    from shoc.agents import ops

    source = _connect(ctx, config, FIRST)
    assert (
        hunter.run_pack(
            ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config
        ).outcome
        == "clear"
    )
    execute(
        ctx.db,
        "UPDATE shoc.source_history SET last_loaded_at = now() - interval '5 days' WHERE tenant_id = %s AND source = %s",
        (config.tenant_id, source),
    )
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.outcome == "gap" and "no data" in run.error
    raised = [a for a in ops.alerts(ctx.db, config.tenant_id) if a.kind == "hunt.gap"]
    assert [(a.subject, "no data" in a.detail) for a in raised] == [(FIRST.id, True)]
    assert not hunter.backlog(ctx.db, config.tenant_id), "a gap is not a hypothesis to hunt"
    told = fetch_all(
        ctx.db,
        "SELECT kind, condition, group_key FROM shoc.notices WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert told == [{"kind": "page", "condition": "coverage_dark", "group_key": f"source:{source}"}]


def test_the_daily_triage_stops_at_its_token_ceiling(ctx, store, config, clean, now):
    """The ceiling is a setting, and a pack over it waits a day with its window (DET-9)."""
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    call("llm.configure", ctx, {"hunt_tokens_per_day": 10})
    model = Hunter("inconclusive")
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=model, config=config)
    assert run.outcome == "gap" and "ceiling" in run.error
    assert not model.prompts, "nothing was sent to the model"

    call("llm.configure", ctx, {"hunt_tokens_per_day": 50_000})
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=model, config=config)
    assert run.outcome == "inconclusive" and model.prompts, "the same window, read the next time"


# -- windows follow ingestion ---------------------------------------------------
def test_a_clear_run_is_written_down_with_its_query(ctx, store, config, clean):
    _connect(ctx, config, FIRST)
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.outcome == "clear"
    rows = hunter.results(ctx.db, config.tenant_id)
    assert rows and rows[0]["outcome"] == "clear"
    assert "ocsf_events" in rows[0]["query"] and rows[0]["query_params"]["tenant_id"]
    assert rows[0]["ingested_to"] is not None, "the window it covered is on the record"


def test_a_late_delivery_is_hunted_rather_than_lost(ctx, store, config, clean, now):
    """An event stamped two days ago but delivered now falls in today's window."""
    _connect(ctx, config, FIRST)
    _mark_hunted(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now - timedelta(days=2))
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.rows > 0


def test_without_a_model_the_window_is_read_again_rather_than_guessed(
    ctx, store, config, clean, now
):
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    first = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert first.outcome == "gap" and "no model" in first.error
    again = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert again.rows == first.rows, "nothing advanced, so the same rows come back"


# -- triage is checked by code ---------------------------------------------------
def test_an_explanation_without_a_checkable_basis_is_inconclusive(ctx, store, config, clean, now):
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(
        ctx.db, store, config.tenant_id, FIRST, client=Hunter("explained"), config=config
    )
    assert run.outcome == "inconclusive"
    assert all(t["verdict"] == "inconclusive" for t in run.tuples)


def test_a_fact_a_person_wrote_is_a_basis(ctx, store, config, clean, now):
    from shoc.agents import memory

    fact = memory.add(
        ctx.db,
        config.tenant_id,
        "deploy-ci reads secrets on every release",
        subject="deploy-ci",
        source="human",
    )
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(
        ctx.db,
        store,
        config.tenant_id,
        FIRST,
        client=Hunter("explained", "human_fact", fact),
        config=config,
    )
    assert run.outcome == "explained"


def test_an_explanation_that_cites_nothing_is_inconclusive(ctx, store, config, clean, now):
    from shoc.agents import memory

    fact = memory.add(
        ctx.db,
        config.tenant_id,
        "deploy-ci reads secrets on every release",
        subject="deploy-ci",
        source="human",
    )
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(
        ctx.db,
        store,
        config.tenant_id,
        FIRST,
        client=Hunter("explained", "human_fact", fact, cite=False),
        config=config,
    )
    assert run.outcome == "inconclusive", "an explanation names the events it explains (SEC-2)"


def test_a_crew_written_fact_is_not_a_basis(ctx, store, config, clean, now):
    from shoc.agents import memory

    fact = memory.add(
        ctx.db, config.tenant_id, "deploy-ci is normal", subject="deploy-ci", source="hunter"
    )
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(
        ctx.db,
        store,
        config.tenant_id,
        FIRST,
        client=Hunter("explained", "human_fact", fact),
        config=config,
    )
    assert run.outcome == "inconclusive", "the crew cannot explain things to itself"


def test_suspicious_without_events_is_inconclusive(ctx, store, config, clean, now):
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(
        ctx.db,
        store,
        config.tenant_id,
        FIRST,
        client=Hunter("suspicious", cite=False),
        config=config,
    )
    assert run.outcome == "inconclusive"


# -- routing: a finding, never a case -------------------------------------------
def test_a_suspicious_tuple_raises_a_low_finding_with_actor_entities(
    ctx, store, config, clean, now
):
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(
        ctx.db, store, config.tenant_id, FIRST, client=Hunter("suspicious"), config=config
    )
    assert run.outcome == "suspicious" and run.finding_uid and not run.case_uid
    rows = fetch_all(
        ctx.db,
        "SELECT rule_id, severity, event_uids, entities, case_uid FROM shoc.findings WHERE tenant_id = %s",
        (config.tenant_id,),
    )
    assert rows and rows[0]["rule_id"] == f"hunt:{FIRST.id}" and rows[0]["severity"] == "low"
    assert rows[0]["event_uids"] and rows[0]["case_uid"] is None, "the Hunter opens no case"
    assert all(e.split(":")[0] in ("user", "key", "host") for e in rows[0]["entities"]), (
        "a hunt finding names who acted, never a shared address or account"
    )
    cases = fetch_all(ctx.db, "SELECT 1 FROM shoc.cases WHERE tenant_id = %s", (config.tenant_id,))
    assert not cases


def test_a_case_only_hunts_opened_has_a_token_ceiling(ctx, store, config, clean, now):
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    hunter.run_pack(
        ctx.db, store, config.tenant_id, FIRST, client=Hunter("suspicious"), config=config
    )
    call("detect.run", ctx, {})
    caps = fetch_all(
        ctx.db, "SELECT token_cap FROM shoc.cases WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert caps and caps[0]["token_cap"] == hunter.HUNT_CASE_TOKENS


def test_too_many_tuples_are_triaged_in_order_and_the_rest_named(
    ctx, store, config, clean, now, monkeypatch
):
    monkeypatch.setattr(hunter, "TOO_MANY_TUPLES", 0)
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    run = hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    assert run.unseen and "too broad" in run.unseen[0]


def test_promotion_counts_confirmed_attacks_only(ctx, store, config, clean, now):
    from shoc.detect.engine import Finding, upsert

    for n, (verdict, by) in enumerate(
        [("malicious", "crew"), ("suspicious", "crew"), ("malicious", "human")]
    ):
        case = f"CASE-{n:020d}"
        execute(
            ctx.db,
            """INSERT INTO shoc.cases (case_uid, tenant_id, title, state, verdict, closed_by, closed_at)
               VALUES (%s,%s,'hunt','closed',%s,%s,now())""",
            (case, config.tenant_id, verdict, by),
        )
        upsert(
            ctx.db,
            Finding(
                finding_uid=f"F-hunt-{n}",
                tenant_id=config.tenant_id,
                rule_id=f"hunt:{FIRST.id}",
                title="Hunt",
                severity="low",
                confidence=0.4,
                entity_key=f"u{n}",
                window_start=now,
                window_end=now,
                first_seen=now,
                last_seen=now,
                event_count=1,
                event_uids=[f"e{n}"],
                attack=[],
                evidence={"run_uid": f"HUNT-{n}"},
                entities=[f"user:u{n}"],
            ),
        )
        execute(
            ctx.db,
            "UPDATE shoc.findings SET case_uid = %s WHERE finding_uid = %s",
            (case, f"F-hunt-{n}"),
        )
    assert hunter.promotions(ctx.db, config.tenant_id, config) == 1
    items = fetch_all(
        ctx.db,
        "SELECT kind, evidence FROM shoc.detection_backlog WHERE tenant_id = %s AND intake = 'hunt'",
        (config.tenant_id,),
    )
    assert items and items[0]["kind"] == "promote"
    assert len(items[0]["evidence"]["case_uids"]) == 2, (
        "a crew's 'suspicious' is not a true positive"
    )


# -- selection --------------------------------------------------------------------
def test_selection_needs_no_model_and_says_why(ctx, store, config, clean):
    chosen = hunter.select(ctx.db, config.tenant_id, config)
    assert chosen and all(c.reason for c in chosen)


def _feed_report(ctx, config) -> str:
    execute(
        ctx.db,
        "INSERT INTO shoc.intel_feeds (tenant_id, feed) VALUES (%s,'labs')",
        (config.tenant_id,),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_reports (report_uid, tenant_id, title, techniques, source)
           VALUES (%s,%s,'Campaign write-up',%s,'labs')""",
        (f"REP-{config.tenant_id}", config.tenant_id, [FIRST.attack[0]]),
    )
    return f"REP-{config.tenant_id}"


def test_intel_from_a_configured_feed_comes_first(ctx, store, config, clean):
    _feed_report(ctx, config)
    chosen = hunter.select(ctx.db, config.tenant_id, config)
    assert chosen[0].pack_id in {p.id for p in PACKS if FIRST.attack[0] in p.attack}
    assert chosen[0].rank == 2 and "intel this week" in chosen[0].reason


def test_a_pack_testing_what_a_report_described_comes_before_a_shared_technique(
    ctx, store, config, clean
):
    report = _feed_report(ctx, config)
    other = next(p for p in PACKS if FIRST.attack[0] not in p.attack)
    hunter.add_to_backlog(
        ctx.db,
        config.tenant_id,
        trigger="cti",
        title="A key used from a host it never used",
        evidence={"report_uid": report, "covered_by": other.id},
    )
    chosen = hunter.select(ctx.db, config.tenant_id, config)
    assert chosen[0].pack_id == other.id and chosen[0].rank == 1
    assert "A key used from a host it never used" in chosen[0].reason


def test_intel_handed_in_by_anyone_does_not_steer_the_hunt(ctx, store, config, clean):
    execute(
        ctx.db,
        """INSERT INTO shoc.intel_reports (report_uid, tenant_id, title, techniques)
           VALUES (%s,%s,'pasted',%s)""",
        (f"REP-x-{config.tenant_id}", config.tenant_id, [FIRST.attack[0], "T9999; DROP"]),
    )
    chosen = hunter.select(ctx.db, config.tenant_id, config)
    assert all(c.rank == 3 for c in chosen)


def test_a_pack_is_not_run_twice_in_its_cadence(ctx, store, config, clean):
    _connect(ctx, config, FIRST)
    hunter.run_pack(ctx.db, store, config.tenant_id, FIRST, client=NoLLM(), config=config)
    chosen = hunter.select(ctx.db, config.tenant_id, config)
    assert FIRST.id not in {c.pack_id for c in chosen}


# -- through the registry -----------------------------------------------------------
def test_hunt_daily_says_what_could_not_be_hunted(ctx, store, config, clean):
    result = call("hunt.daily", ctx, {"limit": 3})
    assert result.data.readiness and all("state" in r for r in result.data.readiness)
    assert "not applicable" in result.summary
    assert "coverage" not in result.summary, "a pack on missing data is not coverage"


def test_hunt_pack_runs_one_named_pack(ctx, store, config, clean, now):
    _connect(ctx, config, FIRST)
    _ingest(store, config.tenant_id, FIRST, "surfaced", now)
    result = call("hunt.pack", ctx, {"pack_id": FIRST.id})
    assert result.data.rows > 0 and result.data.hypothesis


def test_a_caller_cannot_supply_a_query(ctx, store, config, clean):
    from shoc.errors import NotFound

    with pytest.raises(NotFound):
        call("hunt.pack", ctx, {"pack_id": "SELECT * FROM ocsf_events"})


def test_hunt_results_carries_readiness(ctx, store, config, clean):
    call("hunt.daily", ctx, {"limit": 2})
    result = call("hunt.results", ctx, {"days": 7})
    assert set(result.data.metrics) >= {
        "by_outcome",
        "detections_proposed",
        "gaps_open",
        "gaps_closed",
        "packs_hunted",
        "readiness",
    }
    assert {r["pack_id"] for r in result.data.readiness} == {p.id for p in PACKS}
    first = next(r for r in result.data.readiness if r["pack_id"] == FIRST.id)
    assert first["logic"]["detection"]["condition"] == FIRST.detection.condition
    assert first["logic"]["first_seen"] == FIRST.baseline.first_seen and first["logic"]["triage"]


def test_a_source_removed_and_added_again_keeps_its_history(ctx, store, config, clean):
    source = _connect(ctx, config, FIRST)
    call("source.remove", ctx, {"source": source})
    assert hunter.readiness(ctx.db, config.tenant_id, FIRST).state == "not_applicable"
    execute(
        ctx.db,
        "INSERT INTO shoc.connector_config (tenant_id, source, settings) VALUES (%s,%s,'{}')",
        (config.tenant_id, source),
    )
    assert hunter.readiness(ctx.db, config.tenant_id, FIRST).state == "ready", (
        "removing a source must not restart its learning period"
    )


def test_without_a_report_feed_the_operator_is_told_once_how_to_add_one(ctx, store, config, clean):
    hunter.daily(ctx.db, store, config.tenant_id, config, client=NoLLM())
    hunter.daily(ctx.db, store, config.tenant_id, config, client=NoLLM())
    told = fetch_all(
        ctx.db,
        "SELECT body FROM shoc.notices WHERE tenant_id = %s AND group_key = 'intel:report-feed'",
        (config.tenant_id,),
    )
    assert len(told) == 1 and "intel.configure" in told[0]["body"]


# -- packs for the backlog (RFC 0032) ------------------------------------------------
BEDROCK = next(p for p in PACKS if p.id == "aws_bedrock_first_use")


def _item(ctx, config, title: str = "Stolen keys resold for model access") -> str:
    return hunter.add_to_backlog(
        ctx.db, config.tenant_id, trigger="cti", title=title, attack=["T1496.004"]
    )


def _spec(item_uid: str, pack_id: str = "aws_bedrock_first_use_here", baseline=None) -> dict:
    import yaml

    assert BEDROCK.path
    body = yaml.safe_load(BEDROCK.path.read_text())
    body["id"] = pack_id
    fixtures = {
        "source": _source(BEDROCK),
        "surfaced": json.loads((FIXTURES / BEDROCK.id / "surfaced.json").read_text()),
        "baseline": baseline
        if baseline is not None
        else json.loads((FIXTURES / BEDROCK.id / "baseline.json").read_text()),
    }
    return {"item_uid": item_uid, "pack": body, "fixtures": fixtures}


def _state(ctx, config, uid: str) -> dict:
    rows = fetch_all(
        ctx.db,
        "SELECT state, pack_id, evidence FROM shoc.hunt_backlog WHERE tenant_id = %s AND item_uid = %s",
        (config.tenant_id, uid),
    )
    return rows[0]


def test_a_merged_pack_joins_the_cycle_and_its_first_run_closes_the_item(ctx, store, config, clean):
    _connect(ctx, config, BEDROCK)
    uid = _item(ctx, config)
    out = call("hunt.merge", ctx, _spec(uid))
    assert out.data.pack_id == "aws_bedrock_first_use_here"
    assert out.data.checked["readiness"] == "ready" and out.data.checked["tuples"] == 0
    assert _state(ctx, config, uid)["state"] == "packed"

    packs = {p.id: p for p in hunts.load(config, ctx.db, config.tenant_id)}
    assert packs["aws_bedrock_first_use_here"].merged_by == "human:test"
    assert "aws_bedrock_first_use_here" not in {p.id for p in hunts.load(config)}
    chosen = {c.pack_id: c for c in hunter.select(ctx.db, config.tenant_id, config)}
    assert chosen["aws_bedrock_first_use_here"].reason == "never run here"

    pack = packs["aws_bedrock_first_use_here"]
    run = hunter.run_pack(ctx.db, store, config.tenant_id, pack, client=NoLLM(), config=config)
    assert run.outcome == "clear"
    row = _state(ctx, config, uid)
    assert row["state"] == "done" and row["evidence"]["decision"] == "tested"
    assert row["evidence"]["run_uid"] == run.run_uid

    call("hunt.revert", ctx, {"pack_id": pack.id, "reason": "too broad"})
    assert pack.id not in {p.id for p in hunts.load(config, ctx.db, config.tenant_id)}
    assert _state(ctx, config, uid)["state"] == "rejected"


def test_a_backlog_item_says_what_would_show_it_and_the_packs_near_it(ctx, store, config, clean):
    _connect(ctx, config, FIRST)
    hunter.add_to_backlog(
        ctx.db,
        config.tenant_id,
        trigger="cti",
        title="A key calls an API it never called",
        attack=[FIRST.attack[0]],
        evidence={"seen_in": ["admin_api", "process"]},
    )
    (item,) = call("hunt.backlog", ctx, {}).data.items
    context = item["context"]
    assert {"id": FIRST.id, "title": FIRST.title, "live": True} in context["packs"]
    live = [p["live"] for p in context["packs"]]
    assert live == sorted(live, reverse=True), "what reads a product we receive comes first"
    shows = {s["kind"]: s["received"] for s in context["seen_in"]}
    assert shows == {"admin_api": ["AWS CloudTrail"], "process": []}


def test_a_dry_run_checks_a_pack_without_an_item_and_merges_nothing(ctx, store, config, clean):
    _connect(ctx, config, BEDROCK)
    out = call("hunt.merge", ctx, {**_spec(""), "dry_run": True})
    assert out.data.dry_run and out.data.checked["readiness"] == "ready"
    assert "aws_bedrock_first_use_here" not in {
        p.id for p in hunts.load(config, ctx.db, config.tenant_id)
    }
    uid = _item(ctx, config)
    call("hunt.merge", ctx, {**_spec(uid), "dry_run": True})
    assert _state(ctx, config, uid)["state"] == "open"


def test_a_person_merges_a_pack_without_an_item(ctx, store, config, clean):
    from shoc.errors import GateRefused

    _connect(ctx, config, BEDROCK)
    out = call("hunt.merge", ctx, _spec(""))
    assert out.data.pack_id == "aws_bedrock_first_use_here" and out.data.item_uid
    assert _state(ctx, config, out.data.item_uid)["state"] == "packed"
    assert "aws_bedrock_first_use_here" in {
        p.id for p in hunts.load(config, ctx.db, config.tenant_id)
    }
    with pytest.raises(GateRefused, match="is merged here: revert it first"):
        call("hunt.merge", ctx, {**_spec(""), "dry_run": True})


def test_a_person_ends_a_hunt_item_with_a_reason_or_reopens_it(ctx, config, clean):
    """As on the detection backlog, a decision keeps its reason (DET-8, D132)."""
    from shoc.capabilities.registry import Caller, Context
    from shoc.errors import Denied, NotFound, ValidationError

    uid = _item(ctx, config)
    crew = Context(
        tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config
    )
    with pytest.raises(Denied):
        call("hunt.decide", crew, {"item_uid": uid, "state": "rejected", "reason": "no"})
    with pytest.raises(ValidationError, match="say why"):
        call("hunt.decide", ctx, {"item_uid": uid, "state": "rejected"})
    with pytest.raises(NotFound):
        call("hunt.decide", ctx, {"item_uid": "HBL-nope", "state": "done", "reason": "r"})

    out = call("hunt.decide", ctx, {"item_uid": uid, "state": "rejected", "reason": "no Bedrock"})
    row = _state(ctx, config, uid)
    assert out.data.state == row["state"] == "rejected"
    assert (row["evidence"]["decision"], row["evidence"]["because"]) == ("rejected", "no Bedrock")
    call("hunt.decide", ctx, {"item_uid": uid, "state": "open"})
    row = _state(ctx, config, uid)
    assert row["state"] == "open" and row["evidence"]["reopened"] == "reopened by human:test"


def test_the_gate_refuses_a_pack_its_baseline_does_not_silence(ctx, store, config, clean):
    from shoc.errors import ValidationError

    _connect(ctx, config, BEDROCK)
    uid = _item(ctx, config)
    surfaced = json.loads((FIXTURES / BEDROCK.id / "surfaced.json").read_text())
    unrelated = [
        {**r, "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"} for r in surfaced
    ]
    with pytest.raises(ValidationError, match="did not silence"):
        hunter.merge_pack(ctx.db, store, config.tenant_id, config, _spec(uid, baseline=unrelated))
    assert _state(ctx, config, uid)["state"] == "open"


def test_the_gate_refuses_a_pack_no_source_answers_or_a_shipped_id(ctx, store, config, clean):
    from shoc.errors import ValidationError

    uid = _item(ctx, config)
    with pytest.raises(ValidationError, match="no connected source sends"):
        hunter.merge_pack(ctx.db, store, config.tenant_id, config, _spec(uid))
    _connect(ctx, config, BEDROCK)
    with pytest.raises(ValidationError, match="ships in content/"):
        hunter.merge_pack(ctx.db, store, config.tenant_id, config, _spec(uid, BEDROCK.id))


class PackWriter:
    """A stand-in Hunter on its backlog turn: says one outcome for every item."""

    model = "scripted"
    available = True

    def __init__(self, outcome: str, products: list[str] | None = None):
        self.outcome, self.products = outcome, products or []

    def complete(self, system, turns, max_tokens=2048, tools=None):
        prompt = "\n".join(t.content for t in turns)
        uids = sorted(set(re.findall(r"HBL-[0-9a-f]{20}", prompt)))
        outcomes = [
            {"item_uid": u, "outcome": self.outcome, "products": self.products, "because": "b"}
            for u in uids
        ]
        return Completion(
            text=json.dumps({"outcomes": outcomes, "reasoning": "r"}),
            model=self.model,
            tokens_in=100,
            tokens_out=50,
        )


def test_the_hunter_ends_an_item_that_is_not_worth_a_pack(ctx, store, config, clean):
    uid = _item(ctx, config)
    out = hunter.work_backlog(ctx.db, store, config.tenant_id, config, PackWriter("not_worth"))
    assert out["outcomes"] == {"not_worth": 1}
    row = _state(ctx, config, uid)
    assert row["state"] == "rejected" and row["evidence"]["decision"] == "not_worth"


def test_a_pack_the_gate_never_accepted_is_not_packed(ctx, store, config, clean):
    uid = _item(ctx, config)
    for _ in range(hunter.STUCK_AFTER - 1):
        out = hunter.work_backlog(ctx.db, store, config.tenant_id, config, PackWriter("packed"))
        assert out["outcomes"] == {"later": 1}
    row = _state(ctx, config, uid)
    assert row["state"] == "open" and row["evidence"]["gate"] == "hunt.merge was never called"
    out = hunter.work_backlog(ctx.db, store, config.tenant_id, config, PackWriter("packed"))
    assert out["outcomes"] == {"stuck": 1} and _state(ctx, config, uid)["state"] == "rejected"


def test_a_source_gap_comes_back_when_the_source_does(ctx, store, config, clean):
    uid = _item(ctx, config)
    hunter.work_backlog(ctx.db, store, config.tenant_id, config, PackWriter("source_gap", ["aws"]))
    row = _state(ctx, config, uid)
    assert row["state"] == "rejected" and row["evidence"]["waiting_for"]
    _connect(ctx, config, BEDROCK)
    out = hunter.work_backlog(ctx.db, store, config.tenant_id, config, NoLLM())
    assert out["outcomes"] == {"reopened": 1} and _state(ctx, config, uid)["state"] == "open"
