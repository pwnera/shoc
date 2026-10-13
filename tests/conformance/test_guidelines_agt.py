"""The agent and model-use guidelines that need a database (AGT-G2, AGT-G3, AGT-G7).

A rule the code breaks today is listed in a test's KNOWN with why it is allowed
for now; the test fails on a break that is not listed and on a listed one that
no longer breaks, so each list only shrinks.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from evals.run import SCENARIOS, replay
from shoc.agents.llm import ScriptedClient
from shoc.cases import engine, routing
from shoc.db.pool import execute, fetch_all, fetch_one
from tests.conformance.test_injection import BLOCK, INJECTED, _log_text, _obeying

pytestmark = pytest.mark.postgres


def _ratchet(rule: str, found: dict[str, str], known: dict[str, str]) -> None:
    """Fail on a break KNOWN does not list, and on a KNOWN entry that no longer breaks."""
    new = sorted(found[k] for k in found if k not in known)
    assert not new, f"{rule} broken at:\n" + "\n".join(new)
    fixed = sorted(set(known) - set(found))
    assert not fixed, f"{rule} now holds for {', '.join(fixed)}: take it out of KNOWN"


# -- AGT-G2 a closure taken back takes back what it quieted -------------------
def test_a_closure_taken_back_leaves_nothing_quiet(ctx, store, config, clean):
    """AGT-G2: undoing a benign close revokes every suppression it wrote and expires
    its note in memory, so nothing keeps arguing benign on the entity."""
    tenant = config.tenant_id
    replay(SCENARIOS / "leaked_aws_key", tenant_id=tenant, store=store)
    case = fetch_one(ctx.db, "SELECT * FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (tenant,))
    assert case, "the scenario must open a case"
    uid = str(case["case_uid"])
    routing.route(
        ctx.db, tenant, case, "benign_expected", summary="the nightly backup job", closer="human"
    )

    def quiet() -> tuple[list[str], list[str]]:
        held = [
            str(s["suppression_uid"])
            for s in routing.active_suppressions(ctx.db, tenant)
            if s["case_uid"] == uid
        ]
        notes = fetch_all(
            ctx.db,
            """SELECT memory_id FROM shoc.memory
               WHERE tenant_id = %s AND source = 'crew' AND body LIKE %s
                 AND (expires_at IS NULL OR expires_at > now())""",
            (tenant, "%" + routing.closure_mark(uid)),
        )
        return held, [str(n["memory_id"]) for n in notes]

    held, notes = quiet()
    assert held and notes, "the close quieted the rule and taught the crew"
    routing.undo_closure(ctx.db, tenant, uid, "reopened: a test")
    assert quiet() == ([], []), "a suppression or a note outlived the closure"


# -- AGT-G3 every text in a prompt is quoted ----------------------------------
@pytest.mark.parametrize("name", INJECTED)
def test_every_prompt_builder_quotes_the_logs(name, ctx, store, config, clean, monkeypatch):
    """AGT-G3: every prompt built from case, notice or source data quotes the logs.

    `test_injection` replays `run_case` alone. Here an obeying model, one that
    repeats the attacker's text in everything it writes, is handed in turn to
    Ops, Sentinel, the crew, the weekly recheck and the Manager's page wording,
    so text it wrote after reading the logs reaches the builders after it.
    """
    from shoc.agents import manager, ops, recheck, sentinel
    from shoc.agents.loop import run_case

    tenant = config.tenant_id
    replay(SCENARIOS / "benign_ci_day", tenant_id=tenant, store=store)
    replay(SCENARIOS / name, tenant_id=tenant, store=store)
    logs = _log_text(name)
    said = max(logs, key=len)
    cases = [
        str(r["case_uid"])
        for r in fetch_all(
            ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s", (tenant,)
        )
    ]
    assert cases, f"{name} must open a case"
    prompts: dict[str, list[str]] = {}

    def turn(entry: str, run: Callable[[ScriptedClient], object]) -> None:
        client = _obeying(said, "ct-not-in-this-case")
        monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: client)
        run(client)
        prompts[entry] = list(client.calls)

    # First, while no model failure is recorded: Ops does not ask a failing provider.
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_state
               (tenant_id, source, cursor, last_run_at, last_ok_at, last_error)
           VALUES (%s, 'okta', '{}', now(), now() - interval '30 hours', %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               last_ok_at = EXCLUDED.last_ok_at, last_error = EXCLUDED.last_error,
               diagnosed_at = NULL""",
        (tenant, said),
    )
    turn("Ops", lambda c: ops.review(ctx.db, store, tenant, config, c))
    execute(
        ctx.db,
        """UPDATE shoc.findings SET evidence = coalesce(evidence, '{}'::jsonb) - 'sentinel'
           WHERE tenant_id = %s""",
        (tenant,),
    )
    turn("Sentinel", lambda c: sentinel.shape(ctx.db, store, tenant, cases, c, config))
    turn(
        "the crew",
        lambda c: [run_case(ctx.db, store, tenant, u, client=c, config=config) for u in cases],
    )
    # The crew closes each case on the attacker's words, as an obeying model would.
    for uid in cases:
        if engine.require(ctx.db, tenant, uid)["state"] == "closed":
            continue
        cited = fetch_one(
            ctx.db,
            "SELECT event_uids FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s LIMIT 1",
            (tenant, uid),
        )
        uids = list((cited or {}).get("event_uids") or [])
        engine.set_verdict(ctx.db, tenant, uid, "benign_expected", 0.8, said, uids)
        engine.transition(ctx.db, tenant, uid, "closed", "closed by the crew", by="crew")
    monkeypatch.setattr(recheck, "SAMPLE", len(cases))
    turn("the weekly recheck", lambda c: recheck.run(ctx.db, store, tenant, config, client=c))
    rows = [
        {
            "case_uid": cases[0],
            "citations": [],
            "source": "IR Commander",
            "condition": "critical_severity",
            "severity": "critical",
            "body": said,
        }
    ]
    turn("the Manager's page", lambda _c: manager.word(ctx.db, tenant, rows, config, store))

    for entry, sent in prompts.items():
        assert sent, f"{entry} must have asked the model"
        for prompt in sent:
            assert prompt.count("<untrusted-data") == prompt.count("</untrusted-data>"), (
                f"{entry}: a data block was closed early"
            )
            outside = BLOCK.sub("", prompt)
            leaked = [text for text in logs if text in outside]
            assert not leaked, f"{entry}: log content outside a data block: {leaked[0][:80]}"


# -- AGT-G7 spend ceilings are checked before the call ------------------------
SWEEP_KNOWN = {
    "shoc/worker.py:_sweep_cases": "AGT-G7 open (live-9): the sweep queues a case past its "
    "lifetime ceiling; run_case stops it before any model call",
}


def test_the_sweep_does_not_queue_a_case_past_its_lifetime_ceiling(
    ctx, store, config, clean, monkeypatch
):
    """AGT-G7: a case that has spent `LIFETIME_RUNS` budgets is a person's, so the
    sweep does not send the crew back to it."""
    from shoc import worker
    from shoc.agents.loop import LIFETIME_RUNS
    from shoc.agents.openspace import Budget

    tenant = config.tenant_id
    replay(SCENARIOS / "leaked_aws_key", tenant_id=tenant, store=store)
    cases = fetch_all(
        ctx.db, "SELECT case_uid, severity FROM shoc.cases WHERE tenant_id = %s", (tenant,)
    )
    assert cases, "the scenario must open a case"

    def sweep(spent: bool) -> int:
        execute(ctx.db, "DELETE FROM shoc.jobs WHERE tenant_id = %s", (tenant,))
        for case in cases:
            execute(
                ctx.db,
                """UPDATE shoc.cases SET tokens_used = %s, worked_at = NULL,
                          crew_attempts = 0, crew_attempted_at = NULL
                   WHERE tenant_id = %s AND case_uid = %s""",
                (
                    LIFETIME_RUNS * Budget.for_severity(str(case["severity"])).max_tokens
                    if spent
                    else 0,
                    tenant,
                    case["case_uid"],
                ),
            )
        worker._sweep_cases(ctx)
        queued = fetch_one(
            ctx.db,
            """SELECT count(*) AS n FROM shoc.jobs
               WHERE tenant_id = %s AND kind = 'case.investigate'""",
            (tenant,),
        )
        return int(queued["n"]) if queued else 0

    # A crew to send; the sweep is a no-op without one.
    monkeypatch.setattr(config, "llm_provider", "openai")
    assert sweep(spent=False), "a case nobody has read is sent the crew"
    queued = sweep(spent=True)
    found: dict[str, str] = {}
    if queued:
        found["shoc/worker.py:_sweep_cases"] = (
            f"shoc/worker.py: _sweep_cases queued {queued} case(s) past their lifetime ceiling"
        )
    _ratchet("AGT-G7", found, SWEEP_KNOWN)
