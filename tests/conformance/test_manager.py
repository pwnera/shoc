"""The SOC Manager, the operator's one contact (RFC 0015).

Every test here is about one person's attention. A company with no security team
has one technical person who does not open the tool, so a page has to be rare
enough to be read: one per incident, only on a typed condition, and never
decided by a model.
"""

from __future__ import annotations

import pytest

from shoc.agents import manager
from shoc.api.slack import escape
from shoc.cases import actions as action_store
from shoc.cases import engine
from shoc.db.pool import execute, fetch_all

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    rows = fetch_all(
        ctx.db,
        "SELECT case_uid, severity FROM shoc.cases WHERE tenant_id = %s LIMIT 1",
        (config.tenant_id,),
    )
    assert rows, "the scenario must open a case"
    engine.set_severity(ctx.db, config.tenant_id, rows[0]["case_uid"], "critical", "for this test")
    return rows[0]


def pages(conn, tenant_id: str) -> list[dict]:
    return fetch_all(
        conn,
        "SELECT requested_by, state FROM shoc.actions WHERE tenant_id=%s AND type='notify.page'",
        (tenant_id,),
    )


def outcomes(conn, tenant_id: str) -> list[str]:
    return [
        str(r["outcome"])
        for r in fetch_all(
            conn,
            """SELECT outcome FROM shoc.notices
               WHERE tenant_id=%s AND kind='page' AND source <> 'shoc' ORDER BY created_at""",
            (tenant_id,),
        )
    ]


def test_two_senders_on_one_incident_page_once(conn, config, case):
    """The Commander and a playbook on the same leaked key used to page twice."""
    for source in ("IR Commander", "playbook-runner"):
        manager.tell(
            conn,
            config.tenant_id,
            source,
            "page",
            f"{source}: the key is still in use",
            case_uid=case["case_uid"],
            condition="critical_severity",
        )
    done = manager.deliver(conn, config.tenant_id, config)
    assert len(done.paged) == 1 and not done.failed
    assert [p["requested_by"] for p in pages(conn, config.tenant_id)] == ["manager"]
    assert outcomes(conn, config.tenant_id) == ["paged", "paged"]


def test_a_later_notice_on_the_same_incident_is_folded_into_the_page(conn, config, case):
    manager.tell(
        conn,
        config.tenant_id,
        "IR Commander",
        "page",
        "first",
        case_uid=case["case_uid"],
        condition="critical_severity",
    )
    manager.deliver(conn, config.tenant_id, config)
    manager.tell(
        conn,
        config.tenant_id,
        "unattended",
        "page",
        "second",
        case_uid=case["case_uid"],
        condition="deadline_expired",
    )
    done = manager.deliver(conn, config.tenant_id, config)
    assert done.merged == 1 and not done.paged
    assert len(pages(conn, config.tenant_id)) == 1


def test_a_page_without_a_condition_waits_for_the_weekly(conn, config, case):
    manager.tell(conn, config.tenant_id, "Ops", "page", "something looked odd")
    assert manager.deliver(conn, config.tenant_id, config).summary == "manager: nothing to deliver"
    kinds = fetch_all(
        conn,
        "SELECT kind FROM shoc.notices WHERE tenant_id=%s AND source='Ops'",
        (config.tenant_id,),
    )
    assert [k["kind"] for k in kinds] == ["digest"]
    assert not pages(conn, config.tenant_id)


def test_critical_is_the_cases_severity_not_the_senders_word(conn, config, case):
    engine.set_severity(conn, config.tenant_id, case["case_uid"], "high", "for this test")
    manager.tell(
        conn,
        config.tenant_id,
        "IR Commander",
        "page",
        "wake them",
        case_uid=case["case_uid"],
        condition="critical_severity",
    )
    assert manager.deliver(conn, config.tenant_id, config).digest == 1
    assert not pages(conn, config.tenant_id)


def test_a_playbook_page_step_is_handed_to_the_manager(conn, config, case):
    """The step succeeds, so no playbook changes; the gate decides who is woken."""
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="notify.page",
            params={"summary": "contained the key"},
            case_uid=case["case_uid"],
        ),
        "playbook-runner",
        principal_kind="service",
        config=config,
    )
    after, result = action_store.execute(
        conn, config.tenant_id, row["action_uid"], "", by="manager"
    )
    assert after["state"] == "done" and "SOC Manager" in result.detail
    notices = fetch_all(
        conn,
        """SELECT source, condition FROM shoc.notices
           WHERE tenant_id=%s AND kind='page' AND source='playbook-runner'""",
        (config.tenant_id,),
    )
    assert notices == [{"source": "playbook-runner", "condition": "critical_severity"}]


def test_a_pending_approval_is_recorded_for_the_manager(conn, config, case):
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    assert row["state"] == "proposed"
    decisions = fetch_all(
        conn,
        "SELECT body FROM shoc.notices WHERE tenant_id=%s AND kind='decision'",
        (config.tenant_id,),
    )
    assert len(decisions) == 1 and "aws.revoke_role_sessions on deploy" in decisions[0]["body"]


def test_a_stalled_scheduler_pages_once_not_on_every_check(conn, config, clean):
    """`ops.check` is one of the schedules, so a stalled scheduler never reported itself."""
    execute(
        conn,
        """INSERT INTO shoc.schedules (schedule_id, tenant_id, kind, next_run_at, enabled)
           VALUES (%s, %s, 'detect.run', now() - interval '2 hours', true)""",
        (f"{config.tenant_id}:stalled", config.tenant_id),
    )
    try:
        assert manager.scheduler(conn, config.tenant_id, config)
        assert manager.scheduler(conn, config.tenant_id, config)
    finally:
        execute(conn, "DELETE FROM shoc.schedules WHERE tenant_id = %s", (config.tenant_id,))
    assert outcomes(conn, config.tenant_id) == ["paged"]
    assert [p["requested_by"] for p in pages(conn, config.tenant_id)] == ["manager"]
    assert not manager.scheduler(conn, config.tenant_id, config)


def test_the_template_is_enough_without_a_model(conn, config, case):
    manager.tell(
        conn,
        config.tenant_id,
        "IR Commander",
        "page",
        "the key is still in use",
        case_uid=case["case_uid"],
        condition="uncontainable_and_active",
    )
    rows = fetch_all(
        conn,
        "SELECT * FROM shoc.notices WHERE tenant_id=%s AND source='IR Commander'",
        (config.tenant_id,),
    )
    text = manager.template(rows)
    assert text.startswith("CRITICAL (uncontainable and active)")
    assert case["case_uid"] in text and "the key is still in use" in text


def test_ask_is_answered_by_the_manager_and_audited(ctx, conn, config, case, monkeypatch):
    """AGT-14: the Manager's answer reaches past the caller's scopes, so the call is on record."""
    import json

    from shoc.agents.llm import ScriptedClient
    from shoc.capabilities.registry import call
    from tests.support import audit_seq

    uids = list(
        fetch_all(
            conn,
            "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s",
            (config.tenant_id, case["case_uid"]),
        )[0]["event_uids"]
    )[:2]
    said = {"body": "The key read secrets from 203.0.113.7.", "citations": uids}
    client = ScriptedClient(replies={"The operator asks": json.dumps(said)})
    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: client)
    before = audit_seq(conn, config.tenant_id)
    # Named, so the case's events are in what the Manager read and may be cited (SEC-2).
    question = f"what did AKIAIOSFODNN7EXAMPLE do in {case['case_uid']}?"
    answer = call("ask", ctx, {"question": question})
    assert answer.data.intent == "manager" and answer.summary == said["body"]
    assert answer.citations and set(answer.citations) <= set(uids)
    rows = fetch_all(
        conn,
        """SELECT capability, principal_kind || ':' || principal_id AS who, output_hash
           FROM shoc.audit_log WHERE tenant_id = %s AND seq > %s AND capability = 'ask'""",
        (config.tenant_id, before),
    )
    assert [(r["capability"], r["who"]) for r in rows] == [("ask", "human:test")]
    assert rows[0]["output_hash"], "the answer is committed to, not only the question"


def test_a_question_about_the_deployment_needs_no_events(ctx, case, monkeypatch):
    """D135: it used to be thrown away for a week of findings it was not about."""
    import json

    from shoc.agents.llm import ScriptedClient
    from shoc.capabilities.registry import call

    said = {"body": "42 rules are on, and none failed today.", "citations": ["E-invented"]}
    client = ScriptedClient(replies={"The operator asks": json.dumps(said)})
    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: client)
    # Two apostrophes, so a quoted name would be read between them.
    answer = call("ask", ctx, {"question": "what's our rule count? It's been a while"})
    assert answer.data.intent == "manager" and answer.summary == said["body"]
    assert answer.citations == [] and answer.data.findings == [], "invented ids still go"
    # A question that names something still needs its events (D25).
    answer = call("ask", ctx, {"question": "what did 203.0.113.7 do?"})
    assert answer.data.intent == "search"


def test_log_content_cannot_ping_the_workspace():
    assert escape("<!channel> see <https://x.test|here> & more") == (
        "&lt;!channel&gt; see &lt;https://x.test|here&gt; &amp; more"
    )


# -- the exception report (D52) -----------------------------------------------
def test_the_exception_report_carries_only_what_needs_a_person_and_says_it_once(
    conn, store, config, case
):
    from shoc.agents import reporter

    assert reporter.send_exceptions(conn, store, config.tenant_id, config) == (
        "exception report: nothing needs a person"
    ), "silence is the product working"
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    action_store.reject(conn, config.tenant_id, row["action_uid"], "unattended", "expired")
    execute(
        conn,
        """INSERT INTO shoc.source_onboarding (tenant_id, source, step, scopes, click_path)
           VALUES (%s, 'okta', 'credentials', '["okta.logs.read"]', 'Admin Console')""",
        (config.tenant_id,),
    )
    sent = reporter.send_exceptions(conn, store, config.tenant_id, config)
    assert sent.endswith("2 decision(s)")
    report = fetch_all(
        conn,
        "SELECT body, summary FROM shoc.reports WHERE tenant_id=%s AND kind='exception'",
        (config.tenant_id,),
    )[0]
    refs = {i["reference"] for i in report["body"]["items"]}
    assert refs == {row["action_uid"], "credentials:okta"}
    assert "reading" not in report["body"], "no model, no reading; the report stands alone"
    assert reporter.send_exceptions(conn, store, config.tenant_id, config) == (
        "exception report: nothing needs a person"
    ), "a decision is sent once"


def test_reading_the_exception_report_does_not_count_as_sending_it(ctx, conn, store, config, clean):
    from shoc.agents import reporter
    from shoc.capabilities.registry import call

    execute(
        conn,
        """INSERT INTO shoc.source_onboarding (tenant_id, source, step, scopes, click_path)
           VALUES (%s, 'okta', 'credentials', '["okta.logs.read"]', 'Admin Console')""",
        (config.tenant_id,),
    )
    assert call("report.get", ctx, {"kind": "exception"}).data.body["items"]
    assert reporter.send_exceptions(conn, store, config.tenant_id, config).endswith(
        "1 decision(s)"
    ), "the operator opening the console is not the operator being told"


def test_the_weekly_no_longer_holds_decisions(conn, store, config, case):
    from shoc.agents import reporter

    action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "deploy"},
            case_uid=case["case_uid"],
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    manager.tell(conn, config.tenant_id, "Hunter", "digest", "a pack is learning", deliver=False)
    held = reporter.build(conn, store, config.tenant_id, "weekly", config=config).body["held"]
    assert [h["kind"] for h in held] == ["digest"]


def test_the_managers_model_reads_a_report_and_never_writes_its_figures(conn, store, config, case):
    import json

    from shoc.agents import reporter
    from shoc.agents.llm import ScriptedClient

    report = reporter.build(conn, store, config.tenant_id, "weekly", config=config)
    client = ScriptedClient(default=json.dumps({"reading": "A quiet week.", "message": "x"}))
    assert reporter.narrate(report, client, config, conn, config.tenant_id) == "A quiet week."


# -- Ops above its queries (D47) ------------------------------------------------
def test_ops_diagnoses_an_outage_once_and_the_coverage_page_carries_it(conn, store, config, clean):
    import json

    from shoc.agents import ops
    from shoc.agents.llm import NoLLM, ScriptedClient

    execute(
        conn,
        """INSERT INTO shoc.connector_state (tenant_id, source, cursor, last_run_at, last_ok_at,
                                             last_error)
           VALUES (%s, 'okta', '{}', now(), now() - interval '30 hours',
                   'okta rejected the credential (401).')""",
        (config.tenant_id,),
    )
    assert ops.review(conn, store, config.tenant_id, config, NoLLM())["read"] is False
    client = ScriptedClient(
        default=json.dumps(
            {
                "sources": [
                    {
                        "source": "okta",
                        "state": "dark",
                        "retry": True,
                        "diagnosis": "the API token was revoked",
                        "exact_fix": "create a read-only admin token",
                    }
                ],
                "cannot_currently_see": ["Okta sign-ins"],
                "page_human": True,
                "page_reason": "Okta dark 30h",
            }
        )
    )
    said = ops.review(conn, store, config.tenant_id, config, client)
    assert said["read"] and said["diagnosed"] == ["okta"] and said["retried"] == ["okta"]
    again = ops.review(conn, store, config.tenant_id, config, client)
    assert again["read"] is False, "one outage, one turn"
    assert fetch_all(
        conn,
        "SELECT 1 FROM shoc.jobs WHERE tenant_id=%s AND kind='source.sync'",
        (config.tenant_id,),
    ), "retry queues the pull"
    digest = fetch_all(
        conn,
        "SELECT kind, body FROM shoc.notices WHERE tenant_id=%s AND source='Ops'",
        (config.tenant_id,),
    )
    assert digest == [{"kind": "digest", "body": digest[0]["body"]}], (
        "the model's page alone reaches the weekly, not the pager"
    )
    assert manager.coverage(conn, config.tenant_id) == 1, "the query decides the page"
    body = fetch_all(
        conn,
        "SELECT body FROM shoc.notices WHERE tenant_id=%s AND kind='page'",
        (config.tenant_id,),
    )[0]["body"]
    assert "Ops: the API token was revoked; fix: create a read-only admin token" in body
