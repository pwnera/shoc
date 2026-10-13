"""A page leaves, is tried again, and falls back (RSP-4, OPS-1, RFC 0015).

The company's one technical person is absent most days, and a page is how
shoc reaches them. A stock install recorded every page as sent while dry run
kept it from PagerDuty, lost a page to one 503, and had no way to say anything
when neither PagerDuty nor Slack was set up.
"""

from __future__ import annotations

import json
import time

import pytest

from shoc.agents import manager
from shoc.cases import engine
from shoc.db.pool import execute, fetch_all, fetch_one

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(ctx, store, config, clean):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    row = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id = %s LIMIT 1", (config.tenant_id,)
    )
    assert row, "the scenario must open a case"
    engine.set_severity(ctx.db, config.tenant_id, row["case_uid"], "critical", "for this test")
    return row["case_uid"]


def _tell(conn, config, case_uid: str, body: str = "the key is still in use") -> str:
    return manager.tell(
        conn,
        config.tenant_id,
        "IR Commander",
        "page",
        body,
        case_uid=case_uid,
        condition="critical_severity",
        deliver=False,
    )


def _notice(conn, config, uid: str) -> dict:
    row = fetch_one(
        conn,
        """SELECT outcome, attempts, last_error, retry_at, delivered_at,
                  retry_at - now() AS wait FROM shoc.notices
           WHERE tenant_id = %s AND notice_uid = %s""",
        (config.tenant_id, uid),
    )
    assert row
    return row


def test_a_page_leaves_while_dry_run_is_on(conn, config, case, pager, monkeypatch):
    """sre-1: dry run planned the page, nothing reached PagerDuty, and it said 'paged'."""
    monkeypatch.setattr(config, "dry_run", True)
    uid = _tell(conn, config, case)
    done = manager.deliver(conn, config.tenant_id, config)
    assert len(done.paged) == 1 and not done.failed
    assert len(pager.posts) == 1 and pager.posts[0]["routing_key"] == "test-routing-key"
    assert pager.posts[0]["payload"]["severity"] == "critical"
    assert _notice(conn, config, uid)["outcome"] == "paged"
    page = fetch_one(
        conn,
        """SELECT state, dry_run, result FROM shoc.actions
           WHERE tenant_id = %s AND type = 'notify.page' AND requested_by = 'manager'""",
        (config.tenant_id,),
    )
    assert page and page["state"] == "done" and page["result"]["dry_run"] is False
    # The record says what happened: undo resolves the incident, the console
    # and the weekly do not call it planned.
    assert page["dry_run"] is False


def test_no_pager_and_no_channel_is_failed_not_paged(conn, config, case, monkeypatch):
    """With nothing to page through, the record says so and nothing waits on it."""
    monkeypatch.setattr(config, "smtp_url", "")
    uid = _tell(conn, config, case)
    done = manager.deliver(conn, config.tenant_id, config)
    assert done.failed and not done.paged and not done.retrying
    notice = _notice(conn, config, uid)
    assert notice["outcome"] == "failed" and notice["retry_at"] is None
    assert "no pager is configured" in notice["last_error"]
    # A failed page is no page: the next notice on the incident is not folded into it.
    second = _tell(conn, config, case, "the key read a secret")
    manager.deliver(conn, config.tenant_id, config)
    assert _notice(conn, config, second)["outcome"] == "failed"


def test_a_page_pagerduty_refused_is_tried_again_then_goes_out(conn, config, case, pager):
    """sre-11: one 503 lost the page until the next UTC day."""
    pager.status = 503
    uid = _tell(conn, config, case)
    done = manager.deliver(conn, config.tenant_id, config)
    assert done.retrying and not done.paged and not done.failed
    assert "tried again" in done.summary
    notice = _notice(conn, config, uid)
    assert notice["delivered_at"] is None and notice["attempts"] == 1
    assert "503" in notice["last_error"]
    assert 0 < notice["wait"].total_seconds() <= 60 * manager.RETRY_MINUTES[0]
    job = fetch_one(
        conn,
        """SELECT run_at FROM shoc.jobs WHERE tenant_id = %s AND kind = 'manager.deliver'
             AND idempotency_key = %s""",
        (config.tenant_id, f"deliver:{uid}@{notice['retry_at'].isoformat()}"),
    )
    assert job and job["run_at"] == notice["retry_at"], "the job comes back when the gate would"
    again = manager.deliver(conn, config.tenant_id, config)
    assert again.summary == "manager: nothing to deliver", "not before its time"

    execute(
        conn,
        "UPDATE shoc.notices SET retry_at = now() - interval '1 second' WHERE notice_uid = %s",
        (uid,),
    )
    pager.status = 202
    done = manager.deliver(conn, config.tenant_id, config)
    assert len(done.paged) == 1
    notice = _notice(conn, config, uid)
    assert notice["outcome"] == "paged" and notice["attempts"] == 2
    assert len(pager.posts) == 2, "the same dedup key, so PagerDuty keeps one incident"
    assert pager.posts[0]["dedup_key"] == pager.posts[1]["dedup_key"]


def test_a_page_that_keeps_failing_is_settled_failed_after_its_retries(conn, config, case, pager):
    pager.status = 500
    uid = _tell(conn, config, case)
    execute(
        conn,
        "UPDATE shoc.notices SET attempts = %s WHERE notice_uid = %s",
        (len(manager.RETRY_MINUTES), uid),
    )
    done = manager.deliver(conn, config.tenant_id, config)
    assert done.failed and not done.retrying
    notice = _notice(conn, config, uid)
    assert notice["outcome"] == "failed" and notice["attempts"] == len(manager.RETRY_MINUTES) + 1


def test_a_pager_credential_that_cannot_work_is_not_tried_again(
    conn, config, case, pager, monkeypatch
):
    """A region PagerDuty does not have is the same answer in 21 minutes."""
    from shoc.cases import credentials

    monkeypatch.setattr(config, "smtp_url", "")
    credentials.store(
        conn,
        config.tenant_id,
        "notify",
        {"region": "mars"},
        {"routing_key": "test-routing-key"},
        config.master_key,
    )
    uid = _tell(conn, config, case)
    done = manager.deliver(conn, config.tenant_id, config)
    assert done.failed and not done.retrying and not pager.posts
    notice = _notice(conn, config, uid)
    assert notice["outcome"] == "failed" and "ConfigError" in notice["last_error"]


def test_a_page_the_pager_did_not_take_is_emailed_to_admins_and_operators(
    conn, config, case, monkeypatch
):
    """po-3: a company with neither PagerDuty nor Slack heard nothing."""
    from shoc import mail
    from tests.support import audit_seq

    monkeypatch.setattr(config, "smtp_url", "smtps://mail.example.com")
    monkeypatch.setattr(config, "mail_from", "shoc@example.com")
    sent: list[tuple[str, str, str]] = []
    monkeypatch.setattr(mail, "send", lambda _cfg, to, subj, body: sent.append((to, subj, body)))
    for user, role, disabled, password, sso in (
        ("admin@example.com", "admin", False, "x", None),
        ("ops@example.com", "operator", False, None, "sso-ops"),
        ("left@example.com", "operator", True, "x", None),
        ("viewer@example.com", "reader", False, "x", None),
        # Invited, never signed in: a mistyped address reads no case titles.
        ("typo@example.com", "operator", False, None, None),
    ):
        execute(
            conn,
            """INSERT INTO shoc.users (tenant_id, user_id, email, role, created_by, disabled_at,
                                       password_hash, sso_subject)
               VALUES (%s, %s, %s, %s, 'test', CASE WHEN %s THEN now() END, %s, %s)""",
            (config.tenant_id, f"u-{user}", user, role, disabled, password, sso),
        )
    before = audit_seq(conn, config.tenant_id)
    uid = _tell(conn, config, case)
    done = manager.deliver(conn, config.tenant_id, config)
    assert len(done.paged) == 1, "delivered by email counts"
    assert sorted(to for to, _s, _b in sent) == ["admin@example.com", "ops@example.com"]
    assert all("the key is still in use" in body and case in body for _t, _s, body in sent)
    notice = _notice(conn, config, uid)
    assert notice["outcome"] == "paged" and "no pager is configured" in notice["last_error"]
    audited = fetch_all(
        conn,
        """SELECT principal_kind || ':' || principal_id AS who FROM shoc.audit_log
           WHERE tenant_id = %s AND seq > %s AND capability = 'notify.mail'""",
        (config.tenant_id, before),
    )
    assert [r["who"] for r in audited] == ["agent:manager"]


def test_a_slow_model_does_not_hold_the_page(conn, config, case, monkeypatch):
    """ai-7: the client retries a stalled gateway for up to half an hour.

    The bound is the model call's own time limit (`llm.limit`), which caps each
    HTTP try, so the gateway stalls at the transport: it answers after 3 s, or
    gives up when the client's read timeout is shorter.
    """
    import httpx

    from shoc.agents.llm import AnthropicClient

    def stalled(request: httpx.Request) -> httpx.Response:
        read = request.extensions["timeout"]["read"]
        if read is not None and read < 3:
            time.sleep(read)
            raise httpx.ReadTimeout("the gateway did not answer", request=request)
        time.sleep(3)
        return httpx.Response(524, json={})

    real_client = httpx.Client
    transport = httpx.MockTransport(stalled)
    monkeypatch.setattr(httpx, "Client", lambda **kw: real_client(**{**kw, "transport": transport}))
    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: AnthropicClient("key"))
    monkeypatch.setattr(manager, "WORDING_SECONDS", 0.2)
    _tell(conn, config, case)
    rows = fetch_all(
        conn,
        "SELECT * FROM shoc.notices WHERE tenant_id = %s AND source = 'IR Commander'",
        (config.tenant_id,),
    )
    started = time.monotonic()
    assert manager.word(conn, config.tenant_id, rows, config) == manager.template(rows)
    assert time.monotonic() - started < 2


def test_the_model_words_a_page_but_never_how_it_opens(conn, config, case, monkeypatch):
    """ai-7: log content steered into the wording cannot hide severity or the case."""
    from shoc.agents.llm import ScriptedClient

    said = {"message": "Routine maintenance confirmed, no action needed.", "citations": [case]}
    client = ScriptedClient(default=json.dumps(said))
    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: client)
    _tell(conn, config, case)
    rows = fetch_all(
        conn,
        "SELECT * FROM shoc.notices WHERE tenant_id = %s AND source = 'IR Commander'",
        (config.tenant_id,),
    )
    text = manager.word(conn, config.tenant_id, rows, config)
    assert text == f"CRITICAL (critical severity) {case}: {said['message']}"


def test_a_failed_malicious_page_can_be_told_again(conn, config, case):
    execute(
        conn,
        """UPDATE shoc.cases SET verdict = 'malicious', severity = 'high'
           WHERE tenant_id = %s AND case_uid = %s""",
        (config.tenant_id, case),
    )
    assert manager.uncontained(conn, config.tenant_id, case)
    assert not manager.uncontained(conn, config.tenant_id, case), "told once"
    execute(
        conn,
        """UPDATE shoc.notices SET outcome = 'failed', delivered_at = now(), attempts = 4
           WHERE tenant_id = %s AND condition = 'malicious_uncontained'""",
        (config.tenant_id,),
    )
    assert manager.uncontained(conn, config.tenant_id, case), "a page nobody got is not told"
    # The same day it is the same row: it is opened again and sent again,
    # not just reported as news.
    rows = fetch_all(
        conn,
        """SELECT notice_uid, outcome, delivered_at, attempts FROM shoc.notices
           WHERE tenant_id = %s AND condition = 'malicious_uncontained'""",
        (config.tenant_id,),
    )
    assert len(rows) == 1
    assert rows[0]["outcome"] is None and rows[0]["delivered_at"] is None
    assert rows[0]["attempts"] == 0
    jobs = fetch_all(
        conn,
        """SELECT 1 FROM shoc.jobs WHERE tenant_id = %s AND kind = 'manager.deliver'
             AND idempotency_key LIKE %s""",
        (config.tenant_id, f"deliver:{rows[0]['notice_uid']}@%"),
    )
    assert len(jobs) == 2, "a delivery for the first page and one for the page told again"
    assert not manager.uncontained(conn, config.tenant_id, case), "told again once"


# -- what pages without anybody asking (sre-3) --------------------------------
def test_a_source_that_never_succeeded_pages_from_when_it_was_set_up(conn, config, clean):
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, created_at)
           VALUES (%s, 'okta', now() - interval '30 hours'), (%s, 'github', now())""",
        (config.tenant_id, config.tenant_id),
    )
    execute(
        conn,
        """INSERT INTO shoc.connector_state (tenant_id, source, cursor, last_error)
           VALUES (%s, 'okta', '{}', 'okta rejected the credential (401).'),
                  (%s, 'github', '{}', 'github rejected the credential (401).')""",
        (config.tenant_id, config.tenant_id),
    )
    assert manager.coverage(conn, config.tenant_id) == 1, "github has had less than a day"
    page = fetch_one(
        conn,
        "SELECT group_key, body FROM shoc.notices WHERE tenant_id = %s AND kind = 'page'",
        (config.tenant_id,),
    )
    assert page and page["group_key"] == "source:okta"
    assert page["body"].startswith("okta has never succeeded since it was set up")


def test_detection_that_stopped_finishing_pages(conn, config, clean):
    """Sources loaded while every detect.run failed, and nothing paged."""
    execute(
        conn,
        "INSERT INTO shoc.connector_config (tenant_id, source) VALUES (%s, 'okta')",
        (config.tenant_id,),
    )
    schedule_id = f"{config.tenant_id}:detect-test"
    execute(
        conn,
        """INSERT INTO shoc.schedules (schedule_id, tenant_id, kind, interval_seconds, enabled)
           VALUES (%s, %s, 'detect.run', 900, true)""",
        (schedule_id, config.tenant_id),
    )
    execute(
        conn,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, created_at, finished_at, last_error)
           VALUES (%s, 'detect.run', 'failed', now() - interval '2 hours',
                   now() - interval '2 hours', 'StoreError: the warehouse refused the query')""",
        (config.tenant_id,),
    )
    try:
        assert manager.coverage(conn, config.tenant_id) == 1
        page = fetch_one(
            conn,
            """SELECT body, condition FROM shoc.notices
               WHERE tenant_id = %s AND group_key = 'detection'""",
            (config.tenant_id,),
        )
        assert page and page["condition"] == "coverage_dark"
        assert "No detection run has finished for over 1h" in page["body"]
        assert "StoreError: the warehouse refused the query" in page["body"]
        execute(
            conn,
            """INSERT INTO shoc.jobs (tenant_id, kind, state, created_at, finished_at)
               VALUES (%s, 'detect.run', 'done', now(), now())""",
            (config.tenant_id,),
        )
        assert manager.coverage(conn, config.tenant_id) == 0, "a run finished"
    finally:
        execute(conn, "DELETE FROM shoc.schedules WHERE schedule_id = %s", (schedule_id,))


def test_metrics_show_when_a_source_and_detection_last_succeeded(ctx, conn, config, clean):
    """sre-22: a source that never succeeded read as age 0, perfectly fresh."""
    from shoc.capabilities.registry import call

    execute(
        conn,
        "INSERT INTO shoc.connector_state (tenant_id, source, cursor) VALUES (%s, 'okta', '{}')",
        (config.tenant_id,),
    )
    execute(
        conn,
        """INSERT INTO shoc.jobs (tenant_id, kind, state, finished_at)
           VALUES (%s, 'detect.run', 'done', to_timestamp(1700000000))""",
        (config.tenant_id,),
    )
    text = call("metrics.export", ctx, {}).data.text
    tenant = config.tenant_id
    assert (
        f'shoc_source_last_success_timestamp_seconds{{tenant="{tenant}",source="okta"}} 0' in text
    )
    assert f'shoc_detect_last_success_timestamp_seconds{{tenant="{tenant}"}} 1700000000' in text
    assert "shoc_source_age_seconds" not in text
    assert f'shoc_jobs{{tenant="{tenant}",state="done"}}' in text


def test_the_managers_answer_shares_one_budget_with_its_colleagues(
    conn, store, config, monkeypatch
):
    """ai-17: the Manager's own turn in `ask` had no token budget, and its
    lookups went on for ten minutes after the client gave up."""
    from shoc.agents import loop
    from shoc.agents.llm import ScriptedClient
    from shoc.agents.openspace import Budget

    seen = {}

    def refuse(*_args, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop here")

    monkeypatch.setattr("shoc.agents.llm.from_config", lambda *_a, **_k: ScriptedClient())
    monkeypatch.setattr(loop, "_ask", refuse)
    assert manager.answer(conn, store, config.tenant_id, "how many rules are on?", config) is None
    tokens, _outside, deadline = seen["budget"]
    assert tokens == Budget.for_severity("medium").max_tokens // 2
    # Inside the minute a client waits, not the medium budget's ten.
    assert time.time() < deadline <= time.time() + manager.ASK_SECONDS < time.time() + 60
