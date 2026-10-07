"""The Slack app: signatures, who may approve, and what a case looks like (API-3)."""

from __future__ import annotations

import json
import time
import urllib.parse

import httpx
import pytest
from starlette.testclient import TestClient

from shoc.api import slack
from shoc.api.rest import build_app
from shoc.capabilities.registry import call
from shoc.db.pool import fetch_all, fetch_one
from shoc.errors import Denied

pytestmark = pytest.mark.postgres

SIGNING_SECRET = "slack-signing-secret"
APPROVER = "U-SAM"
BYSTANDER = "U-RANDOM"


@pytest.fixture
def slack_app(ctx, config, clean):
    call(
        "slack.configure",
        ctx,
        {
            "bot_token": "xoxb-test",
            "signing_secret": SIGNING_SECRET,
            "channel": "C-SOC",
            "approvers": {APPROVER: "sam"},
        },
    )
    return slack.load_app(ctx.db, config.tenant_id, config.master_key)


@pytest.fixture
def api(config, conn, store, slack_app):
    with TestClient(build_app(config)) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        yield client


def sign(body: bytes, timestamp: str | None = None) -> dict[str, str]:
    timestamp = timestamp or str(int(time.time()))
    base = b"v0:" + timestamp.encode() + b":" + body
    import hashlib
    import hmac

    signature = "v0=" + hmac.new(SIGNING_SECRET.encode(), base, hashlib.sha256).hexdigest()
    return {
        slack.TIMESTAMP_HEADER: timestamp,
        slack.SIGNATURE_HEADER: signature,
        "content-type": "application/x-www-form-urlencoded",
    }


def command(text: str, user: str = APPROVER) -> bytes:
    return urllib.parse.urlencode(
        {"text": text, "user_id": user, "channel_id": "C-SOC", "command": "/shoc"}
    ).encode()


# -- signatures -------------------------------------------------------------
def test_slack_show_names_the_channel_and_approvers_and_never_a_secret(ctx, slack_app):
    view = call("slack.show", ctx, {}).data
    assert view.channel == "C-SOC" and view.approvers == {APPROVER: "sam"}
    assert view.has_bot_token and view.verifies_requests
    assert SIGNING_SECRET not in json.dumps(view.__dict__)


def test_a_signed_command_is_accepted(api):
    body = command("help")
    resp = api.post("/slack/commands", content=body, headers=sign(body))
    assert resp.status_code == 200 and "/shoc cases" in resp.json()["text"]


def test_an_unsigned_command_is_refused(api):
    body = command("help")
    assert api.post("/slack/commands", content=body).status_code == 403


def test_a_replayed_command_is_refused(api):
    body = command("help")
    old = str(int(time.time()) - 3600)
    resp = api.post("/slack/commands", content=body, headers=sign(body, old))
    assert resp.status_code == 403 and "old" in resp.json()["error"]["message"]


def test_a_tampered_body_is_refused(api):
    body = command("help")
    headers = sign(body)
    assert api.post("/slack/commands", content=command("cases"), headers=headers).status_code == 403


def test_verify_rejects_a_wrong_secret():
    body = b"v0-body"
    timestamp = str(int(time.time()))
    with pytest.raises(Denied, match="does not match"):
        slack.verify("other-secret", timestamp, body, "v0=deadbeef")


# -- principals -------------------------------------------------------------
def test_a_listed_approver_is_an_operator(slack_app):
    caller = slack.caller_for(slack_app, APPROVER)
    assert caller.kind == "human" and caller.id == "sam"
    assert caller.allows("actions:approve") and not caller.allows("config:write")


def test_everyone_else_can_only_read(slack_app):
    caller = slack.caller_for(slack_app, BYSTANDER)
    assert caller.kind == "external_agent"
    assert not caller.allows("actions:approve")


# -- commands ---------------------------------------------------------------
def test_asking_from_slack_answers_with_citations(api, ctx, config, store):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    body = command("what happened with AKIAIOSFODNN7EXAMPLE?")
    resp = api.post("/slack/commands", content=body, headers=sign(body))
    text = resp.json()["text"]
    assert "finding(s)" in text and "Evidence:" in text


def test_the_cases_command_lists_open_cases(api, ctx, config, store):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    body = command("cases")
    text = api.post("/slack/commands", content=body, headers=sign(body)).json()["text"]
    assert "CASE-" in text


# -- approvals --------------------------------------------------------------
@pytest.fixture
def pending_action(ctx, config, store, api):
    from evals.run import SCENARIOS, replay
    from shoc.cases import engine

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    case_row = fetch_one(
        ctx.db, "SELECT case_uid FROM shoc.cases WHERE tenant_id=%s LIMIT 1", (config.tenant_id,)
    )
    assert case_row
    case = case_row["case_uid"]
    finding = fetch_one(
        ctx.db,
        "SELECT event_uids FROM shoc.findings WHERE tenant_id=%s AND case_uid=%s LIMIT 1",
        (config.tenant_id, case),
    )
    assert finding
    engine.set_verdict(
        ctx.db, config.tenant_id, case, "malicious", 0.95, "stolen key", list(finding["event_uids"])
    )
    proposed = call(
        "action.propose",
        ctx,
        {"action": "aws.revoke_role_sessions", "params": {"role_name": "deploy"}, "case_uid": case},
    )
    return case, proposed.data.action_uid


def interaction(action_id: str, action_uid: str, user: str) -> bytes:
    payload = {
        "type": "block_actions",
        "user": {"id": user},
        "actions": [{"action_id": action_id, "value": action_uid}],
    }
    return urllib.parse.urlencode({"payload": json.dumps(payload)}).encode()


def test_an_approver_can_approve_from_slack(api, ctx, pending_action):
    _case, action_uid = pending_action
    body = interaction("shoc_approve", action_uid, APPROVER)
    resp = api.post("/slack/interactions", content=body, headers=sign(body))
    assert "approved" in resp.json()["text"]
    row = fetch_one(
        ctx.db, "SELECT state, approved_by FROM shoc.actions WHERE action_uid=%s", (action_uid,)
    )
    assert row and row["state"] == "approved" and row["approved_by"] == "human:sam"


def test_a_bystander_cannot_approve_from_slack(api, ctx, pending_action):
    _case, action_uid = pending_action
    body = interaction("shoc_approve", action_uid, BYSTANDER)
    resp = api.post("/slack/interactions", content=body, headers=sign(body))
    assert "not on the approver list" in resp.json()["text"]
    row = fetch_one(ctx.db, "SELECT state FROM shoc.actions WHERE action_uid=%s", (action_uid,))
    assert row and row["state"] == "proposed", "being in the channel is not authority"


def test_an_approver_can_reject(api, ctx, pending_action):
    _case, action_uid = pending_action
    body = interaction("shoc_reject", action_uid, APPROVER)
    api.post("/slack/interactions", content=body, headers=sign(body))
    row = fetch_one(ctx.db, "SELECT state FROM shoc.actions WHERE action_uid=%s", (action_uid,))
    assert row and row["state"] == "rejected"


# -- outbound ---------------------------------------------------------------
def test_a_case_is_posted_with_buttons_for_what_needs_a_human(ctx, pending_action, config):
    case_uid, _action_uid = pending_action
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True, "ts": "1.0"})

    slack.notify_case(ctx, case_uid, http=httpx.Client(transport=httpx.MockTransport(handler)))
    body = json.loads(seen[0].content)
    assert body["channel"] == "C-SOC"
    blocks = json.dumps(body["blocks"])
    assert (
        "aws.revoke_role_sessions" in blocks
        and "shoc_approve" in blocks
        and "shoc_reject" in blocks
    )
    assert "Evidence:" in blocks


def test_posting_without_a_token_is_a_configuration_error(ctx, config, clean):
    from shoc.errors import ConfigError

    with pytest.raises(ConfigError, match="not configured"):
        slack.notify_case(ctx, "CASE-whatever")


# -- the Manager's mirror (API-3) ----------------------------------------------
@pytest.fixture
def slack_api(monkeypatch):
    """Every post shoc makes to Slack lands in `.posts` and gets `.reply`; never real Slack."""
    from functools import partial
    from types import SimpleNamespace

    fake = SimpleNamespace(posts=[], reply={"ok": True, "ts": "1.0"})

    def handler(request: httpx.Request) -> httpx.Response:
        fake.posts.append(json.loads(request.content))
        return httpx.Response(200, json=fake.reply)

    monkeypatch.setattr(
        httpx, "Client", partial(httpx.Client, transport=httpx.MockTransport(handler))
    )
    return fake


def _page_the_case(conn, config, case_uid):
    from shoc.agents import manager
    from shoc.cases import engine

    engine.set_severity(conn, config.tenant_id, case_uid, "critical", "for this test")
    manager.tell(
        conn,
        config.tenant_id,
        "IR Commander",
        "page",
        "the key is still in use",
        case_uid=case_uid,
        condition="critical_severity",
    )
    return manager.deliver(conn, config.tenant_id, config)


def test_a_page_is_mirrored_to_slack_through_the_audited_notify(
    conn, config, pending_action, slack_api
):
    from tests.support import audit_seq

    case_uid, _action_uid = pending_action
    before = audit_seq(conn, config.tenant_id)
    done = _page_the_case(conn, config, case_uid)
    assert len(done.paged) == 1 and not done.slack_errors
    assert "the key is still in use" in slack_api.posts[0]["text"]
    assert "shoc_approve" in json.dumps(slack_api.posts[1]["blocks"]), (
        "the decision rides on the page"
    )
    audited = fetch_all(
        conn,
        """SELECT principal_kind || ':' || principal_id AS who FROM shoc.audit_log
           WHERE tenant_id = %s AND seq > %s AND capability = 'slack.notify' ORDER BY seq""",
        (config.tenant_id, before),
    )
    assert [r["who"] for r in audited] == ["agent:agent:manager"] * 2


def test_a_mirror_slack_refuses_is_reported_not_swallowed(conn, config, pending_action, slack_api):
    slack_api.reply = {"ok": False, "error": "channel_not_found"}
    case_uid, _action_uid = pending_action
    done = _page_the_case(conn, config, case_uid)
    assert len(done.paged) == 1, "the page itself still went out"
    assert done.slack_errors and "channel_not_found" in done.summary
    row = fetch_one(
        conn,
        """SELECT error FROM shoc.audit_log WHERE tenant_id = %s AND capability = 'slack.notify'
           ORDER BY seq DESC LIMIT 1""",
        (config.tenant_id,),
    )
    assert row and "channel_not_found" in row["error"]


def test_only_the_manager_posts_to_slack_unattended(config, pending_action):
    from shoc.capabilities.registry import Caller, Context

    case_uid, _action_uid = pending_action
    crew = Context(
        tenant_id=config.tenant_id,
        caller=Caller(kind="agent", id="agent:Investigator"),
        config=config,
    )
    with pytest.raises(Denied, match="SOC Manager"):
        call("slack.notify", crew, {"case_uid": case_uid})


def test_the_executive_report_goes_to_slack_as_the_manager(config, ctx, slack_app, slack_api):
    from shoc import worker

    summary = worker.handle(
        {"tenant_id": config.tenant_id, "kind": "report.exec", "payload": {}}, config
    )
    assert "exec report" in summary and "Slack" not in summary
    assert slack_api.posts and "Executive summary" in slack_api.posts[0]["text"]
    assert call("report.get", ctx, {}).data.kind == "weekly", "D58 removed the shift report"


# -- a question answered after Slack's 3-second window (API-3) -------------------
RESPONSE_URL = "https://hooks.slack.com/commands/T0/1/abc"


def test_a_question_is_answered_through_response_url_after_slack_has_its_reply(
    ctx, config, store, slack_app, monkeypatch
):
    import threading

    from evals.run import SCENARIOS, replay
    from shoc.agents import manager

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id)
    release, posted = threading.Event(), threading.Event()
    seen: list[tuple[str, dict]] = []

    def slow_manager(*_args, **_kwargs):
        release.wait(20)  # the crew taking its time
        return None

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), json.loads(request.content)))
        posted.set()
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(manager, "answer", slow_manager)
    form = {
        "text": "what happened with AKIAIOSFODNN7EXAMPLE?",
        "user_id": APPROVER,
        "response_url": RESPONSE_URL,
    }
    started = time.monotonic()
    ack = slack.handle_command(
        ctx, slack_app, form, http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert time.monotonic() - started < 3, "Slack gives up after 3 seconds"
    assert ack["response_type"] == "ephemeral" and not posted.is_set()
    release.set()
    assert posted.wait(30), "the answer follows through response_url"
    url, body = seen[0]
    assert url == RESPONSE_URL and body["response_type"] == "in_channel"
    assert "finding(s)" in body["text"] and "Evidence:" in body["text"]


def test_a_response_url_off_slack_is_refused(ctx, slack_app):
    form = {"text": "what happened?", "user_id": APPROVER, "response_url": "https://203.0.113.9/x"}
    with pytest.raises(Denied, match="response_url"):
        slack.handle_command(ctx, slack_app, form)
