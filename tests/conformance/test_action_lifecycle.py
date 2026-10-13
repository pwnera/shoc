"""An action and a run around the case they answer (RSP-1, RSP-2, RSP-4, RSP-7, OPS-1).

Every test here is containment that used to be skipped or doubled: a second
policy on one user never detached, a page that never went out again, a preview
that stood in for the real run, an action run twice or after its case closed, a
retry that kept the wrong state to restore, and a second key or account on a
case no playbook answered.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from shoc.actions.base import ActionResult, Credentials
from shoc.agents import manager
from shoc.capabilities.registry import call
from shoc.cases import actions as action_store
from shoc.cases import engine, playbooks
from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.errors import StoreError
from tests.support import audit_seq, audit_trail, malicious_case

pytestmark = pytest.mark.postgres

KEY = "AKIAIOSFODNN7EXAMPLE"  # the leaked_aws_key scenario's key
POLICY = "arn:aws:iam::aws:policy/"


@pytest.fixture
def case(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "leaked_aws_key", store)


@pytest.fixture
def okta_case(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "okta_mfa_fatigue", store)


def _approved(ctx, case_uid: str, action: str, **params: str) -> str:
    record = call(
        "action.propose",
        ctx,
        {"action": action, "params": params, "case_uid": case_uid, "rationale": "test"},
    ).data
    if record.state == "proposed":
        call("action.approve", ctx, {"action_uid": record.action_uid})
    return record.action_uid


def _live(conn, uid: str) -> None:
    """The action acts for real, with the one AWS credential."""
    execute(
        conn,
        "UPDATE shoc.actions SET dry_run = false, acts_in = ARRAY['aws'] WHERE action_uid = %s",
        (uid,),
    )


def _state(conn, uid: str) -> str:
    row = fetch_one(conn, "SELECT state FROM shoc.actions WHERE action_uid = %s", (uid,))
    return str(row["state"]) if row else ""


def _started(conn, tenant_id: str, after: int) -> int:
    return sum(1 for what, _who in audit_trail(conn, tenant_id, after) if what == "action.started")


# -- RSP-4: an action is every one of its parameters ---------------------------
def test_two_policies_on_one_user_are_two_actions_and_both_run(ctx, conn, case):
    admin = _approved(
        ctx, case, "aws.detach_user_policy", user_name="deploy-ci", policy_arn=POLICY + "Admin"
    )
    iam = _approved(
        ctx, case, "aws.detach_user_policy", user_name="deploy-ci", policy_arn=POLICY + "IAMFull"
    )
    assert admin != iam, "the second policy came back as the first one's action"
    for uid in (admin, iam):
        call("action.run", ctx, {"action_uid": uid, "dry_run": False})
        assert _state(conn, uid) == "done"


def test_a_done_action_proposed_again_is_not_run_again(ctx, conn, case):
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    call("action.run", ctx, {"action_uid": uid, "dry_run": False})
    again = call(
        "action.propose",
        ctx,
        {"action": "aws.disable_access_key", "params": {"access_key_id": KEY}, "case_uid": case},
    )
    assert again.data.action_uid == uid and again.data.state == "done"


# -- OPS-1: the Manager's page goes out for each outage ---------------------------
def test_a_second_outage_a_day_later_pages_again(conn, config, clean, pager):
    """Without a model the page's words are the same each time; its id was too."""
    execute(
        conn,
        """INSERT INTO shoc.schedules (schedule_id, tenant_id, kind, next_run_at, enabled)
           VALUES (%s, %s, 'detect.run', now() - interval '2 hours', true)""",
        (f"{config.tenant_id}:stalled", config.tenant_id),
    )
    try:
        assert manager.scheduler(conn, config.tenant_id, config)
        # A day on: the first page is history, and its notice is yesterday's.
        execute(
            conn,
            """UPDATE shoc.notices SET delivered_at = delivered_at - interval '25 hours',
                      notice_uid = notice_uid || '-yesterday'
               WHERE tenant_id = %s""",
            (config.tenant_id,),
        )
        assert manager.scheduler(conn, config.tenant_id, config)
    finally:
        execute(conn, "DELETE FROM shoc.schedules WHERE tenant_id = %s", (config.tenant_id,))
    assert len(pager.posts) == 2, "the second outage woke nobody"
    assert all(p["dedup_key"] == pager.posts[0]["dedup_key"] for p in pager.posts)


# -- RSP-7: a plan never stands in for the action or the run that acts ------------
def test_a_dry_run_of_a_live_action_leaves_it_for_the_run_that_acts(
    ctx, conn, config, case, monkeypatch
):
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    _live(conn, uid)
    before = audit_seq(conn, config.tenant_id)
    plan = call("action.run", ctx, {"action_uid": uid})  # dry run is the default
    assert plan.data.dry_run and plan.data.state == "approved"
    assert _state(conn, uid) == "approved" and not _started(conn, config.tenant_id, before)

    acted: list[dict[str, Any]] = []
    action = action_store.get_action("aws.disable_access_key")
    monkeypatch.setattr(action_store.credentials, "load", lambda *a: Credentials("aws"))
    monkeypatch.setattr(type(action), "snapshot", lambda self, creds, params, http=None: {})
    monkeypatch.setattr(
        type(action),
        "execute",
        lambda self, creds, params, http=None, before=None: (
            acted.append(params) or ActionResult(detail="off")
        ),
    )
    live = call("action.run", ctx, {"action_uid": uid, "dry_run": False})
    assert live.data.state == "done" and len(acted) == 1, "the plan used up the real run"


def test_a_dry_playbook_run_never_stands_in_for_the_live_one(ctx, config, case, monkeypatch):
    monkeypatch.setattr(config, "dry_run", False)  # SHOC_DRY_RUN=0: response is on

    def run(dry_run: bool) -> Any:
        return call(
            "playbook.run",
            ctx,
            {"playbook_id": "contain_leaked_cloud_key", "case_uid": case, "dry_run": dry_run},
        ).data

    dry = run(True)
    live = run(False)
    assert live.run_uid != dry.run_uid and dry.dry_run and not live.dry_run
    assert run(True).run_uid == dry.run_uid, "the same start twice is still one run"


def test_a_preview_leaves_nothing_to_approve_chase_run_or_count(
    ctx, conn, config, case, monkeypatch
):
    """Its steps are settled as their plan: no L2 waits, no L1 is queued, and no
    containment is pushed to L2 by the preview's own (RSP-3, RSP-7)."""
    monkeypatch.setattr(config, "dry_run", False)  # SHOC_DRY_RUN=0: response is on
    preview = call(
        "playbook.run",
        ctx,
        {"playbook_id": "contain_leaked_cloud_key", "case_uid": case, "dry_run": True},
    ).data
    rows = fetch_all(
        conn,
        "SELECT state, dry_run FROM shoc.actions WHERE tenant_id = %s AND run_uid = %s",
        (config.tenant_id, preview.run_uid),
    )
    assert rows and all(r["dry_run"] and r["state"] in ("done", "blocked") for r in rows), rows
    assert action_store._auto_actions(conn, config.tenant_id, case, live_only=True) == 0


def test_an_action_a_benign_verdict_rejected_comes_back_when_the_case_turns_out_bad(
    ctx, conn, config, case
):
    """The case answered it, not a person: once the case wants a response again,
    the crew may ask for it again (RSP-1, D152)."""
    kind, params = "aws.revoke_role_sessions", {"role_name": "deploy"}
    asked = {"action": kind, "params": params, "case_uid": case}
    first = call("action.propose", ctx, asked).data
    assert first.state == "proposed"
    finding = fetch_one(
        conn, "SELECT event_uids FROM shoc.findings WHERE case_uid = %s LIMIT 1", (case,)
    )
    cited = list(finding["event_uids"]) if finding else []
    engine.set_verdict(conn, config.tenant_id, case, "false_positive", 0.9, "a test key", cited)
    assert _state(conn, first.action_uid) == "rejected"
    engine.set_verdict(conn, config.tenant_id, case, "malicious", 0.9, "it was not", cited)
    crew = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(action_type=kind, params=params, case_uid=case),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    assert crew["action_uid"] == first.action_uid and crew["state"] == "proposed"


# -- RSP-2: one worker acts --------------------------------------------------------
def test_two_workers_that_both_read_it_approved_act_once(ctx, conn, config, case, monkeypatch):
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    stale = action_store.require(conn, config.tenant_id, uid)
    call("action.run", ctx, {"action_uid": uid, "dry_run": False})
    real, reads = action_store.require, []

    def read(conn: Any, tenant_id: str, action_uid: str) -> dict[str, Any]:
        reads.append(action_uid)
        return stale if len(reads) == 1 else real(conn, tenant_id, action_uid)

    monkeypatch.setattr(action_store, "require", read)
    before = audit_seq(conn, config.tenant_id)
    row, result = action_store.execute(conn, config.tenant_id, uid, "", by="service:worker")
    assert row["state"] == "done" and result.ok and result.detail == "already done"
    assert not _started(conn, config.tenant_id, before), "the second worker acted too"


# -- RSP-4: a retry restores what was there before the first try ------------------
def test_a_retry_after_a_lost_answer_keeps_the_state_from_before_the_first_try(
    ctx, conn, config, case, monkeypatch
):
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    _live(conn, uid)
    reads: list[str] = []

    class Demote:
        """Reads `owner` before its first call and `member` after it, as GitHub would."""

        type, provider, reversible = "aws.disable_access_key", "aws", True
        required_params = ("access_key_id", "user_name")

        def plan(self, params: dict[str, Any]) -> str:
            return "demote"

        def snapshot(self, creds: Credentials, params: dict[str, Any]) -> dict[str, Any]:
            reads.append("read")
            return {"role": "owner" if len(reads) == 1 else "member"}

        def execute(
            self, creds: Credentials, params: dict[str, Any], before: dict[str, Any]
        ) -> ActionResult:
            if "acted" not in reads:
                reads.append("acted")
                raise TimeoutError("the change was made and its answer was lost")
            return ActionResult(detail="member now", undo=dict(before))

    monkeypatch.setattr(action_store, "get_action", lambda _type: Demote())
    monkeypatch.setattr(action_store.credentials, "load", lambda *a: Credentials("aws"))
    first, _ = action_store.execute(conn, config.tenant_id, uid, "", by="service:worker")
    assert first["state"] == "failed"
    assert first["result"]["before"] == {"aws": {"role": "owner"}}
    action_store.retry(conn, config.tenant_id, uid, "service:worker")
    done, _ = action_store.execute(conn, config.tenant_id, uid, "", by="service:worker")
    assert done["state"] == "done" and done["undo"] == {"role": "owner"}
    assert reads.count("read") == 1, "the retry read the changed state again"


def test_a_retry_that_finds_it_gone_with_nothing_kept_is_done_and_not_reversible(
    ctx, conn, config, case, monkeypatch
):
    """A first try made before snapshots were kept, whose answer was lost."""
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    _live(conn, uid)
    execute(
        conn,
        """UPDATE shoc.actions SET result = '{"ok": false, "detail": "lost"}'::jsonb
           WHERE action_uid = %s""",
        (uid,),
    )

    class Gone:
        type, provider, reversible = "aws.disable_access_key", "aws", True
        required_params = ("access_key_id",)

        def plan(self, params: dict[str, Any]) -> str:
            return "remove it"

        def snapshot(self, creds: Credentials, params: dict[str, Any]) -> dict[str, Any]:
            request = httpx.Request("GET", "https://vendor.example/thing")
            response = httpx.Response(404, request=request)
            raise StoreError("not found") from httpx.HTTPStatusError(
                "404", request=request, response=response
            )

        def execute(self, *args: Any, **kwargs: Any) -> ActionResult:
            raise AssertionError("nothing is left to act on")

    monkeypatch.setattr(action_store, "get_action", lambda _type: Gone())
    monkeypatch.setattr(action_store.credentials, "load", lambda *a: Credentials("aws"))
    done, result = action_store.execute(conn, config.tenant_id, uid, "", by="service:worker")
    assert done["state"] == "done" and result.ok and not done["reversible"]


# -- RSP-1: a closed or benign case gets nothing more ----------------------------
def _wait_then_page(monkeypatch) -> str:
    book = playbooks.Playbook.from_dict(
        {
            "id": "wait_then_page",
            "title": "Wait, then page",
            "rules": ["x"],
            "steps": [
                {"name": "give the key a quarter hour", "wait_minutes": 15},
                {"name": "page", "action": "notify.page", "params": {"summary": "still here"}},
            ],
        }
    )
    monkeypatch.setattr(playbooks, "get", lambda playbook_id, *rest: book)
    return book.id


def test_closing_a_case_rejects_what_was_approved_and_stops_its_runs(
    ctx, conn, config, case, monkeypatch
):
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    run = playbooks.start(conn, config.tenant_id, _wait_then_page(monkeypatch), case, config)
    playbooks.advance(conn, config.tenant_id, run["run_uid"], "", config)
    closed = call(
        "case.close",
        ctx,
        {"case_uid": case, "disposition": "malicious", "reason": "the key was rotated by hand"},
    )
    assert closed.data.rejected_actions >= 1 and _state(conn, uid) == "rejected"
    row = fetch_one(
        conn, "SELECT state FROM shoc.playbook_runs WHERE run_uid = %s", (run["run_uid"],)
    )
    assert row and row["state"] == "cancelled"


def test_an_action_approved_before_its_case_closed_is_not_run(ctx, conn, config, case):
    uid = _approved(ctx, case, "aws.disable_access_key", access_key_id=KEY)
    execute(conn, "UPDATE shoc.cases SET state = 'closed' WHERE case_uid = %s", (case,))
    before = audit_seq(conn, config.tenant_id)
    ran = call("action.run", ctx, {"action_uid": uid, "dry_run": False})
    assert ran.data.state == "rejected" and not ran.data.ok
    assert not _started(conn, config.tenant_id, before)


def test_a_run_parked_on_a_timer_does_not_wake_on_a_closed_case(
    ctx, conn, config, case, monkeypatch
):
    run = playbooks.start(conn, config.tenant_id, _wait_then_page(monkeypatch), case, config)
    assert playbooks.advance(conn, config.tenant_id, run["run_uid"], "", config).state == (
        "waiting_timer"
    )
    execute(conn, "UPDATE shoc.cases SET state = 'closed' WHERE case_uid = %s", (case,))
    report = playbooks.advance(conn, config.tenant_id, run["run_uid"], "", config)
    assert report.state == "cancelled"


# -- RSP-2, RFC 0026: every account on the case, and the ones that join later ------
def test_every_user_on_the_case_is_acted_on_and_a_new_one_gets_a_run(
    ctx, conn, config, okta_case, monkeypatch
):
    book = playbooks.Playbook.from_dict(
        {
            "id": "revoke_every_user",
            "title": "Revoke every user",
            "rules": ["okta_mfa_push_fatigue"],
            "steps": [
                {
                    "name": "revoke",
                    "action": "okta.revoke_sessions",
                    "params": {"user": "{{ rule.okta_mfa_push_fatigue.user }}"},
                }
            ],
        }
    )
    monkeypatch.setattr(playbooks, "get", lambda playbook_id, *rest: book)

    def start() -> str:
        return call(
            "playbook.run", ctx, {"playbook_id": book.id, "case_uid": okta_case, "dry_run": True}
        ).data.run_uid

    def revoked() -> set[str]:
        return {
            str(r["target"])
            for r in fetch_all(
                conn,
                """SELECT target FROM shoc.actions
                   WHERE tenant_id = %s AND case_uid = %s AND type = 'okta.revoke_sessions'""",
                (config.tenant_id, okta_case),
            )
        }

    first = start()
    assert start() == first, "nothing changed: the same run"
    execute(
        conn,
        """UPDATE shoc.findings SET entities = array_append(entities, %s)
           WHERE tenant_id = %s AND case_uid = %s AND rule_id = 'okta_mfa_push_fatigue'""",
        ("user:mallory@example.com", config.tenant_id, okta_case),
    )
    second = start()
    assert second != first, "a user who joined the case is answered by a run of its own"
    assert {"jane@example.com", "mallory@example.com"} <= revoked()
    assert start() == second
