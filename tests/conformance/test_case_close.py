"""What a person's close does to the case's actions (RSP-1, RSP-3, RSP-4, D152)."""

from __future__ import annotations

import pytest

from shoc.capabilities.registry import call
from shoc.cases import actions as action_store
from shoc.db.pool import execute
from tests.support import malicious_case

pytestmark = pytest.mark.postgres

KEY = "AKIAIOSFODNN7EXAMPLE"  # the leaked_aws_key scenario's key


@pytest.fixture
def case(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "leaked_aws_key", store)


def _done(conn, config, case_uid: str, name: str, kind: str, dry_run: bool = False) -> str:
    uid = f"ACT-{config.tenant_id}-{name}"
    execute(
        conn,
        """INSERT INTO shoc.actions (action_uid, tenant_id, case_uid, type, target, params,
               autonomy, state, reversible, dry_run, rationale, requested_by, idempotency_key)
           VALUES (%s,%s,%s,%s,%s,'{}','L1','done',true,%s,'','test',%s)""",
        (uid, config.tenant_id, case_uid, kind, KEY, dry_run, uid),
    )
    return uid


def test_a_false_positive_close_names_the_containment_still_in_force(ctx, conn, config, case):
    """The CI key stays disabled after the operator says it was a false positive."""
    live = _done(conn, config, case, "live", "aws.disable_access_key")
    _done(conn, config, case, "plan", "aws.disable_access_key", dry_run=True)
    _done(conn, config, case, "page", "notify.page")
    closed = call(
        "case.close",
        ctx,
        {"case_uid": case, "disposition": "false_positive", "reason": "the CI deploy key"},
    )
    assert [a["action_uid"] for a in closed.data.still_in_force] == [live]
    assert f"1 action(s) still in force: aws.disable_access_key {KEY}" in closed.summary


def test_an_attack_close_lists_nothing_still_in_force(ctx, conn, config, case):
    _done(conn, config, case, "live", "aws.disable_access_key")
    closed = call(
        "case.close", ctx, {"case_uid": case, "disposition": "malicious", "reason": "contained"}
    )
    assert not closed.data.still_in_force and "still in force" not in closed.summary


def test_a_person_asks_again_for_what_their_close_rejected(ctx, conn, config, case):
    """Closing answered the case, not the action; a person's reject of it stands."""
    kind, params = "aws.revoke_role_sessions", {"role_name": "deploy"}
    asked = {"action": kind, "params": params, "case_uid": case}
    first = call("action.propose", ctx, asked).data
    assert first.state == "proposed"
    call("case.close", ctx, {"case_uid": case, "disposition": "malicious", "reason": "by hand"})
    assert action_store.require(conn, config.tenant_id, first.action_uid)["state"] == "rejected"

    def crew() -> dict:
        return action_store.propose(
            conn,
            config.tenant_id,
            action_store.Proposal(action_type=kind, params=params, case_uid=case),
            "IR Commander",
            principal_kind="agent",
            config=config,
        )

    assert crew()["state"] == "rejected", "the crew does not bring it back on a closed case"
    call("case.set_state", ctx, {"case_uid": case, "state": "triage", "note": "not over"})
    assert crew()["state"] == "proposed", "the case is open again: the crew may ask again"
    again = call("action.propose", ctx, asked).data
    assert again.action_uid == first.action_uid and again.state == "proposed"

    # A note written to look like the case's own reject is still the person's.
    note = action_store.BY_CASE + "not this one"
    call("action.reject", ctx, {"action_uid": first.action_uid, "note": note})
    final = call("action.propose", ctx, asked).data
    assert final.state == "rejected", "a person's reject of the action itself stands"
