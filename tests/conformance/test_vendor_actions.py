"""Vendor actions across several tenants of one vendor, and the logins shoc's own
tokens act as (RSP-4, RFC 0021, RFC 0025)."""

from __future__ import annotations

from typing import Any

import pytest

from shoc.actions import get as get_action
from shoc.actions.base import ActionResult, Credentials
from shoc.capabilities.registry import Caller, Context, call
from shoc.cases import actions as action_store
from shoc.cases import credentials, playbooks
from shoc.db.pool import execute, fetch_one
from shoc.errors import NotFound, StoreError
from tests.support import malicious_case

pytestmark = pytest.mark.postgres

ACCOUNT = "123456789012"  # the leaked_aws_key scenario's account
OTHER = "999999999999"
KEY = "AKIAIOSFODNN7EXAMPLE"  # the leaked_aws_key scenario's key


@pytest.fixture
def agent_ctx(config, conn, store):
    c = Context(tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config)
    c._db, c._store = conn, store
    return c


@pytest.fixture
def leaked(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "leaked_aws_key", ctx.store)


def configure(ctx, name: str, **settings: Any) -> None:
    call(
        "credential.configure", ctx, {"provider": name, "settings": settings, "secret": {"k": "v"}}
    )


def disable(agent_ctx, case_uid: str):
    return call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": KEY, "user_name": "deploy-ci"},
            "case_uid": case_uid,
        },
    ).data


def test_a_key_is_disabled_in_the_account_its_arn_names(ctx, agent_ctx, leaked):
    """An org trail files a call under the account that received it; the key
    lives in the account of its user's ARN (ir-14)."""
    execute(
        ctx.db,
        """UPDATE shoc.findings SET entities = array_replace(entities, %s, %s)
           WHERE tenant_id = %s AND case_uid = %s""",
        (f"account:{ACCOUNT}", f"account:{OTHER}", ctx.tenant_id, leaked),
    )
    configure(ctx, "aws", accounts=[OTHER])
    configure(ctx, "aws:prod", accounts=[ACCOUNT])
    assert disable(agent_ctx, leaked).acts_in == ["aws:prod"]


def _run_in_both(ctx, agent_ctx, leaked, config, monkeypatch, refusal: Exception) -> list[str]:
    """Disable the key with `aws` and `aws:prod`, `aws` refusing; the calls made."""
    configure(ctx, "aws", accounts=[OTHER])
    configure(ctx, "aws:prod", accounts=[ACCOUNT])
    record = disable(agent_ctx, leaked)
    action = get_action("aws.disable_access_key")
    used: list[str] = []

    def act(creds: Credentials) -> ActionResult:
        used.append(creds.provider)
        if creds.provider == "aws":
            raise refusal
        return ActionResult(ok=True, detail="disabled", undo={"access_key_id": KEY})

    def undo(creds: Credentials) -> ActionResult:
        used.append(f"undo {creds.provider}")
        return ActionResult(ok=True, detail="enabled")

    monkeypatch.setattr(type(action), "snapshot", lambda self, c, p, http=None: {})
    monkeypatch.setattr(type(action), "execute", lambda self, c, p, http=None, before=None: act(c))
    monkeypatch.setattr(type(action), "undo", lambda self, c, d, http=None: undo(c))
    if record.state != "approved":
        action_store.approve(ctx.db, ctx.tenant_id, record.action_uid, "human:test", "human")
    execute(
        ctx.db,
        "UPDATE shoc.actions SET dry_run = false, acts_in = %s WHERE action_uid = %s",
        (["aws", "aws:prod"], record.action_uid),
    )
    row, _ = action_store.execute(
        ctx.db, ctx.tenant_id, record.action_uid, config.master_key, by="human:test"
    )
    used.append(row["state"])
    row, _ = action_store.undo(
        ctx.db, ctx.tenant_id, record.action_uid, config.master_key, by="human:test"
    )
    used.append(row["state"])
    return used


def test_an_action_that_failed_in_one_account_is_undone_where_it_acted(
    ctx, agent_ctx, leaked, config, monkeypatch
):
    """Recorded failed, it still changed aws:prod, and shoc takes that back (ir-14)."""
    refusal = StoreError("AWS iam call failed: throttled")
    used = _run_in_both(ctx, agent_ctx, leaked, config, monkeypatch, refusal)
    assert used == ["aws", "aws:prod", "failed", "undo aws:prod", "rolled_back"]


def test_a_key_another_account_does_not_hold_is_not_there(
    ctx, agent_ctx, leaked, config, monkeypatch
):
    """IAM in the receiving account has no such key once its own account
    disabled it: done, and undone only where it acted (ir-14)."""
    used = _run_in_both(ctx, agent_ctx, leaked, config, monkeypatch, NotFound("NoSuchEntity"))
    assert used == ["aws", "aws:prod", "done", "undo aws:prod", "rolled_back"]


def test_the_login_an_okta_token_acts_as_waits_for_a_person(conn, store, config, clean):
    """Okta's probe names the token's own login; signing it out would cut shoc
    off from Okta (H6, RFC 0021)."""
    case = malicious_case(conn, config.tenant_id, "okta_mfa_fatigue", store)
    user = playbooks.entities_of_case(conn, config.tenant_id, case)["user"]
    credentials.store(
        conn,
        config.tenant_id,
        "okta",
        {"org_url": "https://example.okta.com"},
        {"api_token": "test"},
        config.master_key,
    )
    credentials.record_check(conn, config.tenant_id, "okta", True, f"signed in as {user}")
    proposal = action_store.Proposal(
        action_type="okta.revoke_sessions", params={"user": user}, case_uid=case
    )
    row = action_store.propose(
        conn,
        config.tenant_id,
        proposal,
        "IR Commander",
        principal_kind="agent",
        config=config,
    )
    assert row["autonomy"] == "L2" and row["state"] == "proposed"
    assert "shoc's own" in row["rationale"]


def test_an_action_s_audit_row_names_what_it_acted_on(ctx, agent_ctx, leaked):
    """Readable without SQL over the action rows (H8, SEC-1)."""
    configure(ctx, "aws", accounts=[ACCOUNT])
    record = disable(agent_ctx, leaked)
    row = fetch_one(
        ctx.db,
        """SELECT subject FROM shoc.audit_log
           WHERE tenant_id = %s AND capability = 'action.proposed' ORDER BY seq DESC LIMIT 1""",
        (ctx.tenant_id,),
    )
    assert row and KEY in row["subject"] and record.action_uid in row["subject"]
