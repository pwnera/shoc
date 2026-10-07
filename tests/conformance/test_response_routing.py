"""An action acts on the platform, and in the tenant, its target was seen in (RSP-4, RFC 0025)."""

from __future__ import annotations

from typing import Any

import pytest

from shoc.actions import get as get_action
from shoc.actions.base import ActionResult, Credentials
from shoc.capabilities.registry import Caller, Context, call
from shoc.cases import actions as action_store
from shoc.cases import credentials, playbooks
from shoc.db.pool import execute
from shoc.errors import ValidationError
from tests.support import malicious_case

pytestmark = pytest.mark.postgres

ACCOUNT = "123456789012"  # the leaked_aws_key scenario's account


@pytest.fixture
def agent_ctx(config, conn, store):
    c = Context(tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config)
    c._db, c._store = conn, store
    return c


@pytest.fixture
def leaked(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "leaked_aws_key", ctx.store)


@pytest.fixture
def entra(ctx, store, config, clean):
    return malicious_case(ctx.db, config.tenant_id, "entra_admin_takeover", ctx.store)


def configure(ctx, name: str, **settings: Any) -> None:
    call(
        "credential.configure", ctx, {"provider": name, "settings": settings, "secret": {"k": "v"}}
    )


def disable(agent_ctx, case_uid: str, **extra: Any):
    return call(
        "action.propose",
        agent_ctx,
        {
            "action": "aws.disable_access_key",
            "params": {"access_key_id": "AKIAEXAMPLE", "user_name": "deploy-ci"},
            "case_uid": case_uid,
            **extra,
        },
    ).data


def test_the_key_is_disabled_with_the_credential_of_its_own_account(ctx, agent_ctx, leaked):
    configure(ctx, "aws", accounts=["999999999999"])
    configure(ctx, "aws:prod", accounts=[ACCOUNT])
    record = disable(agent_ctx, leaked)
    assert record.acts_in == ["aws:prod"]
    assert "in aws:prod" in record.plan


def test_an_account_shoc_has_no_credential_for_is_blocked_with_the_reason(ctx, agent_ctx, leaked):
    configure(ctx, "aws", accounts=["999999999999"])
    record = disable(agent_ctx, leaked)
    assert record.state == "blocked"
    assert f"no aws credentials act in aws account {ACCOUNT}" in record.rationale


def test_naming_the_other_tenant_does_not_send_the_action_there(ctx, agent_ctx, leaked):
    configure(ctx, "aws", accounts=["999999999999"])
    configure(ctx, "aws:prod", accounts=[ACCOUNT])
    assert disable(agent_ctx, leaked, credential="aws").state == "blocked"


def test_an_entra_case_is_not_answered_with_the_okta_credential(ctx, agent_ctx, entra):
    """The provider is the vendor (RFC 0031): Okta's action is refused on an Entra
    case, and Entra's finds only Entra credentials."""
    user = playbooks.entities_of_case(ctx.db, ctx.tenant_id, entra)["user"]
    configure(ctx, "okta", org_url="https://acme.okta.com")
    okta = {"action": "okta.revoke_sessions", "params": {"user": user}, "case_uid": entra}
    blocked = call("action.propose", agent_ctx, okta).data
    assert blocked.state == "blocked" and "acts on okta" in blocked.rationale
    configure(ctx, "entra")
    proposal = {**okta, "action": "entra.revoke_sessions"}
    assert call("action.propose", agent_ctx, proposal).data.acts_in == ["entra"]


def test_the_action_runs_and_is_undone_where_it_was_routed(
    ctx, agent_ctx, leaked, config, monkeypatch
):
    configure(ctx, "aws", accounts=["999999999999"])
    configure(ctx, "aws:prod", accounts=[ACCOUNT])
    record = disable(agent_ctx, leaked)
    action = get_action("aws.disable_access_key")
    used: list[str] = []

    def act(creds: Credentials, params: dict, http: Any = None) -> ActionResult:
        used.append(creds.provider)
        return ActionResult(ok=True, detail="disabled", undo={"access_key_id": "AKIAEXAMPLE"})

    def undo(creds: Credentials, data: dict, http: Any = None) -> ActionResult:
        used.append(f"undo {creds.provider}")
        return ActionResult(ok=True, detail="enabled")

    monkeypatch.setattr(type(action), "execute", lambda self, c, p, http=None: act(c, p))
    monkeypatch.setattr(type(action), "undo", lambda self, c, d, http=None: undo(c, d))
    if record.state != "approved":
        action_store.approve(ctx.db, ctx.tenant_id, record.action_uid, "human:test", "human")
    execute(
        ctx.db,
        "UPDATE shoc.actions SET dry_run = false WHERE action_uid = %s",
        (record.action_uid,),
    )
    row, result = action_store.execute(
        ctx.db, ctx.tenant_id, record.action_uid, config.master_key, by="human:test"
    )
    assert result.ok and row["acts_in"] == ["aws:prod"]
    action_store.undo(ctx.db, ctx.tenant_id, record.action_uid, config.master_key, by="human:test")
    assert used == ["aws:prod", "undo aws:prod"]


def test_two_credentials_that_could_both_act_everywhere_are_refused(ctx, clean):
    configure(ctx, "aws")
    with pytest.raises(ValidationError, match="give each its `accounts`"):
        configure(ctx, "aws:prod")
    configure(ctx, "aws:prod", accounts=[ACCOUNT])
    assert credentials.providers(ctx.db, ctx.tenant_id) == ["aws", "aws:prod"]
