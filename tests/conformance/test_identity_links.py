"""An identity action answers an EDR, Gateway or GitHub case for the IdP login the
case's user is linked to, and never for the name the case holds (RSP-4, RFC 0027)."""

from __future__ import annotations

from typing import Any

import pytest

from shoc.capabilities.registry import Caller, Context, call
from shoc.cases import engine, playbooks
from shoc.db.pool import fetch_all, fetch_one
from shoc.ingest import batch
from tests.support import fixture_rows, load_fixture

pytestmark = pytest.mark.postgres

JANE = "jane.doe@example.com"


@pytest.fixture
def agent_ctx(config, conn, store):
    c = Context(tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config)
    c._db, c._store = conn, store
    return c


def entra_sign_in(user: str, device: str = "LAPTOP-21") -> dict[str, Any]:
    return {
        "userPrincipalName": user,
        "userId": f"u-{user}",
        "appDisplayName": "Microsoft Teams",
        "ipAddress": "198.51.100.7",
        "tenantId": "tid-1",
        "status": {"errorCode": 0},
        "deviceDetail": {"displayName": device},
        "_stream": "signIns",
    }


def okta_sign_in(user: str) -> dict[str, Any]:
    return {
        "eventType": "user.session.start",
        "displayMessage": "User login to Okta",
        "actor": {"id": f"00u-{user}", "type": "User", "alternateId": user},
        "client": {"ipAddress": "198.51.100.5"},
        "outcome": {"result": "SUCCESS"},
    }


def case_from(ctx, config, now, rule_id: str, records: list[dict[str, Any]], **idp: list) -> str:
    """Load a rule's positive fixture and the IdP's events, and rule the case malicious."""
    tenant = config.tenant_id
    rows = fixture_rows(records or load_fixture(rule_id, "positive"), _source(rule_id), tenant, now)
    for source, batch_ in idp.items():
        rows += fixture_rows(batch_, source, tenant, now)
    batch.load(ctx.store, rows)
    call("detect.run", ctx, {"lookback": "1h"})
    row = fetch_one(
        ctx.db,
        "SELECT case_uid, event_uids FROM shoc.findings WHERE tenant_id = %s AND rule_id = %s",
        (tenant, rule_id),
    )
    assert row and row["case_uid"], f"{rule_id} must open a case"
    case = str(row["case_uid"])
    engine.set_verdict(ctx.db, tenant, case, "malicious", 0.95, rule_id, list(row["event_uids"]))
    return case


def _source(rule_id: str) -> str:
    from shoc.detect import rules
    from tests.support import fixture_source

    return fixture_source(next(r for r in rules.load() if r.id == rule_id))


def infostealer(ctx, config, now, **idp: list) -> str:
    case = case_from(ctx, config, now, "defender_browser_credential_file_read", [], **idp)
    assert engine.platforms(ctx.db, config.tenant_id, case, config) == {"edr"}
    return case


def revoke(agent_ctx, case_uid: str, user: str, vendor: str = "entra"):
    return call(
        "action.propose",
        agent_ctx,
        {"action": f"{vendor}.revoke_sessions", "params": {"user": user}, "case_uid": case_uid},
    ).data


def configure(ctx, name: str, **settings: Any) -> None:
    call(
        "credential.configure", ctx, {"provider": name, "settings": settings, "secret": {"k": "v"}}
    )


def test_the_laptop_owner_is_signed_out_in_the_idp_her_laptop_signs_in_to(
    ctx, agent_ctx, config, clean, now
):
    case = infostealer(ctx, config, now, entra=[entra_sign_in(JANE)], okta=[okta_sign_in(JANE)])
    configure(ctx, "okta", org_url="https://acme.okta.com")
    configure(ctx, "entra")
    # Okta names jane too, but only Entra saw her sign in from the laptop. The
    # link holds for both, and each signs her out where it saw her login.
    for vendor in ("okta", "entra"):
        record = revoke(agent_ctx, case, "jdoe", vendor)
        assert record.state != "blocked", record.rationale
        assert record.target == JANE and record.acts_in == [vendor]
        assert f"jdoe signs in as {JANE} (signed in from LAPTOP-21" in record.rationale


def test_an_idp_that_never_saw_the_login_is_not_asked_to_sign_it_out(
    ctx, agent_ctx, config, clean, now
):
    case = infostealer(ctx, config, now, entra=[entra_sign_in(JANE)])
    configure(ctx, "okta", org_url="https://acme.okta.com")
    record = revoke(agent_ctx, case, "jdoe", "okta")
    assert record.state == "blocked"
    assert "has not signed in to okta" in record.rationale


def test_the_idp_tenant_is_the_one_the_linked_login_was_seen_in(ctx, agent_ctx, config, clean, now):
    case = infostealer(ctx, config, now, entra=[entra_sign_in(JANE)])
    configure(ctx, "entra", accounts=["tid-0"])
    configure(ctx, "entra:emea", accounts=["tid-1"])
    assert revoke(agent_ctx, case, "jdoe").acts_in == ["entra:emea"]


def test_a_local_account_nothing_links_is_never_sent(ctx, agent_ctx, config, clean, now):
    case = infostealer(ctx, config, now, entra=[entra_sign_in(JANE, device="LAPTOP-99")])
    record = revoke(agent_ctx, case, "jdoe")
    assert record.state == "blocked"
    assert "nothing links jdoe to an identity-provider login" in record.rationale


def test_a_laptop_two_people_sign_in_from_links_to_neither(ctx, agent_ctx, config, clean, now):
    case = infostealer(
        ctx, config, now, entra=[entra_sign_in(JANE), entra_sign_in("bob@example.com")]
    )
    record = revoke(agent_ctx, case, "jdoe")
    assert record.state == "blocked" and "no single login to act on" in record.rationale


def test_only_the_login_of_the_case_user_can_be_named(ctx, agent_ctx, config, clean, now):
    case = infostealer(
        ctx, config, now, entra=[entra_sign_in(JANE), entra_sign_in("ceo@example.com", "MAC-1")]
    )
    assert revoke(agent_ctx, case, JANE).target == JANE
    record = revoke(agent_ctx, case, "ceo@example.com")
    assert record.state == "blocked"
    assert "neither a user of this case" in record.rationale


def test_identity_resolve_shows_the_login_the_action_acts_on(ctx, config, clean, now):
    infostealer(ctx, config, now, entra=[entra_sign_in(JANE)])
    data = call("identity.resolve", ctx, {"identity": "user:jdoe"}).data
    assert [li["login"] for li in data.logins] == [JANE]
    assert data.logins[0]["via"] == "signed in from LAPTOP-21" and data.logins[0]["event_uids"]
    assert not data.unbridged


def test_a_github_member_is_signed_out_through_their_saml_identity(
    ctx, agent_ctx, config, clean, now
):
    records = [
        {**r, "external_identity_nameid": JANE}
        for r in load_fixture("github_oauth_app_authorized", "positive")
    ]
    case = case_from(
        ctx, config, now, "github_oauth_app_authorized", records, okta=[okta_sign_in(JANE)]
    )
    record = revoke(agent_ctx, case, "mallory", "okta")
    assert record.state != "blocked", record.rationale
    assert record.target == JANE
    assert "github events name it" in record.rationale


def test_the_infostealer_playbook_revokes_the_linked_login(ctx, config, clean, now):
    case = infostealer(ctx, config, now, entra=[entra_sign_in(JANE)])
    configure(ctx, "entra")  # the company signs in with Entra, not Okta
    row = engine.require(ctx.db, config.tenant_id, case)
    assert "contain_infostealer" in [b.id for b in playbooks.match(ctx.db, config.tenant_id, row)]
    run = playbooks.start(ctx.db, config.tenant_id, "contain_infostealer", case, config, True)
    playbooks.advance(ctx.db, config.tenant_id, run["run_uid"], config.master_key, config)
    sent = fetch_all(
        ctx.db,
        "SELECT target, state FROM shoc.actions WHERE tenant_id = %s AND type = %s",
        (config.tenant_id, "entra.revoke_sessions"),
    )
    assert [r["target"] for r in sent] == [JANE]
    assert sent[0]["state"] in ("approved", "done")
    # Okta's step is not proposed in a company that does not use Okta (RFC 0031).
    skipped = playbooks.steps_of(ctx.db, run["run_uid"])
    okta = next(s for s in skipped if s["name"] == "revoke the person's sessions in Okta")
    assert okta["state"] == "skipped" and not okta["action_uid"]
