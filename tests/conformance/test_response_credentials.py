"""Where shoc can act: response credentials and the sources they cover (RSP-4, RFC 0025)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shoc.capabilities.registry import Caller, Context, call
from shoc.cases import credentials
from shoc.db.pool import execute, fetch_all
from shoc.errors import Denied, NotFound, ValidationError

pytestmark = pytest.mark.postgres

KEY = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "topsecret"}


@pytest.fixture
def agent_ctx(config, conn, store):
    c = Context(tenant_id=config.tenant_id, caller=Caller(kind="agent", id="crew"), config=config)
    c._db, c._store = conn, store
    return c


def connect_source(ctx, source: str, accounts: list[str]) -> None:
    execute(
        ctx.db,
        "INSERT INTO shoc.connector_config (tenant_id, source, settings) VALUES (%s,%s,'{}')",
        (ctx.tenant_id, source),
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.source_history (tenant_id, source, products, first_event_at, account_uids)
           VALUES (%s, %s, '{}', now(), %s)""",
        (ctx.tenant_id, source, accounts),
    )


def configure(ctx, name: str, secret: dict[str, Any] | None = None, **settings: Any):
    return call(
        "credential.configure",
        ctx,
        {"provider": name, "settings": settings, "secret": secret or {}, "verify": False},
    ).data


def listed(ctx) -> Any:
    return call("credential.list", ctx, {}).data


def test_a_credential_is_listed_with_what_it_lacks_and_never_its_secret(ctx, clean):
    state = configure(ctx, "aws:prod", {"access_key_id": "AKIAEXAMPLE"}, accounts=["111111111111"])
    assert state.missing == ["secret_access_key"]
    (row,) = listed(ctx).configured
    assert row["name"] == "aws:prod" and row["provider"] == "aws"
    assert row["accounts"] == ["111111111111"] and row["has_secret"]
    assert row["missing"] == ["secret_access_key"]
    assert "AKIAEXAMPLE" not in json.dumps(listed(ctx).__dict__, default=str)


def test_a_blank_secret_keeps_the_stored_one(ctx, config, clean):
    configure(ctx, "aws", KEY)
    configure(ctx, "aws", {"secret_access_key": ""}, regions="eu-west-1")
    stored = credentials.load(ctx.db, ctx.tenant_id, "aws", config.master_key)
    assert stored.secret == KEY and stored.settings == {"regions": "eu-west-1"}
    with pytest.raises(ValidationError, match="needs its secret"):
        configure(ctx, "github")


def test_a_human_disconnects_a_credential_and_an_agent_cannot(ctx, agent_ctx, clean):
    configure(ctx, "aws", KEY)
    with pytest.raises(Denied):
        call("credential.remove", agent_ctx, {"provider": "aws"})
    assert call("credential.remove", ctx, {"provider": "aws"}).data.configured == []
    with pytest.raises(NotFound):
        call("credential.remove", ctx, {"provider": "aws"})
    with pytest.raises(NotFound):
        call("credential.check", ctx, {"provider": "aws"})


def test_each_source_says_which_credential_acts_on_it(ctx, clean):
    connect_source(ctx, "aws_cloudtrail:prod", ["111111111111"])
    connect_source(ctx, "aws_cloudtrail:staging", ["222222222222"])
    connect_source(ctx, "okta", ["acme.okta.com"])
    configure(ctx, "aws:prod", KEY, accounts=["111111111111"])

    rows = {r["source"]: r["response"] for r in call("source.list", ctx, {}).data.configured}
    assert rows["aws_cloudtrail:prod"] == [
        {"provider": "aws", "credentials": ["aws:prod"], "missing": []}
    ]
    assert rows["aws_cloudtrail:staging"][0]["missing"] == ["222222222222"]
    assert rows["okta"] == [{"provider": "okta", "credentials": [], "missing": ["acme.okta.com"]}]

    data = listed(ctx)
    needs = {n["provider"]: n for n in data.needs}
    assert needs["aws"]["credentials"] == ["aws:prod"]
    assert needs["aws"]["missing"] == ["222222222222"]
    assert needs["okta"]["sources"] == ["okta"]
    assert "notify" in needs, "paging answers every case"
    (row,) = data.configured
    assert row["sources"] == ["aws_cloudtrail:prod"]
    assert data.providers["okta"]["settings"] == ["org_url"]


def test_an_okta_credential_does_not_cover_an_entra_source(ctx, clean):
    connect_source(ctx, "entra", [])
    configure(ctx, "okta", {"api_token": "t"}, org_url="https://acme.okta.com")
    (row,) = [r for r in call("source.list", ctx, {}).data.configured if r["source"] == "entra"]
    assert row["response"][0]["credentials"] == []
    configure(ctx, "entra", {"tenant_id": "t", "client_id": "c", "client_secret": "s"})
    (row,) = [r for r in call("source.list", ctx, {}).data.configured if r["source"] == "entra"]
    assert row["response"][0]["credentials"] == ["entra"]


def test_a_credential_that_does_not_work_is_kept_and_said_so(ctx, clean):
    # Nothing listens on port 9: the probe's read is refused at once, with no vendor involved.
    state = call(
        "credential.configure",
        ctx,
        {
            "provider": "gitlab",
            "settings": {"base_url": "http://127.0.0.1:9"},
            "secret": {"token": "x"},
        },
    ).data
    assert state.verified is False and "GitLab call failed" in state.verify_detail
    assert [r["name"] for r in listed(ctx).configured] == ["gitlab"], "saved all the same"
    assert configure(ctx, "gitlab", base_url="http://127.0.0.1:9").verified is None


def test_each_credential_names_the_log_connectors_it_answers_for(ctx, clean):
    providers = listed(ctx).providers
    assert providers["aws"]["connectors"] == ["aws_cloudtrail", "aws_guardduty"]
    assert providers["entra"]["connectors"] == ["entra"], "m365 has its own"
    assert providers["cloudflare"]["connectors"] == ["cloudflare", "cloudflare_logs"]
    assert providers["notify"]["connectors"] == []


def test_the_last_check_is_kept_and_can_be_run_again(ctx, clean):
    configure(ctx, "gitlab", {"token": "x"}, base_url="http://127.0.0.1:9")
    assert listed(ctx).configured[0]["checked_at"] is None, "verify off: never checked"
    state = call("credential.check", ctx, {"provider": "gitlab"}).data
    assert state.verified is False
    (row,) = listed(ctx).configured
    assert row["checked_at"] and row["check_ok"] is False
    assert "GitLab call failed" in row["check_detail"]


def test_migration_043_names_credentials_and_actions_after_the_vendor(ctx, config, clean):
    """RFC 0031: `idp`, `edr` and `waf` rows take their vendor's name, sealed again."""
    from shoc.db.secrets import seal

    tenant = ctx.tenant_id
    legacy = {
        "idp": ({"org_url": "https://acme.okta.com"}, {"api_token": "t"}),
        "idp:entra": ({"flavour": "entra", "accounts": ["tid-1"]}, {"client_secret": "e"}),
        "edr": ({"flavour": "crowdstrike"}, {"client_secret": "s"}),
        "waf": ({"account_id": "acc"}, {"api_token": "w"}),
        "cloudflare": ({"account_id": "acc"}, {"api_token": "c"}),
    }
    for name, (settings, secret) in legacy.items():
        execute(
            ctx.db,
            """INSERT INTO shoc.action_credentials (tenant_id, provider, settings, secret)
               VALUES (%s,%s,%s,%s)""",
            (
                tenant,
                name,
                json.dumps(settings),
                seal(config.master_key, secret, tenant, "action_credentials", name),
            ),
        )
    for uid, kind, acts_in, fallback in [
        ("ACT-043-1", "idp.suspend_user", ["idp:entra"], "idp.revoke_sessions"),
        ("ACT-043-2", "edr.isolate_host", None, ""),
        ("ACT-043-3", "cloudflare.block_ip", ["waf"], ""),
    ]:
        execute(
            ctx.db,
            """INSERT INTO shoc.actions (action_uid, tenant_id, type, target, idempotency_key,
                   acts_in, fallback) VALUES (%s,%s,%s,'x',%s,%s,%s)""",
            (uid, tenant, kind, uid, acts_in, fallback),
        )

    credentials.split_legacy(ctx.db, config)

    assert credentials.providers(ctx.db, tenant) == [
        "cloudflare",
        "cloudflare:waf",
        "crowdstrike",
        "entra",
        "okta",
    ]
    okta = credentials.load(ctx.db, tenant, "okta", config.master_key)
    assert okta.secret == {"api_token": "t"}, "opened under the old name, sealed under the new"
    entra = credentials.load(ctx.db, tenant, "entra", config.master_key)
    assert entra.settings == {"accounts": ["tid-1"]}, "the flavour is gone, the accounts stay"
    assert credentials.load(ctx.db, tenant, "cloudflare:waf", config.master_key).secret == {
        "api_token": "w"
    }
    moved = {
        r["action_uid"]: (r["type"], r["acts_in"], r["fallback"])
        for r in fetch_all(
            ctx.db,
            "SELECT action_uid, type, acts_in, fallback FROM shoc.actions "
            "WHERE action_uid LIKE 'ACT-043-%%'",
        )
    }
    assert moved == {
        "ACT-043-1": ("entra.suspend_user", ["entra"], "entra.revoke_sessions"),
        "ACT-043-2": ("crowdstrike.isolate_host", None, ""),
        "ACT-043-3": ("cloudflare.block_ip", ["cloudflare:waf"], ""),
    }
