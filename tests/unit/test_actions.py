"""Action connectors: what they send, and what they undo (RSP-4).

Each action is exercised against a mock transport, so the exact request an
operator's audit log will show is pinned by a test.
"""

from __future__ import annotations

import json

import httpx
import pytest

from shoc.actions import available, get
from shoc.actions.base import Credentials, dry_run_result, follows_link, out_of_scope
from shoc.errors import ConfigError, ValidationError


def recorder(status: int = 200, body: dict | list | None = None):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body if body is not None else {"result": {"id": "r1"}})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_every_action_declares_what_it_is_and_whether_it_can_be_undone():
    for name in available():
        action = get(name)
        assert action.type == name and action.provider and action.target_kind
        assert action.summary and action.required_params
        assert action.plan({p: "x" for p in action.required_params})


def test_an_action_only_answers_an_incident_on_its_own_platform():
    # A public S3 bucket is an AWS case: making a GitHub repository private is
    # not a response to it, and neither is revoking an Okta session.
    assert "acts on github" in out_of_scope(get("github.make_repo_private"), {"aws"})
    assert out_of_scope(get("okta.revoke_sessions"), {"aws"})
    assert not out_of_scope(get("aws.disable_access_key"), {"aws"})
    assert not out_of_scope(get("github.make_repo_private"), {"github", "okta"})
    assert not out_of_scope(get("notify.page"), {"aws"})  # paging fits every incident
    assert "no known source" in out_of_scope(get("aws.disable_access_key"), set())


def test_an_identity_action_reaches_another_platform_only_through_a_link():
    """RFC 0027: an infostealer case is answered for the IdP login, never the local name."""
    for vendor in ("okta", "entra"):
        revoke = get(f"{vendor}.revoke_sessions")
        assert out_of_scope(revoke, {"edr"}) and follows_link(revoke, {"edr"})
        assert follows_link(revoke, {"cloudflare"}) and follows_link(revoke, {"github"})
        assert not follows_link(revoke, {"aws"})
    assert not follows_link(get("crowdstrike.isolate_host"), {"okta"})


def test_every_platform_an_action_names_is_a_rule_logsource():
    from shoc.store.ocsf import products

    known = {product for product, _ in products()}
    for name in available():
        assert set(get(name).platforms) <= known, name


def test_the_commander_is_only_shown_actions_for_the_case_platform():
    from shoc.cases.actions import catalogue
    from shoc.cases.credentials import Scope

    names = {a["action"] for a in catalogue(scope=Scope({"aws"}, None, {"aws"}))}
    assert "aws.disable_access_key" in names and "notify.page" in names
    assert "github.make_repo_private" not in names


def test_the_commander_is_only_shown_the_vendor_the_case_came_from():
    """RFC 0031: a SentinelOne alert is contained in SentinelOne, and an
    infostealer's login is signed out in the IdP the company uses."""
    from shoc.cases.actions import catalogue
    from shoc.cases.credentials import Scope

    names = {a["action"] for a in catalogue(scope=Scope({"edr"}, {"SentinelOne"}, {"okta"}))}
    assert "sentinelone.isolate_host" in names and "okta.revoke_sessions" in names
    assert not names & {"crowdstrike.isolate_host", "defender.isolate_host"}
    assert "entra.revoke_sessions" not in names


def test_a_vendor_step_is_skipped_on_a_case_from_another_vendor():
    from shoc.cases.credentials import Scope

    okta_case = Scope({"okta"}, {"Okta System Log"}, {"okta", "entra"})
    assert not okta_case.excludes(get("okta.suspend_user"))
    assert "acts on entra" in okta_case.excludes(get("entra.suspend_user"))
    falcon = Scope({"edr"}, {"CrowdStrike Falcon Data Replicator"}, {"crowdstrike"})
    assert not falcon.excludes(get("crowdstrike.isolate_host"))
    assert "come from CrowdStrike" in falcon.excludes(get("defender.isolate_host"))
    # Events that cannot be read leave the vendors the tenant uses.
    unread = Scope({"edr"}, None, {"defender"})
    assert not unread.excludes(get("defender.isolate_host"))
    assert "no crowdstrike source" in unread.excludes(get("crowdstrike.isolate_host"))
    assert not unread.excludes(get("notify.page"))


def test_a_missing_parameter_is_caught_before_anything_is_sent():
    with pytest.raises(ValidationError, match="missing parameter"):
        get("aws.disable_access_key").check({})


def test_a_missing_credential_says_how_to_fix_it():
    with pytest.raises(ConfigError, match=r"credential\.configure"):
        Credentials("aws").require("access_key_id")


def test_dry_run_changes_nothing_and_says_what_it_would_do():
    action = get("crowdstrike.isolate_host")
    result = dry_run_result(action, {"device_id": "dev-1"})
    assert result.dry_run and result.ok
    assert "[dry run]" in result.detail and "dev-1" in result.detail


def test_disabling_an_aws_key_sends_the_right_iam_call():
    seen, client = recorder(body={})
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    result = get("aws.disable_access_key").execute(
        creds, {"access_key_id": "AKIATARGET", "user_name": "deploy-ci"}, client
    )
    body = seen[0].content.decode()
    assert "Action=UpdateAccessKey" in body and "Status=Inactive" in body
    assert "AccessKeyId=AKIATARGET" in body
    assert seen[0].headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA/")
    # IAM joins a repeated header before checking the signature, so one copy only.
    assert seen[0].headers.get_list("content-type") == [
        "application/x-www-form-urlencoded; charset=utf-8"
    ]
    assert result.undo["access_key_id"] == "AKIATARGET"


def test_undoing_it_sets_the_key_active_again():
    seen, client = recorder(body={})
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    get("aws.disable_access_key").undo(creds, {"access_key_id": "AKIATARGET"}, client)
    assert "Status=Active" in seen[0].content.decode()


def test_revoking_role_sessions_writes_a_time_bounded_deny_policy():
    seen, client = recorder(body={})
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    get("aws.revoke_role_sessions").execute(creds, {"role_name": "prod-deployer"}, client)
    body = seen[0].content.decode()
    assert "Action=PutRolePolicy" in body and "AWSRevokeOlderSessions" in body
    assert "TokenIssueTime" in body


def test_okta_session_revocation_and_suspension():
    seen, client = recorder(body={})
    creds = Credentials(
        "okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"}
    )
    get("okta.revoke_sessions").execute(creds, {"user": "00u1"}, client)
    assert seen[0].method == "DELETE" and seen[0].url.path == "/api/v1/users/00u1/sessions"
    assert seen[0].url.params["oauthTokens"] == "true"  # the apps' refresh tokens too

    result = get("okta.suspend_user").execute(creds, {"user": "00u1"}, client)
    assert seen[1].url.path.endswith("/lifecycle/suspend")
    get("okta.suspend_user").undo(creds, result.undo, client)
    assert seen[2].url.path.endswith("/lifecycle/unsuspend")


def test_making_a_repository_private_records_what_it_was():
    seen, client = recorder(body={"private": False})
    creds = Credentials("github", secret={"token": "ghp"})
    result = get("github.make_repo_private").execute(creds, {"repo": "acme/payments"}, client)
    assert seen[0].method == "GET"
    assert seen[1].method == "PATCH" and json.loads(seen[1].content)["private"] is True
    assert result.undo == {"repo": "acme/payments", "private": False}


def test_blocking_an_ip_returns_the_rule_it_created():
    seen, client = recorder(body={"result": {"id": "rule-9"}})
    creds = Credentials("cloudflare", secret={"api_token": "t", "account_id": "acc"})
    result = get("cloudflare.block_ip").execute(creds, {"ip": "203.0.113.55"}, client)
    assert json.loads(seen[0].content)["configuration"]["value"] == "203.0.113.55"
    assert result.undo["rule_id"] == "rule-9"
    get("cloudflare.block_ip").undo(creds, result.undo, client)
    assert seen[1].method == "DELETE" and seen[1].url.path.endswith("/rule-9")


def test_crowdstrike_contains_a_host_and_lifts_it():
    seen, client = recorder(body={})
    creds = Credentials("crowdstrike", secret={"access_token": "t"})
    get("crowdstrike.isolate_host").execute(creds, {"device_id": "dev-1"}, client)
    assert seen[0].url.params["action_name"] == "contain"
    get("crowdstrike.isolate_host").undo(creds, {"device_id": "dev-1"}, client)
    assert seen[1].url.params["action_name"] == "lift_containment"


def test_sentinelone_isolates_by_console_id_and_looks_up_the_id_of_an_agent_uuid():
    seen, client = recorder(body={"data": [{"id": "1088377752722254024"}]})
    creds = Credentials(
        "sentinelone", settings={"console_url": "https://s1.example.com"}, secret={"api_token": "t"}
    )
    get("sentinelone.isolate_host").execute(creds, {"device_id": "1088377752722254024"}, client)
    get("sentinelone.isolate_host").execute(
        creds, {"device_id": "5e4482b45d134ae8bf4901cb52b65e88"}, client
    )
    lookup = seen[1]
    assert lookup.method == "GET"
    assert lookup.url.params["uuids"] == "5e4482b45d134ae8bf4901cb52b65e88"
    posts = [r for r in seen if r.method == "POST"]
    # The agent actions filter on the console id, whichever id the case carried.
    assert [json.loads(r.content)["filter"] for r in posts] == [
        {"ids": ["1088377752722254024"]},
        {"ids": ["1088377752722254024"]},
    ]


def test_sentinelone_refuses_to_isolate_an_agent_uuid_it_does_not_know():
    _seen, client = recorder(body={"data": []})
    creds = Credentials(
        "sentinelone", settings={"console_url": "https://s1.example.com"}, secret={"api_token": "t"}
    )
    with pytest.raises(ValidationError, match="no agent"):
        get("sentinelone.isolate_host").execute(
            creds, {"device_id": "5e4482b45d134ae8bf4901cb52b65e88"}, client
        )


def test_crowdstrike_refuses_a_sha1_it_cannot_prevent_on():
    seen, client = recorder()
    creds = Credentials("crowdstrike", secret={"access_token": "t"})
    with pytest.raises(ValidationError, match="SHA-256 hex"):
        get("crowdstrike.block_hash").execute(creds, {"hash": "a" * 40}, client)
    assert not seen


def test_paging_sends_a_deduplicated_trigger_and_can_resolve_it():
    seen, client = recorder(body={"dedup_key": "CASE-1"})
    creds = Credentials("notify", secret={"routing_key": "rk"})
    result = get("notify.page").execute(
        creds,
        {"summary": "leaked key contained", "severity": "critical", "dedup_key": "CASE-1"},
        client,
    )
    assert json.loads(seen[0].content)["event_action"] == "trigger"
    get("notify.page").undo(creds, result.undo, client)
    assert json.loads(seen[1].content)["event_action"] == "resolve"


def test_an_http_failure_becomes_a_typed_error():
    from shoc.errors import StoreError

    _seen, client = recorder(status=403, body={"message": "forbidden"})
    creds = Credentials("github", secret={"token": "ghp"})
    with pytest.raises(StoreError, match="GitHub call failed"):
        get("github.make_repo_private").execute(creds, {"repo": "acme/payments"}, client)


# -- the Tier 0 platforms (RFC 0014) -----------------------------------------
@pytest.fixture
def tokens(monkeypatch):
    """Microsoft and Google tokens are minted over the network; not here."""
    monkeypatch.setattr("shoc.ingest.connectors.msgraph.access_token", lambda *a, **k: "t")
    monkeypatch.setattr("shoc.ingest.connectors.googleauth.access_token", lambda *a, **k: "t")


def test_every_platform_we_ingest_has_an_action_of_its_own():
    """A case from a platform with no action can only ever end in a page."""
    from shoc.store.ocsf import products

    covered = {p for name in available() for p in get(name).platforms}
    # `dns` is a view over Gateway and the EDR sensors, not a platform: its
    # hunts are answered by the endpoint playbook.
    assert {product for product, _ in products()} - {"dns"} <= covered


def test_every_platform_we_ingest_has_a_lookup_of_its_own():
    """The crew reads what is true now, not only what the logs said (D56)."""
    from shoc.actions import lookups
    from shoc.store.ocsf import products

    covered = {p for lk in lookups().values() for p in lk.platforms}
    assert {product for product, _ in products()} - {"dns"} <= covered


# The vendor whose actions answer each connector (RFC 0031). `file` reads any
# vendor's export and acts on none.
CONNECTOR_PROVIDERS = {
    "anthropic": "anthropic",
    "aws_cloudtrail": "aws",
    "aws_guardduty": "aws",
    "azure_activity": "azure",
    "cloudflare": "cloudflare",
    "cloudflare_logs": "cloudflare",
    "crowdstrike": "crowdstrike",
    "crowdstrike_fdr": "crowdstrike",
    "defender": "defender",
    "defender_hunting": "defender",
    "entra": "entra",
    "gcp_audit": "gcp",
    "github": "github",
    "gitlab": "gitlab",
    "google_workspace": "google",
    "m365": "m365",
    "okta": "okta",
    "openai": "openai",
    "sentinelone": "sentinelone",
    "sentinelone_cloudfunnel": "sentinelone",
    "stripe": "stripe",
    "tailscale": "tailscale",
    "wazuh": "wazuh",
}


def test_every_connector_has_actions_and_lookups_for_its_own_vendor():
    """Wazuh was ingested as `edr` and passed the platform check on CrowdStrike's
    actions, while nothing could act on or read a Wazuh agent (RSP-4, D56)."""
    from shoc.actions import load, lookups
    from shoc.actions.base import RESPONDS
    from shoc.ingest.connectors import available as connectors

    assert set(connectors()) - {"file"} == set(CONNECTOR_PROVIDERS), (
        "a new connector names the provider whose actions and lookups answer it"
    )
    for source, provider in CONNECTOR_PROVIDERS.items():
        assert RESPONDS[source][:1] == (provider,), f"{source}: credential for another vendor"
        assert any(a.provider == provider for a in load().values()), f"{source}: no action"
        assert any(lk.provider == provider for lk in lookups().values()), f"{source}: no lookup"


def test_every_lookup_declares_what_it_reads():
    from shoc.actions import lookups

    for name, lk in lookups().items():
        assert lk.type == name and lk.provider and lk.platforms and lk.summary
        assert lk.required_params


def test_a_target_from_log_content_cannot_reach_another_endpoint():
    seen, client = recorder(body={})
    creds = Credentials(
        "okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"}
    )
    get("okta.revoke_sessions").execute(creds, {"user": "../roles"}, client)
    assert seen[0].url.raw_path == b"/api/v1/users/..%2Froles/sessions?oauthTokens=true"


def test_removing_an_okta_admin_role_remembers_it_and_gives_it_back():
    seen, client = recorder(body={"id": "ra1", "type": "SUPER_ADMIN"})
    creds = Credentials(
        "okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"}
    )
    result = get("okta.remove_admin_role").execute(creds, {"user": "00u1", "role": "ra1"}, client)
    assert [r.method for r in seen] == ["GET", "DELETE"]
    assert seen[1].url.path == "/api/v1/users/00u1/roles/ra1"
    get("okta.remove_admin_role").undo(creds, result.undo, client)
    assert json.loads(seen[2].content) == {"type": "SUPER_ADMIN"}


def test_deleting_an_inbox_rule_keeps_it_for_undo(tokens):
    rule = {"id": "r1", "displayName": "fwd", "actions": {"forwardTo": ["x"]}, "hasError": False}
    seen, client = recorder(body=rule)
    result = get("m365.delete_inbox_rule").execute(
        Credentials("m365"), {"user": "alice@example.com", "rule_id": "r1"}, client
    )
    assert seen[1].method == "DELETE"
    assert seen[1].url.path.endswith("/users/alice@example.com/mailFolders/inbox/messageRules/r1")
    get("m365.delete_inbox_rule").undo(Credentials("m365"), result.undo, client)
    recreated = json.loads(seen[2].content)
    assert seen[2].method == "POST" and "id" not in recreated and "hasError" not in recreated
    assert recreated["actions"] == {"forwardTo": ["x"]}


def test_revoking_an_app_consent_can_be_restored(tokens):
    grant = {
        "id": "g1",
        "clientId": "c",
        "consentType": "Principal",
        "principalId": "p",
        "resourceId": "r",
        "scope": "Mail.Read",
    }
    seen, client = recorder(body=grant)
    result = get("m365.revoke_app_consent").execute(Credentials("m365"), {"grant_id": "g1"}, client)
    assert seen[1].method == "DELETE" and seen[1].url.path.endswith("/oauth2PermissionGrants/g1")
    get("m365.revoke_app_consent").undo(Credentials("m365"), result.undo, client)
    assert json.loads(seen[2].content)["scope"] == "Mail.Read"


def test_google_sign_out_and_suspension(tokens):
    seen, client = recorder(body={})
    creds = Credentials("google", settings={"admin_email": "admin@example.com"})
    get("google.revoke_sessions").execute(creds, {"user": "bob@example.com"}, client)
    assert seen[0].url.path.endswith("/users/bob@example.com/signOut")
    result = get("google.suspend_user").execute(creds, {"user": "bob@example.com"}, client)
    assert json.loads(seen[1].content) == {"suspended": True}
    get("google.suspend_user").undo(creds, result.undo, client)
    assert json.loads(seen[2].content) == {"suspended": False}


def test_google_needs_an_admin_to_act_as():
    with pytest.raises(ConfigError, match="admin_email"):
        get("google.revoke_sessions").execute(Credentials("google"), {"user": "b"}, recorder()[1])


def test_blocking_a_hash_creates_an_indicator_and_undo_deletes_it():
    sha = "a" * 64
    seen, client = recorder(body={"resources": [{"id": "ioc-1"}]})
    creds = Credentials("crowdstrike", secret={"access_token": "t"})
    result = get("crowdstrike.block_hash").execute(creds, {"hash": sha}, client)
    sent = json.loads(seen[0].content)["indicators"][0]
    assert sent["value"] == sha and sent["action"] == "prevent"
    get("crowdstrike.block_hash").undo(creds, result.undo, client)
    assert seen[1].method == "DELETE" and seen[1].url.params["ids"] == "ioc-1"


def test_a_hash_that_is_not_one_is_refused_before_anything_is_sent():
    seen, client = recorder()
    creds = Credentials("defender", secret={"access_token": "t"})
    with pytest.raises(ValidationError, match="SHA"):
        get("defender.block_hash").execute(creds, {"hash": "evil.exe"}, client)
    assert not seen


def test_detaching_a_policy_names_the_right_principal():
    seen, client = recorder(body={})
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    result = get("aws.detach_role_policy").execute(
        creds, {"role_name": "ci", "policy_arn": arn}, client
    )
    body = seen[0].content.decode()
    assert "Action=DetachRolePolicy" in body and "RoleName=ci" in body
    get("aws.detach_role_policy").undo(creds, result.undo, client)
    assert "Action=AttachRolePolicy" in seen[1].content.decode()
    assert get("aws.detach_role_policy").target_kind == "role"  # role:prod-* stays protected


def test_github_owner_demotion_restores_the_old_role():
    seen, client = recorder(body={"role": "admin"})
    creds = Credentials("github", secret={"token": "ghp"})
    result = get("github.demote_org_owner").execute(creds, {"user": "eve", "org": "acme"}, client)
    assert json.loads(seen[1].content) == {"role": "member"}
    get("github.demote_org_owner").undo(creds, result.undo, client)
    assert json.loads(seen[2].content) == {"role": "admin"}


def test_a_removed_deploy_key_can_be_added_back():
    key = {"id": 7, "title": "ci", "key": "ssh-ed25519 AAAA", "read_only": False}
    seen, client = recorder(body=key)
    creds = Credentials("github", secret={"token": "ghp"})
    result = get("github.remove_deploy_key").execute(
        creds, {"key_id": "7", "repo": "acme/payments"}, client
    )
    assert [r.method for r in seen] == ["GET", "DELETE"]
    assert seen[1].url.path == "/repos/acme/payments/keys/7"
    get("github.remove_deploy_key").undo(creds, result.undo, client)
    assert seen[2].method == "POST" and json.loads(seen[2].content) == {
        "title": "ci",
        "key": "ssh-ed25519 AAAA",
        "read_only": False,
    }


def test_secret_scanning_goes_back_to_what_it_was():
    was = {
        "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        }
    }
    seen, client = recorder(body=was)
    creds = Credentials("github", secret={"token": "ghp"})
    result = get("github.enable_secret_scanning").execute(creds, {"repo": "acme/payments"}, client)
    assert json.loads(seen[1].content)["security_and_analysis"]["secret_scanning"] == {
        "status": "enabled"
    }
    get("github.enable_secret_scanning").undo(creds, result.undo, client)
    assert json.loads(seen[2].content)["security_and_analysis"] == was["security_and_analysis"]


def test_a_repo_name_cannot_walk_the_api():
    with pytest.raises(ValidationError, match="owner/name"):
        get("github.make_repo_private").execute(
            Credentials("github", secret={"token": "t"}), {"repo": "../../user"}, recorder()[1]
        )


def test_gitlab_blocks_by_username():
    seen, client = recorder(body=[{"id": 42}])
    creds = Credentials("gitlab", secret={"token": "glpat"})
    result = get("gitlab.block_user").execute(creds, {"user": "mallory"}, client)
    assert seen[1].url.path == "/api/v4/users/42/block"
    get("gitlab.block_user").undo(creds, result.undo, client)
    assert seen[2].url.path == "/api/v4/users/42/unblock"


def test_gitlab_blocks_the_author_the_audit_log_names_by_email():
    found = [{"id": 7, "email": "dana.other@example.com"}, {"id": 42, "email": "Dana@example.com"}]
    seen, client = recorder(body=found)
    creds = Credentials("gitlab", secret={"token": "glpat"})
    get("gitlab.block_user").execute(creds, {"user": "dana@example.com"}, client)
    assert seen[0].url.params["search"] == "dana@example.com"
    assert seen[1].url.path == "/api/v4/users/42/block"


def test_azure_powers_off_and_starts_again(tokens):
    vm = (
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg"
        "/providers/Microsoft.Compute/virtualMachines/web-1"
    )
    seen, client = recorder(body={})
    result = get("azure.stop_vm").execute(Credentials("azure"), {"vm_id": vm}, client)
    assert seen[0].url.path == f"{vm}/powerOff"
    get("azure.stop_vm").undo(Credentials("azure"), result.undo, client)
    assert seen[1].url.path == f"{vm}/start"
    with pytest.raises(ValidationError):
        get("azure.stop_vm").execute(Credentials("azure"), {"vm_id": "/subscriptions/x"}, client)


def test_gcp_disables_a_key_rather_than_deleting_it(tokens):
    seen, client = recorder(body={})
    sa = "ci@acme-prod.iam.gserviceaccount.com"
    params = {"service_account": sa, "key_id": "0" * 40}
    result = get("gcp.disable_service_account_key").execute(Credentials("gcp"), params, client)
    assert seen[0].url.path.endswith(f"/serviceAccounts/{sa}/keys/{'0' * 40}:disable")
    get("gcp.disable_service_account_key").undo(Credentials("gcp"), result.undo, client)
    assert seen[1].url.path.endswith(":enable")
    # The audit log's full key name, as a case's key entity holds it.
    full = f"//iam.googleapis.com/projects/acme-prod/serviceAccounts/{sa}/keys/{'0' * 40}"
    get("gcp.disable_service_account_key").execute(
        Credentials("gcp"), {"service_account": sa, "key_id": full}, client
    )
    assert seen[2].url.path.endswith(f"/keys/{'0' * 40}:disable")


def test_gcp_switches_a_firewall_rule_off_and_restores_it(tokens):
    seen, client = recorder(body={"disabled": False})
    params = {"firewall": "allow-ssh-any", "project": "acme-prod"}
    result = get("gcp.disable_firewall_rule").execute(Credentials("gcp"), params, client)
    assert seen[1].method == "PATCH" and json.loads(seen[1].content) == {"disabled": True}
    assert seen[1].url.path == "/compute/v1/projects/acme-prod/global/firewalls/allow-ssh-any"
    get("gcp.disable_firewall_rule").undo(Credentials("gcp"), result.undo, client)
    assert json.loads(seen[2].content) == {"disabled": False}
    with pytest.raises(ValidationError):
        get("gcp.disable_firewall_rule").execute(
            Credentials("gcp"), {"firewall": "allow-ssh-any", "project": "../acme"}, client
        )
    # The audit log's resource name, as a case's resource entity holds it.
    get("gcp.disable_firewall_rule").execute(
        Credentials("gcp"),
        {"firewall": "projects/acme-prod/global/firewalls/allow-ssh-any", "project": "acme-prod"},
        client,
    )
    assert seen[-1].url.path.endswith("/global/firewalls/allow-ssh-any")


# -- lookups -----------------------------------------------------------------
def test_an_okta_user_lookup_reads_roles_and_factors():
    from shoc.actions import get_lookup

    seen, client = recorder(body={"id": "00u1", "status": "ACTIVE", "profile": {"login": "a"}})
    creds = Credentials(
        "okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"}
    )
    out = get_lookup("okta.get_user").run(creds, {"user": "a"}, client)
    assert {r.method for r in seen} == {"GET"}
    assert [r.url.path for r in seen] == [
        "/api/v1/users/a",
        "/api/v1/users/a/roles",
        "/api/v1/users/a/factors",
    ]
    assert out["status"] == "ACTIVE" and out["login"] == "a"


def test_a_lookup_missing_one_permission_still_answers(tokens):
    from shoc.actions import get_lookup

    def handler(request: httpx.Request) -> httpx.Response:
        if "authentication" in request.url.path:
            return httpx.Response(403, json={})
        return httpx.Response(200, json={"id": "u1", "userPrincipalName": "a", "value": []})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    out = get_lookup("entra.get_user").run(Credentials("entra"), {"user": "a"}, client)
    assert out["login"] == "a" and "unavailable" in out["mfa_methods"]


def test_who_owns_an_access_key():
    from shoc.actions import get_lookup

    xml = (
        '<GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
        "<GetAccessKeyLastUsedResult><UserName>deploy-ci</UserName><AccessKeyLastUsed>"
        "<LastUsedDate>2026-09-01T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName>"
        "<Region>eu-west-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult>"
        "</GetAccessKeyLastUsedResponse>"
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=xml)))
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    out = get_lookup("aws.get_access_key").run(creds, {"access_key_id": "AKIAX"}, client)
    assert out == {
        "user_name": "deploy-ci",
        "last_used": "2026-09-01T00:00:00Z",
        "service": "s3",
        "region": "eu-west-1",
    }


def test_inbox_rules_are_listed_with_what_they_do(tokens):
    from shoc.actions import get_lookup

    rule = {"id": "r1", "displayName": "x", "isEnabled": True, "actions": {"delete": True}}
    _seen, client = recorder(body={"value": [rule]})
    out = get_lookup("m365.list_inbox_rules").run(Credentials("m365"), {"user": "a"}, client)
    assert out["rules"][0] == {
        "rule_id": "r1",
        "name": "x",
        "enabled": True,
        "conditions": None,
        "actions": {"delete": True},
    }


# -- Wazuh (RSP-4, D56) ------------------------------------------------------
def _wazuh(body: dict):
    """A Wazuh server API: login answers a token, every other call `body`."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        return httpx.Response(200, json={"data": body})

    creds = Credentials(
        "wazuh",
        settings={"api_url": "https://wazuh.example:55000"},
        secret={"username": "shoc", "password": "pw"},
    )
    return seen, creds, httpx.Client(transport=httpx.MockTransport(handler))


def test_wazuh_blocks_an_address_by_active_response():
    seen, creds, client = _wazuh({"affected_items": ["001"]})
    result = get("wazuh.block_ip").execute(creds, {"ip": "203.0.113.9", "agent_id": "001"}, client)
    assert result.ok and result.data["agents"] == ["001"]
    login, call = seen
    assert login.method == "POST" and login.headers["authorization"].startswith("Basic ")
    assert call.method == "PUT" and call.url.path == "/active-response"
    assert call.url.params["agents_list"] == "001"
    assert call.headers["authorization"] == "Bearer jwt"
    assert json.loads(call.content) == {
        "command": "!firewall-drop",
        "alert": {"data": {"srcip": "203.0.113.9"}},
    }
    assert not get("wazuh.block_ip").reversible, "the API cannot lift it"


def test_wazuh_reads_an_agent_and_finds_a_file_by_hash():
    from shoc.actions import get_lookup

    seen, creds, client = _wazuh(
        {
            "affected_items": [
                {
                    "id": "001",
                    "name": "laptop-7",
                    "ip": "198.51.100.7",
                    "status": "active",
                    "os": {"name": "Ubuntu"},
                    "file": "/tmp/x",
                    "size": 10,
                    "uname": "bob",
                }
            ]
        }
    )
    agent = get_lookup("wazuh.get_agent").run(creds, {"agent_id": "001"}, client)
    assert agent["name"] == "laptop-7" and agent["os"] == "Ubuntu"
    digest = "a" * 64
    found = get_lookup("wazuh.find_file").run(creds, {"agent_id": "001", "hash": digest}, client)
    assert found["count"] == 1 and found["files"][0]["owner"] == "bob"
    assert seen[-1].url.path == "/syscheck/001" and seen[-1].url.params["hash"] == digest


@pytest.mark.parametrize(
    ("name", "creds", "params", "path"),
    [
        (
            "stripe.get_charge",
            Credentials("stripe", secret={"api_key": "sk"}),
            {"charge": "ch_1"},
            "/v1/charges/ch_1",
        ),
        (
            "openai.get_api_key",
            Credentials("openai", secret={"admin_key": "k"}),
            {"key_id": "key_1", "project_id": "proj_1"},
            "/v1/organization/projects/proj_1/api_keys/key_1",
        ),
        (
            "anthropic.get_api_key",
            Credentials("anthropic", secret={"admin_key": "k"}),
            {"key_id": "apikey_1"},
            "/v1/organizations/api_keys/apikey_1",
        ),
        (
            "cloudflare.get_api_token",
            Credentials("cloudflare", settings={"account_id": "acc"}, secret={"api_token": "t"}),
            {"token_id": "tok"},
            "/client/v4/accounts/acc/tokens/tok",
        ),
    ],
)
def test_the_platforms_without_a_lookup_now_have_one(name, creds, params, path):
    from shoc.actions import get_lookup

    seen, client = recorder(body={"result": {"name": "n"}, "name": "n"})
    out = get_lookup(name).run(creds, params, client)
    assert out.get("name", "n") == "n"
    assert [(r.method, r.url.path) for r in seen] == [("GET", path)]


def test_a_key_proposal_needs_the_key_user():
    """IAM looks a key without UserName up under shoc's own user (RSP-4)."""
    with pytest.raises(ValidationError, match="user_name"):
        get("aws.disable_access_key").check({"access_key_id": "AKIAEXAMPLE"})


# -- containment that reverts the attacker's change (RSP-4) -------------------
AWS = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})


def routed(*answers: tuple[str, int, object]):
    """A transport that answers by the first matching (substring, status, body):
    a substring of the method, URL, X-Amz-Target or body. Text bodies are XML."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        said = " ".join(
            [
                request.method,
                str(request.url),
                request.headers.get("x-amz-target", ""),
                request.content.decode(),
            ]
        )
        for needle, status, body in answers:
            if needle in said:
                if isinstance(body, str):
                    return httpx.Response(status, text=body)
                return httpx.Response(status, json=body)
        return httpx.Response(200, json={})

    return seen, httpx.Client(transport=httpx.MockTransport(handler))


def test_revoking_sessions_behind_a_long_term_key_denies_the_iam_user():
    seen, client = recorder(body={})
    action = get("aws.revoke_sessions")
    result = action.execute(AWS, {"access_key_id": "AKIATARGET", "user_name": "deploy-ci"}, client)
    body = seen[0].content.decode()
    assert "Action=PutUserPolicy" in body and "UserName=deploy-ci" in body
    assert "AWSRevokeOlderSessions" in body and "TokenIssueTime" in body
    action.undo(AWS, result.undo, client)
    assert "Action=DeleteUserPolicy" in seen[1].content.decode()


def test_revoking_sessions_behind_a_session_key_denies_the_role_it_came_from():
    seen, client = recorder(body={})
    params = {
        "access_key_id": "ASIATARGET",
        "user_name": "app-role",
        "principal_type": "AssumedRole",
    }
    result = get("aws.revoke_sessions").execute(AWS, params, client)
    body = seen[0].content.decode()
    assert "Action=PutRolePolicy" in body and "RoleName=app-role" in body
    get("aws.revoke_sessions").undo(AWS, result.undo, client)
    assert "Action=DeleteRolePolicy" in seen[1].content.decode()
    # GetSessionToken and GetFederationToken sessions belong to the IAM user.
    get("aws.revoke_sessions").execute(AWS, {**params, "principal_type": "FederatedUser"}, client)
    assert "Action=PutUserPolicy" in seen[2].content.decode()


def test_a_session_key_nobody_can_place_is_refused_before_anything_is_sent():
    with pytest.raises(ValidationError, match="role"):
        get("aws.revoke_sessions").check({"access_key_id": "ASIAX", "user_name": "who"})
    with pytest.raises(ValidationError, match="Root"):
        get("aws.revoke_sessions").check(
            {"access_key_id": "ASIAX", "user_name": "r", "principal_type": "Root"}
        )


def test_a_stopped_trail_is_started_in_its_home_region_and_stopped_on_undo():
    seen, client = recorder(body={})
    trail = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/main"
    result = get("aws.start_cloudtrail_logging").execute(AWS, {"trail": trail}, client)
    assert seen[0].url.host == "cloudtrail.eu-west-1.amazonaws.com"
    assert seen[0].headers["x-amz-target"].endswith("CloudTrail_20131101.StartLogging")
    assert json.loads(seen[0].content) == {"Name": trail}
    get("aws.start_cloudtrail_logging").undo(AWS, result.undo, client)
    assert seen[1].headers["x-amz-target"].endswith(".StopLogging")


def test_config_and_guardduty_are_turned_back_on_where_they_were_off():
    seen, client = recorder(body={})
    get("aws.start_config_recorder").execute(AWS, {"recorder": "eu-west-3/default"}, client)
    assert seen[0].url.host == "config.eu-west-3.amazonaws.com"
    assert seen[0].headers["x-amz-target"] == "StarlingDoveService.StartConfigurationRecorder"
    assert json.loads(seen[0].content) == {"ConfigurationRecorderName": "default"}

    detector = "us-east-1/12abc34d567e8fa901bc2d34e56789f0"
    result = get("aws.enable_guardduty").execute(AWS, {"detector_id": detector}, client)
    assert (seen[1].method, seen[1].url.host, seen[1].url.path) == (
        "POST",
        "guardduty.us-east-1.amazonaws.com",
        "/detector/12abc34d567e8fa901bc2d34e56789f0",
    )
    assert json.loads(seen[1].content) == {"enable": True}
    get("aws.enable_guardduty").undo(AWS, result.undo, client)
    assert json.loads(seen[2].content) == {"enable": False}
    with pytest.raises(ValidationError, match="detector"):
        get("aws.enable_guardduty").check({"detector_id": "main"})


def test_the_defences_lookup_names_only_what_is_off():
    from shoc.actions import get_lookup

    trail = "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"
    _seen, client = routed(
        ("DescribeTrails", 200, {"trailList": [{"TrailARN": trail}]}),
        ("GetTrailStatus", 200, {"IsLogging": False}),
        (
            "DescribeConfigurationRecorderStatus",
            200,
            {"ConfigurationRecordersStatus": [{"name": "default", "recording": True}]},
        ),
        ("/detector/", 200, {"status": "DISABLED"}),
        ("/detector", 200, {"detectorIds": ["12abc34d567e8fa901bc2d34e56789f0"]}),
    )
    out = get_lookup("aws.get_defences").run(AWS, {}, client)
    assert out["trail"] == trail
    assert out["recorder"] == ""  # recording: nothing for its action to do
    assert out["detector_id"] == "us-east-1/12abc34d567e8fa901bc2d34e56789f0"


def test_a_public_bucket_is_blocked_and_undo_removes_a_block_it_never_had():
    seen, client = routed(("GET", 404, {"Code": "NoSuchPublicAccessBlockConfiguration"}))
    action = get("aws.block_s3_public_access")
    params = {"bucket": "arn:aws:s3:::acme-data", "region": "eu-west-1"}
    result = action.execute(AWS, params, client)
    put = seen[1]
    assert (put.method, put.url.host, put.url.path) == (
        "PUT",
        "s3.eu-west-1.amazonaws.com",
        "/acme-data",
    )
    assert "publicAccessBlock" in str(put.url) and "content-md5" in put.headers
    assert put.content.decode().count(">true<") == 4
    assert result.undo["prior"] is None
    action.undo(AWS, result.undo, client)
    assert seen[2].method == "DELETE"


def test_a_bucket_that_had_its_own_block_gets_it_back():
    was = (
        "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls>"
        "<IgnorePublicAcls>false</IgnorePublicAcls><BlockPublicPolicy>false</BlockPublicPolicy>"
        "<RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>"
    )
    seen, client = routed(("GET", 200, was))
    action = get("aws.block_s3_public_access")
    result = action.execute(AWS, {"bucket": "acme-data", "region": "us-east-1"}, client)
    action.undo(AWS, result.undo, client)
    assert seen[2].method == "PUT" and seen[2].content.decode().count(">true<") == 1
    with pytest.raises(ValidationError, match="bucket"):
        action.check({"bucket": "arn:aws:kms:us-east-1:123456789012:key/x"})


def test_a_key_scheduled_for_deletion_is_cancelled_enabled_and_can_be_rescheduled():
    key = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    seen, client = routed(("DescribeKey", 200, {"KeyMetadata": {"KeyState": "PendingDeletion"}}))
    action = get("aws.cancel_key_deletion")
    result = action.execute(AWS, {"key_id": key}, client)
    assert [r.headers["x-amz-target"] for r in seen] == [
        "TrentService.DescribeKey",
        "TrentService.CancelKeyDeletion",
        "TrentService.EnableKey",
    ]
    action.undo(AWS, result.undo, client)
    assert json.loads(seen[3].content) == {"KeyId": key, "PendingWindowInDays": 30}
    with pytest.raises(ValidationError, match="KMS key"):
        action.check({"key_id": "snap-0123456789abcdef0"})


def test_a_shared_snapshot_loses_every_grant_and_undo_adds_them_back():
    xml = (
        '<DescribeSnapshotAttributeResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
        "<snapshotId>snap-0123456789abcdef0</snapshotId><createVolumePermission>"
        "<item><userId>999988887777</userId></item><item><group>all</group></item>"
        "</createVolumePermission></DescribeSnapshotAttributeResponse>"
    )
    seen, client = routed(("DescribeSnapshotAttribute", 200, xml))
    action = get("aws.unshare_snapshot")
    params = {"snapshot_id": "snap-0123456789abcdef0", "region": "us-east-1"}
    result = action.execute(AWS, params, client)
    removed = seen[1].content.decode()
    assert "Action=ModifySnapshotAttribute" in removed
    assert "CreateVolumePermission.Remove.1.UserId=999988887777" in removed
    assert "CreateVolumePermission.Remove.2.Group=all" in removed
    action.undo(AWS, result.undo, client)
    assert "CreateVolumePermission.Add.1.UserId=999988887777" in seen[2].content.decode()


def test_an_ami_is_unshared_through_its_launch_permission():
    xml = (
        "<DescribeImageAttributeResponse><launchPermission><item><userId>999988887777</userId>"
        "</item></launchPermission></DescribeImageAttributeResponse>"
    )
    seen, client = routed(("DescribeImageAttribute", 200, xml))
    get("aws.unshare_snapshot").execute(
        AWS, {"snapshot_id": "ami-0123456789abcdef0", "region": "us-east-1"}, client
    )
    assert "LaunchPermission.Remove.1.UserId=999988887777" in seen[1].content.decode()


def test_m365_signs_a_user_out_without_an_entra_credential(tokens):
    seen, client = recorder(body={})
    get("m365.revoke_sessions").execute(Credentials("m365"), {"user": "alice@example.com"}, client)
    assert seen[0].method == "POST"
    assert seen[0].url.path == "/v1.0/users/alice@example.com/revokeSignInSessions"


OKTA = Credentials("okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"})


def test_removing_a_factor_deletes_it_on_okta_and_entra(tokens):
    seen, client = recorder(body={})
    get("okta.remove_factor").execute(OKTA, {"user": "00u1", "factor_id": "opf1"}, client)
    assert seen[0].method == "DELETE" and seen[0].url.path == "/api/v1/users/00u1/factors/opf1"
    entra = Credentials("entra")
    get("entra.remove_factor").execute(
        entra, {"user": "a@example.com", "factor_id": "microsoftAuthenticatorMethods/m1"}, client
    )
    assert (
        seen[1].url.path
        == "/v1.0/users/a@example.com/authentication/microsoftAuthenticatorMethods/m1"
    )
    with pytest.raises(ValidationError, match="Methods"):
        get("entra.remove_factor").execute(entra, {"user": "a", "factor_id": "../roles/x"}, client)


def test_the_factor_to_remove_is_the_newest_one_enrolled_this_week():
    from datetime import UTC, datetime, timedelta

    from shoc.actions import get_lookup

    def ago(days: int) -> str:
        return (datetime.now(UTC) - timedelta(days=days)).isoformat().replace("+00:00", "Z")

    factors = [
        {"id": "old", "factorType": "push", "created": ago(400)},
        {"id": "new", "factorType": "sms", "created": ago(1)},
        {"id": "older", "factorType": "token", "created": ago(3)},
    ]
    _seen, client = recorder(body=factors)
    out = get_lookup("okta.recent_factor").run(OKTA, {"user": "00u1"}, client)
    assert out["factor_id"] == "new" and len(out["factors"]) == 3
    _seen, client = recorder(body=factors[:1])
    assert get_lookup("okta.recent_factor").run(OKTA, {"user": "00u1"}, client)["factor_id"] == ""


def test_gmail_forwarding_is_turned_off_and_restored(tokens):
    was = {"enabled": True, "emailAddress": "drop@example.net", "disposition": "trash"}
    seen, client = recorder(body=was)
    action = get("google.disable_mail_forwarding")
    result = action.execute(Credentials("google"), {"user": "bob@example.com"}, client)
    assert seen[0].url.path == "/gmail/v1/users/bob@example.com/settings/autoForwarding"
    assert seen[1].method == "PUT" and json.loads(seen[1].content) == {"enabled": False}
    action.undo(Credentials("google"), result.undo, client)
    assert json.loads(seen[2].content) == was


def test_a_device_key_expiry_is_turned_back_on_and_restored(monkeypatch):
    monkeypatch.setattr("shoc.ingest.connectors.tailscale.access_token", lambda *a, **k: "t")
    seen, client = recorder(body={"keyExpiryDisabled": True})
    action = get("tailscale.enable_key_expiry")
    result = action.execute(Credentials("tailscale"), {"device_id": "n1"}, client)
    assert (seen[1].method, seen[1].url.path) == ("POST", "/api/v2/device/n1/key")
    assert json.loads(seen[1].content) == {"keyExpiryDisabled": False}
    action.undo(Credentials("tailscale"), result.undo, client)
    assert json.loads(seen[2].content) == {"keyExpiryDisabled": True}


def test_an_openai_project_is_throttled_and_its_limits_come_back():
    limits = {
        "data": [
            {
                "id": "rl-gpt",
                "model": "gpt",
                "max_requests_per_1_minute": 500,
                "max_tokens_per_1_minute": 30000,
            },
        ],
        "has_more": False,
    }
    seen, client = recorder(body=limits)
    creds = Credentials("openai", secret={"admin_key": "k"})
    action = get("openai.limit_project")
    result = action.execute(creds, {"project_id": "proj_1"}, client)
    assert seen[0].url.path == "/v1/organization/projects/proj_1/rate_limits"
    assert seen[1].url.path == "/v1/organization/projects/proj_1/rate_limits/rl-gpt"
    assert json.loads(seen[1].content) == {
        "max_requests_per_1_minute": 1,
        "max_tokens_per_1_minute": 1,
    }
    action.undo(creds, result.undo, client)
    assert json.loads(seen[2].content) == {
        "max_requests_per_1_minute": 500,
        "max_tokens_per_1_minute": 30000,
    }


def test_a_missing_parameter_is_filled_from_the_platform(monkeypatch):
    """The events are out of reach here, so the lookup answers: the key's owner,
    and, for an action with no event column, which trail is off right now."""
    from types import SimpleNamespace

    from shoc.cases import actions as action_store

    answers = {
        "aws.get_access_key": {"user_name": "deploy-ci"},
        "aws.get_defences": {"trail": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main"},
    }
    asked: list[dict] = []

    class Lookup:
        provider = "aws"

        def __init__(self, name: str) -> None:
            self.name = name

        def run(self, creds, params, http=None):
            asked.append(params)
            return answers[self.name]

    monkeypatch.setattr("shoc.actions.get_lookup", Lookup)
    monkeypatch.setattr(action_store.credentials, "load", lambda *a: AWS)
    config = SimpleNamespace(master_key="k")

    params: dict = {"access_key_id": "AKIAEXAMPLE"}
    action_store._resolve(None, "t", get("aws.disable_access_key"), params, config)  # type: ignore[arg-type]
    assert params["user_name"] == "deploy-ci" and asked[-1] == {"access_key_id": "AKIAEXAMPLE"}

    params = {}
    action_store._resolve(None, "t", get("aws.start_cloudtrail_logging"), params, config)  # type: ignore[arg-type]
    assert params["trail"].endswith(":trail/main")


def test_every_provider_but_paging_can_prove_its_credential():
    import importlib

    from shoc.actions.base import NEEDS

    lacking = [
        p for p in NEEDS if not hasattr(importlib.import_module(f"shoc.actions.{p}"), "probe")
    ]
    assert lacking == ["notify"], "a routing key is only proven by a page"


def test_a_probe_says_who_the_key_is_or_what_the_vendor_refused():
    from shoc.actions import probe
    from shoc.errors import StoreError

    def answer(status: int, body: dict) -> httpx.Client:
        return httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(status, json=body))
        )

    assert probe(
        Credentials("github:ci", secret={"token": "t"}), answer(200, {"login": "octo"})
    ) == ("signed in as octo")
    with pytest.raises(StoreError, match="401"):
        probe(Credentials("github", secret={"token": "t"}), answer(401, {}))
    gitlab = Credentials("gitlab", secret={"token": "t"})
    with pytest.raises(ConfigError, match="not an administrator"):
        probe(gitlab, answer(200, {"username": "dev"}))
    assert probe(Credentials("notify", secret={"routing_key": "r"})) is None


def test_every_credential_says_where_to_make_it():
    from shoc.actions.base import NEEDS

    lacking = [p for p, need in NEEDS.items() if "→" not in need.where]
    assert not lacking, "a product's Response onboarding shows this click path"


# -- from the SOAR connectors' most-called contain actions (D126) -------------
def test_a_password_reset_takes_the_password_away_and_never_returns_one(tokens):
    seen, client = recorder(body={})
    okta = Credentials(
        "okta", settings={"org_url": "https://acme.okta.com"}, secret={"api_token": "t"}
    )
    result = get("okta.reset_password").execute(okta, {"user": "00u1"}, client)
    assert (
        seen[0].method == "POST"
        and seen[0].url.path == "/api/v1/users/00u1/lifecycle/reset_password"
    )
    assert seen[0].url.params["sendEmail"] == "true", (
        "recovery, not expiry: the old password must not set the next"
    )
    assert not get("okta.reset_password").reversible and not result.undo

    entra = Credentials("entra")
    result = get("entra.reset_password").execute(entra, {"user": "bob@example.com"}, client)
    profile = json.loads(seen[1].content)["passwordProfile"]
    assert profile["forceChangePasswordNextSignIn"] and len(profile["password"]) >= 40
    assert profile["password"] not in json.dumps(result.to_json())

    google = Credentials("google", settings={"admin_email": "admin@example.com"})
    result = get("google.reset_password").execute(google, {"user": "bob@example.com"}, client)
    sent = json.loads(seen[2].content)
    assert sent["changePasswordAtNextLogin"] and sent["password"] not in json.dumps(
        result.to_json()
    )


def test_quarantining_a_key_user_attaches_aws_policy_and_undo_detaches_it():
    seen, client = recorder(body={})
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    action = get("aws.quarantine_user")
    result = action.execute(
        creds, {"access_key_id": "AKIATARGET", "user_name": "deploy-ci"}, client
    )
    body = seen[0].content.decode()
    assert "Action=AttachUserPolicy" in body and "UserName=deploy-ci" in body
    assert "AWSCompromisedKeyQuarantineV3" in body
    action.undo(creds, result.undo, client)
    assert "Action=DetachUserPolicy" in seen[1].content.decode()


INSTANCE_XML = """<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<reservationSet><item><instancesSet><item>
  <instanceId>i-0abc1234def567890</instanceId><instanceType>t3.large</instanceType>
  <instanceState><code>16</code><name>running</name></instanceState>
  <vpcId>vpc-1</vpcId><subnetId>subnet-1</subnetId><privateIpAddress>10.0.0.5</privateIpAddress>
  <ipAddress>203.0.113.7</ipAddress><iamInstanceProfile><arn>arn:aws:iam::111111111111:instance-profile/web</arn></iamInstanceProfile>
  <groupSet><item><groupId>sg-web</groupId><groupName>web</groupName></item></groupSet>
  <tagSet><item><key>Name</key><value>web-1</value></item></tagSet>
  <networkInterfaceSet>
    <item><networkInterfaceId>eni-a</networkInterfaceId><groupSet><item><groupId>sg-web</groupId></item><item><groupId>sg-ssh</groupId></item></groupSet></item>
    <item><networkInterfaceId>eni-b</networkInterfaceId><groupSet><item><groupId>sg-db</groupId></item></groupSet></item>
  </networkInterfaceSet>
</item></instancesSet></item></reservationSet></DescribeInstancesResponse>"""


def _ec2_double():
    """EC2 by action: the instance in eu-west-1 only, and no isolation group yet."""
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(item.split("=", 1) for item in request.content.decode().split("&"))
        calls.append((request.url.host, form["Action"]))
        if form["Action"] == "DescribeInstances":
            if request.url.host != "ec2.eu-west-1.amazonaws.com":
                return httpx.Response(
                    400,
                    text="<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code></Error></Errors></Response>",
                )
            return httpx.Response(200, text=INSTANCE_XML)
        if form["Action"] == "DescribeSecurityGroups":
            return httpx.Response(
                200,
                text="<DescribeSecurityGroupsResponse><securityGroupInfo/></DescribeSecurityGroupsResponse>",
            )
        if form["Action"] == "CreateSecurityGroup":
            return httpx.Response(
                200,
                text="<CreateSecurityGroupResponse><groupId>sg-iso</groupId></CreateSecurityGroupResponse>",
            )
        if form["Action"] == "RevokeSecurityGroupEgress" and "Ipv6" in request.content.decode():
            return httpx.Response(
                400,
                text="<Response><Errors><Error><Code>InvalidPermission.NotFound</Code></Error></Errors></Response>",
            )
        calls[-1] = (request.url.host, request.content.decode())
        return httpx.Response(200, text="<Response><return>true</return></Response>")

    return calls, httpx.Client(transport=httpx.MockTransport(handler))


def test_isolating_an_instance_swaps_every_interface_for_a_closed_group_and_undo_restores_each():
    calls, client = _ec2_double()
    creds = Credentials(
        "aws",
        settings={"regions": ["us-east-1", "eu-west-1"]},
        secret={"access_key_id": "AKIA", "secret_access_key": "s"},
    )
    action = get("aws.isolate_instance")
    result = action.execute(creds, {"instance_id": "i-0abc1234def567890"}, client)
    assert result.undo == {
        "instance_id": "i-0abc1234def567890",
        "region": "eu-west-1",
        "interfaces": {"eni-a": ["sg-web", "sg-ssh"], "eni-b": ["sg-db"]},
    }
    swaps = [body for _, body in calls if "ModifyNetworkInterfaceAttribute" in body]
    assert len(swaps) == 2 and all(
        "SecurityGroupId.1=sg-iso" in s and "SecurityGroupId.2" not in s for s in swaps
    )
    assert any("RevokeSecurityGroupEgress" in body and "0.0.0.0" in body for _, body in calls)

    calls.clear()
    action.undo(creds, result.undo, client)
    restored = [body for _, body in calls]
    assert any(
        "eni-a" in b and "SecurityGroupId.1=sg-web" in b and "SecurityGroupId.2=sg-ssh" in b
        for b in restored
    )


def test_only_an_instance_is_isolated_and_one_found_nowhere_is_named():
    from shoc.errors import NotFound

    with pytest.raises(ValidationError):
        get("aws.isolate_instance").check({"instance_id": "AKIATARGET"})
    _, client = _ec2_double()
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    with pytest.raises(NotFound, match="us-east-1"):
        get("aws.isolate_instance").execute(creds, {"instance_id": "i-0abc1234def567890"}, client)


def test_an_instance_lookup_reads_its_network_role_and_tags():
    from shoc.actions import get_lookup

    _, client = _ec2_double()
    creds = Credentials("aws", secret={"access_key_id": "AKIA", "secret_access_key": "s"})
    out = get_lookup("aws.get_instance").run(
        creds, {"instance_id": "i-0abc1234def567890", "region": "eu-west-1"}, client
    )
    assert out["state"] == "running" and out["public_ip"] == "203.0.113.7"
    assert out["security_groups"] == ["sg-web"] and out["tags"] == {"Name": "web-1"}
    assert out["role"].endswith("instance-profile/web")
