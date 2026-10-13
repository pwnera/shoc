"""shoc's own response credentials and the people who run it are never acted on
without a person (RFC 0021, D78, D141)."""

from __future__ import annotations

import pytest

from shoc.cases import actions as action_store
from shoc.cases import credentials, own, playbooks
from shoc.db.pool import execute
from tests.support import malicious_case

pytestmark = pytest.mark.postgres

KEY = "AKIAIOSFODNN7EXAMPLE"  # the leaked_aws_key scenario's key


def _crew(conn, config, case_uid: str, action: str, **params: str) -> dict:
    """A proposal as the crew's loop makes it: grounded, from an agent."""
    return action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(action_type=action, params=params, case_uid=case_uid),
        "IR Commander",
        principal_kind="agent",
        config=config,
    )


def test_shocs_own_response_key_waits_for_a_person(conn, store, config, clean):
    """Disabled by a playbook, the key could not have undone it."""
    case = malicious_case(conn, config.tenant_id, "leaked_aws_key", store)
    credentials.store(
        conn,
        config.tenant_id,
        "aws",
        {},
        {"access_key_id": KEY, "secret_access_key": "test"},
        config.master_key,
    )
    row = _crew(conn, config, case, "aws.disable_access_key", access_key_id=KEY)
    assert row["autonomy"] == "L2" and row["state"] == "proposed"
    assert "shoc's own" in row["rationale"]


def test_a_playbook_step_on_shocs_own_key_waits_for_a_person(conn, store, config, clean):
    """The runner acts as a service, not an agent; the guard is the same."""
    case = malicious_case(conn, config.tenant_id, "leaked_aws_key", store)
    credentials.store(
        conn,
        config.tenant_id,
        "aws",
        {},
        {"access_key_id": KEY, "secret_access_key": "test"},
        config.master_key,
    )
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.disable_access_key",
            params={"access_key_id": KEY},
            case_uid=case,
            run_uid="RUN-test",
        ),
        "playbook-runner",
        principal_kind="service",
        config=config,
    )
    assert row["autonomy"] == "L2" and row["state"] == "proposed"
    assert "shoc's own" in row["rationale"]


def test_the_key_shoc_reads_cloudtrail_with_waits_for_a_person(conn, store, config, clean):
    """Disabled by a playbook, shoc would stop seeing the account it protects."""
    import json

    from shoc.db.secrets import seal

    case = malicious_case(conn, config.tenant_id, "leaked_aws_key", store)
    secret = {"access_key_id": KEY, "secret_access_key": "test"}
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'aws_cloudtrail', true, %s, %s)""",
        (
            config.tenant_id,
            json.dumps({"region": "us-east-1"}),
            seal(config.master_key, secret, config.tenant_id, "connector_config", "aws_cloudtrail"),
        ),
    )
    assert KEY.lower() in own.protected(conn, config.tenant_id, config.master_key)
    row = _crew(conn, config, case, "aws.disable_access_key", access_key_id=KEY)
    assert row["autonomy"] == "L2" and row["state"] == "proposed"
    assert "shoc's own" in row["rationale"]


def test_a_source_whose_secret_cannot_be_opened_is_skipped(conn, config, clean):
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'okta', true, '{}'::jsonb, %s)""",
        (config.tenant_id, b"not a sealed secret"),
    )
    with_key = own.protected(conn, config.tenant_id, config.master_key)
    assert with_key == own.protected(conn, config.tenant_id), "and nothing else fails"


def test_the_login_a_response_token_acts_as_is_protected(conn, config, clean):
    """Okta's and GitHub's probes record it as `acts_as` (WP-VENDOR)."""
    credentials.store(
        conn,
        config.tenant_id,
        "okta",
        {"org_url": "https://example.okta.com", "acts_as": "Svc-Shoc@example.com"},
        {"api_token": "test"},
        config.master_key,
    )
    assert "svc-shoc@example.com" in own.protected(conn, config.tenant_id, config.master_key)
    assert "svc-shoc@example.com" not in own.protected(conn, config.tenant_id)


def test_the_aws_role_shoc_assumes_waits_for_a_person(conn, store, config, clean):
    """Its sessions revoked, shoc could not sign another call; even where a
    deployment's policy lets the crew revoke a role's sessions alone."""
    from shoc.cases.policy import Policy

    case = malicious_case(conn, config.tenant_id, "leaked_aws_key", store)
    credentials.store(
        conn,
        config.tenant_id,
        "aws",
        {"role_arn": "arn:aws:iam::000000000001:role/security/ShocResponder"},
        {"access_key_id": KEY, "secret_access_key": "test"},
        config.master_key,
    )
    held = own.protected(conn, config.tenant_id, config.master_key)
    assert "shocresponder" in held, "the role's name, past its path"
    assert "arn:aws:iam::000000000001:role/security/shocresponder" in held
    policy = Policy.load(config)
    policy.actions["aws.revoke_role_sessions"] = dict(policy.actions["aws.disable_access_key"])
    row = action_store.propose(
        conn,
        config.tenant_id,
        action_store.Proposal(
            action_type="aws.revoke_role_sessions",
            params={"role_name": "ShocResponder"},
            case_uid=case,
        ),
        "IR Commander",
        principal_kind="agent",
        config=config,
        policy=policy,
    )
    assert row["autonomy"] == "L2" and row["state"] == "proposed"
    assert "shoc's own" in row["rationale"]


def test_an_enabled_shoc_admin_is_not_signed_out_without_a_person(conn, store, config, clean):
    """In a company this size, the admin who granted a role is often the operator."""
    case = malicious_case(conn, config.tenant_id, "okta_mfa_fatigue", store)
    user = playbooks.entities_of_case(conn, config.tenant_id, case)["user"]
    execute(
        conn,
        """INSERT INTO shoc.users (tenant_id, user_id, email, role, created_by)
           VALUES (%s, 'u-admin', %s, 'admin', 'test')""",
        (config.tenant_id, user.lower()),
    )
    assert user.lower() in own.protected(conn, config.tenant_id)
    row = _crew(conn, config, case, "okta.revoke_sessions", user=user)
    assert row["autonomy"] == "L2" and "the operator's" in row["rationale"]
