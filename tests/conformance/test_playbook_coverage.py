"""Every shipped rule's playbook acts on what its positive fixture names (RSP-2, DET-2).

An optional step whose target renders empty is skipped (RFC 0026). A rule whose
findings never carry the entity its playbook's steps read would end every real
case with a page and nothing contained, and the content tests, which only
compare platforms, would still pass. A rule whose events never name the target
is listed in KNOWN with why (qa-1).
"""

from __future__ import annotations

import copy
import functools

import pytest

from shoc.actions import get as get_action
from shoc.capabilities.registry import call
from shoc.cases import engine, playbooks
from shoc.db.pool import execute, fetch_all
from shoc.detect import hunts
from shoc.detect import rules as ruleset
from shoc.ingest import batch
from tests.support import fixture_rows, fixture_source, load_fixture
from tests.unit.test_rules_content import CANNOT_ACT

pytestmark = pytest.mark.postgres

RULES = [r for r in ruleset.load() if r.id not in CANNOT_ACT]
BOOKS = playbooks.load()

# Rules whose playbook has a step on their platform, but whose events never name
# its target, each with why (qa-1). A new rule like these fails, and so does one
# of these that starts acting, so its entry comes out.
_CONSOLE = "a Console session made the change; no API key signed it and none can end it"
_CLOUDFLARE = "a member's session made the change, not an API token; the API cannot end it"
_GCP = "a person's session made the call, not a service account key; removing a grant is a human's"
_GKE = "a person or a Kubernetes service account made the call; no GCP key signed it"
_OKTA = "no sign-in succeeded; okta_sign_in_after_attack_from_address names who got in"
_OPENAI = "a dashboard session names no API key, and no action takes a role back (D56)"
KNOWN = {
    "anthropic_artifact_shared_publicly": _CONSOLE,
    "anthropic_federation_trust_added": _CONSOLE,
    "anthropic_org_data_exported": _CONSOLE,
    "aws_console_login_without_mfa": "a console sign-in carries no access key to disable",
    "aws_root_console_login_without_mfa": "root signs in with no access key; IAM cannot touch root",
    "aws_console_mfa_failed_after_password": "MFA stopped the sign-in; nothing got in",
    "aws_root_account_activity": "IAM cannot disable root's keys or end its sessions",
    # AWS signs the AttachUserPolicy with a session key (ASIA…) of its own.
    "aws_key_quarantined_by_aws": "CloudTrail names the quarantined user, not the leaked key",
    "cloudflare_access_opened": _CLOUDFLARE,
    "cloudflare_api_token_revoked": _CLOUDFLARE,
    "cloudflare_domain_unlocked_or_zone_removed": _CLOUDFLARE,
    "cloudflare_email_routing_forward_added": _CLOUDFLARE,
    "cloudflare_logpush_job_disabled": _CLOUDFLARE,
    "cloudflare_mail_auth_record_changed": _CLOUDFLARE,
    "cloudflare_mail_dns_record_changed": _CLOUDFLARE,
    "cloudflare_member_added_or_changed": _CLOUDFLARE,
    "cloudflare_ssl_downgraded": _CLOUDFLARE,
    "gcp_audit_log_export_tampered": _GCP,
    "gcp_bucket_made_public": _GCP,
    "gcp_disk_image_or_snapshot_shared": _GCP,
    "gcp_identity_federation_changed": _GCP,
    "gcp_kms_key_destroyed": _GCP,
    "gcp_org_guardrail_changed": _GCP,
    "gcp_service_account_impersonated_first_time": "impersonation signs with a token, not a key",
    # The new key is in protoPayload.response.name, but disabling it also needs
    # its service account's email, which no entity kind carries.
    "gcp_service_account_key_created": "the new key's service account is no entity",
    "gke_cluster_admin_bound": _GKE,
    "gke_cluster_opened_to_anonymous": _GKE,
    "gke_privileged_workload_created": _GKE,
    "okta_lockouts_from_one_address": _OKTA,
    "okta_login_failure_burst": _OKTA,
    "okta_password_guessing_one_user_many_addresses": _OKTA,
    "openai_defence_disabled": _OPENAI,
    "openai_login_failure_burst": "failed sign-ins name no key, and nothing got in",
    "openai_owner_role_granted": _OPENAI,
    "openai_workload_identity_trust_added": "a dashboard session names no API key; no action "
    "removes a trust",
    # Blocking the cards one by one does not stop the run; a human adds a CAPTCHA.
    "stripe_card_testing_burst": "a card-testing run has many cards; the playbook pages",
}


@pytest.fixture(scope="module", autouse=True)
def _content_parsed_once():
    """Each step of a run reads every shipped rule and hunt pack again to learn
    the case's platforms (engine.products), and every playbook and the policy:
    most of a second of YAML a step, half an hour over this module. content/
    does not change while it runs, so each file is parsed once. Every call
    still gets its own list, and reads the tenant's merges as before."""

    def once(load_dir):
        parsed = functools.cache(load_dir)
        return lambda directory: list(parsed(directory))

    parse = functools.cache(ruleset.load_yaml)
    with pytest.MonkeyPatch.context() as patch:
        # Nothing changes a loaded rule or pack in place.
        patch.setattr(ruleset, "load_dir", once(ruleset.load_dir))
        patch.setattr(hunts, "load_dir", once(hunts.load_dir))
        # Playbooks and the policy read through rules.load_yaml at call time; a
        # tenant's merges change a loaded playbook's rules (playbooks._bind).
        patch.setattr(ruleset, "load_yaml", lambda text: copy.deepcopy(parse(text)))
        yield


def test_known_lists_only_rules_this_test_runs():
    assert not set(KNOWN) - {r.id for r in RULES}


def _acts_on(action_type: str, product: str) -> bool:
    """On the rule's platform, or on the login its user signs in with (RFC 0027)."""
    action = get_action(action_type)
    return product in (*action.platforms, *action.linked_from)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_the_playbook_acts_on_the_rules_positive_fixture(rule, ctx, config, store, clean, now):
    product = str(rule.logsource.get("product", "")).lower()
    book = next(b for b in BOOKS if rule.id in b.rules)
    # A linked step acts only on an identity provider the tenant reads.
    for source in ("okta", "entra"):
        execute(
            ctx.db,
            """INSERT INTO shoc.connector_config (tenant_id, source, settings)
               VALUES (%s,%s,'{}') ON CONFLICT (tenant_id, source) DO NOTHING""",
            (config.tenant_id, source),
        )
    rows = fixture_rows(
        load_fixture(rule.id, "positive"), fixture_source(rule), config.tenant_id, now
    )
    batch.load(store, rows)
    call("detect.run", ctx, {"rule_id": rule.id, "lookback": "1h"})
    # Every case the fixture opens: its variants can be separate cases, a
    # GuardDuty database finding next to one that names a key.
    found = fetch_all(
        ctx.db,
        """SELECT DISTINCT ON (case_uid) case_uid, event_uids FROM shoc.findings
           WHERE tenant_id = %s AND rule_id = %s AND case_uid IS NOT NULL
           ORDER BY case_uid""",
        (config.tenant_id, rule.id),
    )
    assert found, f"{rule.id} opened no case on its positive fixture"
    acted: list[dict] = []
    said: list[str] = []
    for row in found:
        case, cited = row["case_uid"], list(row["event_uids"])
        engine.set_verdict(ctx.db, config.tenant_id, case, "malicious", 0.95, rule.id, cited)
        run = call("playbook.run", ctx, {"playbook_id": book.id, "case_uid": case, "dry_run": True})
        steps = playbooks.steps_of(ctx.db, run.data.run_uid)
        # Not every optional step renders (a file-hash block on an alert with no
        # hash), but one that acts on the rule's platform must.
        acted += [s for s in steps if s["action_uid"] and _acts_on(s["action_type"], product)]
        said += [f"{case} {s['name']}: {s['state']} {s['result']}" for s in steps]
    if rule.id in KNOWN:
        assert not acted, f"{rule.id} acts now; take it out of KNOWN ({KNOWN[rule.id]})"
    else:
        assert acted, f"{book.id} acted on nothing for {rule.id}: {'; '.join(said)}"
