"""Detection, hunting and intel content guidelines that need no database (CON-G1 to CON-G10).

Each test names its guideline in its docstring. Where shipped content or code
breaks a rule today, the breaches sit in a dict with the reason each is allowed
for now. A test fails on a breach the dict does not hold and on an entry that no
longer breaks the rule, so the dicts only shrink.
"""

from __future__ import annotations

import ast
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from shoc.agents import hunter
from shoc.cases import playbooks
from shoc.cases.policy import SEVERITY_ORDER
from shoc.detect import compiler, engine, hunts, intel, osint
from shoc.detect import rules as ruleset
from shoc.ingest import ocsf
from shoc.store import ocsf as layout
from tests.support import FIXTURES, ROOT, fixture_rows, fixture_source

RULES = ruleset.load()
BY_ID = {r.id: r for r in RULES}
PACKS = hunts.load()
BOOKS = playbooks.load()
NOW = datetime(2026, 10, 1, 12, tzinfo=UTC)
THIS = Path(__file__).resolve()


def _ratchet(found: dict[str, str], known: dict[str, str]) -> None:
    """Fail on a breach `known` does not hold, and on an entry that is no longer one."""
    new = {k: v for k, v in found.items() if k not in known}
    gone = sorted(set(known) - set(found))
    assert not new, "new breaches:\n" + "\n".join(f"  {k}: {v}" for k, v in sorted(new.items()))
    assert not gone, f"these no longer break the rule; take them out of the list: {gone}"


def _products(item: Any) -> set[str]:
    source = item.logsource
    return set(layout.products_for(str(source.get("product", "")), str(source.get("service", ""))))


def _alternatives(block: Any) -> list[dict[str, Any]]:
    """A selection block's alternatives: a list of maps is OR, a map is one."""
    return [a for a in (block if isinstance(block, list) else [block]) if isinstance(a, dict)]


def _rows(kind: str, item_id: str, names: tuple[str, ...], source: str) -> list[dict[str, Any]]:
    """An item's fixtures, mapped as ingest maps them."""
    rows: list[dict[str, Any]] = []
    for name in names:
        path = FIXTURES / kind / item_id / f"{name}.json"
        if path.exists():
            rows += fixture_rows(json.loads(path.read_text()), source, "t", NOW)
    return rows


def _strings(tree: ast.AST) -> list[tuple[ast.AST, str]]:
    """Every string literal, an f-string with each `{}` part written as `{}`."""
    out: list[tuple[ast.AST, str]] = []
    parts: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            text = ""
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.add(id(value))
                    text += str(value.value)
                else:
                    text += "{}"
            out.append((node, text))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in parts:
            continue
        if isinstance(node.value, str):
            out.append((node, node.value))
    return out


def _scopes(tree: ast.AST) -> dict[int, str]:
    """id(node) -> the innermost function or class holding it, dotted."""
    out: dict[int, str] = {}

    def visit(node: ast.AST, name: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = f"{name}.{child.name}" if name else child.name
                for sub in ast.walk(child):
                    out[id(sub)] = inner
                visit(child, inner)
            else:
                visit(child, name)

    visit(tree, "")
    return out


def _sources() -> list[Path]:
    return sorted((ROOT / "shoc").rglob("*.py"))


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


# -- CON-G1 severity moves with its playbook --------------------------------------
DETECT_4 = "detect-4: below its playbook's trigger; contained only if the Investigator raises it"
BELOW_TRIGGER: dict[str, tuple[str, ...]] = {
    "contain_account_recovery_abuse": (
        "okta_password_reset_by_admin",
        "entra_password_reset_by_admin",
        "entra_temporary_access_pass_created",
        "google_backup_codes_issued_by_admin",
    ),
    "contain_account_takeover": (
        "okta_fastpass_phishing_blocked",
        "edr_medium_identity_or_email_alert",
    ),
    "contain_admin_account_misuse": (
        "okta_api_token_created",
        "okta_user_deactivated_or_deleted",
        "okta_support_impersonation",
        "okta_api_token_revoked",
        "okta_super_admin_revoked",
    ),
    "contain_anthropic_org_change": (
        "anthropic_admin_role_granted",
        "anthropic_federation_trust_added",
        "anthropic_artifact_shared_publicly",
    ),
    "contain_aws_data_exposure": ("aws_lambda_opened_to_outside",),
    "contain_azure_compromise": (
        "azure_privileged_access_granted",
        "azure_disk_download_link_created",
        "azure_automation_runbook_or_webhook_created",
    ),
    "contain_cloudflare_account_change": ("cloudflare_mail_auth_record_changed",),
    "contain_endpoint_compromise": (
        "edr_medium_severity_detection",
        "sentinelone_exclusion_changed",
        "endpoint_local_admin_granted",
        "endpoint_anydesk_unattended_setup",
        "endpoint_autostart_runs_script_from_user_folder",
    ),
    "contain_github_org_tampering": (
        "github_secret_changed",
        "github_webhook_deleted",
        "github_self_hosted_runner_registered",
        "github_deploy_key_added",
        "github_mass_clone",
        "github_force_push_to_default_branch",
        "github_workflow_change_blocked",
        "github_fine_grained_pat_granted",
        "github_actions_permissions_loosened",
        "github_collaborator_given_admin",
    ),
    "contain_gitlab_tampering": (
        "gitlab_member_made_owner",
        "gitlab_access_token_created",
        "gitlab_runner_registered",
    ),
    "contain_google_workspace_compromise": (
        "google_admin_privilege_granted",
        "google_marketplace_app_installed",
        "google_custom_admin_role_changed",
        "google_suspended_user_reactivated",
        "google_third_party_app_access_loosened",
        "google_drive_external_share_burst",
    ),
    "contain_leaked_cloud_key": (
        "aws_access_key_created",
        "aws_access_denied_burst",
        "aws_iam_user_created",
        "aws_console_password_set_for_user",
        "aws_access_key_new_address",
        "aws_caller_identity_first_call",
    ),
    "contain_leaked_llm_key": ("anthropic_api_key_created", "openai_api_key_created"),
    "contain_m365_account_abuse": (
        "m365_mailbox_permission_granted",
        "m365_anonymous_sharing_link_created",
        "m365_bulk_file_download",
        "m365_file_download_by_script",
        "m365_transport_rule_changed",
        "m365_mail_connector_changed",
    ),
    "contain_openai_owner_change": (
        "openai_owner_role_granted",
        "openai_login_failure_burst",
        "openai_workload_identity_trust_added",
    ),
    "contain_password_spray": (
        "okta_login_failure_burst",
        "entra_sign_in_failure_burst",
        "aws_console_login_failure_burst",
        "okta_lockouts_from_one_address",
        "okta_password_guessing_one_user_many_addresses",
        "m365_sign_in_failure_burst",
        "m365_password_guessing_one_user",
    ),
    "contain_phishing_site_visit": ("cloudflare_gateway_phishing_resolved",),
    "contain_privilege_grant": (
        "okta_admin_privilege_granted",
        "entra_admin_role_assigned",
        "m365_exchange_role_assigned",
        "entra_guest_promoted_to_member",
    ),
    "contain_stripe_account_takeover": (
        "stripe_admin_access_granted",
        "stripe_secret_key_created_or_viewed",
        "stripe_sign_in_factor_changed",
    ),
    "contain_tailscale_tampering": (
        "tailscale_admin_role_granted",
        "tailscale_acl_changed",
        "tailscale_dns_config_changed",
        "tailscale_node_shared_out",
    ),
    "restore_aws_defences": ("aws_password_policy_weakened",),
    "revoke_third_party_app_access": ("github_oauth_app_authorized", "entra_app_credential_added"),
}


def test_every_rule_can_reach_its_playbooks_trigger():
    """CON-G1: a rule's severity reaches the trigger of the playbook that lists it."""
    found: dict[str, str] = {}
    for book in BOOKS:
        floor = SEVERITY_ORDER.index(book.trigger.severity_at_least)
        for rule_id in book.rules:
            if rule_id.startswith("hunt:"):
                continue
            rule = BY_ID[rule_id]
            if SEVERITY_ORDER.index(rule.severity) < floor:
                found[f"{book.id}:{rule_id}"] = (
                    f"{rule.severity} under a {book.trigger.severity_at_least} trigger"
                )
    known = {f"{book}:{rule}": DETECT_4 for book, ids in BELOW_TRIGGER.items() for rule in ids}
    _ratchet(found, known)


def test_sibling_rules_share_a_severity():
    """CON-G1: rules that differ only in their product token share one severity."""
    groups: dict[str, dict[str, str]] = {}
    for rule in RULES:
        _, _, rest = rule.id.partition("_")
        groups.setdefault(rest, {})[rule.id] = rule.severity
    split = {name: ids for name, ids in groups.items() if len(set(ids.values())) > 1}
    assert not split, f"siblings disagree on severity: {split}"


# -- CON-G2 every named field is written by a mapping -----------------------------
# Columns map_record writes for every source, whatever its mapping says.
ALWAYS_WRITTEN = {
    "tenant_id",
    "event_uid",
    "time",
    "ingested_at",
    "metadata_version",
    "observables",
    "unmapped",
    "raw",
    "category_uid",
    "type_uid",
}
# `raw.` and `unmapped.` paths no row of the item's own fixtures holds.
UNPROVEN_PATHS = {
    "aws_ses_identity_verified_then_deleted:fields:raw.requestParameters.emailIdentity": (
        "a display field the SES v2 call writes; the fixture is the v1 call"
    ),
    "gcp_identity_federation_changed:fields:"
    "raw.protoPayload.request.workloadIdentityPoolProvider.attributeCondition": (
        "a display field; the fixture creates a pool provider without a condition"
    ),
    "stripe_payout_to_new_destination:fields:raw.data.object.arrival_date": (
        "a display field the fixture's payout does not carry"
    ),
    "aws_iam_user_temporary_token_iam_calls:filter_console": (
        "the pack's fixtures hold no console session, so the filter is never exercised"
    ),
    "aws_sns_sms_first_use:selection_sms": "the surfaced fixture shows only the SMS set-up calls",
    "endpoint_remote_logon_new_source:sel_defender": "the fixtures hold SentinelOne logons only",
    "endpoint_remote_logon_new_source:sel_falcon": "the fixtures hold SentinelOne logons only",
    "linux_rare_process_external_connection:sel_linux_fdr": (
        "the fixtures hold SentinelOne Cloud Funnel records only"
    ),
}


def _written() -> dict[str, set[str]]:
    """metadata_product -> the columns its mappings write."""
    out: dict[str, set[str]] = {}
    for source in ocsf.available_sources():
        mapping = ocsf.load_mapping(source)
        columns = set(mapping.constants) | set(mapping.fields) | ALWAYS_WRITTEN
        for rule in mapping.derive:
            columns |= set(rule.get("set") or {})
        product = str(mapping.constants.get("metadata_product") or "")
        out.setdefault(product, set()).update(columns)
    return out


def _named_lists(item: Any) -> list[tuple[str, list[str]]]:
    """The field lists an item names outside its selection blocks."""
    if isinstance(item, hunts.Pack):
        b = item.baseline
        among = [b.rare_among] if b.rare_by else []
        return [
            ("first_seen", b.first_seen),
            ("rare.by", b.rare_by),
            ("rare.among", among),
            ("pivot", item.pivot),
        ]
    det = item.detection
    return [
        ("entity", item.entity),
        ("fields", item.fields),
        ("group_by", det.group_by),
        ("sequence.by", list(det.sequence.get("by") or [])),
        ("first_seen", item.first_seen),
        ("count_distinct", [det.count_distinct] if det.count_distinct else []),
    ]


def _block_fields(alternative: dict[str, Any]) -> list[str]:
    out = []
    for key, value in alternative.items():
        name, _, modifier = key.partition("|")
        out.append(name)
        if modifier == "fieldref":
            out.append(str(value))
    return out


def _content() -> list[tuple[Any, str, tuple[str, ...]]]:
    """Every shipped rule and pack, with its fixtures directory and fixture names."""
    rules = [(r, "rules", ("positive", "negative")) for r in RULES]
    packs = [(p, "hunts", ("surfaced", "baseline")) for p in PACKS]
    return [*rules, *packs]


def _resolves(rows: list[dict[str, Any]], path: str) -> bool:
    match = layout.JSON_FIELD.match(path)
    assert match, path
    root, rest = match.group(1), match.group(2)[1:]
    return any(ocsf.dig(row.get(root) or {}, rest) is not None for row in rows)


def test_every_named_field_is_written_by_a_mapping():
    """CON-G2: a field a rule or pack names is written by a mapping on its products,
    or is a raw path its own fixtures hold."""
    written = _written()
    missing: list[str] = []
    found: dict[str, str] = {}
    for item, kind, names in _content():
        products = _products(item)
        columns = set().union(*(written.get(p, set()) for p in products))
        rows = _rows(kind, item.id, names, fixture_source(item))
        named = [(f, where) for where, fields in _named_lists(item) for f in fields]
        for block, value in item.detection.blocks.items():
            named += [(f, block) for a in _alternatives(value) for f in _block_fields(a)]
        for field, where in named:
            if layout.JSON_FIELD.match(field):
                continue
            column = layout.column_for(field)
            if column not in columns:
                missing.append(f"{kind}/{item.id} {where}: {field} ({column}) on {products}")
        # A raw path: one alternative of a block, or every path of a list, in a fixture row.
        for block, value in item.detection.blocks.items():
            paths = [
                [f for f in _block_fields(a) if layout.JSON_FIELD.match(f)]
                for a in _alternatives(value)
            ]
            paths = [p for p in paths if p]
            if paths and not any(all(_resolves(rows, f) for f in p) for p in paths):
                found[f"{item.id}:{block}"] = f"{paths} in no row of {kind}/{item.id}"
        for where, fields in _named_lists(item):
            raw = [f for f in fields if layout.JSON_FIELD.match(f)]
            if where == "entity":
                # The first entity field with a value keys the finding.
                if raw and not any(_resolves(rows, f) for f in raw):
                    found[f"{item.id}:entity"] = f"{raw} in no row of {kind}/{item.id}"
                continue
            for f in raw:
                if not _resolves(rows, f):
                    found[f"{item.id}:{where}:{f}"] = f"in no row of {kind}/{item.id}"
    assert not missing, "fields no mapping on the item's products writes:\n" + "\n".join(missing)
    _ratchet(found, UNPROVEN_PATHS)


# Columns kernel code reads by name off a scan row that are not evidence columns:
# each is read only when the rule or pack selects it.
SELECTED_ONLY = {
    "device_hostname": (
        "left out of the evidence on purpose (compiler.EVIDENCE_COLUMNS); a rule's "
        "fields or a pack's pivot selects it"
    ),
}
# What every compiled pack selects besides its own fields (compiler.compile_pack).
PACK_SELECTS = {"api_operation", "class_name", "time", "ingested_at"}


def test_kernel_reads_only_selected_columns():
    """CON-G2: kernel code reads off a scan row only columns the scan selects."""
    evidence = set(compiler.EVIDENCE_COLUMNS)
    tree = ast.parse((ROOT / "shoc" / "detect" / "engine.py").read_text())
    entities_of = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "entities_of"
    )
    literal: set[str] = set()
    for node in ast.walk(entities_of):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "row"
            and isinstance(node.slice, ast.Constant)
        ):
            literal.add(str(node.slice.value))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "row"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            literal.add(str(node.args[0].value))
    reads = {
        "engine.ENTITY_COLUMNS": set(engine.ENTITY_COLUMNS),
        "engine.HASH_COLUMNS": set(engine.HASH_COLUMNS),
        "engine.entities_of": literal,
        "hunter.ACTORS": set(hunter.ACTORS) - PACK_SELECTS,
    }
    unselected = {
        where: sorted(columns - evidence - set(SELECTED_ONLY))
        for where, columns in reads.items()
        if columns - evidence - set(SELECTED_ONLY)
    }
    assert not unselected, f"read off a scan row but never selected: {unselected}"
    used = set().union(*reads.values())
    assert set(SELECTED_ONLY) <= used, f"stale: {set(SELECTED_ONLY) - used}"
    assert not set(SELECTED_ONLY) & evidence, "an evidence column needs no entry"


# -- CON-G3 coverage counts only what the tenant delivers -------------------------
ATTACK_19 = "not in the ATT&CK 19.2 map content/attack_platforms.json ships; retag it"
UNMAPPED_TAGS: dict[str, tuple[str, ...]] = {
    "rules/anthropic_defence_disabled": ("T1562.008", "T1562.007"),
    "rules/aws_admin_policy_attached": ("T1562.008",),
    "rules/aws_cloudtrail_logging_disabled": ("T1562.008",),
    "rules/aws_config_recorder_stopped": ("T1562.008",),
    "rules/aws_guardduty_disabled": ("T1562.001",),
    "rules/aws_secondary_logging_disabled": ("T1562.008", "T1562.001"),
    "rules/aws_security_group_admin_port_opened": ("T1562.007",),
    "rules/azure_logging_disabled": ("T1562.008",),
    "rules/azure_nsg_opened_to_internet": ("T1562.007",),
    "rules/cloudflare_access_opened": ("T1562.007",),
    "rules/cloudflare_api_token_revoked": ("T1562.008",),
    "rules/cloudflare_domain_unlocked_or_zone_removed": ("T1562.007",),
    "rules/cloudflare_logpush_job_disabled": ("T1562.008",),
    "rules/cloudflare_mail_auth_record_changed": ("T1656",),
    "rules/cloudflare_ssl_downgraded": ("T1562",),
    "rules/endpoint_event_log_cleared": ("T1070.001",),
    "rules/endpoint_remote_desktop_enabled": ("T1562.004",),
    "rules/endpoint_security_tool_disabled": ("T1562.001",),
    "rules/endpoint_service_kill_burst": ("T1562.001",),
    "rules/entra_auth_policy_changed": ("T1562.001",),
    "rules/entra_conditional_access_changed": ("T1562.001",),
    "rules/gcp_audit_log_export_tampered": ("T1562.008",),
    "rules/gcp_firewall_opened_to_internet": ("T1562.007",),
    "rules/gcp_org_guardrail_changed": ("T1562",),
    "rules/github_actions_permissions_loosened": ("T1562.001",),
    "rules/github_protected_branch_removed": ("T1562.001",),
    "rules/github_security_feature_disabled": ("T1562.001",),
    "rules/github_webhook_deleted": ("T1562.008",),
    "rules/gitlab_protected_branch_removed": ("T1562.001",),
    "rules/google_backup_codes_issued_by_admin": ("T1656",),
    "rules/m365_mail_protection_weakened": ("T1562.001", "T1562.008"),
    "rules/m365_transport_rule_changed": ("T1562.001",),
    "rules/okta_network_zone_changed": ("T1562.007",),
    "rules/okta_org_attack_protection_relaxed": ("T1562.001",),
    "rules/okta_org_authenticator_deactivated": ("T1562.001",),
    "rules/openai_defence_disabled": ("T1562.007",),
    "rules/sentinelone_exclusion_changed": ("T1562.001",),
    "rules/stripe_defence_disabled": ("T1562",),
    "rules/tailscale_acl_changed": ("T1562.007",),
    "rules/tailscale_defence_disabled": ("T1562.001",),
    "hunts/endpoint_defender_exclusion_first_seen": ("T1562.001",),
    "hunts/endpoint_defender_exclusion_registry_first_seen": ("T1562.001",),
}


def test_every_attack_tag_is_in_the_shipped_attack_map():
    """CON-G3: an ATT&CK tag on shipped content is a technique the shipped map lists."""
    known_ids = json.loads((ROOT / "content" / "attack_platforms.json").read_text())["platforms"]
    found = {
        f"{kind}/{item.id}:{tag}": "not in content/attack_platforms.json"
        for kind, items in (("rules", RULES), ("hunts", PACKS))
        for item in items
        for tag in item.attack
        if tag not in known_ids
    }
    known = {f"{item}:{tag}": ATTACK_19 for item, tags in UNMAPPED_TAGS.items() for tag in tags}
    _ratchet(found, known)


# Filters that leave out the rule's own noise rather than hand values to another rule.
EXCLUSIONS = {
    "aws_bedrock_abuse:filter_bedrock": "Bedrock's own endpoints are the key's expected use",
    "aws_bedrock_abuse:filter_credential_check": "SDK credential checks before a Bedrock call",
    "defender_browser_credential_file_read:filter_browsers": (
        "the browsers and Defender reading their own files"
    ),
    "edr_medium_severity_detection:filter_rollups": (
        "Falcon's incident and lead summaries repeat the detections they group"
    ),
    "endpoint_browser_debugging_cookie_theft:filter_automation_parent": (
        "test automation and editor debuggers"
    ),
    "endpoint_remote_desktop_enabled:filter_gui": "the switches an admin clicks in Settings",
    "github_oauth_app_authorized:filter_cleanup": "the clean-up after an app, not a grant",
    "github_repo_made_public:filter_not_public": "the other direction of repo.access",
    "gitlab_member_made_owner:filter_was_owner": "a member who was already an owner",
    "google_suspicious_login_flagged:filter_passkey": "Google files passkey changes as warnings",
    "m365_inbox_rule_created:filter_rule_removed": "a rule being removed, not created",
    "okta_security_policy_changed:filter_runtime": "a policy running, not a policy changed",
}
DETECT_2 = (
    "detect-2: Defender XDR delivers these alerts; only azure_vendor_alert selects them, "
    "on Azure Activity"
)
HANDED_OFF = {
    f"{rule}:filter_not_endpoint:{value}": DETECT_2
    for rule in (
        "edr_detection_on_many_hosts",
        "edr_high_severity_detection",
        "edr_medium_severity_detection",
        "edr_ransomware_detection",
    )
    for value in ("microsoftDefenderForCloud", "unknownFutureValue")
}


def _selected(rule: ruleset.Rule) -> dict[str, set[str]]:
    """field -> the values a rule's selection blocks match it against, lower-cased."""
    out: dict[str, set[str]] = {}
    for name, block in rule.detection.blocks.items():
        if name.startswith("filter"):
            continue
        for alternative in _alternatives(block):
            for key, value in alternative.items():
                if "|" in key:
                    continue
                values = value if isinstance(value, list) else [value]
                out.setdefault(key, set()).update(str(v).lower() for v in values)
    return out


def test_values_a_rule_hands_off_are_selected_elsewhere():
    """CON-G3: every value a filter lists is selected by another rule on the same products."""
    selected = {r.id: _selected(r) for r in RULES}
    products = {r.id: _products(r) for r in RULES}
    found: dict[str, str] = {}
    lists: set[str] = set()
    for rule in RULES:
        for name, block in rule.detection.blocks.items():
            if not name.startswith("filter"):
                continue
            for alternative in _alternatives(block):
                if len(alternative) != 1:
                    continue
                ((key, values),) = alternative.items()
                if "|" in key or not isinstance(values, list):
                    continue
                lists.add(f"{rule.id}:{name}")
                if f"{rule.id}:{name}" in EXCLUSIONS:
                    continue
                for value in values:
                    if not any(
                        str(value).lower() in selected[other.id].get(key, set())
                        for other in RULES
                        if other.id != rule.id and products[other.id] & products[rule.id]
                    ):
                        found[f"{rule.id}:{name}:{value}"] = f"{key} selected by no other rule"
    assert set(EXCLUSIONS) <= lists, f"stale exclusions: {set(EXCLUSIONS) - lists}"
    _ratchet(found, HANDED_OFF)


# -- CON-G4 a baseline says how it learns -----------------------------------------
DETECT_7 = "detect-7: learning left to the quiet default (D142); the maintainers still choose"
LEARNING_UNSAID = {
    rule_id: DETECT_7
    for rule_id in (
        "anthropic_api_key_usage_spike",
        "aws_access_key_new_address",
        "aws_caller_identity_first_call",
        "aws_ses_abuse",
        "entra_first_party_client_oauth_phishing",
        "gcp_service_account_impersonated_first_time",
        "openai_api_key_usage_spike",
        "stripe_payout_to_new_destination",
    )
}


def test_a_first_seen_rule_says_how_it_learns():
    """CON-G4: a first_seen rule sets baseline.while_learning itself."""
    found: dict[str, str] = {}
    for rule in RULES:
        if not rule.first_seen:
            continue
        assert rule.path, rule.id
        baseline = (yaml.safe_load(rule.path.read_text()) or {}).get("baseline") or {}
        if "while_learning" not in baseline:
            found[rule.id] = f"{_rel(rule.path)} has no baseline.while_learning"
    _ratchet(found, LEARNING_UNSAID)


UNINDEXED = "13 packs anti-join weeks of history on unindexed keys and time out on Postgres"
UNINDEXED_PACKS = {
    pack_id: UNINDEXED
    for pack_id in (
        "anthropic_mcp_server_first_seen",
        "dns_remote_access_relay_first_seen",
        "endpoint_cloud_storage_client_first_seen_on_host",
        "endpoint_defender_exclusion_first_seen",
        "endpoint_defender_exclusion_registry_first_seen",
        "endpoint_remote_access_tool_first_seen",
        "endpoint_tunnel_client_first_seen_on_host",
        "entra_app_consent_first_seen",
        "github_self_hosted_runner_first_seen",
        "github_workflow_first_run_in_repo",
        "gws_oauth_client_first_seen",
        "gws_oauth_client_new_network",
        "okta_sign_in_via_new_identity_provider",
    )
}


def test_a_first_seen_pack_starts_from_an_indexed_column():
    """CON-G4: a first_seen pack keys on an indexed column; a rare pack below a band is new_only."""
    found: dict[str, str] = {}
    for pack in PACKS:
        b = pack.baseline
        keys = {layout.alias_for(f) for f in b.first_seen}
        if b.first_seen and not keys & set(compiler.INDEXED):
            found[pack.id] = f"first_seen {b.first_seen} holds none of {compiler.INDEXED}"
    _ratchet(found, UNINDEXED_PACKS)
    loose = [p.id for p in PACKS if p.baseline.seen_by_fewer_than > 0 and not p.baseline.new_only]
    assert not loose, f"rare packs reporting the same grouping every day: {loose}"


# -- CON-G5 a sequence joins on ids -----------------------------------------------
JOIN_KEYS = {
    "actor.user.uid",
    "actor.session.uid",
    "device.uid",
    "resource.uid",
    "cloud.account.uid",
    "src_endpoint.ip",
}
JOINED_ON_NAMES = {
    "aws_federation_token_used": (
        "a federated session names the IAM user that issued it, so both CloudTrail "
        "events write the same userName"
    ),
    "google_sign_in_after_prompt_denial": (
        "both login events are Workspace's own and name the account by its primary email"
    ),
}


def test_a_sequence_joins_on_ids():
    """CON-G5: a sequence's `by` keys are ids both events write byte for byte."""
    found = {
        rule.id: f"by {rule.detection.sequence['by']}"
        for rule in RULES
        if rule.detection.sequence and not set(rule.detection.sequence["by"]) <= JOIN_KEYS
    }
    _ratchet(found, JOINED_ON_NAMES)


# -- CON-G6 fixtures are what the connector delivers ------------------------------
DETECT_15 = "detect-15: the negative has no history record, so the baseline is never exercised"
NO_HISTORY = {
    rule_id: DETECT_15
    for rule_id in (
        "anthropic_api_key_usage_spike",
        "aws_access_key_new_address",
        "aws_caller_identity_first_call",
        "aws_ses_abuse",
        "entra_first_party_client_oauth_phishing",
        "openai_api_key_usage_spike",
    )
}
# A negative row from another stream than the rule's, on purpose.
OTHER_STREAM = {
    "edr_high_severity_detection": (
        "the same Defender alert read from Advanced Hunting must not fire the alert rule twice"
    ),
    "edr_ransomware_detection": (
        "the same Defender alert read from Advanced Hunting must not fire the alert rule twice"
    ),
}


def test_negatives_are_near_misses():
    """CON-G6: a negative fixture is on the rule's own products, a baseline rule's negative
    carries the history that silences it, and an alert rule's carries an update record."""
    history: dict[str, str] = {}
    elsewhere: dict[str, str] = {}
    updates: list[str] = []
    for rule in RULES:
        products = _products(rule)
        mapped_by = fixture_source(rule)
        records = json.loads((FIXTURES / "rules" / rule.id / "negative.json").read_text())
        negative = fixture_rows(records, mapped_by, "t", NOW)
        off = sorted({str(r.get("metadata_product")) for r in negative} - products)
        if off:
            elsewhere[rule.id] = f"negative rows from {off}"
        if (
            rule.first_seen
            and rule.while_learning != "fire"
            and not any(float(r.get("_day_offset") or 0) > 0 for r in records)
        ):
            history[rule.id] = "no negative record with a _day_offset"
        positive = _rows("rules", rule.id, ("positive",), mapped_by)
        source = rule.logsource
        alerts = source.get("product") == "edr" and source.get("service") == "alerts"
        if (
            alerts
            and any(r.get("class_uid") == 2004 for r in positive)
            and not any(r.get("activity_id") == 2 for r in negative)
        ):
            updates.append(rule.id)
    for pack in PACKS:
        products = _products(pack)
        for kind in ("surfaced", "baseline"):
            rows = _rows("hunts", pack.id, (kind,), fixture_source(pack))
            off = sorted({str(r.get("metadata_product")) for r in rows} - products)
            if off:
                elsewhere[f"hunt:{pack.id}:{kind}"] = f"rows from {off}"
    _ratchet(elsewhere, OTHER_STREAM)
    _ratchet(history, NO_HISTORY)
    assert not updates, f"alert rules with no update record in their negative: {updates}"


# -- CON-G7 a cap sorts, filters first and reports what it cut --------------------
# Every module-level int in the detection and hunting modules, and what keeps it
# honest: a test that pins it, `harmless:` with why it drops no input, or `gap:`
# for a cap that drops input with no test yet.
CAPS = {
    "shoc/detect/context.py:DAYS": "harmless: the history a context block reads, not a row cap",
    "shoc/detect/context.py:SHOWN": "harmless: what a context block shows; it moves no cursor",
    "shoc/detect/engine.py:MAX_EVIDENCE": (
        "tests/conformance/test_rules.py::test_every_hit_is_evaluated_however_many_there_are"
    ),
    "shoc/detect/engine.py:PAGE": (
        "tests/conformance/test_rules.py::test_every_hit_is_evaluated_however_many_there_are"
    ),
    "shoc/detect/engine.py:MAX_GROUPS": (
        "tests/conformance/test_rules.py::test_more_groups_than_the_cap_still_fire_on_the_heaviest"
    ),
    "shoc/detect/engine.py:MAX_BUCKETS": (
        "gap: past it the newest buckets are evaluated and the rest named in rule_state; "
        "no test pins it"
    ),
    "shoc/detect/engine.py:ADHOC_LIMIT": (
        "tests/conformance/test_rules.py::test_an_ad_hoc_run_reads_at_most_its_limit"
    ),
    "shoc/detect/intake.py:SAME_STORY_DAYS": "harmless: when two reports are one story",
    "shoc/detect/intel.py:PER_SOURCE": (
        "gap: each source's best 5,000 indicators are matched; the rest are not, unrecorded"
    ),
    "shoc/detect/intel.py:PREVALENT_ACTORS": (
        "tests/conformance/test_intel.py::test_a_value_everybody_touches_is_held_not_raised"
    ),
    "shoc/detect/intel.py:AUTHENTICATION": "harmless: an OCSF class id",
    "shoc/detect/intel.py:FEODO_DAYS": (
        "tests/unit/test_intel_feeds.py::test_feodo_becomes_high_confidence_c2_addresses"
    ),
    "shoc/detect/intel.py:OTX_PAGES": (
        "tests/unit/test_intel_feeds.py::test_otx_reads_every_page_on_its_own_host"
    ),
    "shoc/detect/intel.py:MISP_PAGES": (
        "tests/unit/test_intel_feeds.py::test_misp_asks_for_published_detection_values_page_by_page"
    ),
    "shoc/detect/intel.py:FULL_TEXT": (
        "tests/unit/test_intel_feeds.py::test_rss_keeps_the_summary_date_and_categories"
    ),
    "shoc/detect/intel.py:SUMMARY_CHARS": (
        "harmless: cuts the summary a feed item carries; the report itself is read whole"
    ),
    "shoc/detect/intel.py:ROWS": (
        "tests/conformance/test_intel.py::test_a_noisy_value_does_not_hide_a_quiet_one_in_its_batch"
    ),
    "shoc/detect/intel.py:PRESENT": (
        "harmless: past it the matcher asks the store about each indicator instead"
    ),
    "shoc/detect/report.py:MAX_BYTES": (
        "tests/unit/test_report.py::test_a_body_is_read_no_further_than_the_cap_or_the_deadline"
    ),
    "shoc/detect/report.py:MAX_TEXT": (
        "gap: a report's text is cut at 200,000 characters and marked truncated; no test pins it"
    ),
    "shoc/detect/report.py:REDIRECTS": (
        "tests/unit/test_report.py::test_redirects_are_followed_by_hand_and_counted"
    ),
    "shoc/detect/report.py:PROSE_LIMIT": (
        "tests/unit/test_report.py::test_ioc_tables_reach_the_model_once_in_the_values_list"
    ),
    "shoc/agents/hunter.py:MAX_ROWS_PER_PACK": (
        "tests/conformance/test_hunts.py::"
        "test_a_pack_that_stops_at_its_limit_ends_its_window_at_the_last_row_read"
    ),
    "shoc/agents/hunter.py:TOO_MANY_TUPLES": (
        "tests/conformance/test_hunts.py::"
        "test_too_many_tuples_are_triaged_in_order_and_the_rest_named"
    ),
    "shoc/agents/hunter.py:SLICES_PER_RUN": (
        "tests/unit/test_hunter.py::test_catch_up_stops_at_its_slices_and_says_what_it_lost"
    ),
    "shoc/agents/hunter.py:SHOWN_EVENTS": (
        "tests/unit/test_hunter.py::"
        "test_the_prompt_shows_a_few_event_ids_and_the_tuple_keeps_them_all"
    ),
    "shoc/agents/hunter.py:TRIAGE_STEPS": "harmless: a model budget; it moves no cursor",
    "shoc/agents/hunter.py:TRIAGE_CALLS": "harmless: a model budget; it moves no cursor",
    "shoc/agents/hunter.py:HUNT_CASE_TOKENS": (
        "tests/conformance/test_hunts.py::test_a_case_only_hunts_opened_has_a_token_ceiling"
    ),
    "shoc/agents/hunter.py:PROMOTE_AFTER": "harmless: readings before a finding, not a row cap",
    "shoc/agents/hunter.py:MAX_AGENDA_TECHNIQUES": (
        "harmless: the day's agenda, worked out again the next day; it moves no cursor"
    ),
    "shoc/agents/hunter.py:LISTED": (
        "tests/unit/test_hunter.py::test_a_new_country_from_many_addresses_is_one_tuple_per_person"
    ),
    "shoc/agents/hunter.py:LEARNING_SHOWN": (
        "tests/unit/test_hunter.py::"
        "test_the_learning_digest_reads_every_product_and_names_the_quietest"
    ),
    "shoc/agents/hunter.py:ITEMS_PER_RUN": "harmless: the items left stay open for the next run",
    "shoc/agents/hunter.py:PACK_STEPS": "harmless: a model budget; it moves no cursor",
    "shoc/agents/hunter.py:PACK_CALLS": "harmless: a model budget; it moves no cursor",
    "shoc/agents/hunter.py:PACK_TOKENS_PER_DAY": "harmless: a model budget; it moves no cursor",
    "shoc/agents/hunter.py:STUCK_AFTER": (
        "tests/conformance/test_hunts.py::test_a_pack_the_gate_never_accepted_is_not_packed"
    ),
    "shoc/agents/hunter.py:BASELINE_DAYS_BEFORE": "harmless: where a fixture is placed",
    "shoc/agents/detection_engineer.py:NOISY_FINDINGS_7D": "harmless: a health threshold",
    "shoc/agents/detection_engineer.py:SILENT_DAYS": "harmless: a health threshold",
    "shoc/agents/detection_engineer.py:BACKTEST_DAYS": "harmless: a backtest's default window",
    "shoc/agents/detection_engineer.py:NARROWING_DAYS": "harmless: a narrowing's replay window",
    "shoc/agents/detection_engineer.py:SEEN_ON_DAYS": "harmless: an exclusion's evidence floor",
    "shoc/agents/detection_engineer.py:ITEMS_PER_TURN": (
        "harmless: the items left stay open for the next turn"
    ),
    "shoc/agents/detection_engineer.py:STEPS_PER_ITEM": "harmless: a model budget",
    "shoc/agents/detection_engineer.py:CALLS_PER_ITEM": "harmless: a model budget",
    "shoc/agents/detection_engineer.py:DAILY_TOKENS": "harmless: a model budget",
    "shoc/agents/detection_engineer.py:STUCK_AFTER": "harmless: failed turns before an item stops",
    "shoc/capabilities/intel.py:MAX_ATTEMPTS": (
        "tests/conformance/test_intel_reading.py::"
        "test_a_report_that_keeps_failing_is_dropped_and_reported"
    ),
    "shoc/capabilities/intel.py:QUEUE_DAYS": (
        "tests/conformance/test_intel_reading.py::"
        "test_a_report_that_keeps_failing_is_dropped_and_reported"
    ),
    "shoc/capabilities/intel.py:KEEP_DAYS": "harmless: how long a queue row already read is kept",
    "shoc/capabilities/intel.py:LISTED": (
        "harmless: a digest lists this many values per type; the lines holding the rest stay"
    ),
}
CAP_MODULES = (
    *sorted((ROOT / "shoc" / "detect").glob("*.py")),
    ROOT / "shoc" / "agents" / "hunter.py",
    ROOT / "shoc" / "agents" / "detection_engineer.py",
    ROOT / "shoc" / "capabilities" / "intel.py",
    ROOT / "shoc" / "capabilities" / "hunting.py",
)


def _int_value(node: ast.AST | None) -> int | None:
    """An int a module-level constant holds: a literal, or literals multiplied or added."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add, ast.Sub)):
        left, right = _int_value(node.left), _int_value(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Mult):
            return left * right
        return left + right if isinstance(node.op, ast.Add) else left - right
    return None


def _test_exists(ref: str) -> bool:
    path, _, name = ref.partition("::")
    file = ROOT / path
    if not file.exists():
        return False
    tree = ast.parse(file.read_text())
    return any(isinstance(n, ast.FunctionDef) and n.name == name for n in tree.body)


def test_every_cap_is_reported_or_harmless():
    """CON-G7: every int cap in the detection and hunting modules is pinned by a test or
    said to drop no input."""
    found: dict[str, int] = {}
    for module in CAP_MODULES:
        for node in ast.parse(module.read_text()).body:
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            else:
                continue
            number = _int_value(node.value)
            for target in targets:
                name = target.id if isinstance(target, ast.Name) else ""
                if number is not None and name.lstrip("_").isupper():
                    found[f"{_rel(module)}:{name}"] = number
    assert not set(found) - set(CAPS), f"say what keeps these honest: {set(found) - set(CAPS)}"
    assert not set(CAPS) - set(found), f"stale: {set(CAPS) - set(found)}"
    tests = [p for p in (ROOT / "tests").rglob("*.py") if p.resolve() != THIS]
    texts = [p.read_text() for p in tests]
    for key, why in CAPS.items():
        name = key.rsplit(":", 1)[1]
        if why.startswith("tests/"):
            assert _test_exists(why), f"{key}: no test {why}"
        elif why.startswith("gap: "):
            named = re.compile(rf"\.{name}\b|[\"']{name}[\"']")
            pinned = [p for p, t in zip(tests, texts, strict=True) if named.search(t)]
            assert not pinned, f"{key}: {pinned[0]} now names it; map it to that test"
        else:
            assert why.startswith("harmless: "), f"{key}: a test, `harmless:` or `gap:`"


LIMIT = re.compile(r"\bLIMIT\s+(\{\}|%\(\w+\)s|%s|:\w+|\w+)")
UNORDERED_ON_PURPOSE = {
    "shoc/detect/intel.py:_present": (
        "LIMIT n + 1 only tells an overflow; a truncated answer is thrown away whole"
    ),
    "shoc/worker.py:prune": "a batch delete that loops until no row is left",
}
UNORDERED = {
    "shoc/agents/surveyor.py:exposure_of": "CON-G7: five exposures of an entity, any five",
    "shoc/cases/credentials.py:owners": "CON-G7: 200 cited events of a case, any 200",
    "shoc/cases/credentials.py:products_behind": "CON-G7: 200 cited events of a case, any 200",
    "shoc/cases/review.py:case_citations": "CON-G7: a case's citations, cut in no set order",
}


def test_every_limit_has_an_order():
    """CON-G7: a SELECT with a LIMIT other than 1 orders its rows before the LIMIT."""
    found: dict[str, str] = {}
    for path in _sources():
        tree = ast.parse(path.read_text())
        scopes = _scopes(tree)
        for node, text in _strings(tree):
            if not re.search(r"\bSELECT\b", text):
                continue
            for match in LIMIT.finditer(text):
                if match.group(1) == "1" or re.search(r"\bORDER\s+BY\b", text[: match.start()]):
                    continue
                where = f"{_rel(path)}:{scopes.get(id(node), '<module>')}"
                found[where] = f"line {getattr(node, 'lineno', '?')}: {match.group(0)}"
    stale = sorted(set(UNORDERED_ON_PURPOSE) - set(found))
    assert not stale, f"no longer an unordered LIMIT: {stale}"
    _ratchet({k: v for k, v in found.items() if k not in UNORDERED_ON_PURPOSE}, UNORDERED)


# -- CON-G8 one classifier per indicator kind -------------------------------------
# What an UPDATE of a stored indicator sets.
IOC_UPDATE = re.compile(r"\bUPDATE\s+shoc\.iocs\s+SET\b(.*?)(?:\bWHERE\b|$)", re.S)


def test_iocs_are_written_in_one_place():
    """CON-G8: only intel.store_indicators inserts into shoc.iocs, and no UPDATE retypes
    or rewrites a stored value."""
    inserts: list[str] = []
    rewrites: list[str] = []
    for path in _sources():
        tree = ast.parse(path.read_text())
        scopes = _scopes(tree)
        for node, text in _strings(tree):
            where = f"{_rel(path)}:{scopes.get(id(node), '<module>')}"
            if re.search(r"\bINSERT\s+INTO\s+shoc\.iocs\b", text, re.I):
                inserts.append(where)
            for sets in IOC_UPDATE.findall(text):
                if re.search(r"(?<![\w.])(value|type)\s*=", sets):
                    rewrites.append(where)
    assert inserts == ["shoc/detect/intel.py:store_indicators"], inserts
    assert not rewrites, f"a stored indicator's value or type is rewritten in {rewrites}"


SAMPLES = {
    "ipv4": "203.0.113.7",
    "ipv6": "2001:db8::1",
    "domain": "evil.example.com",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
# Matched by anything: a pattern that takes these recognises no kind.
CONTROLS = ("hello", "zz", "x y", "12", "abc_def")
CLASSIFIERS = {"shoc/detect/report.py", "shoc/detect/osint.py"}
NOT_INDICATORS = {
    "shoc/actions/gcp.py:KEY": "a service-account key id an action is handed, not an indicator",
    "shoc/capabilities/users.py:DOMAIN": "an email domain a person sets for sign-in",
}
CTI_3 = "cti-3: a second typing of indicators; read them through report.extract or osint.classify"
OWN_PATTERNS = {
    "shoc/agents/observables.py:_HASHES": CTI_3,
    "shoc/agents/observables.py:_IPV4": CTI_3 + " (it knows no IPv6)",
    "shoc/capabilities/ask.py:IP": CTI_3 + " (it knows no IPv6)",
}


def _flags(node: ast.AST) -> int:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return int(getattr(re, node.attr, 0))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _flags(node.left) | _flags(node.right)
    return 0


def _compiled(tree: ast.AST) -> list[tuple[str, ast.Call]]:
    """(name, call) for each re.compile of a literal; the name is what it is assigned to."""
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "compile"
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "re"
        and n.args
        and isinstance(n.args[0], ast.Constant)
        and isinstance(n.args[0].value, str)
    ]
    names: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            for sub in ast.walk(node.value):
                names.setdefault(id(sub), node.targets[0].id)
    return [(names.get(id(c), f"line {c.lineno}"), c) for c in calls]


def test_indicator_patterns_live_in_report_and_osint():
    """CON-G8: only report.py and osint.py hold patterns that type an address, a domain
    or a hash."""
    found: dict[str, str] = {}
    for path in _sources():
        if _rel(path) in CLASSIFIERS:
            continue
        for name, call in _compiled(ast.parse(path.read_text())):
            literal = call.args[0]
            assert isinstance(literal, ast.Constant)
            flags = _flags(call.args[1]) if len(call.args) > 1 else 0
            flags |= sum(_flags(k.value) for k in call.keywords if k.arg == "flags")
            try:
                pattern = re.compile(str(literal.value), flags)
            except re.error:
                continue
            if any(pattern.fullmatch(c) for c in CONTROLS):
                continue
            kinds = [kind for kind, value in SAMPLES.items() if pattern.fullmatch(value)]
            if kinds:
                found[f"{_rel(path)}:{name}"] = f"types {', '.join(kinds)}"
    stale = sorted(set(NOT_INDICATORS) - set(found))
    assert not stale, f"no longer a match; take them out of NOT_INDICATORS: {stale}"
    _ratchet({k: v for k, v in found.items() if k not in NOT_INDICATORS}, OWN_PATTERNS)


@pytest.mark.parametrize(
    ("kind", "value", "stored"),
    [
        ("ip", "2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("ip", "2001:db8::1", "2001:db8::1"),
        ("ip", "203.0.113.7", "203.0.113.7"),
        ("ip", "203.0.113.0/24", ""),
        ("domain", "Evil.Example.TEST.", "evil.example.test"),
        ("domain", "shop.example.xn--p1ai", "shop.example.xn--p1ai"),
        ("url", "https://user:pw@Bad.example.test/x", "https://user:pw@bad.example.test/x"),
        ("url", "http://[2001:DB8::5]/x", "http://[2001:db8::5]/x"),
    ],
)
def test_normalise_matches_what_events_write(kind, value, stored):
    """CON-G8: intel.normalise stores a value as the matcher reads events: an address as
    the mapping's `ip` transform writes it, a name and a URL lower-cased as the matcher
    lower-cases event values, and '' for what no event column holds."""
    assert osint.classify(value) in (kind, "")
    assert intel.normalise(kind, value) == stored
    if kind == "ip":
        assert stored == (ocsf.TRANSFORMS["ip"](value) or "")


# -- CON-G10 feed indicators expire and stay below the action floor ---------------
ACTION_FLOOR = 0.8
# A curated C2 list may meet the floor on its own.
CURATED = {"abuse_ch_feodo"}
FEODO = (
    "# abuse.ch Feodo Tracker\n"
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
    '"2026-09-01 10:00:00","203.0.113.10","443","online","2026-09-30","Dridex"\n'
)
CANNED: dict[str, tuple[dict[str, Any], Any]] = {
    "abuse_ch_feodo": ({}, FEODO),
    "abuse_ch_urlhaus": ({}, "# urlhaus\nhttps://bad.example.test/loader.bin\n"),
    "otx": (
        {},
        {
            "results": [
                {"name": "Pulse", "indicators": [{"type": "IPv4", "indicator": "203.0.113.5"}]}
            ],
            "next": None,
        },
    ),
    "misp": (
        {"url": "https://misp.example.test"},
        {"response": {"Attribute": [{"type": "ip-dst", "value": "203.0.113.6"}]}},
    ),
    "list": ({"url": "https://iocs.example.test/list.txt"}, "203.0.113.80\nc2.example.com\n"),
}
SECRETS = {"otx": {"api_key": "k"}, "misp": {"api_key": "k"}}
CTI_5 = "cti-5: listing passes a person's confidence and days: 0 through unclamped"
OVER_THE_FLOOR = {"list:configured": CTI_5}


def _serve(monkeypatch: pytest.MonkeyPatch, body: Any) -> None:
    """Answer every feed request, and a listed page, with `body`."""
    from shoc.detect import report

    def answer(request: httpx.Request) -> httpx.Response:
        if isinstance(body, (dict, list)):
            return httpx.Response(200, json=body, request=request)
        return httpx.Response(200, text=body, request=request)

    monkeypatch.setattr(
        intel,
        "_client",
        lambda headers=None, follow_redirects=True: httpx.Client(
            transport=httpx.MockTransport(answer), follow_redirects=follow_redirects
        ),
    )
    monkeypatch.setattr(report, "get", lambda url: answer(httpx.Request("GET", url)))


def test_every_feed_expires_and_stays_under_the_action_floor(monkeypatch):
    """CON-G10: every feed indicator expires and sits below the 0.8 action floor, except a
    curated C2 list's."""
    assert set(CANNED) == set(intel.FEEDS), "give a new feed a canned response here"
    cases = [(name, settings, body) for name, (settings, body) in CANNED.items()]
    configured = {**CANNED["list"][0], "confidence": 0.95, "days": 0}
    cases.append(("list:configured", configured, CANNED["list"][1]))
    found: dict[str, str] = {}
    for case, settings, body in cases:
        name = case.split(":", 1)[0]
        _serve(monkeypatch, body)
        indicators = intel.FEEDS[name](settings, SECRETS.get(name, {}))
        assert indicators, f"{case}: the canned response gave no indicator"
        for ioc in indicators:
            if ioc.expires_at is None:
                found[case] = f"{ioc.value} never expires"
            elif name not in CURATED and ioc.confidence >= ACTION_FLOOR:
                found[case] = f"{ioc.value} at {ioc.confidence} meets the action floor"
    _ratchet(found, OVER_THE_FLOOR)


# An OTX or MISP pull with nothing new in its window is an ordinary day.
EMPTY_IS_NORMAL = {"otx", "misp"}
EMPTY = {
    "abuse_ch_feodo": '# abuse.ch\n"first_seen_utc","dst_ip","dst_port","c2_status"\n',
    "abuse_ch_urlhaus": "# urlhaus\n",
    "list": "",
}
CTI_EMPTY = "an empty abuse.ch body or page counts as success while its indicators expire"
QUIET_WHEN_EMPTY = dict.fromkeys(EMPTY, CTI_EMPTY)


def test_an_empty_pull_is_a_failure(monkeypatch):
    """CON-G10: a pull that comes back empty or header-only is recorded as an error."""
    assert set(EMPTY) | EMPTY_IS_NORMAL == set(intel.FEEDS)
    recorded: dict[str, intel.FeedResult] = {}
    monkeypatch.setattr(intel, "ours", lambda conn, tenant_id: lambda value, kind: False)
    monkeypatch.setattr(
        intel,
        "record_run",
        lambda conn, tenant_id, feed, settings, result: recorded.__setitem__(feed, result),
    )
    found: dict[str, str] = {}
    conn: Any = None  # refresh reaches the database only through what is patched above
    for name, body in EMPTY.items():
        _serve(monkeypatch, body)
        settings = CANNED[name][0]
        result = intel.refresh(conn, "t", name, settings, SECRETS.get(name, {}))
        assert recorded[name] is result
        if not result.error:
            found[name] = f"fetched {result.fetched}, no error"
    _ratchet(found, QUIET_WHEN_EMPTY)
