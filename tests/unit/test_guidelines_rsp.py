"""The response, autonomy and paging guidelines, checked on the code (RSP-G1 to RSP-G12).

No database, no model. The walks read shoc/ with `ast`, and content/ through the
loaders. A rule the code breaks today is listed in a test's KNOWN with why it is
allowed for now; the test fails on a break that is not listed and on a listed
one that no longer breaks, so each list only shrinks.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from shoc.actions import available
from shoc.actions import get as get_action
from shoc.actions.base import NEEDS
from shoc.cases import credentials, own, playbooks
from shoc.cases.actions import make_uid, target_key
from shoc.cases.policy import Policy
from shoc.detect import rules as ruleset
from tests.support import ROOT

SHOC = ROOT / "shoc"
ACTIONS = {name: get_action(name) for name in available()}
BOOKS = playbooks.load()
RULES = ruleset.load()


# -- walking shoc/ --------------------------------------------------------------
@dataclass
class Site:
    """One call in shoc/: where it is, the function around it, and the node."""

    path: str
    scope: str
    call: ast.Call
    # The outermost function the call is in, to read what its arguments were.
    function: ast.AST | None = None

    @property
    def key(self) -> str:
        return f"{self.path}:{self.scope}"

    @property
    def where(self) -> str:
        return f"{self.path}:{self.call.lineno} in {self.scope or '<module>'}"


@dataclass
class Text:
    """One string in shoc/, an f-string's parts joined with `{name}` for each value."""

    path: str
    scope: str
    line: int
    text: str
    names: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.path}:{self.scope}"

    @property
    def where(self) -> str:
        return f"{self.path}:{self.line} in {self.scope or '<module>'}"


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _receiver(call: ast.Call) -> str:
    """`engine` in `engine.transition(...)`, or "" for a bare name."""
    func = call.func
    return _name(func.value) if isinstance(func, ast.Attribute) else ""


def _arg(call: ast.Call, at: int, name: str) -> ast.expr | None:
    """The argument passed at position `at` or as `name`."""
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return call.args[at] if len(call.args) > at else None


def _inner(child: ast.AST, scope: str) -> str:
    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return f"{scope}.{child.name}" if scope else child.name
    return scope


def _walk(node: ast.AST, path: str, scope: str, top: ast.AST | None) -> Iterator[Site]:
    for child in ast.iter_child_nodes(node):
        inner = _inner(child, scope)
        outer = top
        if top is None and isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
            outer = child
        if isinstance(child, ast.Call):
            yield Site(path, inner, child, outer)
        yield from _walk(child, path, inner, outer)


def _strings(node: ast.AST, path: str, scope: str) -> Iterator[Text]:
    for child in ast.iter_child_nodes(node):
        inner = _inner(child, scope)
        if not scope and isinstance(child, ast.Assign | ast.AnnAssign):
            # A module constant is named after what it is assigned to.
            target = child.targets[0] if isinstance(child, ast.Assign) else child.target
            inner = target.id if isinstance(target, ast.Name) else inner
        if isinstance(child, ast.JoinedStr):
            parts: list[str] = []
            names: list[str] = []
            for value in child.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    names.append(ast.unparse(value.value))
                    parts.append("{" + names[-1] + "}")
            yield Text(path, inner, child.lineno, "".join(parts), tuple(names))
            continue
        if isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant):
            continue  # a docstring says what the code does; it is not SQL
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield Text(path, inner, child.lineno, child.value)
        yield from _strings(child, path, inner)


def _files(*under: str) -> list[tuple[str, ast.Module]]:
    out: list[tuple[str, ast.Module]] = []
    for place in under or ("shoc",):
        root = ROOT / place
        for file in [root] if root.is_file() else sorted(root.rglob("*.py")):
            rel = file.relative_to(ROOT).as_posix()
            out.append((rel, ast.parse(file.read_text(), rel)))
    return out


def _calls(*callees: str) -> list[Site]:
    """Every call in shoc/ whose callee's last name is one of `callees`."""
    return [
        site
        for rel, tree in _files()
        for site in _walk(tree, rel, "", None)
        if _name(site.call.func) in callees
    ]


def _texts(*under: str) -> list[Text]:
    return [text for rel, tree in _files(*under) for text in _strings(tree, rel, "")]


def _ratchet(rule: str, found: Mapping[str, str], known: Mapping[str, object]) -> None:
    """Fail on a break KNOWN does not list, and on a KNOWN entry that no longer breaks."""
    new = sorted(found[k] for k in found if k not in known)
    assert not new, f"{rule} broken at:\n" + "\n".join(new)
    fixed = sorted(set(known) - set(found))
    assert not fixed, f"{rule} now holds for {', '.join(fixed)}: take it out of KNOWN"


def _identity(action: Any) -> tuple[str, ...]:
    return tuple(getattr(action, "identity_params", None) or action.required_params)


def _acts(step: playbooks.Step) -> bool:
    return bool(step.action) and not step.action.startswith("notify.")


def _reads(step: playbooks.Step) -> list[str]:
    """Every placeholder a step's parameters read, `rule.x.user` for `{{ rule.x.user }}`."""
    return playbooks.PLACEHOLDER.findall(json.dumps(step.params))


# -- RSP-G1 an action's id covers its whole target ------------------------------
def test_every_identity_parameter_changes_the_action_id_and_shows_in_its_plan():
    """RSP-G1: every parameter that names a target is in the action's id and in its plan.

    A partial id merged a second inbox rule or IAM policy on one user into the
    first one's done row (ir-1).
    """
    wrong: list[str] = []
    for name, action in ACTIONS.items():
        names = _identity(action)
        if not set(names) <= set(action.required_params):
            wrong.append(f"{name}: identity_params {names} are not all required parameters")
        params = {p: f"[{p}]" for p in action.required_params}
        uid = make_uid("t", name, target_key(action, params), "C")
        for p in names:
            other = make_uid("t", name, target_key(action, {**params, p: "other"}), "C")
            if other == uid:
                wrong.append(f"{name}: {p} does not change its action id")
        plan = action.plan(params)
        wrong += [f"{name}: its plan leaves out {p}" for p in params if params[p] not in plan]
    assert not wrong, "\n".join(wrong)


def _keyed(function: ast.AST | None, name: str) -> bool:
    """Whether `name` in this function is set from `target_key(...)`, and only
    ever has a constant appended (the preview's `|dry run`)."""
    made = False
    for node in ast.walk(function) if function is not None else ():
        if isinstance(node, ast.Assign) and name in [_name(t) for t in node.targets]:
            if not isinstance(node.value, ast.Call) or _name(node.value.func) != "target_key":
                return False
            made = True
        elif isinstance(node, ast.AugAssign) and _name(node.target) == name:
            if not isinstance(node.value, ast.Constant):
                return False
    return made


def test_an_action_id_comes_only_from_target_key():
    """RSP-G1: `make_uid` makes an action's id in `actions.propose` alone, from
    the key `target_key` gives over every identity parameter."""
    wrong: list[str] = []
    for site in _calls("make_uid"):
        if site.path == "shoc/cases/engine.py" or _receiver(site.call) == "engine":
            continue  # a case's id, made from its entity and day
        if site.key != "shoc/cases/actions.py:propose":
            wrong.append(f"{site.where}: an action id made outside actions.propose")
            continue
        target = _arg(site.call, 2, "target")
        if not isinstance(target, ast.Name) or not _keyed(site.function, target.id):
            wrong.append(f"{site.where}: the id's target does not come from target_key")
    assert not wrong, "\n".join(wrong)


def _context(values: dict[str, list[str]]) -> dict[str, Any]:
    return {
        "case": {"title": "t"},
        "rule": {"x": {p: v[0] for p, v in values.items()}},
        "each": {"rule": {"x": values}},
    }


# A step fans out and is hashed on its action's first required parameter alone,
# so a second policy or role on one user is never a step of its own.
TARGET_TEXT_KNOWN = {
    "shoc/cases/playbooks.py:_target_text": "RSP-G1 gap: reads required_params[0] only",
}


def test_a_step_fans_out_on_every_parameter_of_its_action_id():
    """RSP-G1: the parameters that make an action's id drive a step's fan-out and
    the run's target hash (`playbooks.plan`, `playbooks.targets`)."""
    missed: list[str] = []
    for name, action in ACTIONS.items():
        names = _identity(action)
        if name.startswith("notify.") or len(names) < 2:
            continue
        book = playbooks.Playbook.from_dict(
            {
                "id": "fan_out",
                "title": "Fan out",
                "rules": ["x"],
                "steps": [
                    {
                        "name": "act",
                        "action": name,
                        "params": {p: "{{ rule.x." + p + " }}" for p in names},
                    }
                ],
            }
        )
        one = {p: [f"[{p}]"] for p in names}
        for p in names:
            two = playbooks.plan(book, _context({**one, p: [f"[{p}]", f"[{p}]-2"]}))
            moved = playbooks.targets(book, _context({**one, p: ["other"]}))
            if len(two) != 2 or moved == playbooks.targets(book, _context(one)):
                missed.append(f"{name}.{p}")
    found: dict[str, str] = {}
    if missed:
        found["shoc/cases/playbooks.py:_target_text"] = (
            f"shoc/cases/playbooks.py: a step never fans out or re-runs on {', '.join(missed)}"
        )
    _ratchet("RSP-G1", found, TARGET_TEXT_KNOWN)


# -- RSP-G2 a page counts as sent only when a channel took it --------------------
def test_a_page_is_never_a_dry_run():
    """RSP-G2: notify.* is never a dry run, whatever SHOC_DRY_RUN or a policy says.

    A stock install recorded every dry-run page as sent while nobody was woken (sre-1).
    """
    shipped = Policy.load()
    pages = sorted({t for t in [*shipped.actions, *available()] if t.startswith("notify.")})
    assert pages, "notify.page is shipped"
    for kind in pages:
        assert kind in shipped.actions, f"{kind} is not in the policy, so it is never decided"
        assert shipped.dry_run_for(kind, True) is False, f"{kind}: SHOC_DRY_RUN=1 held it"
        assert shipped.dry_run_for(kind, None) is False, f"{kind}: the policy held it"
        decision = shipped.decide(
            kind, principal_kind="agent", severity="critical", dry_run_default=True
        )
        assert not decision.dry_run, f"{kind} was decided as a plan"
        # A policy file that asks for a dry run of a page is not obeyed either.
        asked = Policy(actions={kind: {"autonomy": "L1", "reversible": True, "dry_run": True}})
        assert asked.dry_run_for(kind, None) is False, f"{kind}: a policy's dry_run held it"


# -- RSP-G4 undo restores the recorded state ------------------------------------
# Reversible actions that keep no snapshot because they need none: execute only
# creates what shoc owns and undo deletes it by the id execute returned, or what
# they change does not outlive them (a sign-out, a page).
CREATES_ONLY = {
    "cloudflare.block_ip": "creates an access rule; undo deletes that rule by its id",
    "crowdstrike.block_hash": "creates an indicator; undo deletes that indicator by its id",
    "defender.block_hash": "creates an indicator; undo deletes that indicator by its id",
    "sentinelone.block_hash": "creates blocklist entries; undo deletes only the ones it made",
    "stripe.block_charge_card": "creates Radar list items; undo deletes those items by id",
    "notify.page": "triggers a page; undo resolves that page by its dedup key",
    "entra.revoke_sessions": "a sign-out; undo has nothing to put back",
    "google.revoke_sessions": "a sign-out; undo has nothing to put back",
    "m365.revoke_sessions": "a sign-out; undo has nothing to put back",
    "okta.revoke_sessions": "a sign-out; undo has nothing to put back",
}
# ir-11: the before-state is read inside execute, so a retry after a lost answer
# reads the changed state as the one to restore.
READ_IN_EXECUTE = "ir-11: reads its before-state in execute, which a retry reads again"
# ir-11: undo assumes the state before was the opposite of what execute set.
ASSUMED = "ir-11: undo puts back an assumed state, not one it read"
SNAPSHOT_KNOWN = {
    "anthropic.disable_api_key": READ_IN_EXECUTE,
    "aws.block_s3_public_access": READ_IN_EXECUTE,
    "aws.cancel_key_deletion": READ_IN_EXECUTE,
    "aws.unshare_snapshot": READ_IN_EXECUTE,
    "cloudflare.disable_api_token": READ_IN_EXECUTE,
    "gcp.disable_firewall_rule": READ_IN_EXECUTE,
    "github.enable_secret_scanning": READ_IN_EXECUTE,
    "github.make_repo_private": READ_IN_EXECUTE,
    "github.remove_deploy_key": READ_IN_EXECUTE,
    "google.disable_mail_forwarding": READ_IN_EXECUTE,
    "m365.revoke_app_consent": READ_IN_EXECUTE,
    "openai.limit_project": READ_IN_EXECUTE,
    "tailscale.enable_key_expiry": READ_IN_EXECUTE,
    "aws.detach_role_policy": ASSUMED,
    "aws.detach_user_policy": ASSUMED,
    "aws.enable_guardduty": ASSUMED,
    "aws.start_cloudtrail_logging": ASSUMED,
    "aws.start_config_recorder": ASSUMED,
    "azure.stop_vm": ASSUMED,
    "crowdstrike.isolate_host": ASSUMED,
    "defender.isolate_host": ASSUMED,
    "entra.suspend_user": ASSUMED,
    "gcp.disable_service_account": ASSUMED,
    "gcp.disable_service_account_key": ASSUMED,
    "gitlab.block_user": ASSUMED,
    "google.suspend_user": ASSUMED,
    "okta.suspend_user": ASSUMED,
    "sentinelone.isolate_host": ASSUMED,
    "tailscale.deauthorize_device": ASSUMED,
    "tailscale.suspend_user": ASSUMED,
}


def test_every_reversible_action_keeps_what_it_changed():
    """RSP-G4: a reversible action reads what it changes through `snapshot`, which
    `actions._act_with` stores before the change and reuses on every retry.

    Undo restored an assumed state: a key already Inactive was turned on again (ir-11).
    """
    found = {
        name: f"{name}: reversible, and its undo restores a state no snapshot read"
        for name, action in ACTIONS.items()
        if action.reversible and name not in CREATES_ONLY and not hasattr(action, "snapshot")
    }
    _ratchet("RSP-G4", found, SNAPSHOT_KNOWN)
    stale = [
        name
        for name in CREATES_ONLY
        if name not in ACTIONS or not ACTIONS[name].reversible or hasattr(ACTIONS[name], "snapshot")
    ]
    assert not stale, f"take {', '.join(stale)} out of CREATES_ONLY"


# -- RSP-G5 a step acts on what a rule named ------------------------------------
# ir-5: steps that act on `{{ entity.<kind> }}`, the case's alphabetically first
# value of a kind, which on a case of several findings is the wrong account or
# key. Each names the placeholders it reads today; it may only lose them.
ENTITY_SCOPED = {
    "contain_account_recovery_abuse": {
        "revoke the reset account's sessions in Okta": "entity.resource",
        "revoke the reset account's sessions in Entra ID": "entity.resource",
        "sign the reset account out of every Google session": "entity.resource",
        "remove the factor enrolled after the reset in Okta": "entity.resource",
        "remove the factor enrolled after the reset in Entra ID": "entity.resource",
        "suspend the reset account in Okta": "entity.resource",
        "suspend the reset account in Entra ID": "entity.resource",
        "suspend the reset account in Google": "entity.resource",
    },
    "contain_account_takeover": {
        "revoke the user's sessions in Okta": "entity.user",
        "revoke the user's sessions in Entra ID": "entity.user",
        "remove the factor the attacker enrolled in Okta": "entity.user",
        "remove the factor the attacker enrolled in Entra ID": "entity.user",
        "make the password stop working in Okta": "entity.user",
        "make the password stop working in Entra ID": "entity.user",
        "suspend the account in Okta": "entity.user",
        "suspend the account in Entra ID": "entity.user",
    },
    "contain_admin_account_misuse": {
        "revoke the admin's sessions": "entity.user",
        "revoke the admin's sessions in Entra ID": "entity.user",
        "suspend the admin": "entity.user",
        "suspend the admin in Entra ID": "entity.user",
    },
    "contain_anthropic_org_change": {
        "disable the API key the change was made with": "entity.key",
    },
    "contain_aws_data_exposure": {
        "disable the actor's access key": "entity.key",
        "revoke the sessions minted from the actor's key": "entity.key",
    },
    "contain_aws_privilege_escalation": {
        "disable the actor's access key": "entity.key",
        "revoke the sessions minted from the actor's key": "entity.key",
    },
    "contain_azure_compromise": {
        "revoke the caller's sessions": "entity.user",
    },
    "contain_cloudflare_account_change": {
        "disable the API token the change was made with": "entity.key",
    },
    "contain_gcp_compromise": {
        "disable the service account key the calls were signed with": "entity.key, entity.user",
    },
    "contain_github_org_tampering": {
        "make the owner who made the change a member": "entity.account, entity.user",
    },
    "contain_gitlab_tampering": {
        "block the account that made the change": "entity.user",
    },
    "contain_google_app_grant": {
        "sign the user out of every Google session": "entity.user",
        "revoke the app's token": "entity.resource, entity.user",
    },
    "contain_google_workspace_compromise": {
        "sign the user out of every Google session": "entity.user",
        "turn off mail forwarding": "entity.user",
        "make the password stop working": "entity.user",
        "suspend the account": "entity.user",
    },
    "contain_identity_policy_tampering": {
        "revoke the actor's sessions in Okta": "entity.user",
        "revoke the actor's sessions in Entra ID": "entity.user",
        "sign the actor out of every Google session": "entity.user",
    },
    "contain_leaked_cloud_key": {
        "disable the access key": "entity.key",
    },
    "contain_leaked_llm_key": {
        "disable the Claude API key": "entity.key",
        "delete the OpenAI API key": "entity.key, entity.resource",
        "throttle the OpenAI project": "entity.resource",
    },
    "contain_openai_owner_change": {
        "delete the API key the new owner made": "entity.key, entity.resource",
    },
    "contain_tailscale_tampering": {
        "suspend the user who made the change": "entity.user",
    },
    "restore_aws_defences": {
        "disable the actor's access key": "entity.key",
        "revoke the sessions minted from the actor's key": "entity.key",
    },
    "revoke_third_party_app_access": {
        "revoke the granting user's sessions in Okta": "entity.user",
        "revoke the granting user's sessions in Entra ID": "entity.user",
    },
}


def test_a_step_acts_on_what_a_rule_named():
    """RSP-G5: a step that acts reads `rule.<id>.<kind>` or `platform.<p>.<kind>`;
    `entity.<kind>` is only for a page's words.

    A leaked-key run could disable the CI key and leave the attacker's active (ir-5).
    """
    known = {
        f"{book}: {step}": set(reads.split(", "))
        for book, steps in ENTITY_SCOPED.items()
        for step, reads in steps.items()
    }
    found: dict[str, str] = {}
    grew: list[str] = []
    for book in BOOKS:
        for step in filter(_acts, book.steps):
            reads = {p for p in _reads(step) if p.startswith("entity.")}
            key = f"{book.id}: {step.name}"
            if reads:
                found[key] = f"{key} ({step.action}) reads {', '.join(sorted(reads))}"
            if key in known and not reads <= known[key]:
                grew.append(f"{key} now also reads {', '.join(sorted(reads - known[key]))}")
    assert not grew, "RSP-G5 broken at:\n" + "\n".join(grew)
    _ratchet("RSP-G5", found, known)


# -- RSP-G6 persistence a rule records gets removed ------------------------------
PERSISTENCE = {"T1098.001", "T1098.003", "T1114.003", "T1564.008", "T1556.006"}
NO_ACTION = "no shoc action removes what it records on its platform"
NOT_AN_OBJECT = "it records a sign-in or a protection turned off, not an object to remove"
ON_ENTITY = "an action could remove it, but its playbook's step reads entity.* (RSP-G5)"
NO_STEP = "an action could remove it, and its playbook has no step that does"
LEAVES_PERSISTENCE = {
    "anthropic_admin_added_then_admin_key": NO_ACTION,
    "anthropic_admin_role_granted": NO_ACTION,
    "anthropic_api_key_created": ON_ENTITY,
    "anthropic_federation_trust_added": NO_ACTION,
    "aws_admin_policy_attached": NO_STEP,
    "aws_bedrock_abuse": NO_ACTION,
    "aws_console_login_without_mfa": NOT_AN_OBJECT,
    "aws_console_password_set_for_user": NO_ACTION,
    "aws_identity_center_tampered": NO_ACTION,
    "aws_instance_role_swapped": NO_ACTION,
    "aws_mfa_device_changed": NO_ACTION,
    "aws_role_trust_policy_changed": NO_ACTION,
    "aws_root_console_login_without_mfa": NOT_AN_OBJECT,
    "azure_privileged_access_granted": NO_ACTION,
    "cloudflare_access_opened": NO_ACTION,
    "cloudflare_email_routing_forward_added": NO_ACTION,
    "entra_app_credential_added": NO_ACTION,
    "entra_app_granted_mailbox_or_directory_permission": NO_STEP,
    "entra_global_admin_assigned": NO_STEP,
    "entra_mfa_disabled": NOT_AN_OBJECT,
    "entra_mfa_registered_after_risky_sign_in": ON_ENTITY,
    "gcp_iam_grant_to_personal_account": NO_ACTION,
    "gcp_privileged_role_granted": NO_ACTION,
    "gcp_service_account_key_created": ON_ENTITY,
    "github_collaborator_given_admin": NO_STEP,
    "github_fine_grained_pat_granted": NO_ACTION,
    "gitlab_access_token_created": NO_ACTION,
    "gitlab_group_sign_in_protection_weakened": NOT_AN_OBJECT,
    "gitlab_member_made_owner": NO_ACTION,
    "gke_cluster_admin_bound": NO_ACTION,
    "gke_cluster_opened_to_anonymous": NO_ACTION,
    "google_admin_privilege_granted": NO_ACTION,
    "google_backup_codes_issued_by_admin": NO_ACTION,
    "google_custom_admin_role_changed": NO_ACTION,
    "google_domain_wide_delegation_granted": NO_ACTION,
    "google_gmail_forwarding_out_of_domain": ON_ENTITY,
    "google_gmail_routing_changed": NO_ACTION,
    "google_marketplace_app_installed": NO_ACTION,
    "google_risky_session_action_blocked": NOT_AN_OBJECT,
    "google_two_step_verification_disabled": NOT_AN_OBJECT,
    "m365_exchange_role_assigned": NO_ACTION,
    "m365_mail_connector_changed": NO_ACTION,
    "m365_mailbox_forwarding_set": NO_ACTION,
    "m365_mfa_disabled": NOT_AN_OBJECT,
    "m365_transport_rule_changed": NO_ACTION,
    "okta_api_token_created": NO_ACTION,
    "okta_factor_enrolled_for_another_user": ON_ENTITY,
    "okta_mfa_factors_reset": NOT_AN_OBJECT,
    "okta_org_authenticator_deactivated": NOT_AN_OBJECT,
    "okta_security_policy_changed": NOT_AN_OBJECT,
    "openai_api_key_created": ON_ENTITY,
    "openai_workload_identity_trust_added": NO_ACTION,
    "stripe_defence_disabled": NOT_AN_OBJECT,
    "stripe_secret_key_created_or_viewed": NO_ACTION,
    "stripe_sign_in_factor_changed": NO_ACTION,
}


def _removes(step: playbooks.Step, rule_id: str) -> bool:
    """Whether a step acts on what this rule recorded, every other parameter it
    needs filled by a lookup its action declares."""
    if not _acts(step) or not any(p.startswith(f"rule.{rule_id}.") for p in _reads(step)):
        return False
    action = get_action(step.action)
    resolved = getattr(action, "resolve", {})
    return all(p in step.params or p in resolved for p in action.required_params)


def test_persistence_a_rule_records_has_a_step_that_removes_it():
    """RSP-G6: a rule that records what an attacker made to keep access is answered
    by a step that acts on that rule's own value.

    Playbooks revoked sessions, reported done and left the second access key (ir-6).
    """
    found: dict[str, str] = {}
    for rule in RULES:
        if not PERSISTENCE & {a.upper() for a in rule.attack}:
            continue
        book = next(b for b in BOOKS if rule.id in b.rules)
        if not any(_removes(step, rule.id) for step in book.steps):
            found[rule.id] = f"{rule.id} ({book.id}) has no step that acts on rule.{rule.id}.*"
    _ratchet("RSP-G6", found, LEAVES_PERSISTENCE)


# -- RSP-G7 every close goes through one function -------------------------------
# The kernel close RSP-G7 asks for, deciding by who closed and with what verdict.
# It does not exist yet; name it here when it lands.
CLOSER = "shoc/cases/engine.py:close"
CLOSE_GAP = "ir-15: closes the case itself, so what it does to actions and runs is its own"
CLOSE_KNOWN = {
    "shoc/agents/loop.py:run_case": CLOSE_GAP,
    "shoc/agents/sentinel.py:apply": CLOSE_GAP,
    "shoc/capabilities/cases.py:close_case": CLOSE_GAP,
    "shoc/capabilities/cases.py:set_state": CLOSE_GAP,
    "shoc/cases/unattended.py:_close": CLOSE_GAP,
}


def test_only_the_close_function_closes():
    """RSP-G7: only the one close function moves a case to closed.

    An approved L1 still disabled a key seconds after a false-positive verdict (ir-15).
    """
    found: dict[str, str] = {}
    for site in _calls("transition"):
        state = _arg(site.call, 3, "state")
        if isinstance(state, ast.Constant) and state.value != "closed":
            continue  # reopens or moves a case on
        if site.key != CLOSER:
            found.setdefault(site.key, f"{site.where}: closes a case, or may")
    _ratchet("RSP-G7", found, CLOSE_KNOWN)


# -- RSP-G8 paging reads the worst severity on the case ---------------------------
CASE_SEVERITY = re.compile(r"\bc\.severity\b|\bcases\.severity\b")


def test_paging_reads_one_severity():
    """RSP-G8: the Manager and the chase read a case's severity only as `engine.FLOORED`.

    A critical case a model lowered to low became a digest line and closed
    unattended (ai-3).
    """
    wrong: list[str] = []
    floored: set[str] = set()
    for text in _texts("shoc/agents/manager.py", "shoc/cases/unattended.py"):
        if any(n.endswith("FLOORED") for n in text.names):
            floored.add(text.path)
        if CASE_SEVERITY.search(text.text):
            wrong.append(f"{text.where}: reads the case's own severity column")
    assert not wrong, "\n".join(wrong)
    assert floored == {"shoc/agents/manager.py", "shoc/cases/unattended.py"}, floored


# -- RSP-G9 containment has one predicate ---------------------------------------
DONE = re.compile(r"\bstate\s*=\s*'done'")
CONTAINED_KNOWN = {
    "shoc/cases/engine.py:CONTAINED": "the predicate itself",
    # Lists what ran while nobody watched, pages and plans included, as such.
    "shoc/agents/reporter.py:_unattended": "says what ran, not what was contained",
    "shoc/agents/ops.py:metrics": "live-5: contained_at is the first done action of any kind",
    "shoc/capabilities/cases.py:close_case": "still_in_force restates CONTAINED to list its rows",
}


def test_containment_is_one_predicate():
    """RSP-G9: whether a case was contained is read through `engine.CONTAINED` alone.

    `ops.metrics` takes contained_at from any done action, so a page or a dry-run
    plan counts in time-to-contain (live-5).
    """
    found: dict[str, str] = {}
    for text in _texts():
        sql = text.text.strip()
        if sql[:6].upper() in ("UPDATE", "INSERT", "DELETE"):
            continue  # a write settles a row; it does not read containment
        if "shoc.actions" not in sql or not DONE.search(sql):
            continue
        if not any(n.endswith("CONTAINED") for n in text.names):
            found.setdefault(text.key, f"{text.where}: restates which done actions count")
    _ratchet("RSP-G9", found, CONTAINED_KNOWN)


# -- RSP-G11 a state change names the state it leaves ------------------------------
UPDATE = re.compile(r"UPDATE\s+shoc\.actions(?:\s+\w+)?\s+SET\b(.*?)\bWHERE\b(.*)", re.S | re.I)
UPSERT = re.compile(r"INSERT\s+INTO\s+shoc\.actions\b.*?\bDO\s+UPDATE\s+SET\b(.*)", re.S | re.I)
SETS_STATE = re.compile(r"\bstate\s*=")
NAMES_STATE = re.compile(r"\bstate\b")
GUARDED = re.compile(r"\bWHERE\b.*\bstate\b", re.S)
STATE_KNOWN = {
    "shoc/cases/actions.py:approve": "ir-10: approves whatever state it read before",
    "shoc/cases/actions.py:execute": "ir-10: the settle after the vendor call has no guard",
    "shoc/cases/actions.py:_hand_to_manager": "ir-10: settles a page as done from any state",
    "shoc/cases/actions.py:undo": "ir-10: a second undo, or one racing a run, is not refused",
    "shoc/cases/actions.py:propose": "a proposal again overwrites the state it read before",
}


def test_every_action_state_change_names_the_state_it_leaves():
    """RSP-G11: every write of `shoc.actions.state` names the state it leaves.

    Two workers ran one approved action, and the second overwrote the success
    with failed and an empty undo (ir-10).
    """
    found: dict[str, str] = {}
    for text in _texts():
        m = UPDATE.search(text.text)
        if m and SETS_STATE.search(m.group(1)) and not NAMES_STATE.search(m.group(2)):
            found.setdefault(text.key, f"{text.where}: sets state from any state")
        m = UPSERT.search(text.text)
        if m and SETS_STATE.search(m.group(1)) and not GUARDED.search(m.group(1)):
            found.setdefault(text.key, f"{text.where}: an upsert sets state from any state")
    _ratchet("RSP-G11", found, STATE_KNOWN)


# -- RSP-G12 shoc protects the identities it acts as -------------------------------
ACTS_AS_KNOWN = {
    "anthropic": "an Admin key names no user, and its probe reads the member list",
    "cloudflare": "an account token names no user, and its probe reads only its status",
    "gitlab": "its probe names the token's user, but credentials.NAMELESS leaves gitlab out",
    "openai": "an Admin key names no user, and its probe reads the member list",
    "sentinelone": "a service-user token names no user, and its probe reads one agent",
    "stripe": "a restricted key names no user",
    "wazuh": "its username is not in own.ACTS_AS, and its probe does not record it",
}


def test_every_response_provider_says_who_it_acts_as():
    """RSP-G12: every response credential names who shoc acts as there, in a field
    `own.ACTS_AS` lists or as the `acts_as` its probe records, so `own.protected`
    holds an action against that login for a person.

    An L1 step could disable shoc's own response key and make undo impossible (ir-8).
    """
    found: dict[str, str] = {}
    for provider, need in NEEDS.items():
        if provider == "notify":
            continue  # a routing key pages; nothing acts on it
        if {*need.settings, *need.secret, *need.optional} & set(own.ACTS_AS):
            continue
        probe = getattr(importlib.import_module(f"shoc.actions.{provider}"), "probe", None)
        said = probe is not None and credentials.SIGNED_IN.strip() in inspect.getsource(probe)
        if provider in credentials.NAMELESS and said:
            continue
        found[provider] = f"{provider}: no field in own.ACTS_AS, and no probe kept as acts_as"
    _ratchet("RSP-G12", found, ACTS_AS_KNOWN)
