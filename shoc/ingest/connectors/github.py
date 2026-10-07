"""GitHub organisation audit-log connector (ING-1), and its webhook (ING-2).

The REST audit-log endpoint exists only for organisations on GitHub Enterprise
Cloud; on any other plan it answers 404. Free and Team organisations send an
organisation webhook instead, which `from_webhook` turns into the audit-log
record the mapping and the rules already read.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs

from shoc.errors import ConfigError, ValidationError
from shoc.ingest.connectors.base import FetchResult, client, since_default

API = "https://api.github.com"

# (webhook event, its action) -> the audit-log action for the same change, so a
# rule written against the audit log matches either way. An event not listed
# keeps `<event>.<action>`. `repository.privatized` stays itself: the audit log
# calls both directions `repo.access`, and a rule reading it as "made public"
# should not fire when a repository is closed.
WEBHOOK_ACTIONS = {
    ("repository", "publicized"): "repo.access",
    ("public", ""): "repo.access",
    ("repository", "created"): "repo.create",
    ("repository", "deleted"): "repo.destroy",
    ("repository", "renamed"): "repo.rename",
    ("repository", "transferred"): "repo.transfer",
    ("repository", "archived"): "repo.archived",
    ("repository", "unarchived"): "repo.unarchived",
    ("member", "added"): "repo.add_member",
    ("member", "edited"): "repo.update_member",
    ("member", "removed"): "repo.remove_member",
    ("organization", "member_added"): "org.add_member",
    ("organization", "member_removed"): "org.remove_member",
    ("organization", "member_invited"): "org.invite_member",
    ("organization", "renamed"): "org.rename",
    ("team", "created"): "team.create",
    ("team", "deleted"): "team.destroy",
    ("team", "added_to_repository"): "team.add_repository",
    ("team", "removed_from_repository"): "team.remove_repository",
    ("membership", "added"): "team.add_member",
    ("membership", "removed"): "team.remove_member",
    ("branch_protection_rule", "created"): "protected_branch.create",
    # The audit log has one action per setting; this stands for any of them.
    ("branch_protection_rule", "edited"): "protected_branch.update",
    ("branch_protection_rule", "deleted"): "protected_branch.destroy",
    (
        "branch_protection_configuration",
        "disabled",
    ): "repository_branch_protection_evaluation.disable",
    ("repository_ruleset", "created"): "repository_ruleset.create",
    ("repository_ruleset", "edited"): "repository_ruleset.update",
    ("repository_ruleset", "deleted"): "repository_ruleset.destroy",
    ("deploy_key", "created"): "public_key.create",
    ("deploy_key", "deleted"): "public_key.delete",
    ("personal_access_token_request", "created"): "personal_access_token.request_created",
    ("personal_access_token_request", "approved"): "personal_access_token.access_granted",
    ("personal_access_token_request", "denied"): "personal_access_token.request_denied",
    ("personal_access_token_request", "cancelled"): "personal_access_token.request_cancelled",
    ("org_block", "blocked"): "org.block_user",
    ("org_block", "unblocked"): "org.unblock_user",
    ("meta", "deleted"): "hook.destroy",
    ("secret_scanning_alert", "created"): "secret_scanning_alert.create",
    ("secret_scanning_alert", "publicly_leaked"): "secret_scanning_alert.public_leak",
}

# A `security_and_analysis` event has no action: the feature it changed, and
# that feature's new status, name the audit-log action (enabled, disabled).
SECURITY_FEATURES = {
    "advanced_security": ("repo.advanced_security_enabled", "repo.advanced_security_disabled"),
    "secret_scanning": ("repository_secret_scanning.enable", "repository_secret_scanning.disable"),
    "secret_scanning_push_protection": (
        "repository_secret_scanning_push_protection.enable",
        "repository_secret_scanning_push_protection.disable",
    ),
    "secret_scanning_non_provider_patterns": (
        "repository_secret_scanning_non_provider_patterns.enabled",
        "repository_secret_scanning_non_provider_patterns.disabled",
    ),
    "secret_scanning_validity_checks": (
        "repository_secret_scanning_automatic_validity_checks.enabled",
        "repository_secret_scanning_automatic_validity_checks.disabled",
    ),
    "dependabot_security_updates": (
        "dependabot_security_updates.enable",
        "dependabot_security_updates.disable",
    ),
}

# 100-nanosecond steps from the UUID epoch (1582-10-15) to the Unix epoch.
_UUID_EPOCH = 0x01B21DD213814000


def from_webhook(headers: Mapping[str, str], body: bytes) -> list[dict[str, Any]]:
    """One organisation webhook delivery as an audit-log record (ING-2).

    The whole payload is kept; the fields the mapping reads are added on top.
    A webhook carries no source address and no event time, so the time is the
    delivery's, and `ping` loads nothing.
    """
    event = headers.get("x-github-event", "")
    delivery = headers.get("x-github-delivery", "")
    if not event or not delivery:
        raise ValidationError("a GitHub webhook needs X-GitHub-Event and X-GitHub-Delivery")
    if event == "ping":
        return []
    text = body.decode()
    if headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        text = (parse_qs(text).get("payload") or ["{}"])[0]
    payload = json.loads(text or "{}")
    action = str(payload.get("action") or "")
    # Only what the payload has: an organisation event names no repository,
    # and a record field is never null (a push's `base_ref` often is).
    payload = {k: v for k, v in payload.items() if v is not None}
    found = {
        "actor": (payload.get("sender") or {}).get("login"),
        "actor_id": (payload.get("sender") or {}).get("id"),
        "org": (payload.get("organization") or {}).get("login"),
        "repo": (payload.get("repository") or {}).get("full_name"),
    }
    return [
        {
            **payload,
            "_document_id": f"github-webhook-{delivery}",
            "@timestamp": _delivered_at(delivery),
            "action": _security_change(payload)
            if event == "security_and_analysis"
            else WEBHOOK_ACTIONS.get((event, action), f"{event}.{action}".strip(".")),
            **{k: v for k, v in found.items() if v is not None},
            "webhook": {"event": event, "action": action, "delivery": delivery},
        }
    ]


def _security_change(payload: dict[str, Any]) -> str:
    """The audit-log action for the first known feature the delivery changed;
    the whole `changes` block stays on the record."""
    before = ((payload.get("changes") or {}).get("from") or {}).get("security_and_analysis") or {}
    now = (payload.get("repository") or {}).get("security_and_analysis") or {}
    for feature in before:
        if feature in SECURITY_FEATURES:
            enabled = (now.get(feature) or {}).get("status") == "enabled"
            return SECURITY_FEATURES[feature][not enabled]
    return "security_and_analysis"


def _delivered_at(delivery: str) -> int:
    """Milliseconds since the epoch: the time a version-1 UUID delivery id was
    made, else now. A replay is refused by its id, not by its time (ING-2)."""
    try:
        uid = uuid.UUID(delivery)
    except ValueError:
        uid = None
    if uid is not None and uid.version == 1:
        return (uid.time - _UUID_EPOCH) // 10_000
    return int(time.time() * 1000)


class GitHubConnector:
    source = "github"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        org = settings.get("org")
        token = secret.get("token")
        if not org or not token:
            raise ConfigError("github: settings need org and the secret needs token")
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        params: dict[str, Any] = {
            "per_page": min(int(limit), 100),
            "order": "asc",
            "include": settings.get("include", "all"),
            "phrase": f"created:>={since[:19]}",
        }
        if cursor.get("after"):
            params["after"] = cursor["after"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        with client(headers) as http:
            resp = http.get(f"{API}/orgs/{org}/audit-log", params=params)
            if resp.status_code == 404:
                raise ConfigError(
                    f"github: no audit log for org '{org}' (404); the audit-log API needs "
                    "GitHub Enterprise Cloud"
                )
            resp.raise_for_status()
            records = resp.json() or []
            after = _next_after(resp.headers.get_list("link"))
        newest = str(cursor.get("newest") or since)
        for r in records:
            ts = r.get("@timestamp") or r.get("created_at")
            if ts:
                iso = datetime.fromtimestamp(float(ts) / 1000, tz=UTC).isoformat()
                newest = max(newest, iso)
        if after and records:
            # `after` pages through the phrase it was issued for, so the
            # created:>= bound stays put until the walk is done.
            held = {"since": since, "newest": newest, "after": after}
            return FetchResult(records=records, cursor=held, more=True)
        return FetchResult(records=records, cursor={"since": newest}, more=False)


def _next_after(links: list[str]) -> str | None:
    for link in links:
        if 'rel="next"' in link and "after=" in link:
            return link.split("after=", 1)[1].split("&", 1)[0].split(">", 1)[0]
    return None


CONNECTOR = GitHubConnector()
