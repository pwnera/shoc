"""GitLab actions (RSP-4) and lookups (RFC 0014).

The Splunk SOAR GitLab connector only reads projects and runs pipelines, so this
takes GitLab's own admin API: block a user, which ends their sessions and tokens
without deleting anything, and unblock them on undo. Blocking needs an admin
token, which means a self-managed instance or a GitLab Dedicated tenant.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send
from shoc.errors import ConfigError, NotFound


def _client(action: Any, creds: Credentials, http: httpx.Client | None) -> tuple[str, httpx.Client]:
    from shoc.ingest.connectors.gitlab import DEFAULT_URL

    (token,) = creds.require("token")
    base = str(creds.settings.get("base_url") or DEFAULT_URL).rstrip("/") + "/api/v4"
    return base, action.client({"PRIVATE-TOKEN": str(token), "Accept": "application/json"}, http)


def _user_id(client: httpx.Client, base: str, user: Any) -> str:
    """A numeric id as given, or the id behind a username or an email.

    The audit log names its author by email; `search` also matches names, so
    only an exact email counts."""
    if str(user).isdigit():
        return str(user)
    by = "search" if "@" in str(user) else "username"
    found = send(client, "GET", f"{base}/users", "GitLab", params={by: str(user)}).json()
    if by == "search":
        found = [u for u in found if str(u.get("email", "")).lower() == str(user).lower()]
    if not found:
        raise NotFound(f"gitlab: no user '{user}'")
    return str(found[0]["id"])


class BlockUser(BaseAction):
    type = "gitlab.block_user"
    provider = "gitlab"
    platforms = ("gitlab",)
    target_kind = "user"
    summary = "Block a GitLab user: no sign-in, no API, no Git"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Block GitLab user {params.get('user')}; their projects and history stay"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        base, client = _client(self, creds, http)
        uid = _user_id(client, base, params["user"])
        send(client, "POST", f"{base}/users/{seg(uid)}/block", "GitLab")
        return ActionResult(
            ok=True,
            detail=f"{params['user']} blocked",
            data={"user": params["user"], "id": uid},
            undo={"id": uid},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        base, client = _client(self, creds, http)
        send(client, "POST", f"{base}/users/{seg(undo['id'])}/unblock", "GitLab")
        return ActionResult(ok=True, detail=f"user {undo['id']} unblocked")


class GetUser(BaseLookup):
    type = "gitlab.get_user"
    provider = "gitlab"
    platforms = ("gitlab",)
    summary = "A GitLab user's state, admin flag, 2FA and last sign-in"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, client = _client(self, creds, http)
        uid = _user_id(client, base, params["user"])
        u = send(client, "GET", f"{base}/users/{seg(uid)}", "GitLab").json()
        keep = (
            "id",
            "username",
            "state",
            "is_admin",
            "two_factor_enabled",
            "created_at",
            "last_sign_in_at",
            "current_sign_in_ip",
            "last_activity_on",
        )
        return {k: u.get(k) for k in keep}


ACTIONS = [BlockUser()]
LOOKUPS = [GetUser()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The token's own user, who must be an administrator to block anyone."""
    base, client = _client(READ, creds, http)
    me = send(client, "GET", f"{base}/user", "GitLab").json()
    if not me.get("is_admin"):
        raise ConfigError(f"{me.get('username', 'the token')} is not an administrator")
    return f"signed in as {me['username']}"
