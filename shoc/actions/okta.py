"""Okta actions (RSP-4) and lookups (RFC 0014), over the Okta management API.

The set follows the Splunk SOAR Okta connector, narrowed to what answers an
account takeover: sign the user out, suspend them, take back an admin role,
remove a factor the attacker enrolled, and read who they are before doing any
of it. The credential is an API token of a super administrator (RFC 0031).
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from shoc.actions.base import (
    IDP_LINKED_FROM,
    READ,
    ActionResult,
    BaseAction,
    BaseLookup,
    Credentials,
    newest,
    only_recent,
    section,
    seg,
    send,
)
from shoc.errors import StoreError, ValidationError


def _okta(creds: Credentials) -> tuple[str, dict[str, str]]:
    org_url, token = creds.require("org_url", "api_token")
    return str(org_url).rstrip("/"), {
        "Authorization": f"SSWS {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Okta", **kw)


def _pages(client: httpx.Client, url: str) -> list[dict[str, Any]]:
    """Every item of a listing Okta pages with a `Link: rel="next"` header."""
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url:
        resp = _send(client, "GET", next_url)
        items += resp.json()
        next_url = resp.links.get("next", {}).get("url")
    return items


# The standard roles Okta scopes to groups; APP_ADMIN is scoped to apps.
GROUP_SCOPED = ("USER_ADMIN", "HELP_DESK_ADMIN", "GROUP_MEMBERSHIP_ADMIN")


class RevokeSessions(BaseAction):
    type = "okta.revoke_sessions"
    provider = "okta"
    platforms = ("okta",)
    linked_from = IDP_LINKED_FROM
    target_kind = "user"
    summary = "Revoke a user's Okta sessions and refresh tokens"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Sign {params.get('user')} out of every Okta session and invalidate refresh tokens"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user"]
        base, headers = _okta(creds)
        # Without oauthTokens the refresh tokens Okta issued to apps outlive
        # the sign-out, and an attacker holding one never notices it.
        _send(
            self.client(headers, http),
            "DELETE",
            f"{base}/api/v1/users/{seg(user)}/sessions",
            params={"oauthTokens": "true"},
        )
        return ActionResult(
            ok=True,
            detail=f"sessions revoked for {user}; they must sign in again",
            data={"user": user},
            undo={},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        # Nothing to undo: the user simply signs in again.
        return ActionResult(ok=True, detail="nothing to undo; the user can sign in again")


class SuspendUser(BaseAction):
    type = "okta.suspend_user"
    provider = "okta"
    platforms = ("okta",)
    linked_from = IDP_LINKED_FROM
    target_kind = "user"
    summary = "Suspend an Okta user"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Suspend {params.get('user')} in Okta: they lose access to everything behind SSO"

    def _lifecycle(
        self, creds: Credentials, user: str, step: str, http: httpx.Client | None
    ) -> None:
        base, headers = _okta(creds)
        _send(
            self.client(headers, http), "POST", f"{base}/api/v1/users/{seg(user)}/lifecycle/{step}"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user"]
        self._lifecycle(creds, user, "suspend", http)
        return ActionResult(
            ok=True, detail=f"{user} is suspended", data={"user": user}, undo={"user": user}
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._lifecycle(creds, undo["user"], "unsuspend", http)
        return ActionResult(ok=True, detail=f"{undo['user']} is active again")


class ResetPassword(BaseAction):
    type = "okta.reset_password"
    provider = "okta"
    platforms = ("okta",)
    linked_from = IDP_LINKED_FROM
    target_kind = "user"
    summary = "Make a user's Okta password stop working; Okta emails them a link to set one"
    # The old password is gone for good: nothing can put it back.
    reversible = False
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Invalidate {params.get('user')}'s Okta password: whoever knows it can no longer "
            "sign in, and Okta emails the user a link to set a new one"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user"]
        # Expiring the password would let anyone who knows it choose the next one.
        # Recovery takes it away and emails the user a link to set a new one.
        base, headers = _okta(creds)
        _send(
            self.client(headers, http),
            "POST",
            f"{base}/api/v1/users/{seg(user)}/lifecycle/reset_password",
            params={"sendEmail": "true"},
        )
        return ActionResult(
            ok=True,
            detail=f"{user}'s password no longer works; Okta emailed them a link to set one",
            data={"user": user},
        )


class RemoveAdminRole(BaseAction):
    """Take back one admin role assignment, remembering it so it can be given back.

    `role` is the assignment id on the user, which `okta.get_user` lists.
    """

    type = "okta.remove_admin_role"
    provider = "okta"
    platforms = ("okta",)
    target_kind = "user"
    summary = "Remove an Okta admin role a user was just given"
    reversible = True
    required_params = ("user", "role")
    # A playbook names the grantee; the role given this week is the lookup's (ir-7),
    # narrowed to the one the case's grant names.
    resolve: ClassVar = {"role": (None, None, "okta.recent_admin_role")}
    granted_at: ClassVar = ("raw.debugContext.debugData.privilegeGranted",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Remove Okta admin role assignment {params.get('role')} from {params.get('user')}"

    def _url(self, creds: Credentials, params: dict[str, Any]) -> str:
        base = _okta(creds)[0]
        return f"{base}/api/v1/users/{seg(params['user'])}/roles/{seg(params['role'])}"

    def snapshot(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        """The grant to give back, read and kept before it is removed (RSP-4).

        Okta assigns a standard role with no targets for every group or every
        app, so a role scoped to some keeps them, and undo puts them back.
        """
        self.check(params)
        client, url = self.client(_okta(creds)[1], http), self._url(creds, params)
        was = _send(client, "GET", url).json()
        kind = was.get("type")
        grant: dict[str, Any] = {"type": kind}
        if kind == "CUSTOM":
            grant |= {"role": was.get("role"), "resource-set": was.get("resource-set")}
        try:
            if kind in GROUP_SCOPED:
                grant["groups"] = [g.get("id") for g in _pages(client, f"{url}/targets/groups")]
            elif kind == "APP_ADMIN":
                apps = _pages(client, f"{url}/targets/catalog/apps")
                # An app instance has an id; a whole app (every instance) has none.
                grant["apps"] = [{"name": a.get("name"), "id": a.get("id")} for a in apps]
        except StoreError:
            grant["targets_unread"] = True
        return grant

    def execute(
        self,
        creds: Credentials,
        params: dict[str, Any],
        http: httpx.Client | None = None,
        before: dict[str, Any] | None = None,
    ) -> ActionResult:
        self.check(params)
        user, role = params["user"], params["role"]
        client = self.client(_okta(creds)[1], http)
        grant = before if before is not None else self.snapshot(creds, params, client)
        try:
            _send(client, "DELETE", self._url(creds, params))
        except StoreError as exc:
            # Removed already: the first try did it and its answer was lost (RSP-4).
            cause = exc.__cause__
            if before is None or not (
                isinstance(cause, httpx.HTTPStatusError) and cause.response.status_code == 404
            ):
                raise
        lost = bool(grant.get("targets_unread"))
        return ActionResult(
            ok=True,
            detail=f"admin role {role} removed from {user}"
            + ("; its targets could not be read, so it cannot be given back" if lost else ""),
            data={"user": user, "role": role, "was": grant} | ({"undo_lost": True} if lost else {}),
            undo={"user": user, "grant": grant},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        user, grant = undo["user"], dict(undo["grant"])
        if grant.get("targets_unread"):
            # Given back with no targets, it would cover every group or app.
            raise ValidationError(
                f"{self.type}: the role's targets could not be read, so it cannot be given "
                f"back to {user} as it was"
            )
        groups, apps = grant.pop("groups", None) or [], grant.pop("apps", None) or []
        base, headers = _okta(creds)
        client = self.client(headers, http)
        roles = f"{base}/api/v1/users/{seg(user)}/roles"
        made = f"{roles}/{seg(_send(client, 'POST', roles, json=grant).json().get('id', ''))}"
        targets = [f"{made}/targets/groups/{seg(g)}" for g in groups]
        for app in apps:
            instance = f"/{seg(app['id'])}" if app.get("id") else ""
            targets.append(f"{made}/targets/catalog/apps/{seg(app['name'])}{instance}")
        try:
            for target in targets:
                _send(client, "PUT", target)
        except StoreError:
            # Unscoped, the role covers every group or app: more than was taken.
            _send(client, "DELETE", made)
            raise
        return ActionResult(ok=True, detail=f"admin role given back to {user}")


class RemoveFactor(BaseAction):
    """Delete one MFA factor. Nobody but the user can enrol it again, so this
    waits for a human. With no `factor_id`, the factor is the newest one
    enrolled in the last week, which okta.recent_factor reads."""

    type = "okta.remove_factor"
    provider = "okta"
    platforms = ("okta",)
    target_kind = "user"
    summary = "Remove an MFA factor an attacker enrolled on an Okta user"
    required_params = ("user", "factor_id")
    resolve: ClassVar = {"factor_id": (None, None, "okta.recent_factor")}

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Remove Okta factor {params.get('factor_id')} from {params.get('user')}; "
            "only the user can enrol it again"
        )

    def _url(self, creds: Credentials, params: dict[str, Any]) -> str:
        base = _okta(creds)[0]
        return f"{base}/api/v1/users/{seg(params['user'])}/factors/{seg(params['factor_id'])}"

    def snapshot(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        """The factor as it was, kept before it is deleted, so the record says what
        went and a retry whose first answer was lost knows it is done (RSP-4)."""
        self.check(params)
        f = _send(self.client(_okta(creds)[1], http), "GET", self._url(creds, params)).json()
        return {
            "type": f.get("factorType"),
            "provider": f.get("provider"),
            "created": f.get("created"),
        }

    def execute(
        self,
        creds: Credentials,
        params: dict[str, Any],
        http: httpx.Client | None = None,
        before: dict[str, Any] | None = None,
    ) -> ActionResult:
        self.check(params)
        user, factor = str(params["user"]), str(params["factor_id"])
        client = self.client(_okta(creds)[1], http)
        was = before if before is not None else self.snapshot(creds, params, client)
        try:
            _send(client, "DELETE", self._url(creds, params))
        except StoreError as exc:
            # Deleted already: the first try did it and its answer was lost (RSP-4).
            cause = exc.__cause__
            if before is None or not (
                isinstance(cause, httpx.HTTPStatusError) and cause.response.status_code == 404
            ):
                raise
        return ActionResult(
            ok=True,
            detail=f"factor {factor} removed from {user}",
            data={"user": user, "factor_id": factor, "was": was},
        )


class RecentFactor(BaseLookup):
    type = "okta.recent_factor"
    provider = "okta"
    platforms = ("okta",)
    summary = "A user's Okta factors with their ids, and the newest one enrolled in the last week"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, headers = _okta(creds)
        found = _send(
            self.client(headers, http), "GET", f"{base}/api/v1/users/{seg(params['user'])}/factors"
        )
        factors = [
            {"factor_id": f.get("id"), "type": f.get("factorType"), "created": f.get("created")}
            for f in found.json()
        ]
        latest = newest(factors)
        return {"factor_id": latest.get("factor_id", ""), "newest": latest, "factors": factors}


class RecentAdminRole(BaseLookup):
    type = "okta.recent_admin_role"
    provider = "okta"
    platforms = ("okta",)
    summary = "A user's Okta admin role assignments, and the one given in the last week"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, headers = _okta(creds)
        found = _send(
            self.client(headers, http), "GET", f"{base}/api/v1/users/{seg(params['user'])}/roles"
        )
        roles = [
            {
                "role": r.get("id"),
                "type": r.get("type"),
                "label": r.get("label"),
                "created": r.get("created"),
            }
            for r in found.json()
        ]
        # The one the case's grant names, when the runner read it; of two given
        # this week, which one the case is about is not ours to guess otherwise.
        granted = {_letters(g) for g in str(params.get("granted") or "").split(",")} - {""}
        named = (
            [r for r in roles if {_letters(r["label"]), _letters(r["type"])} & granted]
            if granted
            else roles
        )
        return {"role": only_recent(named).get("role", ""), "roles": roles}


def _letters(name: Any) -> str:
    """The System Log names a role "Super administrator"; the roles API labels it
    "Super Administrator" and types it SUPER_ADMIN."""
    return "".join(c for c in str(name or "").lower() if c.isalpha())


class GetUser(BaseLookup):
    type = "okta.get_user"
    provider = "okta"
    platforms = ("okta",)
    summary = "Who an Okta user is: status, admin roles, MFA factors and last sign-in"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        user = seg(params["user"])
        base, headers = _okta(creds)
        client = self.client(headers, http)
        u = _send(client, "GET", f"{base}/api/v1/users/{user}").json()
        roles = section(client, f"{base}/api/v1/users/{user}/roles", "Okta")
        factors = section(client, f"{base}/api/v1/users/{user}/factors", "Okta")
        return {
            "id": u.get("id"),
            "login": (u.get("profile") or {}).get("login"),
            "status": u.get("status"),
            "created": u.get("created"),
            "last_login": u.get("lastLogin"),
            "password_changed": u.get("passwordChanged"),
            "admin_roles": [
                {"role": r.get("id"), "type": r.get("type"), "label": r.get("label")} for r in roles
            ]
            if isinstance(roles, list)
            else roles,
            "mfa_factors": [
                {
                    "type": f.get("factorType"),
                    "status": f.get("status"),
                    "created": f.get("created"),
                }
                for f in factors
            ]
            if isinstance(factors, list)
            else factors,
        }


ACTIONS = [RevokeSessions(), SuspendUser(), ResetPassword(), RemoveAdminRole(), RemoveFactor()]
LOOKUPS = [GetUser(), RecentFactor(), RecentAdminRole()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The token's own user, which `credentials.record_check` keeps as `acts_as`."""
    base, headers = _okta(creds)
    me = _send(READ.client(headers, http), "GET", f"{base}/api/v1/users/me").json()
    return f"signed in as {(me.get('profile') or {}).get('login', '')}"
