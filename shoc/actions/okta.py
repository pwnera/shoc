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
    section,
    seg,
    send,
)


def _okta(creds: Credentials) -> tuple[str, dict[str, str]]:
    org_url, token = creds.require("org_url", "api_token")
    return str(org_url).rstrip("/"), {
        "Authorization": f"SSWS {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Okta", **kw)


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

    def plan(self, params: dict[str, Any]) -> str:
        return f"Remove Okta admin role assignment {params.get('role')} from {params.get('user')}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user, role = params["user"], params["role"]
        base, headers = _okta(creds)
        client = self.client(headers, http)
        url = f"{base}/api/v1/users/{seg(user)}/roles/{seg(role)}"
        was = _send(client, "GET", url).json()
        _send(client, "DELETE", url)
        grant = {"type": was.get("type")}
        if was.get("type") == "CUSTOM":
            grant |= {"role": was.get("role"), "resource-set": was.get("resource-set")}
        return ActionResult(
            ok=True,
            detail=f"admin role {role} removed from {user}",
            data={"user": user, "role": role, "was": grant},
            undo={"user": user, "grant": grant},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        user = undo["user"]
        base, headers = _okta(creds)
        _send(
            self.client(headers, http),
            "POST",
            f"{base}/api/v1/users/{seg(user)}/roles",
            json=undo["grant"],
        )
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

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user, factor = str(params["user"]), str(params["factor_id"])
        base, headers = _okta(creds)
        url = f"{base}/api/v1/users/{seg(user)}/factors/{seg(factor)}"
        _send(self.client(headers, http), "DELETE", url)
        return ActionResult(
            ok=True,
            detail=f"factor {factor} removed from {user}",
            data={"user": user, "factor_id": factor},
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
LOOKUPS = [GetUser(), RecentFactor()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The token's own user."""
    base, headers = _okta(creds)
    me = _send(READ.client(headers, http), "GET", f"{base}/api/v1/users/me").json()
    return f"signed in as {(me.get('profile') or {}).get('login', '')}"
