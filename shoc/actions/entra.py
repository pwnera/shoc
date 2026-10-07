"""Entra ID actions (RSP-4) and lookups (RFC 0014), over Microsoft Graph.

The set follows the Splunk SOAR Azure AD connector, narrowed to what answers an
account takeover: sign the user out, disable them, take back a directory role,
remove a method the attacker registered, and read who they are before doing
any of it. An Azure Activity caller and a Microsoft 365 user are Entra
principals, so the account actions answer those cases too (RFC 0031).
"""

from __future__ import annotations

import re
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
    unknowable_password,
)
from shoc.errors import ValidationError

GRAPH = "https://graph.microsoft.com/v1.0"
# The platforms whose principals are Entra users.
PRINCIPALS = ("entra", "m365", "azure")


def _headers(creds: Credentials) -> dict[str, str]:
    from shoc.ingest.connectors.msgraph import access_token

    return {"Authorization": f"Bearer {access_token(creds.secret)}", "Accept": "application/json"}


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Microsoft Graph", **kw)


class RevokeSessions(BaseAction):
    type = "entra.revoke_sessions"
    provider = "entra"
    platforms = PRINCIPALS
    linked_from = IDP_LINKED_FROM
    target_kind = "user"
    summary = "Revoke a user's Entra ID sessions and refresh tokens"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Sign {params.get('user')} out of every Entra ID session and invalidate refresh tokens"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user"]
        client = self.client(_headers(creds), http)
        _send(client, "POST", f"{GRAPH}/users/{seg(user)}/revokeSignInSessions")
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
    type = "entra.suspend_user"
    provider = "entra"
    platforms = PRINCIPALS
    linked_from = IDP_LINKED_FROM
    target_kind = "user"
    summary = "Disable an Entra ID user"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Disable {params.get('user')} in Entra ID: they lose access to everything behind SSO"
        )

    def _enable(
        self, creds: Credentials, user: str, enabled: bool, http: httpx.Client | None
    ) -> None:
        client = self.client(_headers(creds), http)
        _send(client, "PATCH", f"{GRAPH}/users/{seg(user)}", json={"accountEnabled": enabled})

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user"]
        self._enable(creds, user, False, http)
        return ActionResult(
            ok=True, detail=f"{user} is suspended", data={"user": user}, undo={"user": user}
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._enable(creds, undo["user"], True, http)
        return ActionResult(ok=True, detail=f"{undo['user']} is active again")


class ResetPassword(BaseAction):
    type = "entra.reset_password"
    provider = "entra"
    platforms = PRINCIPALS
    linked_from = IDP_LINKED_FROM
    target_kind = "user"
    summary = "Replace a user's Entra ID password with one nobody holds, so they set a new one"
    # The old password is gone for good: nothing can put it back.
    reversible = False
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Replace {params.get('user')}'s Entra ID password with one nobody holds: whoever "
            "knows the old one can no longer sign in, and the user sets a new one"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = params["user"]
        # A flag alone would let the old password set the next one; a password
        # nobody holds replaces it, and the user resets it themselves.
        client = self.client(_headers(creds), http)
        profile = {"forceChangePasswordNextSignIn": True, "password": unknowable_password()}
        _send(client, "PATCH", f"{GRAPH}/users/{seg(user)}", json={"passwordProfile": profile})
        return ActionResult(
            ok=True,
            detail=f"{user}'s password no longer works; they set a new one through self-service "
            "password reset, or an administrator gives them one",
            data={"user": user},
        )


class RemoveAdminRole(BaseAction):
    """Take back one directory role assignment, remembering it so it can be given back.

    `role` is the assignment id, which `entra.get_user` lists.
    """

    type = "entra.remove_admin_role"
    provider = "entra"
    platforms = ("entra",)
    target_kind = "user"
    summary = "Remove an Entra ID directory role a user was just given"
    reversible = True
    required_params = ("user", "role")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Remove Entra ID role assignment {params.get('role')} from {params.get('user')}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user, role = params["user"], params["role"]
        client = self.client(_headers(creds), http)
        url = f"{GRAPH}/roleManagement/directory/roleAssignments/{seg(role)}"
        was = _send(client, "GET", url).json()
        _send(client, "DELETE", url)
        grant = {k: was.get(k) for k in ("roleDefinitionId", "principalId", "directoryScopeId")}
        return ActionResult(
            ok=True,
            detail=f"admin role {role} removed from {user}",
            data={"user": user, "role": role, "was": grant},
            undo={"user": user, "grant": grant},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        _send(
            client, "POST", f"{GRAPH}/roleManagement/directory/roleAssignments", json=undo["grant"]
        )
        return ActionResult(ok=True, detail=f"admin role given back to {undo['user']}")


# An Entra method id is `<collection>/<id>`: Graph deletes a method only under
# its own type, as in microsoftAuthenticatorMethods/{id}.
METHOD = re.compile(r"([A-Za-z0-9]+Methods)/([\w-]+)")


class RemoveFactor(BaseAction):
    """Delete one authentication method. Nobody but the user can register it
    again, so this waits for a human. With no `factor_id`, the method is the
    newest one registered in the last week, which entra.recent_factor reads."""

    type = "entra.remove_factor"
    provider = "entra"
    platforms = ("entra", "m365")
    target_kind = "user"
    summary = "Remove an MFA method an attacker registered on an Entra ID user"
    required_params = ("user", "factor_id")
    resolve: ClassVar = {"factor_id": (None, None, "entra.recent_factor")}

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Remove Entra ID method {params.get('factor_id')} from {params.get('user')}; "
            "only the user can register it again"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user, factor = str(params["user"]), str(params["factor_id"])
        method = METHOD.fullmatch(factor)
        if not method:
            raise ValidationError(f"{self.type}: '{factor}' is not <type>Methods/<id>")
        url = f"{GRAPH}/users/{seg(user)}/authentication/{method[1]}/{seg(method[2])}"
        _send(self.client(_headers(creds), http), "DELETE", url)
        return ActionResult(
            ok=True,
            detail=f"factor {factor} removed from {user}",
            data={"user": user, "factor_id": factor},
        )


class RecentFactor(BaseLookup):
    type = "entra.recent_factor"
    provider = "entra"
    platforms = ("entra", "m365")
    summary = (
        "A user's Entra ID methods with their ids, and the newest one registered in the last week"
    )
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = self.client(_headers(creds), http)
        url = f"{GRAPH}/users/{seg(params['user'])}/authentication/methods"
        factors = []
        for m in _send(client, "GET", url).json().get("value", []):
            kind = (
                str(m.get("@odata.type", ""))
                .rsplit(".", 1)[-1]
                .removesuffix("AuthenticationMethod")
            )
            if kind and kind != "password":  # the password is not a factor to remove
                factors.append(
                    {
                        "factor_id": f"{kind}Methods/{m.get('id')}",
                        "type": kind,
                        "created": m.get("createdDateTime"),
                    }
                )
        latest = newest(factors)
        return {"factor_id": latest.get("factor_id", ""), "newest": latest, "factors": factors}


class GetUser(BaseLookup):
    type = "entra.get_user"
    provider = "entra"
    platforms = PRINCIPALS
    summary = "Who an Entra ID user is: status, directory roles, MFA methods and password change"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        user = seg(params["user"])
        client = self.client(_headers(creds), http)
        u = _send(
            client,
            "GET",
            f"{GRAPH}/users/{user}",
            params={
                "$select": "id,userPrincipalName,accountEnabled,createdDateTime,"
                "lastPasswordChangeDateTime,onPremisesSyncEnabled"
            },
        ).json()
        roles = section(
            client,
            f"{GRAPH}/roleManagement/directory/roleAssignments",
            "Microsoft Graph",
            params={"$filter": f"principalId eq '{u.get('id')}'", "$expand": "roleDefinition"},
        )
        methods = section(client, f"{GRAPH}/users/{user}/authentication/methods", "Microsoft Graph")
        return {
            "id": u.get("id"),
            "login": u.get("userPrincipalName"),
            "enabled": u.get("accountEnabled"),
            "created": u.get("createdDateTime"),
            "password_changed": u.get("lastPasswordChangeDateTime"),
            "synced_from_ad": u.get("onPremisesSyncEnabled"),
            "admin_roles": [
                {"role": r.get("id"), "label": (r.get("roleDefinition") or {}).get("displayName")}
                for r in roles.get("value", [])
            ]
            if "value" in roles
            else roles,
            "mfa_methods": [
                str(m.get("@odata.type", "")).rsplit(".", 1)[-1] for m in methods.get("value", [])
            ]
            if "value" in methods
            else methods,
        }


ACTIONS = [RevokeSessions(), SuspendUser(), ResetPassword(), RemoveAdminRole(), RemoveFactor()]
LOOKUPS = [GetUser(), RecentFactor()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One user read, which the grant covers."""
    client = READ.client(_headers(creds), http)
    _send(client, "GET", f"{GRAPH}/users", params={"$top": "1", "$select": "id"})
    return "Graph read a user"
