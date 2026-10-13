"""Entra ID actions (RSP-4) and lookups (RFC 0014), over Microsoft Graph.

The set follows the Splunk SOAR Azure AD connector, narrowed to what answers an
account takeover: sign the user out, disable them, take back a directory role,
remove a method the attacker registered, and read who they are before doing
any of it. An Azure Activity caller and a Microsoft 365 user are Entra
principals, so the account actions answer those cases too (RFC 0031).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx

from shoc.actions.base import (
    IDP_LINKED_FROM,
    READ,
    ActionResult,
    BaseAction,
    BaseLookup,
    Credentials,
    holders,
    newest,
    only_recent,
    section,
    seg,
    send,
    unknowable_password,
)
from shoc.errors import StoreError, ValidationError

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
    platforms = ("entra", "m365")  # a Global Administrator seen in M365's audit
    target_kind = "user"
    summary = "Remove an Entra ID directory role a user was just given"
    reversible = True
    required_params = ("user", "role")
    # The assignment given this week, when a playbook names only the grantee
    # (ir-7); then how many others hold the role, for whoever reads the plan (ir-9).
    resolve: ClassVar = {
        "role": (None, None, "entra.recent_role_assignment"),
        "holders_left": (None, None, "entra.role_holders"),
    }
    looked_up = ("holders_left",)
    # The role template the case's grant names (Entra's audit, then M365's).
    granted_at: ClassVar = (
        "unmapped.modified.Role_TemplateId.newValue",
        "unmapped.modified.Role_TemplateId.NewValue",
    )

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Remove Entra ID role assignment {params.get('role')} from {params.get('user')}"
            + holders(params, "other holders of the role")
        )

    def _url(self, params: dict[str, Any]) -> str:
        return f"{GRAPH}/roleManagement/directory/roleAssignments/{seg(params['role'])}"

    def snapshot(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        """The assignment to give back, read and kept before it is removed (RSP-4)."""
        self.check(params)
        was = _send(self.client(_headers(creds), http), "GET", self._url(params)).json()
        return {k: was.get(k) for k in ("roleDefinitionId", "principalId", "directoryScopeId")}

    def execute(
        self,
        creds: Credentials,
        params: dict[str, Any],
        http: httpx.Client | None = None,
        before: dict[str, Any] | None = None,
    ) -> ActionResult:
        self.check(params)
        user, role = params["user"], params["role"]
        client = self.client(_headers(creds), http)
        grant = before if before is not None else self.snapshot(creds, params, client)
        try:
            _send(client, "DELETE", self._url(params))
        except StoreError as exc:
            # Removed already: the first try did it and its answer was lost (RSP-4).
            cause = exc.__cause__
            if before is None or not (
                isinstance(cause, httpx.HTTPStatusError) and cause.response.status_code == 404
            ):
                raise
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

    def _url(self, params: dict[str, Any]) -> str:
        factor = str(params["factor_id"])
        method = METHOD.fullmatch(factor)
        if not method:
            raise ValidationError(f"{self.type}: '{factor}' is not <type>Methods/<id>")
        user = seg(params["user"])
        return f"{GRAPH}/users/{user}/authentication/{method[1]}/{seg(method[2])}"

    def snapshot(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        """The method as it was, kept before it is deleted, so the record says what
        went and a retry whose first answer was lost knows it is done (RSP-4)."""
        self.check(params)
        m = _send(self.client(_headers(creds), http), "GET", self._url(params)).json()
        keep = ("phoneType", "displayName", "createdDateTime")
        return {"type": str(m.get("@odata.type", "")).rsplit(".", 1)[-1]} | {
            k: m[k] for k in keep if m.get(k)
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
        client = self.client(_headers(creds), http)
        was = before if before is not None else self.snapshot(creds, params, client)
        try:
            _send(client, "DELETE", self._url(params))
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


def _registered(client: httpx.Client, user: str) -> dict[str, str] | None:
    """When each phone and email method of the user was registered in the last
    week, keyed like `phone:mobile` or `email`. Both the user's own registration
    and an admin's count: an attacker holding an admin role adds the phone as the
    admin. Read by the user's object id, the audit's target, whatever name the
    case gave. None when the user or the audit cannot be read."""
    since = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        me = _send(client, "GET", f"{GRAPH}/users/{seg(user)}", params={"$select": "id"})
        uid = str(me.json().get("id") or "")
    except StoreError:
        return None
    if not uid:
        return None
    quoted = uid.replace("'", "''")  # an OData string literal
    events: list[dict[str, Any]] = []
    for activity in ("User registered security info", "Admin registered security info"):
        found = section(
            client,
            f"{GRAPH}/auditLogs/directoryAudits",
            "Microsoft Graph",
            params={
                "$filter": f"activityDisplayName eq '{activity}' and "
                f"activityDateTime ge {since} and targetResources/any(t: t/id eq '{quoted}')"
            },
        )
        if "value" not in found:
            return None
        events += found["value"]
    out: dict[str, str] = {}
    for event in events:
        # As in 'User registered Mobile Phone SMS'. Not additionalDetails: its
        # user agent says iPhone on any registration made from one.
        said = str(event.get("resultReason") or "").lower()
        if "alternate" in said:
            slot = "phone:alternateMobile"
        elif "office" in said:
            slot = "phone:office"
        elif "phone" in said or "sms" in said:
            slot = "phone:mobile"
        elif "email" in said:
            slot = "email"
        else:
            continue
        at = str(event.get("activityDateTime") or "")
        if at > out.get(slot, ""):
            out[slot] = at
    return out


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
        user = str(params["user"])
        client = self.client(_headers(creds), http)
        url = f"{GRAPH}/users/{seg(user)}/authentication/methods"
        factors: list[dict[str, Any]] = []
        slots: dict[str, str] = {}
        for m in _send(client, "GET", url).json().get("value", []):
            kind = (
                str(m.get("@odata.type", ""))
                .rsplit(".", 1)[-1]
                .removesuffix("AuthenticationMethod")
            )
            if kind and kind != "password":  # the password is not a factor to remove
                factor_id = f"{kind}Methods/{m.get('id')}"
                slots[factor_id] = f"phone:{m.get('phoneType')}" if kind == "phone" else kind
                factors.append(
                    {"factor_id": factor_id, "type": kind, "created": m.get("createdDateTime")}
                )
        # Graph dates no phone, email or OATH method. An attacker's own phone is
        # the usual MFA persistence, so its registration in the audit dates it.
        registered = None
        if any(f["type"] in ("phone", "email") and not f["created"] for f in factors):
            registered = _registered(client, user)
        for f in factors:
            if not f["created"] and registered:
                f["created"] = registered.get(slots[f["factor_id"]])
        # A method still undated may be the newest: say so rather than guess.
        # With the audit read, an undated phone or email is older than the week.
        undated = [
            f["factor_id"]
            for f in factors
            if not f["created"] and not (registered is not None and f["type"] in ("phone", "email"))
        ]
        latest = newest(factors)
        return {
            "factor_id": "" if undated else latest.get("factor_id", ""),
            "newest": latest,
            "factors": factors,
            "undated": undated,
        }


def _role_grants(client: httpx.Client, uid: str) -> dict[str, str]:
    """When each directory role was given to a user in the last week, by role
    template id, as the audit's 'Add member to role' says: Graph dates no
    assignment. Empty when the audit cannot be read."""
    since = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    found = section(
        client,
        f"{GRAPH}/auditLogs/directoryAudits",
        "Microsoft Graph",
        params={
            "$filter": "activityDisplayName eq 'Add member to role' and "
            f"activityDateTime ge {since} and targetResources/any(t: t/id eq '{uid}')"
        },
    )
    out: dict[str, str] = {}
    for event in found.get("value", []):
        at = str(event.get("activityDateTime") or "")
        for target in event.get("targetResources") or []:
            for prop in target.get("modifiedProperties") or []:
                if prop.get("displayName") == "Role.TemplateId":
                    # Graph writes each value as JSON text, quotes included.
                    role = str(prop.get("newValue") or "").strip('"')
                    out[role] = max(out.get(role, ""), at)
    return out


class RecentRoleAssignment(BaseLookup):
    type = "entra.recent_role_assignment"
    provider = "entra"
    platforms = ("entra", "m365")
    summary = "A user's directory role assignments, and the one given in the last week"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = self.client(_headers(creds), http)
        user = _send(
            client, "GET", f"{GRAPH}/users/{seg(params['user'])}", params={"$select": "id"}
        ).json()
        uid = str(user.get("id", "")).replace("'", "''")
        held = _send(
            client,
            "GET",
            f"{GRAPH}/roleManagement/directory/roleAssignments",
            params={"$filter": f"principalId eq '{uid}'"},
        ).json()
        given = _role_grants(client, uid)
        assignments = [
            {
                "role": a.get("id"),
                "definition": a.get("roleDefinitionId"),
                "created": given.get(str(a.get("roleDefinitionId"))),
            }
            for a in held.get("value", [])
        ]
        # The one the case's grant names, when the runner read it: a built-in
        # role's definition id is its template id. Of two given this week, which
        # one the case is about is not ours to guess otherwise.
        granted = str(params.get("granted") or "").lower()
        named = (
            [a for a in assignments if str(a["definition"]).lower() == granted]
            if granted
            else assignments
        )
        return {"role": only_recent(named).get("role", ""), "assignments": assignments}


class RoleHolders(BaseLookup):
    type = "entra.role_holders"
    provider = "entra"
    platforms = ("entra", "m365")
    summary = "Who else holds the directory role of a role assignment"
    required_params = ("role",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = self.client(_headers(creds), http)
        url = f"{GRAPH}/roleManagement/directory/roleAssignments"
        role = _send(client, "GET", f"{url}/{seg(params['role'])}").json()
        definition = str(role.get("roleDefinitionId", "")).replace("'", "''")
        found = _send(
            client, "GET", url, params={"$filter": f"roleDefinitionId eq '{definition}'"}
        ).json()
        others = [
            a.get("principalId") for a in found.get("value", []) if a.get("id") != role.get("id")
        ]
        return {
            "role_definition": role.get("roleDefinitionId"),
            "holders": others,
            "holders_left": str(len(others)),
        }


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
LOOKUPS = [GetUser(), RecentFactor(), RecentRoleAssignment(), RoleHolders()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One user read, which the grant covers."""
    client = READ.client(_headers(creds), http)
    _send(client, "GET", f"{GRAPH}/users", params={"$top": "1", "$select": "id"})
    return "Graph read a user"
