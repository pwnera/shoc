"""Microsoft 365 actions (RSP-4) and lookups (RFC 0014), over Microsoft Graph.

Business email compromise shows up as a mailbox rule that forwards or hides
mail, and consent phishing as a delegated grant to an app nobody asked for. The
Splunk SOAR Graph connector documents reading both; these remove them, keep a
copy, and put them back on undo.

Credentials are their own provider, `m365`, because a company can sign in with
Okta and still keep its mail in Microsoft 365. The app registration needs
MailboxSettings.ReadWrite, DelegatedPermissionGrant.ReadWrite.All and
User.RevokeSessions.All.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send

GRAPH = "https://graph.microsoft.com/v1.0"
# What Graph returns on a rule but refuses on create.
RULE_READ_ONLY = ("id", "@odata.context", "@odata.etag", "hasError", "isReadOnly")
GRANT_FIELDS = ("clientId", "consentType", "principalId", "resourceId", "scope")


def _client(action: Any, creds: Credentials, http: httpx.Client | None) -> httpx.Client:
    from shoc.ingest.connectors.msgraph import access_token

    return action.client(
        {"Authorization": f"Bearer {access_token(creds.secret)}", "Accept": "application/json"},
        http,
    )


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Microsoft Graph", **kw)


def _rules_url(user: str) -> str:
    return f"{GRAPH}/users/{seg(user)}/mailFolders/inbox/messageRules"


class DeleteInboxRule(BaseAction):
    type = "m365.delete_inbox_rule"
    provider = "m365"
    platforms = ("m365",)
    target_kind = "user"
    summary = "Delete a mailbox rule that forwards, hides or deletes mail"
    reversible = True
    required_params = ("user", "rule_id")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Delete inbox rule {params.get('rule_id')} from {params.get('user')}'s mailbox"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user, rule_id = params["user"], params["rule_id"]
        client = _client(self, creds, http)
        url = f"{_rules_url(user)}/{seg(rule_id)}"
        rule = _send(client, "GET", url).json()
        _send(client, "DELETE", url)
        kept = {k: v for k, v in rule.items() if k not in RULE_READ_ONLY}
        return ActionResult(
            ok=True,
            detail=f"inbox rule '{rule.get('displayName', rule_id)}' deleted from {user}",
            data={"user": user, "rule": kept},
            undo={"user": user, "rule": kept},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = _client(self, creds, http)
        _send(client, "POST", _rules_url(undo["user"]), json=undo["rule"])
        return ActionResult(ok=True, detail=f"inbox rule recreated for {undo['user']}")


class RevokeSessions(BaseAction):
    """Microsoft 365's own sign-out, so a mailbox case does not wait on an `entra`
    credential the company may not have: it signs in with Okta."""

    type = "m365.revoke_sessions"
    provider = "m365"
    platforms = ("m365",)
    target_kind = "user"
    summary = "Sign a Microsoft 365 user out and invalidate their refresh tokens"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Sign {params.get('user')} out of Microsoft 365 everywhere; they sign in again"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = _client(self, creds, http)
        _send(client, "POST", f"{GRAPH}/users/{seg(params['user'])}/revokeSignInSessions")
        return ActionResult(
            ok=True,
            detail=f"{params['user']} signed out of Microsoft 365",
            data={"user": params["user"]},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        return ActionResult(ok=True, detail="nothing to undo; the user can sign in again")


class RevokeAppConsent(BaseAction):
    """Delete one delegated permission grant (an `oauth2PermissionGrant`).

    Application permissions an admin consented to are app role assignments, not
    grants, and are left to a human.
    """

    type = "m365.revoke_app_consent"
    provider = "m365"
    platforms = ("entra", "m365")
    target_kind = "user"
    summary = "Revoke the permissions a user or admin granted a third-party app"
    reversible = True
    required_params = ("grant_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Delete delegated permission grant {params.get('grant_id')}. The app loses "
            "access to mail and files until someone consents again."
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = _client(self, creds, http)
        url = f"{GRAPH}/oauth2PermissionGrants/{seg(params['grant_id'])}"
        grant = _send(client, "GET", url).json()
        _send(client, "DELETE", url)
        kept = {k: grant.get(k) for k in GRANT_FIELDS}
        return ActionResult(
            ok=True,
            detail=f"grant {params['grant_id']} revoked (scopes: {grant.get('scope', '')})",
            data={"grant": kept},
            undo={"grant": kept},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = _client(self, creds, http)
        _send(client, "POST", f"{GRAPH}/oauth2PermissionGrants", json=undo["grant"])
        return ActionResult(ok=True, detail="permission grant restored")


class ListInboxRules(BaseLookup):
    type = "m365.list_inbox_rules"
    provider = "m365"
    platforms = ("m365",)
    summary = "A mailbox's inbox rules: what each one forwards, moves or deletes"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = _client(self, creds, http)
        rules = _send(client, "GET", _rules_url(params["user"])).json().get("value", [])
        return {
            "rules": [
                {
                    "rule_id": r.get("id"),
                    "name": r.get("displayName"),
                    "enabled": r.get("isEnabled"),
                    "conditions": r.get("conditions"),
                    "actions": r.get("actions"),
                }
                for r in rules
            ]
        }


class ListAppConsents(BaseLookup):
    type = "m365.list_app_consents"
    provider = "m365"
    platforms = ("entra", "m365")
    summary = "The third-party apps a user has granted delegated access, with scopes"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = _client(self, creds, http)
        uid = _send(
            client, "GET", f"{GRAPH}/users/{seg(params['user'])}", params={"$select": "id"}
        ).json()["id"]
        grants = (
            _send(client, "GET", f"{GRAPH}/users/{seg(uid)}/oauth2PermissionGrants")
            .json()
            .get("value", [])
        )
        out = []
        for g in grants[:20]:
            app = _send(
                client,
                "GET",
                f"{GRAPH}/servicePrincipals/{seg(g.get('clientId'))}",
                params={"$select": "displayName,appId,verifiedPublisher,appOwnerOrganizationId"},
            ).json()
            out.append(
                {
                    "grant_id": g.get("id"),
                    "scope": g.get("scope"),
                    "consent_type": g.get("consentType"),
                    "app": app.get("displayName"),
                    "app_id": app.get("appId"),
                    "verified_publisher": (app.get("verifiedPublisher") or {}).get("displayName"),
                }
            )
        return {"grants": out, "total": len(grants)}


ACTIONS = [DeleteInboxRule(), RevokeSessions(), RevokeAppConsent()]
LOOKUPS = [ListInboxRules(), ListAppConsents()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One app-consent read, which DelegatedPermissionGrant covers."""
    client = _client(READ, creds, http)
    _send(client, "GET", f"{GRAPH}/oauth2PermissionGrants", params={"$top": "1"})
    return "Graph read the app consents"
