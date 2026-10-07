"""Google Workspace actions (RSP-4) and lookups (RFC 0014), over the Admin SDK.

Until now a Google case could only page: the identity-provider actions speak
Okta and Entra. These are the Directory API calls the Splunk SOAR Google
connectors wrap, signed with the same service account and domain-wide
delegation the connector already uses. Settings need `admin_email`, the admin
the service account acts as. Gmail settings are the mailbox owner's, so mail
forwarding is changed acting as that user, with the gmail.settings.sharing
scope added to the delegation.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import (
    READ,
    ActionResult,
    BaseAction,
    BaseLookup,
    Credentials,
    seg,
    send,
    unknowable_password,
)
from shoc.errors import ConfigError

DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user "
    "https://www.googleapis.com/auth/admin.directory.user.security"
)


def _client(action: Any, creds: Credentials, http: httpx.Client | None) -> httpx.Client:
    from shoc.ingest.connectors import googleauth

    admin = creds.settings.get("admin_email")
    if not admin:
        raise ConfigError("google: settings need admin_email — set them with credential.configure")
    token = googleauth.access_token(creds.secret, SCOPES, subject=str(admin))
    return action.client({"Authorization": f"Bearer {token}", "Accept": "application/json"}, http)


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Google Admin SDK", **kw)


GMAIL = "https://gmail.googleapis.com/gmail/v1/users"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.settings.sharing"
FORWARDING = ("enabled", "emailAddress", "disposition")


def _user(user: str) -> str:
    return f"{DIRECTORY}/users/{seg(user)}"


class RevokeSessions(BaseAction):
    type = "google.revoke_sessions"
    provider = "google"
    platforms = ("google",)
    target_kind = "user"
    summary = "Sign a Google user out of every browser and device"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Sign {params.get('user')} out of every Google session; they sign in again"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        _send(_client(self, creds, http), "POST", f"{_user(params['user'])}/signOut")
        return ActionResult(
            ok=True, detail=f"{params['user']} signed out everywhere", data={"user": params["user"]}
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        return ActionResult(ok=True, detail="nothing to undo; the user can sign in again")


class SuspendUser(BaseAction):
    type = "google.suspend_user"
    provider = "google"
    platforms = ("google",)
    target_kind = "user"
    summary = "Suspend a Google Workspace account"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Suspend {params.get('user')} — they lose Gmail, Drive and every Google sign-in"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        _send(_client(self, creds, http), "PUT", _user(params["user"]), json={"suspended": True})
        return ActionResult(
            ok=True,
            detail=f"{params['user']} is suspended",
            data={"user": params["user"]},
            undo={"user": params["user"]},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        _send(_client(self, creds, http), "PUT", _user(undo["user"]), json={"suspended": False})
        return ActionResult(ok=True, detail=f"{undo['user']} is active again")


class ResetPassword(BaseAction):
    type = "google.reset_password"
    provider = "google"
    platforms = ("google",)
    target_kind = "user"
    summary = "Make a Google user's password stop working, so they set a new one"
    # The old password is gone for good: nothing can put it back.
    reversible = False
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Invalidate {params.get('user')}'s Google password: whoever knows it can no longer "
            "sign in, and the user sets a new one"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        # "Change at next sign-in" alone would let the old password choose the next
        # one; a password nobody holds replaces it.
        body = {"password": unknowable_password(), "changePasswordAtNextLogin": True}
        _send(_client(self, creds, http), "PUT", _user(params["user"]), json=body)
        return ActionResult(
            ok=True,
            detail=f"{params['user']}'s password no longer works; an administrator gives them a "
            "new one in the Admin console, or they recover the account",
            data={"user": params["user"]},
        )


class DisableMailForwarding(BaseAction):
    """Turn off a mailbox's automatic forwarding, keeping the address and what
    happened to the original for undo. The forwarding address stays verified,
    so undo can turn it back on."""

    type = "google.disable_mail_forwarding"
    provider = "google"
    platforms = ("google",)
    target_kind = "user"
    summary = "Turn off automatic forwarding on a Gmail mailbox"
    reversible = True
    required_params = ("user",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Turn off automatic mail forwarding for {params.get('user')}"

    def _gmail(
        self, creds: Credentials, user: str, http: httpx.Client | None
    ) -> tuple[httpx.Client, str]:
        from shoc.ingest.connectors import googleauth

        token = googleauth.access_token(creds.secret, GMAIL_SCOPE, subject=user)
        client = self.client(
            {"Authorization": f"Bearer {token}", "Accept": "application/json"}, http
        )
        return client, f"{GMAIL}/{seg(user)}/settings/autoForwarding"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        user = str(params["user"])
        client, url = self._gmail(creds, user, http)
        was = _send(client, "GET", url).json()
        kept = {k: was[k] for k in FORWARDING if k in was}
        _send(client, "PUT", url, json={"enabled": False})
        detail = (
            f"{user} no longer forwards mail to {kept.get('emailAddress')}"
            if kept.get("enabled")
            else f"{user} was not forwarding mail"
        )
        return ActionResult(
            ok=True,
            detail=detail,
            data={"user": user, "was": kept},
            undo={"user": user, "was": kept},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        if undo["was"].get("enabled"):
            client, url = self._gmail(creds, undo["user"], http)
            _send(client, "PUT", url, json=undo["was"])
        return ActionResult(ok=True, detail=f"mail forwarding for {undo['user']} is as it was")


class RevokeAppToken(BaseAction):
    """Delete the OAuth token a user issued to one app. The user can grant it again,
    but shoc cannot, so this is not reversible."""

    type = "google.revoke_app_token"
    provider = "google"
    platforms = ("google",)
    target_kind = "user"
    summary = "Revoke a third-party app's access to a Google account"
    reversible = False
    required_params = ("user", "client_id")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Revoke app {params.get('client_id')}'s token for {params.get('user')}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        _send(
            _client(self, creds, http),
            "DELETE",
            f"{_user(params['user'])}/tokens/{seg(params['client_id'])}",
        )
        return ActionResult(
            ok=True,
            detail=f"app {params['client_id']} can no longer act as {params['user']}",
            data={"user": params["user"], "client_id": params["client_id"]},
        )


class GetUser(BaseLookup):
    type = "google.get_user"
    provider = "google"
    platforms = ("google",)
    summary = "A Google user's status, admin rights, 2-step enrolment and last sign-in"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        u = _send(_client(self, creds, http), "GET", _user(params["user"])).json()
        keep = (
            "id",
            "primaryEmail",
            "suspended",
            "isAdmin",
            "isDelegatedAdmin",
            "isEnrolledIn2Sv",
            "isEnforcedIn2Sv",
            "lastLoginTime",
            "creationTime",
            "orgUnitPath",
        )
        return {k: u.get(k) for k in keep}


class ListAppTokens(BaseLookup):
    type = "google.list_app_tokens"
    provider = "google"
    platforms = ("google",)
    summary = "The third-party apps a Google user has granted access, with scopes"
    required_params = ("user",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        items = (
            _send(_client(self, creds, http), "GET", f"{_user(params['user'])}/tokens")
            .json()
            .get("items", [])
        )
        return {
            "tokens": [
                {
                    "client_id": t.get("clientId"),
                    "app": t.get("displayText"),
                    "scopes": t.get("scopes"),
                    "native_app": t.get("nativeApp"),
                }
                for t in items
            ]
        }


ACTIONS = [
    RevokeSessions(),
    SuspendUser(),
    ResetPassword(),
    DisableMailForwarding(),
    RevokeAppToken(),
]
LOOKUPS = [GetUser(), ListAppTokens()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One user read as the delegated admin: the key and the delegation both work."""
    client = _client(READ, creds, http)
    params = {"customer": "my_customer", "maxResults": "1"}
    _send(client, "GET", f"{DIRECTORY}/users", params=params)
    return f"read a user as {creds.settings.get('admin_email')}"
