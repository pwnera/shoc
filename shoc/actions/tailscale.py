"""Tailscale actions (RSP-4) and lookups (RFC 0014).

Take a device off the tailnet and put it back, turn its key expiry back on,
suspend a user and restore them, and revoke a key. A revoked key cannot be restored and does not remove the
devices it already added, so it waits for a human and is paired with the device
action.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send
from shoc.errors import NotFound

API = "https://api.tailscale.com/api/v2"


def _headers(creds: Credentials) -> dict[str, str]:
    from shoc.ingest.connectors.tailscale import access_token

    return {"Authorization": f"Bearer {access_token({**creds.settings, **creds.secret})}"}


def _tailnet(creds: Credentials) -> str:
    return seg(creds.settings.get("tailnet") or "-")


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Tailscale", **kw)


class DeauthorizeDevice(BaseAction):
    type = "tailscale.deauthorize_device"
    provider = "tailscale"
    platforms = ("tailscale",)
    target_kind = "device"
    summary = "Take a device off the tailnet until it is authorized again"
    reversible = True
    required_params = ("device_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Deauthorize Tailscale device {params.get('device_id')}; it reaches nothing on the "
            "tailnet, and a subnet router or exit node takes its routes down with it"
        )

    def _authorize(
        self, creds: Credentials, device: str, on: bool, http: httpx.Client | None
    ) -> None:
        client = self.client(_headers(creds), http)
        _send(client, "POST", f"{API}/device/{seg(device)}/authorized", json={"authorized": on})

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._authorize(creds, params["device_id"], False, http)
        kept = {"device_id": params["device_id"]}
        return ActionResult(
            ok=True, detail=f"device {params['device_id']} deauthorized", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._authorize(creds, undo["device_id"], True, http)
        return ActionResult(ok=True, detail=f"device {undo['device_id']} authorized again")


class EnableKeyExpiry(BaseAction):
    """A device with key expiry disabled stays on the tailnet for ever; with it
    on, the device must sign in again once its node key's expiry date passes."""

    type = "tailscale.enable_key_expiry"
    provider = "tailscale"
    platforms = ("tailscale",)
    target_kind = "device"
    summary = "Turn key expiry back on for a Tailscale device"
    reversible = True
    required_params = ("device_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Turn key expiry on for Tailscale device {params.get('device_id')}; it must "
            "sign in again when its key expires"
        )

    def _set(self, client: httpx.Client, device: str, disabled: bool) -> None:
        _send(
            client, "POST", f"{API}/device/{seg(device)}/key", json={"keyExpiryDisabled": disabled}
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = self.client(_headers(creds), http)
        device = params["device_id"]
        was = bool(
            _send(client, "GET", f"{API}/device/{seg(device)}").json().get("keyExpiryDisabled")
        )
        self._set(client, device, False)
        kept = {"device_id": device, "key_expiry_disabled": was}
        return ActionResult(
            ok=True, detail=f"key expiry on for device {device}", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._set(
            self.client(_headers(creds), http), undo["device_id"], bool(undo["key_expiry_disabled"])
        )
        return ActionResult(ok=True, detail=f"key expiry for {undo['device_id']} is as it was")


class SuspendUser(BaseAction):
    type = "tailscale.suspend_user"
    provider = "tailscale"
    platforms = ("tailscale",)
    target_kind = "user"
    summary = "Suspend a Tailscale user: their devices, keys and tokens stop working"
    reversible = True
    required_params = ("user",)

    def _user_id(self, client: httpx.Client, creds: Credentials, user: str) -> str:
        """The audit log names a user by login; the API wants the user id."""
        people = _send(client, "GET", f"{API}/tailnet/{_tailnet(creds)}/users").json()
        for person in people.get("users") or []:
            if user in (person.get("id"), person.get("loginName")):
                return str(person["id"])
        raise NotFound(f"tailscale: no user '{user}' in this tailnet")

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = self.client(_headers(creds), http)
        uid = self._user_id(client, creds, str(params["user"]))
        _send(client, "POST", f"{API}/users/{seg(uid)}/suspend")
        kept = {"user": params["user"], "user_id": uid}
        return ActionResult(ok=True, detail=f"{params['user']} suspended", data=kept, undo=kept)

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        _send(client, "POST", f"{API}/users/{seg(undo['user_id'])}/restore")
        return ActionResult(ok=True, detail=f"{undo['user']} restored")


class RevokeKey(BaseAction):
    type = "tailscale.revoke_key"
    provider = "tailscale"
    platforms = ("tailscale",)
    target_kind = "key"
    summary = "Revoke a Tailscale auth key or API token"
    required_params = ("key_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Revoke Tailscale key {params.get('key_id')}. This cannot be undone, and devices "
            "the key already added stay on the tailnet"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = self.client(_headers(creds), http)
        _send(client, "DELETE", f"{API}/tailnet/{_tailnet(creds)}/keys/{seg(params['key_id'])}")
        return ActionResult(
            ok=True, detail=f"key {params['key_id']} revoked", data={"key_id": params["key_id"]}
        )


class GetDevice(BaseLookup):
    type = "tailscale.get_device"
    provider = "tailscale"
    platforms = ("tailscale",)
    summary = "A device's owner, addresses, OS, last seen, authorization and key expiry"
    required_params = ("device_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = self.client(_headers(creds), http)
        d = _send(
            client, "GET", f"{API}/device/{seg(params['device_id'])}", params={"fields": "all"}
        ).json()
        keys = (
            "name",
            "hostname",
            "user",
            "addresses",
            "os",
            "clientVersion",
            "created",
            "lastSeen",
            "authorized",
            "keyExpiryDisabled",
            "expires",
            "tags",
            "multipleConnections",
            "enabledRoutes",
        )
        return {k: d.get(k) for k in keys}


ACTIONS = [DeauthorizeDevice(), EnableKeyExpiry(), SuspendUser(), RevokeKey()]
LOOKUPS = [GetDevice()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The tailnet's auth keys, which the grant covers."""
    client = READ.client(_headers(creds), http)
    keys = _send(client, "GET", f"{API}/tailnet/{_tailnet(creds)}/keys").json()
    return f"reads the tailnet: {len(keys.get('keys') or [])} auth key(s)"
