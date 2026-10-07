"""Anthropic (Claude API) actions (RSP-4).

Disable an API key and enable it again. The Admin API marks it `inactive`, and
the key keeps its name, workspace and value, so undo is exact. Admin keys
cannot be disabled through the API.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send

API = "https://api.anthropic.com/v1/organizations"


def _headers(creds: Credentials) -> dict[str, str]:
    from shoc.ingest.connectors.anthropic import headers

    creds.require("admin_key")
    return {**headers(creds.secret), "content-type": "application/json"}


class DisableApiKey(BaseAction):
    type = "anthropic.disable_api_key"
    provider = "anthropic"
    platforms = ("anthropic",)
    target_kind = "key"
    summary = "Disable a Claude API key"
    reversible = True
    required_params = ("key_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Disable Claude API key {params.get('key_id')}; every request made with it is "
            "refused, the company's own included, until it is enabled again"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = self.client(_headers(creds), http)
        url = f"{API}/api_keys/{seg(params['key_id'])}"
        was = send(client, "GET", url, "Anthropic").json().get("status") or "active"
        send(client, "POST", url, "Anthropic", json={"status": "inactive"})
        kept = {"key_id": params["key_id"], "status": was}
        return ActionResult(
            ok=True, detail=f"Claude API key {params['key_id']} disabled", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        send(
            client,
            "POST",
            f"{API}/api_keys/{seg(undo['key_id'])}",
            "Anthropic",
            json={"status": undo.get("status") or "active"},
        )
        return ActionResult(ok=True, detail=f"Claude API key {undo['key_id']} enabled again")


class GetApiKey(BaseLookup):
    type = "anthropic.get_api_key"
    provider = "anthropic"
    platforms = ("anthropic",)
    summary = "A Claude API key's name, status, workspace, who made it and when"
    required_params = ("key_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = self.client(_headers(creds), http)
        k = send(client, "GET", f"{API}/api_keys/{seg(params['key_id'])}", "Anthropic").json()
        return {
            "name": k.get("name"),
            "status": k.get("status"),
            "workspace_id": k.get("workspace_id"),
            "hint": k.get("partial_key_hint"),
            "created_at": k.get("created_at"),
            "created_by": (k.get("created_by") or {}).get("id"),
        }


ACTIONS = [DisableApiKey()]
LOOKUPS = [GetApiKey()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One organization member read, which only an Admin key may make."""
    client = READ.client(_headers(creds), http)
    send(client, "GET", f"{API}/users", "Anthropic", params={"limit": "1"})
    return "the Admin API answered"
