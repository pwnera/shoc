"""Cloudflare account actions (RSP-4): block an address at the edge, and disable
an account-owned API token.

A disabled token keeps its name, permissions and conditions, so undo gives back
exactly what was there. A token a user owns can only be changed by that user;
removing the member is what cuts it off, and that is a human's call.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send

API = "https://api.cloudflare.com/client/v4"
# What a PUT carries back: it replaces the token, and `name` and `policies` are required.
KEPT = ("name", "policies", "condition", "expires_on", "not_before")


def _headers(creds: Credentials) -> dict[str, str]:
    (token,) = creds.require("api_token")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


class DisableApiToken(BaseAction):
    type = "cloudflare.disable_api_token"
    provider = "cloudflare"
    platforms = ("cloudflare",)
    target_kind = "token"
    summary = "Disable a Cloudflare account API token"
    reversible = True
    required_params = ("token_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Disable Cloudflare API token {params.get('token_id')}; whatever uses it, "
            "a deploy included, is refused until it is enabled again"
        )

    def _set(
        self, creds: Credentials, token_id: str, status: str, http: httpx.Client | None
    ) -> str:
        (account,) = creds.require("account_id")
        client = self.client(_headers(creds), http)
        url = f"{API}/accounts/{seg(account)}/tokens/{seg(token_id)}"
        token = send(client, "GET", url, "Cloudflare").json().get("result") or {}
        body = {k: token[k] for k in KEPT if token.get(k) is not None}
        send(client, "PUT", url, "Cloudflare", json={**body, "status": status})
        return str(token.get("status") or "active")

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        was = self._set(creds, params["token_id"], "disabled", http)
        kept = {"token_id": params["token_id"], "status": was}
        return ActionResult(
            ok=True, detail=f"Cloudflare token {params['token_id']} disabled", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._set(creds, undo["token_id"], undo.get("status") or "active", http)
        return ActionResult(ok=True, detail=f"Cloudflare token {undo['token_id']} enabled again")


class BlockIP(BaseAction):
    type = "cloudflare.block_ip"
    provider = "cloudflare"
    platforms = ("cloudflare",)
    target_kind = "ip"
    summary = "Block a source address at the Cloudflare edge"
    reversible = True
    required_params = ("ip",)

    def plan(self, params: dict[str, Any]) -> str:
        ttl = params.get("ttl_minutes", 120)
        return f"Block {params.get('ip')} at the Cloudflare edge for {ttl} minutes"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        (account_id,) = creds.require("account_id")
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": params["ip"]},
            "notes": params.get("note", "blocked by shoc"),
        }
        body = send(
            self.client(_headers(creds), http),
            "POST",
            f"{API}/accounts/{seg(account_id)}/firewall/access_rules/rules",
            "Cloudflare",
            json=payload,
        ).json()
        rule_id = (body.get("result") or {}).get("id", "")
        return ActionResult(
            ok=True,
            detail=f"{params['ip']} blocked at the edge (rule {rule_id})",
            data={"ip": params["ip"], "rule_id": rule_id},
            undo={"rule_id": rule_id, "account_id": account_id, "ip": params["ip"]},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        rules = f"{API}/accounts/{seg(undo['account_id'])}/firewall/access_rules/rules"
        send(
            self.client(_headers(creds), http),
            "DELETE",
            f"{rules}/{seg(undo['rule_id'])}",
            "Cloudflare",
        )
        return ActionResult(ok=True, detail=f"{undo.get('ip')} unblocked")


class GetApiToken(BaseLookup):
    type = "cloudflare.get_api_token"
    provider = "cloudflare"
    platforms = ("cloudflare",)
    summary = "An account API token's name, status, address conditions, expiry and last use"
    required_params = ("token_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        (account,) = creds.require("account_id")
        client = self.client(_headers(creds), http)
        t = (
            send(
                client,
                "GET",
                f"{API}/accounts/{seg(account)}/tokens/{seg(params['token_id'])}",
                "Cloudflare",
            )
            .json()
            .get("result")
            or {}
        )
        return {
            "name": t.get("name"),
            "status": t.get("status"),
            "issued_on": t.get("issued_on"),
            "last_used_on": t.get("last_used_on"),
            "expires_on": t.get("expires_on"),
            "condition": t.get("condition"),
            "policies": len(t.get("policies") or []),
        }


ACTIONS = [BlockIP(), DisableApiToken()]
LOOKUPS = [GetApiToken()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """Cloudflare's own check of an account token."""
    (account,) = creds.require("account_id")
    url = f"{API}/accounts/{seg(account)}/tokens/verify"
    out = send(READ.client(_headers(creds), http), "GET", url, "Cloudflare").json()
    return f"token {(out.get('result') or {}).get('status', 'active')}"
