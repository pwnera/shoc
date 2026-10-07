"""Stripe actions (RSP-4).

Block the card and the email behind a fraudulent charge in Radar, and lift the
block. That is the one response Stripe's API offers an account about itself:
it cannot revoke an API key, remove a team member or hold payouts, so a
takeover of the Stripe account is a page.

Radar's default block lists are found by their item type; `block_lists`
({"card_fingerprint": "rsl_…", "email": "rsl_…"}) names others. An item on a
default list is enforced by Radar's default block rules; a custom list needs a
rule of its own, which Radar's paid tiers allow.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send
from shoc.errors import ConfigError, ValidationError

API = "https://api.stripe.com/v1"


def _headers(creds: Credentials) -> dict[str, str]:
    (key,) = creds.require("api_key")
    return {"Authorization": f"Bearer {key}"}


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Stripe", **kw)


def _block_list(client: httpx.Client, creds: Credentials, item_type: str) -> str:
    named = (creds.settings.get("block_lists") or {}).get(item_type)
    if named:
        return str(named)
    lists = _send(client, "GET", f"{API}/radar/value_lists", params={"limit": 100}).json()
    for vl in lists.get("data") or []:
        label = f"{vl.get('alias', '')} {vl.get('name', '')}".lower()
        if vl.get("item_type") == item_type and "block" in label:
            return str(vl["id"])
    raise ConfigError(
        f"stripe: no Radar block list for {item_type}; name one in the settings' block_lists"
    )


class BlockChargeCard(BaseAction):
    type = "stripe.block_charge_card"
    provider = "stripe"
    platforms = ("stripe",)
    target_kind = "charge"
    summary = "Block the card and email behind a charge in Radar"
    reversible = True
    required_params = ("charge",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Add the card fingerprint and the email of charge {params.get('charge')} to "
            "Radar's block lists, so the next payment from either is refused"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        if not str(params["charge"]).startswith(("ch_", "py_")):
            raise ValidationError("stripe: charge must be a charge id (ch_…)")
        client = self.client(_headers(creds), http)
        charge = _send(client, "GET", f"{API}/charges/{seg(params['charge'])}").json()
        card = (charge.get("payment_method_details") or {}).get("card") or {}
        values = {
            "card_fingerprint": card.get("fingerprint"),
            "email": (charge.get("billing_details") or {}).get("email")
            or charge.get("receipt_email"),
        }
        items = []
        for item_type, value in values.items():
            if not value:
                continue
            listed = _block_list(client, creds, item_type)
            item = _send(
                client,
                "POST",
                f"{API}/radar/value_list_items",
                data={"value_list": listed, "value": value},
            ).json()
            items.append({"id": item.get("id"), "type": item_type, "value": value})
        if not items:
            return ActionResult(
                ok=False, detail=f"charge {params['charge']} names no card or email"
            )
        kept = {"charge": params["charge"], "items": items}
        blocked = ", ".join(i["type"] for i in items)
        return ActionResult(
            ok=True, detail=f"blocked the {blocked} of {params['charge']}", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        for item in undo.get("items") or []:
            _send(client, "DELETE", f"{API}/radar/value_list_items/{seg(item['id'])}")
        return ActionResult(ok=True, detail=f"Radar block on {undo.get('charge')} lifted")


class GetCharge(BaseLookup):
    type = "stripe.get_charge"
    provider = "stripe"
    platforms = ("stripe",)
    summary = "A charge's amount, status, Radar outcome, dispute, card fingerprint and email"
    required_params = ("charge",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = self.client(_headers(creds), http)
        c = _send(client, "GET", f"{API}/charges/{seg(params['charge'])}").json()
        card = (c.get("payment_method_details") or {}).get("card") or {}
        outcome = c.get("outcome") or {}
        return {
            "amount": c.get("amount"),
            "currency": c.get("currency"),
            "status": c.get("status"),
            "disputed": c.get("disputed"),
            "risk_level": outcome.get("risk_level"),
            "outcome": outcome.get("type"),
            "card_fingerprint": card.get("fingerprint"),
            "card_country": card.get("country"),
            "email": (c.get("billing_details") or {}).get("email") or c.get("receipt_email"),
            "created": c.get("created"),
        }


ACTIONS = [BlockChargeCard()]
LOOKUPS = [GetCharge()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One charge read, which the restricted key's Charges: read covers."""
    _send(READ.client(_headers(creds), http), "GET", f"{API}/charges", params={"limit": "1"})
    return "read a charge"
