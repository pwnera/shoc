"""Notification actions (RSP-4): wake a human.

Paging is an action like any other — typed, recorded and audited — because "we
paged someone" is part of the incident record.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import ActionResult, BaseAction, Credentials
from shoc.errors import ConfigError, StoreError

# PagerDuty's Events API per service region. An account in the EU region is
# paged through its EU host, so case titles stay in the region it chose.
EVENTS_API = {
    "us": "https://events.pagerduty.com/v2/enqueue",
    "eu": "https://events.eu.pagerduty.com/v2/enqueue",
}


def events_api(creds: Credentials) -> str:
    """Where to post: the credential's optional `region`, us unless it says eu."""
    region = str(creds.settings.get("region") or creds.secret.get("region") or "us").lower()
    if region not in EVENTS_API:
        raise ConfigError(f"notify: region is us or eu, not {region!r}")
    return EVENTS_API[region]


class PageOnCall(BaseAction):
    type = "notify.page"
    provider = "notify"
    target_kind = "oncall"
    summary = "Page the on-call engineer"
    reversible = True
    required_params = ("summary",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Page the on-call engineer: {params.get('summary')}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        (routing_key,) = creds.require("routing_key")
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": params.get("dedup_key") or params["summary"][:120],
            "payload": {
                "summary": params["summary"][:1024],
                "severity": params.get("severity", "warning"),
                "source": "shoc",
                "custom_details": params.get("details", {}),
            },
        }
        client = self.client({"Content-Type": "application/json"}, http)
        try:
            resp = client.post(events_api(creds), json=payload)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPError as exc:
            raise StoreError(f"paging failed: {exc}") from exc
        return ActionResult(
            ok=True,
            detail=f"paged on-call: {params['summary'][:80]}",
            data={"dedup_key": body.get("dedup_key", payload["dedup_key"])},
            undo={
                "routing_key_set": True,
                "dedup_key": body.get("dedup_key", payload["dedup_key"]),
            },
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        (routing_key,) = creds.require("routing_key")
        client = self.client({"Content-Type": "application/json"}, http)
        client.post(
            events_api(creds),
            json={
                "routing_key": routing_key,
                "event_action": "resolve",
                "dedup_key": undo["dedup_key"],
            },
        )
        return ActionResult(ok=True, detail="page resolved")


ACTIONS = [PageOnCall()]
