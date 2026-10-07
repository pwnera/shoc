"""OpenAI API Platform actions (RSP-4).

OpenAI has no way to disable a key: it can only be deleted, and a deleted key
is gone, so this waits for a human. A key that belongs to a service account
cannot be deleted on its own; the service account has to go. Throttling the
key's project to the floor is reversible, and runs while the deletion waits.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send

API = "https://api.openai.com/v1/organization"


class DeleteApiKey(BaseAction):
    type = "openai.delete_api_key"
    provider = "openai"
    platforms = ("openai",)
    target_kind = "key"
    summary = "Delete an OpenAI project API key"
    required_params = ("key_id", "project_id")

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Delete OpenAI API key {params.get('key_id')} from project "
            f"{params.get('project_id')}. It cannot be restored; whatever uses it needs a new key"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        (key,) = creds.require("admin_key")
        client = self.client({"Authorization": f"Bearer {key}"}, http)
        send(
            client,
            "DELETE",
            f"{API}/projects/{seg(params['project_id'])}/api_keys/{seg(params['key_id'])}",
            "OpenAI",
        )
        return ActionResult(
            ok=True,
            detail=f"OpenAI API key {params['key_id']} deleted",
            data={"key_id": params["key_id"], "project_id": params["project_id"]},
        )


# The project rate-limit fields, each set to 1 while the project is held.
LIMITS = (
    "max_requests_per_1_minute",
    "max_tokens_per_1_minute",
    "max_images_per_1_minute",
    "max_audio_megabytes_per_1_minute",
    "max_requests_per_1_day",
    "batch_1_day_max_input_tokens",
)


class LimitProject(BaseAction):
    """Set every model's rate limits in a project to the minimum, keeping the old
    ones for undo. Every key in the project slows to a trickle, the leaked one too."""

    type = "openai.limit_project"
    provider = "openai"
    platforms = ("openai",)
    target_kind = "resource"
    summary = "Throttle an OpenAI project's rate limits to the minimum"
    reversible = True
    required_params = ("project_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Set every rate limit in OpenAI project {params.get('project_id')} to 1; "
            "every key in the project slows to a trickle until undone"
        )

    def _limits(self, client: httpx.Client, project: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        query: dict[str, Any] = {"limit": 100}
        while True:
            page = send(
                client, "GET", f"{API}/projects/{seg(project)}/rate_limits", "OpenAI", params=query
            ).json()
            out += page.get("data") or []
            if not page.get("has_more") or not out:
                return out
            query["after"] = out[-1]["id"]

    def _set(
        self, client: httpx.Client, project: str, limit_id: str, values: dict[str, Any]
    ) -> None:
        url = f"{API}/projects/{seg(project)}/rate_limits/{seg(limit_id)}"
        send(client, "POST", url, "OpenAI", json=values)

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        (key,) = creds.require("admin_key")
        client = self.client({"Authorization": f"Bearer {key}"}, http)
        project = str(params["project_id"])
        was = {
            str(r["id"]): {k: r[k] for k in LIMITS if r.get(k) is not None}
            for r in self._limits(client, project)
        }
        for limit_id, old in was.items():
            if old:
                self._set(client, project, limit_id, dict.fromkeys(old, 1))
        return ActionResult(
            ok=True,
            detail=f"{len(was)} rate limit(s) in project {project} set to 1",
            data={"project_id": project, "models": len(was)},
            undo={"project_id": project, "was": was},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        (key,) = creds.require("admin_key")
        client = self.client({"Authorization": f"Bearer {key}"}, http)
        for limit_id, old in undo["was"].items():
            if old:
                self._set(client, undo["project_id"], limit_id, old)
        return ActionResult(ok=True, detail=f"rate limits in {undo['project_id']} restored")


class GetApiKey(BaseLookup):
    type = "openai.get_api_key"
    provider = "openai"
    platforms = ("openai",)
    summary = "A project API key's name, owner, redacted value, and when it was made and last used"
    required_params = ("key_id", "project_id")

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        (key,) = creds.require("admin_key")
        client = self.client({"Authorization": f"Bearer {key}"}, http)
        k = send(
            client,
            "GET",
            f"{API}/projects/{seg(params['project_id'])}/api_keys/{seg(params['key_id'])}",
            "OpenAI",
        ).json()
        owner = k.get("owner") or {}
        holder = owner.get("user") or owner.get("service_account") or {}
        return {
            "name": k.get("name"),
            "redacted_value": k.get("redacted_value"),
            "created_at": k.get("created_at"),
            "last_used_at": k.get("last_used_at"),
            "owner_type": owner.get("type"),
            "owner": holder.get("email") or holder.get("name") or holder.get("id"),
        }


ACTIONS = [DeleteApiKey(), LimitProject()]
LOOKUPS = [GetApiKey()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """One organization member read, which only an Admin key may make."""
    (key,) = creds.require("admin_key")
    client = READ.client({"Authorization": f"Bearer {key}"}, http)
    send(client, "GET", f"{API}/users", "OpenAI", params={"limit": "1"})
    return "the Admin API answered"
