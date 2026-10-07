"""Wazuh actions (RSP-4) and lookups (RFC 0014), over the Wazuh server API.

The connector reads alerts from the indexer; acting and reading live state go
through the server API (port 55000), with a user that holds the
`active-response:command`, `agent:read` and `syscheck:read` permissions. A token
comes from `POST /security/user/authenticate` with that user's password and
lasts 15 minutes, so each call logs in.

Wazuh's response is active response: a script the agent runs. `firewall-drop`
drops an address on the agent's host firewall. The API can start it and cannot
stop it, so the block lasts until the agent's own active-response timeout, or
until somebody removes the firewall rule; that makes it irreversible here.
"""

from __future__ import annotations

from typing import Any

import httpx

from shoc.actions.base import TIMEOUT, ActionResult, BaseAction, BaseLookup, Credentials, seg, send


def _api(creds: Credentials, http: httpx.Client | None) -> tuple[str, httpx.Client]:
    """The API's base URL and a client carrying a fresh token."""
    url, user, password = creds.require("api_url", "username", "password")
    base = str(url).rstrip("/")
    # The installer's API runs on a certificate it made itself.
    client = http or httpx.Client(
        timeout=TIMEOUT, verify=creds.settings.get("verify_tls", True) is not False
    )
    token = send(
        client,
        "POST",
        f"{base}/security/user/authenticate",
        "Wazuh",
        auth=(str(user), str(password)),
    ).json()["data"]["token"]
    client.headers["Authorization"] = f"Bearer {token}"
    return base, client


def _items(resp: httpx.Response) -> list[dict[str, Any]]:
    return list((resp.json().get("data") or {}).get("affected_items") or [])


class BlockIP(BaseAction):
    type = "wazuh.block_ip"
    provider = "wazuh"
    platforms = ("edr",)
    target_kind = "ip"
    summary = "Drop an address on the host firewall of Wazuh agents (active response)"
    required_params = ("ip",)

    def plan(self, params: dict[str, Any]) -> str:
        where = f"agent {params['agent_id']}" if params.get("agent_id") else "every Wazuh agent"
        return (
            f"Drop {params.get('ip')} on the host firewall of {where}. Wazuh cannot lift "
            "it through its API: it lasts until the agent's own active-response timeout"
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        base, client = _api(creds, http)
        command = str(creds.settings.get("block_command") or "!firewall-drop")
        query = {"agents_list": str(params["agent_id"])} if params.get("agent_id") else {}
        resp = send(
            client,
            "PUT",
            f"{base}/active-response",
            "Wazuh",
            params=query,
            json={"command": command, "alert": {"data": {"srcip": str(params["ip"])}}},
        )
        agents = [str(a) for a in _items(resp)]
        return ActionResult(
            ok=bool(agents),
            detail=f"{params['ip']} dropped on {len(agents)} agent(s)"
            if agents
            else f"no agent accepted the block of {params['ip']}",
            data={"ip": params["ip"], "agents": agents},
        )


class GetAgent(BaseLookup):
    type = "wazuh.get_agent"
    provider = "wazuh"
    platforms = ("edr",)
    summary = "A Wazuh agent's name, addresses, OS, groups, version and whether it is connected"
    required_params = ("agent_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, client = _api(creds, http)
        found = _items(
            send(
                client,
                "GET",
                f"{base}/agents",
                "Wazuh",
                params={"agents_list": str(params["agent_id"])},
            )
        )
        a = found[0] if found else {}
        return {
            "name": a.get("name"),
            "ip": a.get("ip"),
            "registered_ip": a.get("registerIP"),
            "os": (a.get("os") or {}).get("name"),
            "status": a.get("status"),
            "last_keep_alive": a.get("lastKeepAlive"),
            "groups": a.get("group"),
            "version": a.get("version"),
        }


class FindFile(BaseLookup):
    type = "wazuh.find_file"
    provider = "wazuh"
    platforms = ("edr",)
    summary = "Which files on a Wazuh agent have this MD5, SHA-1 or SHA-256 (FIM)"
    required_params = ("agent_id", "hash")

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, client = _api(creds, http)
        files = _items(
            send(
                client,
                "GET",
                f"{base}/syscheck/{seg(params['agent_id'])}",
                "Wazuh",
                params={"hash": str(params["hash"]), "limit": 50},
            )
        )
        return {
            "files": [
                {
                    "file": f.get("file"),
                    "size": f.get("size"),
                    "mtime": f.get("mtime"),
                    "owner": f.get("uname"),
                }
                for f in files
            ],
            "count": len(files),
        }


ACTIONS = [BlockIP()]
LOOKUPS = [GetAgent(), FindFile()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The API's own login."""
    base, _ = _api(creds, http)
    return f"signed in to {base}"
