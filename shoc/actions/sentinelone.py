"""SentinelOne actions (RSP-4) and lookups (RFC 0014).

What the Splunk SOAR SentinelOne connector does for an endpoint case: disconnect
an agent from the network, blocklist a file by hash, read an agent, and ask
which agents have seen a file. The credential is a service user's API token
for the management console (RFC 0031).
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
    digest,
    send,
)
from shoc.errors import ConfigError, ValidationError


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "SentinelOne", **kw)


def _console(
    acting: Any, creds: Credentials, http: httpx.Client | None
) -> tuple[str, httpx.Client]:
    (token,) = creds.require("api_token")
    base = str(creds.settings.get("console_url") or creds.settings.get("base_url") or "")
    if not base:
        raise ConfigError("sentinelone: settings need console_url")
    return base.rstrip("/"), acting.client({"Authorization": f"ApiToken {token}"}, http)


def _agent(device_id: str) -> dict[str, list[str]]:
    """The filter for one agent: the console id from an alert is a number, the
    UUID from Cloud Funnel telemetry is not."""
    return {"ids": [device_id]} if device_id.isdigit() else {"uuids": [device_id]}


def _agent_id(client: httpx.Client, base: str, device_id: str) -> str:
    """The console's agent id, which the agent actions take. Alerts carry it; the
    device entity and Cloud Funnel carry the agent UUID, which is looked up
    (RFC 0026)."""
    if device_id.isdigit():
        return device_id
    found = _send(
        client, "GET", f"{base}/web/api/v2.1/agents", params={"uuids": device_id}
    ).json().get("data") or [{}]
    if not found[0].get("id"):
        raise ValidationError(f"sentinelone: no agent with UUID {device_id}")
    return str(found[0]["id"])


class IsolateHost(BaseAction):
    type = "sentinelone.isolate_host"
    provider = "sentinelone"
    platforms = ("edr",)
    target_kind = "host"
    summary = "Disconnect a SentinelOne agent's host from the network"
    reversible = True
    required_params = ("device_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Disconnect {params.get('device_id')} from the network, except the SentinelOne "
            "console. Whoever is using it loses their call, their VPN and their files."
        )

    def _call(self, creds: Credentials, device_id: str, verb: str, http: Any) -> None:
        base, client = _console(self, creds, http)
        _send(
            client,
            "POST",
            f"{base}/web/api/v2.1/agents/actions/{verb}",
            json={"filter": {"ids": [_agent_id(client, base, device_id)]}},
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        device_id = params["device_id"]
        self._call(creds, device_id, "disconnect", http)
        return ActionResult(
            ok=True,
            detail=f"{device_id} isolated (disconnect)",
            data={"device_id": device_id},
            undo={"device_id": device_id},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._call(creds, undo["device_id"], "connect", http)
        return ActionResult(ok=True, detail=f"{undo['device_id']} back on the network")


class BlockHash(BaseAction):
    type = "sentinelone.block_hash"
    provider = "sentinelone"
    platforms = ("edr",)
    target_kind = "hash"
    summary = "Blocklist a file on every SentinelOne endpoint, by SHA-1 or SHA-256"
    reversible = True
    required_params = ("hash",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Block file {params.get('hash')} on every endpoint SentinelOne manages"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        value = digest(params, "sentinelone")
        base, client = _console(self, creds, http)
        body = _send(
            client,
            "POST",
            f"{base}/web/api/v2.1/restrictions",
            json={
                "data": {
                    "type": "black_hash",
                    "value": value,
                    "osType": params.get("os", "windows"),
                    "description": str(params.get("note") or "blocked by shoc"),
                },
                "filter": {"tenant": True},
            },
        ).json()
        data = body.get("data") or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        rule_id = data.get("id", "")
        return ActionResult(
            ok=True,
            detail=f"{value} blocked (sentinelone indicator {rule_id})",
            data={"hash": value, "indicator_id": rule_id},
            undo={"hash": value, "indicator_id": rule_id},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        base, client = _console(self, creds, http)
        _send(
            client,
            "DELETE",
            f"{base}/web/api/v2.1/restrictions",
            json={"data": {"type": "black_hash", "ids": [undo["indicator_id"]]}},
        )
        return ActionResult(ok=True, detail=f"{undo['hash']} unblocked")


class GetHost(BaseLookup):
    type = "sentinelone.get_host"
    provider = "sentinelone"
    platforms = ("edr",)
    summary = "A SentinelOne agent's host name, OS, last user, address, last seen and network state"
    required_params = ("device_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, client = _console(self, creds, http)
        agent = {k: v[0] for k, v in _agent(str(params["device_id"])).items()}
        found = _send(client, "GET", f"{base}/web/api/v2.1/agents", params=agent).json()
        d = (found.get("data") or [{}])[0]
        return {
            "hostname": d.get("computerName"),
            "os": d.get("osName"),
            "last_user": d.get("lastLoggedInUserName"),
            "external_ip": d.get("externalIp"),
            "last_seen": d.get("lastActiveDate"),
            "containment": d.get("networkStatus"),
            "infected": d.get("infected"),
        }


class FindHash(BaseLookup):
    type = "sentinelone.find_hash"
    provider = "sentinelone"
    platforms = ("edr",)
    summary = "Which SentinelOne agents raised a threat on a file, by SHA-1 or SHA-256"
    required_params = ("hash",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        value = digest(params, "sentinelone")
        base, client = _console(self, creds, http)
        threats = (
            _send(
                client,
                "GET",
                f"{base}/web/api/v2.1/threats",
                params={"contentHashes": value, "limit": 100},
            )
            .json()
            .get("data")
            or []
        )
        hosts = sorted(
            {str((t.get("agentRealtimeInfo") or {}).get("agentComputerName", "")) for t in threats}
            - {""}
        )
        return {"hosts": hosts, "threats": len(threats)}


ACTIONS = [IsolateHost(), BlockHash()]
LOOKUPS = [GetHost(), FindHash()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The token is static, so one agent is read with it."""
    base, client = _console(READ, creds, http)
    _send(client, "GET", f"{base}/web/api/v2.1/agents", params={"limit": "1"})
    return "sentinelone accepted the credential"
