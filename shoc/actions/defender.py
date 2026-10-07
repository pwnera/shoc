"""Microsoft Defender for Endpoint actions (RSP-4) and lookups (RFC 0014).

What the Splunk SOAR Defender connector does for an endpoint case: isolate a
machine, block a file with an indicator, read a machine, and ask which machines
have seen a file. The credential is an app registration with WindowsDefenderATP
Machine.Isolate and Ti.ReadWrite (RFC 0031).
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
    seg,
    send,
)

API = "https://api.securitycenter.microsoft.com"
SCOPE = f"{API}/.default"


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "Defender", **kw)


def _client(acting: Any, creds: Credentials, http: httpx.Client | None) -> httpx.Client:
    """A static `access_token` in the secret still works, for a token minted elsewhere."""
    from shoc.ingest.connectors.msgraph import access_token

    token = creds.secret.get("access_token") or access_token(creds.secret, SCOPE)
    return acting.client({"Authorization": f"Bearer {token}"}, http)


class IsolateHost(BaseAction):
    type = "defender.isolate_host"
    provider = "defender"
    platforms = ("edr",)
    target_kind = "host"
    summary = "Isolate a machine from the network in Defender"
    reversible = True
    required_params = ("device_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Isolate {params.get('device_id')} from everything except Defender. Whoever is "
            "using it loses their call, their VPN and their files."
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        device_id = params["device_id"]
        _send(
            _client(self, creds, http),
            "POST",
            f"{API}/api/machines/{seg(device_id)}/isolate",
            json={"Comment": "shoc containment", "IsolationType": "Full"},
        )
        return ActionResult(
            ok=True,
            detail=f"{device_id} isolated (isolate)",
            data={"device_id": device_id},
            undo={"device_id": device_id},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        _send(
            _client(self, creds, http),
            "POST",
            f"{API}/api/machines/{seg(undo['device_id'])}/unisolate",
            json={"Comment": "shoc containment lifted"},
        )
        return ActionResult(ok=True, detail=f"{undo['device_id']} back on the network")


class BlockHash(BaseAction):
    type = "defender.block_hash"
    provider = "defender"
    platforms = ("edr",)
    target_kind = "hash"
    summary = "Block and remediate a file on every Defender machine, by SHA-1 or SHA-256"
    reversible = True
    required_params = ("hash",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Block file {params.get('hash')} on every machine Defender manages"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        value = digest(params, "defender")
        body = _send(
            _client(self, creds, http),
            "POST",
            f"{API}/api/indicators",
            json={
                "indicatorValue": value,
                "indicatorType": "FileSha256" if len(value) == 64 else "FileSha1",
                "action": "BlockAndRemediate",
                "severity": "High",
                "title": "shoc block",
                "description": str(params.get("note") or "blocked by shoc"),
            },
        ).json()
        rule_id = str(body.get("id", ""))
        return ActionResult(
            ok=True,
            detail=f"{value} blocked (defender indicator {rule_id})",
            data={"hash": value, "indicator_id": rule_id},
            undo={"hash": value, "indicator_id": rule_id},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = _client(self, creds, http)
        _send(client, "DELETE", f"{API}/api/indicators/{seg(undo['indicator_id'])}")
        return ActionResult(ok=True, detail=f"{undo['hash']} unblocked")


class GetHost(BaseLookup):
    type = "defender.get_host"
    provider = "defender"
    platforms = ("edr",)
    summary = "A Defender machine's name, OS, addresses, last seen, health and risk"
    required_params = ("device_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        client = _client(self, creds, http)
        d = _send(client, "GET", f"{API}/api/machines/{seg(params['device_id'])}").json()
        return {
            "hostname": d.get("computerDnsName"),
            "os": d.get("osPlatform"),
            "local_ip": d.get("lastIpAddress"),
            "external_ip": d.get("lastExternalIpAddress"),
            "last_seen": d.get("lastSeen"),
            "health": d.get("healthStatus"),
            "risk": d.get("riskScore"),
        }


class FindHash(BaseLookup):
    type = "defender.find_hash"
    provider = "defender"
    platforms = ("edr",)
    summary = "Which Defender machines have seen a file, by SHA-1 or SHA-256"
    required_params = ("hash",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        value = digest(params, "defender")
        machines = _send(
            _client(self, creds, http), "GET", f"{API}/api/files/{value}/machines"
        ).json()
        hosts = [
            {"device_id": m.get("id"), "hostname": m.get("computerDnsName")}
            for m in machines.get("value", [])
        ]
        return {"hosts": hosts, "count": len(hosts)}


ACTIONS = [IsolateHost(), BlockHash()]
LOOKUPS = [GetHost(), FindHash()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """A token from Entra for the Defender API."""
    _client(READ, creds, http)
    return "defender accepted the credential"
