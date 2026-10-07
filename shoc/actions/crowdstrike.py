"""CrowdStrike Falcon actions (RSP-4) and lookups (RFC 0014).

What the Splunk SOAR Falcon connector does for an endpoint case: contain a
host, block a file by hash, read a device, and ask which devices have seen a
file. The credential is the API client the connector pulls alerts with, given
Hosts and IOC Management write (RFC 0031).
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


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "CrowdStrike", **kw)


def _falcon(acting: Any, creds: Credentials, http: httpx.Client | None) -> tuple[str, httpx.Client]:
    """(base URL, authenticated client). A static `access_token` in the secret
    still works, for a token minted elsewhere."""
    from shoc.ingest.connectors import crowdstrike

    base = str(creds.settings.get("base_url") or crowdstrike.base_url(creds.settings))
    token = creds.secret.get("access_token") or crowdstrike.access_token(base, creds.secret)
    return base.rstrip("/"), acting.client({"Authorization": f"Bearer {token}"}, http)


class IsolateHost(BaseAction):
    type = "crowdstrike.isolate_host"
    provider = "crowdstrike"
    platforms = ("edr",)
    target_kind = "host"
    summary = "Network-contain a host in CrowdStrike Falcon"
    reversible = True
    required_params = ("device_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Contain {params.get('device_id')} in Falcon: cut off from everything except the "
            "Falcon cloud. Whoever is using it loses their call, their VPN and their files."
        )

    def _call(self, creds: Credentials, device_id: str, verb: str, http: Any) -> None:
        base, client = _falcon(self, creds, http)
        _send(
            client,
            "POST",
            f"{base}/devices/entities/devices-actions/v2",
            params={"action_name": verb},
            json={"ids": [device_id]},
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        device_id = params["device_id"]
        self._call(creds, device_id, "contain", http)
        return ActionResult(
            ok=True,
            detail=f"{device_id} isolated (contain)",
            data={"device_id": device_id},
            undo={"device_id": device_id},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._call(creds, undo["device_id"], "lift_containment", http)
        return ActionResult(ok=True, detail=f"{undo['device_id']} back on the network")


class BlockHash(BaseAction):
    """Stop a file from running on every managed endpoint. Falcon prevents on
    SHA-256 only."""

    type = "crowdstrike.block_hash"
    provider = "crowdstrike"
    platforms = ("edr",)
    target_kind = "hash"
    summary = "Block a file from running on every Falcon endpoint, by SHA-256"
    reversible = True
    required_params = ("hash",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Block file {params.get('hash')} on every endpoint Falcon manages"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        value = digest(params, "crowdstrike", (64,))
        base, client = _falcon(self, creds, http)
        body = _send(
            client,
            "POST",
            f"{base}/iocs/entities/indicators/v1",
            json={
                "indicators": [
                    {
                        "type": "sha256",
                        "value": value,
                        "action": "prevent",
                        "severity": "high",
                        "platforms": ["windows", "mac", "linux"],
                        "applied_globally": True,
                        "description": str(params.get("note") or "blocked by shoc"),
                    }
                ],
            },
        ).json()
        rule_id = ((body.get("resources") or [{}])[0]).get("id", "")
        return ActionResult(
            ok=True,
            detail=f"{value} blocked (crowdstrike indicator {rule_id})",
            data={"hash": value, "indicator_id": rule_id},
            undo={"hash": value, "indicator_id": rule_id},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        base, client = _falcon(self, creds, http)
        _send(
            client,
            "DELETE",
            f"{base}/iocs/entities/indicators/v1",
            params={"ids": undo["indicator_id"]},
        )
        return ActionResult(ok=True, detail=f"{undo['hash']} unblocked")


class GetHost(BaseLookup):
    type = "crowdstrike.get_host"
    provider = "crowdstrike"
    platforms = ("edr",)
    summary = "A Falcon device's name, OS, last user, addresses, last seen and containment state"
    required_params = ("device_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        base, client = _falcon(self, creds, http)
        found = _send(
            client,
            "GET",
            f"{base}/devices/entities/devices/v2",
            params={"ids": str(params["device_id"])},
        ).json()
        d = (found.get("resources") or [{}])[0]
        return {
            "hostname": d.get("hostname"),
            "os": d.get("os_version"),
            "last_user": d.get("last_login_user"),
            "local_ip": d.get("local_ip"),
            "external_ip": d.get("external_ip"),
            "last_seen": d.get("last_seen"),
            "containment": d.get("status"),
        }


class FindHash(BaseLookup):
    type = "crowdstrike.find_hash"
    provider = "crowdstrike"
    platforms = ("edr",)
    summary = "Which Falcon devices have run a file, by SHA-256"
    required_params = ("hash",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        value = digest(params, "crowdstrike", (64,))
        base, client = _falcon(self, creds, http)
        ids = (
            _send(
                client,
                "GET",
                f"{base}/indicators/queries/devices/v1",
                params={"type": "sha256", "value": value},
            )
            .json()
            .get("resources")
            or []
        )
        return {"device_ids": ids, "count": len(ids)}


ACTIONS = [IsolateHost(), BlockHash()]
LOOKUPS = [GetHost(), FindHash()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """A token from Falcon."""
    _falcon(READ, creds, http)
    return "crowdstrike accepted the credential"
