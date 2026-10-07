"""Azure actions (RSP-4) and lookups (RFC 0014), over Azure Resource Manager.

From the Splunk SOAR Azure Compute connector: power off a virtual machine an
attacker is using, and start it again on undo. Powering off keeps the disks and
the allocation, so nothing is lost and the address stays. Same Azure AD app as
the Activity Log connector, with Virtual Machine Contributor on the VMs.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, send
from shoc.errors import ConfigError, ValidationError

ARM = "https://management.azure.com"
API_VERSION = "2024-07-01"
VM = re.compile(
    r"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[\w().-]+"
    r"/providers/Microsoft\.Compute/virtualMachines/[\w.-]+$"
)


def _client(action: Any, creds: Credentials, http: httpx.Client | None) -> httpx.Client:
    from shoc.ingest.connectors.azure_activity import SCOPE
    from shoc.ingest.connectors.msgraph import access_token

    token = access_token(creds.secret, SCOPE)
    return action.client({"Authorization": f"Bearer {token}", "Accept": "application/json"}, http)


def _vm(params: dict[str, Any]) -> str:
    """The VM's resource id, as the Activity Log records it in `resourceId`."""
    vm = str(params.get("vm_id", ""))
    if not VM.match(vm):
        raise ValidationError("azure: vm_id must be a virtual machine resource id")
    return vm


class StopVM(BaseAction):
    type = "azure.stop_vm"
    provider = "azure"
    platforms = ("azure",)
    target_kind = "resource"
    summary = "Power off an Azure virtual machine, keeping its disks"
    reversible = True
    required_params = ("vm_id",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Power off {params.get('vm_id')}; whatever it serves goes down until undo"

    def _power(self, creds: Credentials, vm: str, verb: str, http: httpx.Client | None) -> None:
        send(
            _client(self, creds, http),
            "POST",
            f"{ARM}{vm}/{verb}",
            "Azure",
            params={"api-version": API_VERSION},
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        vm = _vm(params)
        self._power(creds, vm, "powerOff", http)
        return ActionResult(
            ok=True,
            detail=f"{vm.rsplit('/', 1)[-1]} is powering off",
            data={"vm_id": vm},
            undo={"vm_id": vm},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._power(creds, _vm(undo), "start", http)
        return ActionResult(ok=True, detail=f"{undo['vm_id'].rsplit('/', 1)[-1]} is starting")


class GetVM(BaseLookup):
    type = "azure.get_vm"
    provider = "azure"
    platforms = ("azure",)
    summary = "An Azure VM's size, OS, power state, network interfaces and tags"
    required_params = ("vm_id",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        vm = send(
            _client(self, creds, http),
            "GET",
            f"{ARM}{_vm(params)}",
            "Azure",
            params={"api-version": API_VERSION, "$expand": "instanceView"},
        ).json()
        props = vm.get("properties") or {}
        statuses = (props.get("instanceView") or {}).get("statuses") or []
        return {
            "name": vm.get("name"),
            "location": vm.get("location"),
            "size": (props.get("hardwareProfile") or {}).get("vmSize"),
            "os": ((props.get("storageProfile") or {}).get("osDisk") or {}).get("osType"),
            "power": next(
                (
                    s.get("displayStatus")
                    for s in statuses
                    if str(s.get("code", "")).startswith("PowerState/")
                ),
                None,
            ),
            "nics": [
                n.get("id")
                for n in (props.get("networkProfile") or {}).get("networkInterfaces", [])
            ],
            "tags": vm.get("tags") or {},
        }


ACTIONS = [StopVM()]
LOOKUPS = [GetVM()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The subscriptions the app sees: none means it holds no role to act with."""
    client = _client(READ, creds, http)
    params = {"api-version": "2022-12-01"}
    subs = send(client, "GET", f"{ARM}/subscriptions", "Azure", params=params).json()
    if not subs.get("value"):
        raise ConfigError("the app signs in but holds no role on any subscription")
    return f"sees {len(subs['value'])} subscription(s)"
