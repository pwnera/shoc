"""GCP actions (RSP-4) and lookups (RFC 0014), over the IAM API.

The leaked-key scenario on GCP is a service account key, and the Splunk SOAR
Google Cloud IAM connector covers it: disable the key, or the whole service
account, and list its keys first. Disabling is reversible where deleting is not,
so shoc disables. Same service account as the Cloud Audit connector, with
Service Account Key Admin, and Compute Security Admin to switch off a firewall
rule that opened a port to the internet.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send
from shoc.errors import ValidationError

IAM = "https://iam.googleapis.com/v1/projects/-/serviceAccounts"
COMPUTE = "https://compute.googleapis.com/compute/v1/projects"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
ACCOUNT = re.compile(r"^[a-z0-9-]+@[a-z0-9.-]+\.iam\.gserviceaccount\.com$")
KEY = re.compile(r"^[0-9a-f]{40}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
FIREWALL = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


def _client(action: Any, creds: Credentials, http: httpx.Client | None) -> httpx.Client:
    from shoc.ingest.connectors import googleauth

    token = googleauth.access_token(creds.secret, SCOPE)
    return action.client({"Authorization": f"Bearer {token}", "Accept": "application/json"}, http)


def _account(params: dict[str, Any]) -> str:
    email = str(params.get("service_account", ""))
    if not ACCOUNT.match(email):
        raise ValidationError("gcp: service_account must be a service account email")
    return seg(email)


class DisableServiceAccount(BaseAction):
    type = "gcp.disable_service_account"
    provider = "gcp"
    platforms = ("gcp",)
    target_kind = "account"
    summary = "Disable a GCP service account and every key it has"
    reversible = True
    required_params = ("service_account",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Disable {params.get('service_account')}. Every workload that runs as it "
            "stops authenticating until it is enabled again."
        )

    def _set(
        self, creds: Credentials, params: dict[str, Any], verb: str, http: httpx.Client | None
    ) -> None:
        send(
            _client(self, creds, http),
            "POST",
            f"{IAM}/{_account(params)}:{verb}",
            "GCP IAM",
            json={},
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._set(creds, params, "disable", http)
        kept = {"service_account": params["service_account"]}
        return ActionResult(
            ok=True, detail=f"{params['service_account']} disabled", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._set(creds, undo, "enable", http)
        return ActionResult(ok=True, detail=f"{undo['service_account']} enabled again")


class DisableServiceAccountKey(BaseAction):
    type = "gcp.disable_service_account_key"
    provider = "gcp"
    platforms = ("gcp",)
    target_kind = "key"
    summary = "Disable one GCP service account key"
    reversible = True
    required_params = ("key_id", "service_account")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Disable key {params.get('key_id')} of {params.get('service_account')}"

    def _set(
        self, creds: Credentials, params: dict[str, Any], verb: str, http: httpx.Client | None
    ) -> None:
        # The audit log names a key in full (`//iam.googleapis.com/.../keys/<id>`).
        key = str(params.get("key_id", "")).rsplit("/", 1)[-1]
        if not KEY.match(key):
            raise ValidationError("gcp: key_id must be a 40-character key id")
        send(
            _client(self, creds, http),
            "POST",
            f"{IAM}/{_account(params)}/keys/{key}:{verb}",
            "GCP IAM",
            json={},
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        self._set(creds, params, "disable", http)
        kept = {p: params[p] for p in self.required_params}
        return ActionResult(
            ok=True, detail=f"key {params['key_id']} disabled", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._set(creds, undo, "enable", http)
        return ActionResult(ok=True, detail=f"key {undo['key_id']} enabled again")


class DisableFirewallRule(BaseAction):
    type = "gcp.disable_firewall_rule"
    provider = "gcp"
    platforms = ("gcp",)
    target_kind = "firewall"
    summary = "Switch off a VPC firewall rule without deleting it"
    reversible = True
    required_params = ("firewall", "project")

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Disable firewall rule {params.get('firewall')} in {params.get('project')}. "
            "Whatever it let in is refused until it is enabled again."
        )

    def _url(self, params: dict[str, Any]) -> str:
        # A rule's name, or its resource name as the audit log gives it.
        project = str(params.get("project", ""))
        name = str(params.get("firewall", "")).rsplit("/", 1)[-1]
        if not PROJECT.match(project) or not FIREWALL.match(name):
            raise ValidationError("gcp: project and firewall must be a project id and a rule name")
        return f"{COMPUTE}/{project}/global/firewalls/{name}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        url, client = self._url(params), _client(self, creds, http)
        was = bool(send(client, "GET", url, "GCP Compute").json().get("disabled"))
        send(client, "PATCH", url, "GCP Compute", json={"disabled": True})
        kept = {"firewall": params["firewall"], "project": params["project"], "disabled": was}
        return ActionResult(
            ok=True, detail=f"firewall rule {params['firewall']} disabled", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        send(
            _client(self, creds, http),
            "PATCH",
            self._url(undo),
            "GCP Compute",
            json={"disabled": bool(undo["disabled"])},
        )
        return ActionResult(
            ok=True,
            detail=f"firewall rule {undo['firewall']} restored, disabled={bool(undo['disabled'])}",
        )


class ListKeys(BaseLookup):
    type = "gcp.list_service_account_keys"
    provider = "gcp"
    platforms = ("gcp",)
    summary = "A service account's keys: which are user-managed, disabled, and how old"
    required_params = ("service_account",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        keys = (
            send(_client(self, creds, http), "GET", f"{IAM}/{_account(params)}/keys", "GCP IAM")
            .json()
            .get("keys", [])
        )
        return {
            "keys": [
                {
                    "key_id": str(k.get("name", "")).rsplit("/", 1)[-1],
                    "type": k.get("keyType"),
                    "disabled": bool(k.get("disabled")),
                    "created": k.get("validAfterTime"),
                    "expires": k.get("validBeforeTime"),
                }
                for k in keys
            ]
        }


ACTIONS = [DisableServiceAccount(), DisableServiceAccountKey(), DisableFirewallRule()]
LOOKUPS = [ListKeys()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """A token minted with the key. Its roles are per project and show on the first act."""
    _client(READ, creds, http)
    return f"token minted for {creds.secret.get('client_email', 'the key')}"
