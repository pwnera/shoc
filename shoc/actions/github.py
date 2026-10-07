"""GitHub actions (RSP-4) and lookups (RFC 0014).

Put a repository back behind the wall, take back an owner role, and remove a
collaborator: the access changes the Splunk SOAR GitHub connector documents,
each recording what it replaced so undo can restore it. Removing a deploy key
and switching secret scanning back on follow the same rule.

Not here, because neither has an undo: removing a self-hosted runner (it must
be registered again from the machine) and revoking a fine-grained token's
access to the organisation (its owner has to request it again).
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from shoc.actions.base import READ, ActionResult, BaseAction, BaseLookup, Credentials, seg, send
from shoc.errors import ValidationError

API = "https://api.github.com"
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _headers(creds: Credentials) -> dict[str, str]:
    (token,) = creds.require("token")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _send(client: httpx.Client, method: str, url: str, **kw: Any) -> httpx.Response:
    return send(client, method, url, "GitHub", **kw)


def _repo(value: Any) -> str:
    if not REPO.match(str(value)) or ".." in str(value):
        raise ValidationError("github: repo must be owner/name")
    return str(value)


class MakeRepoPrivate(BaseAction):
    type = "github.make_repo_private"
    provider = "github"
    platforms = ("github",)
    target_kind = "repo"
    summary = "Make a repository private again"
    reversible = True
    required_params = ("repo",)

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Set {params.get('repo')} back to private. Anyone who already cloned it keeps "
            "what they took, so rotate any secret that was in it."
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        repo = _repo(params["repo"])
        client = self.client(_headers(creds), http)
        before = _send(client, "GET", f"{API}/repos/{repo}").json()
        _send(client, "PATCH", f"{API}/repos/{repo}", json={"private": True})
        return ActionResult(
            ok=True,
            detail=f"{repo} is private again",
            data={"repo": repo, "was_private": bool(before.get("private"))},
            undo={"repo": repo, "private": bool(before.get("private"))},
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        _send(
            client, "PATCH", f"{API}/repos/{_repo(undo['repo'])}", json={"private": undo["private"]}
        )
        return ActionResult(
            ok=True, detail=f"{undo['repo']} visibility restored to private={undo['private']}"
        )


class DemoteOrgOwner(BaseAction):
    type = "github.demote_org_owner"
    provider = "github"
    platforms = ("github",)
    target_kind = "user"
    summary = "Turn an organization owner back into a member"
    reversible = True
    required_params = ("user", "org")

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Make {params.get('user')} a plain member of {params.get('org')} instead of an owner"
        )

    def _url(self, params: dict[str, Any]) -> str:
        return f"{API}/orgs/{seg(params['org'])}/memberships/{seg(params['user'])}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = self.client(_headers(creds), http)
        was = _send(client, "GET", self._url(params)).json().get("role", "")
        _send(client, "PUT", self._url(params), json={"role": "member"})
        kept = {"user": params["user"], "org": params["org"], "role": was}
        return ActionResult(
            ok=True,
            detail=f"{params['user']} is a member of {params['org']}, was {was}",
            data=kept,
            undo=kept,
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        _send(client, "PUT", self._url(undo), json={"role": undo["role"] or "admin"})
        return ActionResult(ok=True, detail=f"{undo['user']} is {undo['role']} again")


class RemoveCollaborator(BaseAction):
    type = "github.remove_collaborator"
    provider = "github"
    platforms = ("github",)
    target_kind = "user"
    summary = "Remove a collaborator from a repository"
    reversible = True
    required_params = ("user", "repo")

    def plan(self, params: dict[str, Any]) -> str:
        return f"Remove {params.get('user')}'s access to {params.get('repo')}"

    def _url(self, params: dict[str, Any]) -> str:
        return f"{API}/repos/{_repo(params['repo'])}/collaborators/{seg(params['user'])}"

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        client = self.client(_headers(creds), http)
        was = _send(client, "GET", f"{self._url(params)}/permission").json()
        _send(client, "DELETE", self._url(params))
        kept = {
            "user": params["user"],
            "repo": params["repo"],
            "permission": was.get("role_name") or was.get("permission", "read"),
        }
        return ActionResult(
            ok=True, detail=f"{params['user']} removed from {params['repo']}", data=kept, undo=kept
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        _send(client, "PUT", self._url(undo), json={"permission": undo["permission"]})
        # An outside collaborator gets an invitation, not access, until they accept.
        return ActionResult(
            ok=True, detail=f"{undo['user']} re-invited to {undo['repo']} with {undo['permission']}"
        )


class RemoveDeployKey(BaseAction):
    type = "github.remove_deploy_key"
    provider = "github"
    platforms = ("github",)
    target_kind = "key"
    summary = "Remove a deploy key from a repository"
    reversible = True
    required_params = ("key_id", "repo")

    def plan(self, params: dict[str, Any]) -> str:
        return (
            f"Remove deploy key {params.get('key_id')} from {params.get('repo')}. A deploy "
            "that uses it fails until it is added back."
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        url = f"{API}/repos/{_repo(params['repo'])}/keys/{seg(params['key_id'])}"
        client = self.client(_headers(creds), http)
        key = _send(client, "GET", url).json()
        _send(client, "DELETE", url)
        # The public half is all GitHub keeps, and all adding it back needs.
        kept = {
            "repo": params["repo"],
            "title": key.get("title", ""),
            "key": key.get("key", ""),
            "read_only": bool(key.get("read_only", True)),
        }
        return ActionResult(
            ok=True,
            detail=f"deploy key '{kept['title']}' removed from {params['repo']}",
            data=kept,
            undo=kept,
        )

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        client = self.client(_headers(creds), http)
        _send(
            client,
            "POST",
            f"{API}/repos/{_repo(undo['repo'])}/keys",
            json={k: undo[k] for k in ("title", "key", "read_only")},
        )
        return ActionResult(
            ok=True, detail=f"deploy key '{undo['title']}' added back to {undo['repo']}"
        )


SCANNING = ("secret_scanning", "secret_scanning_push_protection")


class EnableSecretScanning(BaseAction):
    type = "github.enable_secret_scanning"
    provider = "github"
    platforms = ("github",)
    target_kind = "repo"
    summary = "Turn secret scanning and push protection back on for a repository"
    reversible = True
    required_params = ("repo",)

    def plan(self, params: dict[str, Any]) -> str:
        return f"Turn secret scanning and push protection on for {params.get('repo')}"

    def _set(self, client: httpx.Client, repo: str, status: dict[str, str]) -> None:
        _send(
            client,
            "PATCH",
            f"{API}/repos/{_repo(repo)}",
            json={"security_and_analysis": {f: {"status": s} for f, s in status.items()}},
        )

    def execute(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self.check(params)
        repo = _repo(params["repo"])
        client = self.client(_headers(creds), http)
        now = _send(client, "GET", f"{API}/repos/{repo}").json().get("security_and_analysis") or {}
        was = {f: (now.get(f) or {}).get("status", "disabled") for f in SCANNING}
        self._set(client, repo, dict.fromkeys(SCANNING, "enabled"))
        kept = {"repo": repo, "status": was}
        return ActionResult(ok=True, detail=f"secret scanning on for {repo}", data=kept, undo=kept)

    def undo(
        self, creds: Credentials, undo: dict[str, Any], http: httpx.Client | None = None
    ) -> ActionResult:
        self._set(self.client(_headers(creds), http), undo["repo"], undo["status"])
        return ActionResult(
            ok=True, detail=f"secret scanning on {undo['repo']} back to {undo['status']}"
        )


class RepoAccess(BaseLookup):
    type = "github.get_repo_access"
    provider = "github"
    platforms = ("github",)
    summary = "A repository's visibility and who can push to it, with their permission"
    required_params = ("repo",)

    def run(
        self, creds: Credentials, params: dict[str, Any], http: httpx.Client | None = None
    ) -> dict[str, Any]:
        self.check(params)
        repo = _repo(params["repo"])
        client = self.client(_headers(creds), http)
        r = _send(client, "GET", f"{API}/repos/{repo}").json()
        people = _send(
            client, "GET", f"{API}/repos/{repo}/collaborators", params={"per_page": 100}
        ).json()
        return {
            "visibility": r.get("visibility"),
            "default_branch": r.get("default_branch"),
            "pushed_at": r.get("pushed_at"),
            "collaborators": [
                {"user": p.get("login"), "permission": p.get("role_name")} for p in people
            ],
        }


ACTIONS = [
    MakeRepoPrivate(),
    DemoteOrgOwner(),
    RemoveCollaborator(),
    RemoveDeployKey(),
    EnableSecretScanning(),
]
LOOKUPS = [RepoAccess()]


def probe(creds: Credentials, http: httpx.Client | None = None) -> str:
    """The token's own user."""
    me = _send(READ.client(_headers(creds), http), "GET", f"{API}/user").json()
    return f"signed in as {me.get('login', '')}"
