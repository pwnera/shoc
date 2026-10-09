"""GitLab audit-events connector (ING-1).

Instance audit events need an administrator token, which a GitLab.com customer
does not have, so a `group` in the settings switches to the group. GitLab keeps
an event with the group or project it happened in, and a group's endpoint
returns only the group's own, so the group, each group below it and each of
their projects is read as a stream with its own cursor (D155).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, Streams, client, since_default

DEFAULT_URL = "https://gitlab.com"


def listing(http: httpx.Client, url: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Every item of a GitLab list, page by page."""
    items: list[dict[str, Any]] = []
    page = "1"
    while page:
        resp = http.get(url, params={**params, "per_page": 100, "page": page})
        resp.raise_for_status()
        items += resp.json() or []
        page = (resp.headers.get("x-next-page") or "").strip()
    return items


class GitLabConnector:
    source = "gitlab"

    def account(self, settings: dict[str, Any]) -> str:
        """The group it reads, or the instance: audit events name neither (RFC 0025)."""
        return str(settings.get("group") or "") or (
            urlsplit(str(settings.get("base_url") or DEFAULT_URL)).hostname or ""
        )

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        base = (settings.get("base_url") or DEFAULT_URL).rstrip("/")
        token = secret.get("token")
        if not token:
            raise ConfigError("gitlab: the secret needs token (a read_api personal access token)")
        headers = {"PRIVATE-TOKEN": str(token), "Accept": "application/json"}
        group, scope = settings.get("group"), settings.get("scope")
        if group and not scope:
            top = quote(str(group), safe="")
            with client(headers) as http:
                groups = listing(http, f"{base}/api/v4/groups/{top}/descendant_groups", {})
                projects = listing(
                    http,
                    f"{base}/api/v4/groups/{top}/projects",
                    # A project shared into the group belongs to another namespace.
                    {"include_subgroups": "true", "with_shared": "false", "simple": "true"},
                )
            scopes = (
                [f"groups/{top}"]
                + [f"groups/{g['id']}" for g in groups]
                + [f"projects/{p['id']}" for p in projects]
            )
            return Streams(self, "scope").fetch(
                {**settings, "scope": scopes}, secret, cursor, limit
            )
        path = f"/api/v4/{scope}/audit_events" if scope else "/api/v4/audit_events"
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        page = int(cursor.get("page", 1))
        params: dict[str, Any] = {
            "created_after": since,
            "per_page": min(int(limit), 100),
            "page": page,
        }
        with client(headers) as http:
            resp = http.get(f"{base}{path}", params=params)
            resp.raise_for_status()
            records = resp.json() or []
            next_page = resp.headers.get("x-next-page") or ""
        # While paging, `since` stays where the window started: page numbers only
        # line up against an unchanged `created_after`.
        if next_page.strip() and records:
            return FetchResult(
                records=records, cursor={"since": since, "page": int(next_page)}, more=True
            )
        newest = max([str(r.get("created_at", "")) for r in records] + [since])
        return FetchResult(records=records, cursor={"since": newest}, more=False)


CONNECTOR = GitLabConnector()
