"""GitLab audit-events connector (ING-1).

Instance audit events need an administrator token, which a GitLab.com customer
does not have, so a `group` in the settings switches to that group's events —
the same scope a GitHub organisation audit log covers. Records can also be
pushed to `/ingest/gitlab` (ING-2).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, since_default

DEFAULT_URL = "https://gitlab.com"


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
        group = settings.get("group")
        path = f"/api/v4/groups/{group}/audit_events" if group else "/api/v4/audit_events"
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        page = int(cursor.get("page", 1))
        params: dict[str, Any] = {
            "created_after": since,
            "per_page": min(int(limit), 100),
            "page": page,
        }
        headers = {"PRIVATE-TOKEN": str(token), "Accept": "application/json"}
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
