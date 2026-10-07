"""Okta System Log connector (ING-1), and a snapshot of Okta's users and
network zones (D49).

Polling follows the `next` link Okta hands back, as it is: Okta asks clients
not to build requests from the `after` value inside it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import Asset, FetchResult, client, since_default


class OktaConnector:
    source = "okta"

    def account(self, settings: dict[str, Any]) -> str:
        """The org its System Log records never name: `acme.okta.com` (RFC 0025)."""
        return urlsplit(str(settings.get("org_url") or "")).hostname or ""

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        org_url = (settings.get("org_url") or "").rstrip("/")
        token = secret.get("api_token")
        if not org_url or not token:
            raise ConfigError("okta: settings need org_url and the secret needs api_token")
        since = since_default(cursor, hours=int(settings.get("backfill_hours", 24)))
        size = min(int(limit), 1000)
        # A cursor from before the link was kept whole still holds `after`.
        link = cursor.get("next") or (
            f"{org_url}/api/v1/logs?after={cursor['after']}&limit={size}"
            if cursor.get("after")
            else None
        )
        headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
        with client(headers) as http:
            if link:
                resp = http.get(link)
            else:
                resp = http.get(f"{org_url}/api/v1/logs", params={"limit": size, "since": since})
            resp.raise_for_status()
            records = resp.json() or []
            nxt = _next_link(resp.headers.get_list("link"), org_url)
        newest = max(
            [str(r.get("published", "")) for r in records] + [str(cursor.get("newest") or since)]
        )
        if nxt:
            # Okta hands back a `next` link even once caught up, and polling
            # goes on from it; `since` is only read again if the link is lost.
            held = {"since": since, "newest": newest, "next": nxt}
            return FetchResult(records=records, cursor=held, more=bool(records))
        return FetchResult(records=records, cursor={"since": newest}, more=False)

    def snapshot(self, settings: dict[str, Any], secret: dict[str, Any]) -> list[Asset]:
        """Every user Okta holds, with its last sign-in, and every IP range in a
        network zone. A user who never signs in is in here and in no log."""
        org_url = (settings.get("org_url") or "").rstrip("/")
        token = secret.get("api_token")
        if not org_url or not token:
            raise ConfigError("okta: settings need org_url and the secret needs api_token")
        headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
        out: list[Asset] = []
        with client(headers) as http:
            link: str | None = f"{org_url}/api/v1/users?limit=200"
            while link:
                resp = http.get(link)
                resp.raise_for_status()
                for user in resp.json() or []:
                    login = (user.get("profile") or {}).get("login") or user.get("id")
                    out.append(
                        Asset(
                            entity=f"user:{login}",
                            kind="user",
                            last_active=user.get("lastLogin"),
                            attributes={
                                k: user.get(k)
                                for k in ("id", "status", "created", "passwordChanged")
                            },
                        )
                    )
                link = _next_link(resp.headers.get_list("link"), org_url)
            resp = http.get(f"{org_url}/api/v1/zones")
            resp.raise_for_status()
            for zone in resp.json() or []:
                for gateway in (zone.get("gateways") or []) + (zone.get("proxies") or []):
                    if gateway.get("value"):
                        out.append(
                            Asset(
                                entity=f"network:{gateway['value']}",
                                kind="network",
                                attributes={
                                    "zone": zone.get("name"),
                                    "usage": zone.get("usage"),
                                    "status": zone.get("status"),
                                },
                            )
                        )
        return out


def _next_link(links: list[str], org_url: str) -> str | None:
    """The RFC 5988 `next` link, kept only when it points back at the org."""
    for link in links:
        if 'rel="next"' in link:
            url = link.split(";", 1)[0].strip().strip("<>")
            return url if url.startswith(f"{org_url}/") else None
    return None


CONNECTOR = OktaConnector()
