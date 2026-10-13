"""Tailscale configuration audit-log connector (ING-1).

On every plan, the free one included, kept 90 days. The API answers a whole
window at once, with no page token and no event id, so the window is bounded
here and a window read twice loads once: a record without an id is keyed by
its content. Each entry gets `event`, the `TYPE.ACTION[.PROPERTY]` name
Tailscale's own event filter uses (`TAILNET.UPDATE.ACL`).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import FetchResult, client, client_token, since_default, utc

API = "https://api.tailscale.com/api/v2"
WINDOW = timedelta(hours=6)


def access_token(secret: dict[str, Any]) -> str:
    """An API access token as given, or one minted from an OAuth client.

    An access token expires within 90 days; an OAuth client does not, which is
    why it is the one to give a service nobody watches.
    """
    if secret.get("api_key"):
        return str(secret["api_key"])
    client_id, client_secret = secret.get("client_id"), secret.get("client_secret")
    if not (client_id and client_secret):
        raise ConfigError("tailscale: the secret needs api_key, or client_id and client_secret")
    from shoc.cases.own import note_token

    return client_token(
        f"{API}/oauth/token",
        {"client_id": client_id, "client_secret": client_secret},
        minted=lambda: note_token(str(client_id)),
    )


def credentials(settings: dict[str, Any], secret: dict[str, Any]) -> list[tuple[str, str]]:
    """shoc's own credential, as the configuration log names its actor."""
    client_id = str(secret.get("client_id") or "")
    return [(client_id, "")] if client_id else []


def event_name(entry: dict[str, Any]) -> str:
    target = entry.get("target") or {}
    parts = [target.get("type"), entry.get("action"), target.get("property")]
    return ".".join(str(p) for p in parts if p)


def _rfc3339(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TailscaleConnector:
    source = "tailscale"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        tailnet = settings.get("tailnet") or "-"
        start = utc(since_default(cursor, settings))
        now = datetime.now(UTC)
        end = min(now, start + WINDOW)
        headers = {"Authorization": f"Bearer {access_token(secret)}"}
        with client(headers) as http:
            resp = http.get(
                f"{API}/tailnet/{tailnet}/logging/configuration",
                params={"start": _rfc3339(start), "end": _rfc3339(end)},
            )
            resp.raise_for_status()
            payload = resp.json()
        name = payload.get("tailnetId") or payload.get("tailnet") or tailnet
        records = [
            {**entry, "event": event_name(entry), "tailnet": name}
            for entry in payload.get("logs") or []
        ]
        # The window was read whole: the next one starts `OVERLAP` before it
        # ended (`since_default`), so an entry logged late behind its end is read.
        return FetchResult(
            records=records,
            cursor={"since": end.isoformat()},
            more=end < now,
            since=str(cursor.get("since") or ""),
        )


CONNECTOR = TailscaleConnector()
