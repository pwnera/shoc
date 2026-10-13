"""Wazuh connector (ING-1): alerts read from the Wazuh indexer.

Reading `wazuh-alerts-*` from the indexer is the route Wazuh documents for a
third-party SIEM, and it needs nothing installed on the manager: a read-only
indexer user and the indexer's address, port 9200 by default. The records are
the alerts the manager wrote, so the mapping reads them as they are.

Alerts come oldest first. `search_after` on the timestamp and the alert id
pages through a second that holds more alerts than one page, and the window
start is held while it does.
"""

from __future__ import annotations

import ssl
from typing import Any

import httpx

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import DEFAULT_TIMEOUT, FetchResult, reached, since_default

INDEX = "wazuh-alerts-4.x-*"


def verify(settings: dict[str, Any]) -> ssl.SSLContext | bool:
    """What a Wazuh client trusts. The indexer and the server API usually run on
    the certificates Wazuh's installer made itself: `ca_cert`, the PEM of its
    root-ca.pem, trusts them without turning verification off, which would hand
    the password to whoever answers. `verify_tls: false` is the fallback."""
    pem = settings.get("ca_cert")
    if pem:
        return ssl.create_default_context(cadata=str(pem))
    return settings.get("verify_tls", True) is not False


class WazuhConnector:
    source = "wazuh"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        url = str(settings.get("indexer_url") or "").rstrip("/")
        user, password = secret.get("username"), secret.get("password")
        if not url or not user or not password:
            raise ConfigError(
                "wazuh: settings need indexer_url and the secret needs username and password"
            )
        since = since_default(cursor, settings)
        body: dict[str, Any] = {
            "size": min(int(limit), 1000),
            "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            "query": {"range": {"timestamp": {"gt": since}}},
        }
        if cursor.get("after"):
            body["search_after"] = cursor["after"]
        with httpx.Client(
            timeout=DEFAULT_TIMEOUT, auth=(str(user), str(password)), verify=verify(settings)
        ) as http:
            resp = http.post(f"{url}/{settings.get('index') or INDEX}/_search", json=body)
            resp.raise_for_status()
            hits = (resp.json().get("hits") or {}).get("hits") or []
        records = [h.get("_source") or {} for h in hits]
        newest = max([str(r.get("timestamp") or "") for r in records] + [reached(cursor, since)])
        late = str(cursor.get("since") or "")
        if len(hits) == body["size"]:
            held = {**cursor, "start": since, "newest": newest, "after": hits[-1].get("sort")}
            return FetchResult(records=records, cursor=held, more=True, since=late)
        return FetchResult(records=records, cursor={"since": newest}, more=False, since=late)


CONNECTOR = WazuhConnector()
