"""Microsoft Entra ID connector (ING-1): sign-in logs, directory audits and
Identity Protection risk.

Every kind of sign-in comes from the beta endpoint with the `signInEventTypes`
filter Microsoft documents for it. Interactive sign-ins are read there too:
v1.0 leaves out the user agent, the authentication protocol and the ASN, which
is where device code phishing and adversary-in-the-middle kits show. Risk
detections and risky users come from `identityProtection`. Each kind is its own
stream, so one the tenant cannot read (no P2, no permission) does not hold back
the others.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from shoc.errors import ConfigError
from shoc.ingest.connectors.base import (
    OVERLAP,
    FetchResult,
    Streams,
    client,
    reached,
    settled,
    since_default,
    utc,
)
from shoc.ingest.connectors.msgraph import access_token

GRAPH = "https://graph.microsoft.com/v1.0"
SIGN_INS = "https://graph.microsoft.com/beta/auditLogs/signIns"
SIGNED = "createdDateTime"

# stream -> (endpoint, time field, extra $filter). Risk detections take no
# $orderby and at most 500 a page.
STREAMS = {
    "signIns": (SIGN_INS, SIGNED, "signInEventTypes/any(t: t eq 'interactiveUser')"),
    "nonInteractiveSignIns": (
        SIGN_INS,
        SIGNED,
        "signInEventTypes/any(t: t eq 'nonInteractiveUser')",
    ),
    "servicePrincipalSignIns": (
        SIGN_INS,
        SIGNED,
        "signInEventTypes/any(t: t eq 'servicePrincipal')",
    ),
    "managedIdentitySignIns": (SIGN_INS, SIGNED, "signInEventTypes/any(t: t eq 'managedIdentity')"),
    "directoryAudits": (f"{GRAPH}/auditLogs/directoryAudits", "activityDateTime", ""),
    "riskDetections": (f"{GRAPH}/identityProtection/riskDetections", "lastUpdatedDateTime", ""),
    "riskyUsers": (f"{GRAPH}/identityProtection/riskyUsers", "riskLastUpdatedDateTime", ""),
}
RISK = ("riskDetections", "riskyUsers")
# Microsoft's "Microsoft Entra reporting latencies" reference gave audit and
# sign-in logs 2 minutes at the 95th percentile and 5 at the 99th. A sign-in or
# audit read stops that far behind now, and starts at the newest event the last
# one read (D164). Risk is scored again after the fact and has no figure: those
# streams re-read the overlap instead.
LAG = timedelta(minutes=5)


class EntraConnector:
    source = "entra"

    def fetch(
        self, settings: dict[str, Any], secret: dict[str, Any], cursor: dict[str, Any], limit: int
    ) -> FetchResult:
        stream = settings["stream"]
        if stream not in STREAMS:
            raise ConfigError(f"entra: unknown stream '{stream}' (have: {', '.join(STREAMS)})")
        endpoint, field, kind = STREAMS[stream]
        risk = stream in RISK
        since = since_default(cursor, settings, OVERLAP if risk else timedelta(0))
        window = f"{field} gt {since}"
        until = ""
        if not risk:
            until = settled(cursor, LAG)
            if utc(since) >= utc(until):
                return FetchResult(cursor=dict(cursor), since=str(cursor.get("since") or ""))
            # `ge`: an event sharing the newest time read is not skipped, and
            # the one already stored is dropped before the store.
            window = f"{field} ge {since} and {field} le {until}"
        token = access_token(secret)
        url = cursor.get("next_link") or endpoint
        params: dict[str, Any] = {}
        if not cursor.get("next_link"):
            params = {"$filter": window + (f" and {kind}" if kind else "")}
            if stream in RISK:
                params["$top"] = min(int(limit), 500)
            else:
                params |= {"$orderby": f"{field} asc", "$top": min(int(limit), 1000)}
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        with client(headers) as http:
            resp = http.get(url, params=params or None)
            resp.raise_for_status()
            payload = resp.json()
        records = payload.get("value", [])
        for record in records:
            record["_stream"] = stream
        newest = max([str(r.get(field, "")) for r in records] + [reached(cursor, since)])
        late = str(cursor.get("since") or "")
        next_link = payload.get("@odata.nextLink")
        if next_link and records:
            # The nextLink carries the $filter it was issued for: hold its start
            # and end until the pages run out.
            held = {**cursor, "start": since, "newest": newest, "next_link": next_link}
            if until:
                held["until"] = until
            return FetchResult(records=records, cursor=held, more=True, since=late)
        return FetchResult(records=records, cursor={"since": newest}, more=False, since=late)


CONNECTOR = Streams(EntraConnector(), "stream", tuple(STREAMS))
