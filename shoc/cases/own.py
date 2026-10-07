"""shoc's own footprint, and the people who run it (AGT-13, RFC 0021, D78).

shoc reads its sources with credentials it was given, from an address it calls
out from, and every one of those reads is logged by the vendor. With nothing to
tell the crew so, a Google token shoc fetched for itself every hour was "an
external OAuth client authorised from an unaccounted host", and two cases about
shoc watching its own installation cost three million tokens.

So shoc records what it is, at the moment it learns it:

- **credential**  the non-secret id of each credential a source was given,
                  with the scope it was given, written when the source is
                  configured;
- **address**     an address shoc calls out from;
- **operator**    an account of the person who runs shoc;
- **automation**  an account of the company's own automation.

And it records every token request it makes with one of those credentials.

A finding is checked against this as it arrives (`classify`). The check states
a fact, it does not judge, so it is code: an event by shoc's credential that
lines up with a token request shoc made (`use`), or the creation of that
credential with exactly its scope before the source was configured (`setup`),
is shoc's own. Everything else takes the normal path, so a stolen shoc key used
from anywhere, or at a time shoc asked for no token, still opens a case, and so
does any revoke, delete or scope change on shoc's credential. A matching finding
is kept and marked `self` with the events it cited; nothing is dropped (D44).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all

KINDS = ("credential", "address", "operator", "automation")

# How far apart shoc's token request and the vendor's record of it may be.
TOKEN_SKEW = timedelta(seconds=60)
# Token requests are kept this long; findings older than that are past checking.
TOKEN_REQUEST_DAYS = 30

# Operations that take something away from a credential, or change what it may
# do. On shoc's own credential these always reach a person.
CHANGES = re.compile(r"revoke|delete|remove|roll|rotate|disable|suspend|update|expire", re.I)
# Operations that create a credential or grant it something: the install.
GRANTS = re.compile(r"create|grant|authori[sz]e|assign|add|insert|approve", re.I)
# How long before a source was configured its credential may have been made.
SETUP_WINDOW = timedelta(days=7)


def note_token(credential: str) -> None:
    """A connector asked a vendor for a token with this credential, just now.

    Written at once, on this thread's connection and under its tenant, so a
    process that dies before its pull ends has still recorded the request and
    the vendor's log of it is read as shoc's own (D78). Connectors run inside a
    capability call, which pins the connection to its tenant; with no tenant
    there is nobody to record it for, and the next event by the credential
    opens a case, which is the safe direction.
    """
    from shoc.db.pool import ALL_TENANTS, connect, current_tenant

    if not credential:
        return
    try:
        conn = connect()
        tenant = current_tenant(conn)
    except Exception:  # no database here: a connector run by hand, a unit test
        return
    if tenant in ("", ALL_TENANTS):
        return
    execute(
        conn,
        """INSERT INTO shoc.own_token_requests (tenant_id, source, credential)
           VALUES (%s, coalesce((SELECT source FROM shoc.own_identities
                                 WHERE tenant_id = %s AND kind = 'credential' AND value = %s
                                 LIMIT 1), ''), %s)""",
        (tenant, tenant, str(credential), str(credential)),
    )
    execute(
        conn,
        """DELETE FROM shoc.own_token_requests
           WHERE tenant_id = %s AND requested_at < now() - %s * interval '1 day'""",
        (tenant, TOKEN_REQUEST_DAYS),
    )


def register(
    conn: Conn,
    tenant_id: str,
    kind: str,
    value: str,
    *,
    source: str = "",
    scope: str = "",
    note: str = "",
    by: str = "",
) -> None:
    """Record one identity. A value registered twice keeps its first date."""
    value = bare(value)
    if kind not in KINDS or not value:
        return
    execute(
        conn,
        """INSERT INTO shoc.own_identities
               (tenant_id, kind, value, source, scope, note, created_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, kind, value) DO UPDATE SET
               source = EXCLUDED.source, scope = EXCLUDED.scope,
               note = EXCLUDED.note, created_by = EXCLUDED.created_by""",
        (tenant_id, kind, value, source, scope, note[:500], by),
    )


def forget(conn: Conn, tenant_id: str, kind: str, value: str) -> bool:
    return bool(
        execute(
            conn,
            "DELETE FROM shoc.own_identities WHERE tenant_id = %s AND kind = %s AND value = %s",
            (tenant_id, kind, bare(value)),
        )
    )


def listing(conn: Conn, tenant_id: str) -> list[dict[str, Any]]:
    return fetch_all(
        conn,
        """SELECT kind, value, source, scope, note, created_by, created_at
           FROM shoc.own_identities WHERE tenant_id = %s ORDER BY kind, value""",
        (tenant_id,),
    )


def values(conn: Conn, tenant_id: str, *kinds: str) -> set[str]:
    return {
        str(r["value"]).lower()
        for r in fetch_all(
            conn,
            "SELECT value FROM shoc.own_identities WHERE tenant_id = %s AND kind = ANY(%s)",
            (tenant_id, list(kinds)),
        )
    }


def is_person(conn: Conn, tenant_id: str, value: str) -> bool:
    """Whether this is one of the operator's own accounts."""
    return bare(value).lower() in values(conn, tenant_id, "operator")


def protected(conn: Conn, tenant_id: str) -> set[str]:
    """Targets an agent's proposal against which always waits for a human (L2)."""
    return values(conn, tenant_id, *KINDS)


def bare(value: str) -> str:
    """`user:alice@example.com` and `alice@example.com` are the same account."""
    value = str(value or "").strip()
    kind, sep, rest = value.partition(":")
    if sep and kind in ("user", "key", "ip", "host", "resource", "account", "entity") and rest:
        return rest.strip()
    return value


def routable(ip: str) -> bool:
    """An address on the internet. Carrier-grade NAT (100.64.0.0/10), which
    Tailscale and Starlink use, is not, though `is_global` disagrees on some
    Python versions. The documentation ranges stand for internet addresses in
    this project's fixtures and docs, so they count as routable."""
    from shoc.detect.osint import is_documentation

    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return addr.is_global or is_documentation(addr)


# -- the intake check ----------------------------------------------------------
@dataclass
class Verdict:
    """Whether a finding is shoc's own, and the events that show it."""

    own: bool = False
    why: str = ""
    citations: list[str] = field(default_factory=list)


def classify(conn: Conn, store: Any, tenant_id: str, finding: dict[str, Any]) -> Verdict:
    """`own` only when every event the finding cites is shoc's own (see the module)."""
    uids = [u for u in (finding.get("event_uids") or []) if u]
    credentials = {
        str(r["value"]): r
        for r in fetch_all(
            conn,
            """SELECT i.value, i.scope, i.source, c.created_at AS configured_at
               FROM shoc.own_identities i
               LEFT JOIN shoc.connector_config c
                 ON c.tenant_id = i.tenant_id AND c.source = i.source
               WHERE i.tenant_id = %s AND i.kind = 'credential'""",
            (tenant_id,),
        )
    }
    if not uids or not credentials or store is None:
        return Verdict()
    addresses = values(conn, tenant_id, "address")
    events = _events(store, tenant_id, uids)
    if len(events) < len(set(uids)):
        return Verdict()  # an event we cannot read is an event we cannot vouch for
    reasons: list[str] = []
    for event in events:
        why = _own_event(conn, tenant_id, event, credentials, addresses)
        if not why:
            return Verdict()
        reasons.append(why)
    return Verdict(
        own=True,
        why="; ".join(sorted(set(reasons)))[:500],
        citations=[str(e["event_uid"]) for e in events],
    )


def _events(store: Any, tenant_id: str, uids: list[str]) -> list[dict[str, Any]]:
    from shoc.store import ocsf as layout

    wanted = list(dict.fromkeys(uids))[:200]
    params: dict[str, Any] = {f"u{i}": u for i, u in enumerate(wanted)}
    params["tenant_id"] = tenant_id
    marks = ", ".join(f":u{i}" for i in range(len(wanted)))
    rows = store.query(
        f"""SELECT DISTINCT event_uid, time, api_operation, activity_name, resource_uid,
                   actor_user_uid, actor_session_uid, src_endpoint_ip, raw
            FROM {layout.EVENTS_TABLE}
            WHERE tenant_id = :tenant_id AND event_uid IN ({marks})""",
        params,
        limit=len(wanted) * 4,
    ).rows
    seen: dict[str, dict[str, Any]] = {}
    for row in rows:
        seen.setdefault(str(row["event_uid"]), row)
    return list(seen.values())


def _own_event(
    conn: Conn,
    tenant_id: str,
    event: dict[str, Any],
    credentials: dict[str, dict[str, Any]],
    addresses: set[str],
) -> str:
    """Why this one event is shoc's own, or ''."""
    credential = next(
        (
            str(event.get(c))
            for c in ("resource_uid", "actor_user_uid", "actor_session_uid")
            if str(event.get(c) or "") in credentials
        ),
        "",
    )
    if not credential:
        return ""
    held = credentials[credential]
    operation = f"{event.get('api_operation') or ''} {event.get('activity_name') or ''}"
    ip = str(event.get("src_endpoint_ip") or "")
    # An address shoc does not call out from is not shoc, whatever the credential.
    if ip and routable(ip) and addresses and ip.lower() not in addresses:
        return ""
    scopes = scopes_of(event.get("raw"))
    granted = {s for s in str(held.get("scope") or "").split() if s}
    if scopes and granted and not scopes <= granted:
        return ""  # shoc's credential asking for more than shoc was given
    when = event.get("time")
    if not isinstance(when, datetime):
        return ""
    if _requested_near(conn, tenant_id, credential, when):
        return f"use: a token shoc requested with its {held['source']} credential {credential}"
    configured = held.get("configured_at")
    if (
        isinstance(configured, datetime)
        and configured - SETUP_WINDOW <= when <= configured
        and GRANTS.search(operation)
        and not CHANGES.search(operation)
        and (not granted or scopes == granted or not scopes)
    ):
        return f"setup: the {held['source']} credential {credential} created before shoc used it"
    return ""


def scopes_of(raw: Any) -> set[str]:
    """Every scope a record names: a `scope`/`scopes` key, or a named parameter
    called `scope` (Google's `{name: scope, multiValue: [...]}`)."""
    import json

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return set()
    found: set[str] = set()

    def take(value: Any) -> None:
        if isinstance(value, str):
            found.update(v for v in value.split() if v)
        elif isinstance(value, list):
            found.update(str(v) for v in value if isinstance(v, str) and v)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if str(node.get("name", "")).lower() in ("scope", "scopes", "api_scopes"):
                take(node.get("multiValue") or node.get("value"))
            for key, child in node.items():
                if str(key).lower() in ("scope", "scopes") and not isinstance(child, dict):
                    take(child)
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(raw)
    return found


def _requested_near(conn: Conn, tenant_id: str, credential: str, when: datetime) -> bool:
    return bool(
        fetch_all(
            conn,
            """SELECT 1 FROM shoc.own_token_requests
           WHERE tenant_id = %s AND credential = %s
             AND requested_at BETWEEN %s AND %s LIMIT 1""",
            (tenant_id, credential, when - TOKEN_SKEW, when + TOKEN_SKEW),
        )
    )


def mark(conn: Conn, tenant_id: str, finding_uid: str, verdict: Verdict) -> None:
    """Keep the finding, marked as shoc's own, with what showed it."""
    import json

    execute(
        conn,
        """UPDATE shoc.findings SET status = 'self',
               evidence = coalesce(evidence, '{}'::jsonb) || %s
           WHERE tenant_id = %s AND finding_uid = %s""",
        (
            json.dumps({"own": {"why": verdict.why, "citations": verdict.citations}}),
            tenant_id,
            finding_uid,
        ),
    )
