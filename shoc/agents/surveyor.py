"""The Surveyor (AGT-3, RFC 0006 §3): what this company actually has.

MITRE's first strategy for a world-class SOC is *know what you are protecting
and why*, and until now nothing in the pool owned it: the Investigator had no
idea whether an account was privileged, the IR Commander guessed what suspending
it would cost, and CTI could not say whether a CVE was relevant.

The Surveyor answers from **events we already ingest**, and from what a
source's own API says exists (D49). No scanner, no agent on anything, no new
service. Five questions, each a join, each returning the event UIDs behind it:

1. **What exists** — every entity seen in the window, typed.
2. **What is exposed** — which of them acted from outside our own ranges.
3. **Who is privileged** — who performed administrative operations. Observed,
   not declared: a title in an IdP is a claim, an `AttachUserPolicy` is a fact.
4. **What is stale** — an identity that has not authenticated in 60 days, a key
   older than its rotation window that is still in use. An identity the latest
   survey did not see keeps its row, so staleness is measured across surveys,
   and a snapshot's own last sign-in counts.
5. **What is unwatched** — products we ingest that no rule reads. This is the
   number the founder should see.

"What is exploitable now" is gone (D57): it joined against a KEV feed shoc no
longer ships. CTI answers vulnerability relevance per case.

**The queries are deterministic on purpose**, and identical every time they are
asked. The Surveyor's model sits above them (D47, `read`): it says what the
picture means, which unwatched products matter, and what changed.

**The limit.** Events show what *happened*. A connector that takes snapshots
(Okta's users and network zones today) adds what exists and never acts; for
everything else an idle machine is invisible, and the caveat says which.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.detect.engine import ENTITY_COLUMNS
from shoc.store import ocsf as layout

CAVEAT = (
    "Derived from ingested events only: this describes what acted in the window, "
    "not everything that exists. An asset that did nothing is not here."
)

WINDOW_DAYS = 30
# An identity that has not authenticated in this long is stale whether or not
# anybody has got round to disabling it — that is the point of asking.
STALE_IDENTITY_DAYS = 60
# A key seen for longer than this without a gap has outlived any sane rotation
# window. It is an observation, not a policy: the number is what most cloud
# guidance settles on.
KEY_ROTATION_DAYS = 90
# The most events one survey reads, newest first. A busier window is cut here,
# and the answer says so (`truncated`).
MAX_ROWS = 20_000
# Kinds whose row outlives a survey that did not see them: they are what
# "stale" is about. Other absent rows are dropped.
IDENTITY_KINDS = ("user", "account")

# Operations that only somebody with administrative rights can perform. Being
# able to do one of these is what "privileged" means here — not a group name,
# not a title, not what an inventory says.
ADMIN_OPERATIONS = (
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "CreateUser",
    "CreateRole",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy",
    "CreatePolicyVersion",
    "AddUserToGroup",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "PutBucketAcl",
    "user.account.privilege.grant",
    "group.user_membership.add",
    "application.policy.sign_on.update",
    "user.account.update_password",
    "org.update_member",
    "org.add_member",
    "repo.transfer",
    "protected_branch.destroy",
    "org.oauth_app_access_approved",
)

# Addresses that are ours by definition. `guards.known_egress` in
# `content/policy.yaml` adds whatever else the company knows about itself.
PRIVATE_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128")


@dataclass
class Entity:
    """One thing the company has, as the events describe it."""

    entity: str
    kind: str
    events: int = 0
    exposed: bool = False
    privileged: bool = False
    stale: bool = False
    sources: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    operations: set[str] = field(default_factory=set)
    event_uids: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # The sources whose own API lists it (D49), and the last sign-in they keep.
    listed_by: set[str] = field(default_factory=set)
    last_active: datetime | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "kind": self.kind,
            "events": self.events,
            "exposed": self.exposed,
            "privileged": self.privileged,
            "stale": self.stale,
            "sources": sorted(self.sources),
            "countries": sorted(self.countries),
            "operations": sorted(self.operations),
            "citations": self.event_uids[:10],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "listed_by": sorted(self.listed_by),
        }


@dataclass
class Posture:
    """The picture, with the caveat attached to it rather than to a footnote."""

    window_days: int = WINDOW_DAYS
    taken_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    counts: dict[str, int] = field(default_factory=dict)
    exposed: list[dict[str, Any]] = field(default_factory=list)
    privileged: list[dict[str, Any]] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    unwatched: dict[str, Any] = field(default_factory=dict)
    citations: list[str] = field(default_factory=list)
    caveat: str = CAVEAT
    # True when the window held more than `limit` events: the answer then covers
    # the newest `limit`, and no entity is marked absent on its strength.
    truncated: bool = False
    limit: int = MAX_ROWS

    def to_json(self) -> dict[str, Any]:
        return {
            "window_days": self.window_days,
            "taken_at": self.taken_at,
            "counts": self.counts,
            "exposed": self.exposed,
            "privileged": self.privileged,
            "stale": self.stale,
            "unwatched": self.unwatched,
            "caveat": self.caveat,
            "truncated": self.truncated,
            "limit": self.limit,
        }


def _own_networks(config: Any = None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Our own address space: the private ranges, plus whatever policy names."""

    nets: list[Any] = [ipaddress.ip_network(n) for n in PRIVATE_NETWORKS]
    with contextlib.suppress(Exception):
        from shoc.cases.policy import Policy

        for value in Policy.load(config).guards.get("known_egress", []) or []:
            text = str(value)
            if "*" in text:  # a glob is not a network; the exposure check skips it
                continue
            with contextlib.suppress(ValueError):
                nets.append(ipaddress.ip_network(text, strict=False))
    return nets


def _outside(address: str, nets: list[Any]) -> bool:
    """True when this address is on the internet and not one of ours.

    A private or carrier-grade NAT address (a tailnet's 100.64.0.0/10) is inside
    by construction, and an unparseable address is not exposure.
    """
    from shoc.cases.own import routable
    from shoc.detect.osint import is_documentation

    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if not (routable(address) or is_documentation(ip)):
        return False
    return not any(ip.version == net.version and ip in net for net in nets)


def survey(
    conn: Conn,
    store: Any,
    tenant_id: str,
    days: int = WINDOW_DAYS,
    config: Any = None,
    limit: int = MAX_ROWS,
    keep: bool = True,
) -> Posture:
    """Read the window once and answer all five questions from it, and keep the answer."""
    started = datetime.now(UTC)
    since = started - timedelta(days=days)
    columns = ", ".join(
        [
            "event_uid",
            "time",
            "metadata_product",
            "api_operation",
            "src_endpoint_ip",
            "src_endpoint_location_country",
            *ENTITY_COLUMNS,
        ]
    )
    read = store.query(
        f"SELECT {columns} FROM {layout.EVENTS_TABLE} "
        "WHERE tenant_id = :tenant_id AND time >= :since ORDER BY time DESC",
        {"tenant_id": tenant_id, "since": since},
        limit,
    )
    rows = read.rows

    nets = _own_networks(config)
    entities: dict[str, Entity] = {}
    for row in rows:
        source_ip = str(row.get("src_endpoint_ip") or "")
        from_outside = _outside(source_ip, nets) if source_ip else False
        operation = str(row.get("api_operation") or "")
        admin = operation in ADMIN_OPERATIONS
        when = row.get("time")
        for column, kind in ENTITY_COLUMNS.items():
            value = row.get(column)
            if value in (None, "", "-"):
                continue
            key = f"{kind}:{value}"
            item = entities.setdefault(key, Entity(entity=key, kind=kind))
            item.events += 1
            if row.get("metadata_product"):
                item.sources.add(str(row["metadata_product"]))
            if row.get("src_endpoint_location_country"):
                item.countries.add(str(row["src_endpoint_location_country"]))
            # An address is not "exposed from outside" because it is outside —
            # it *is* the outside. The identity that used it is what is exposed.
            if from_outside and kind != "ip":
                item.exposed = True
            if admin:
                item.privileged = True
                item.operations.add(operation)
            if len(item.event_uids) < 10:
                item.event_uids.append(str(row["event_uid"]))
            if when is not None:
                item.first_seen = min(item.first_seen or when, when)
                item.last_seen = max(item.last_seen or when, when)

    listed = _listed(conn, tenant_id, entities)

    now = datetime.now(UTC)
    for item in entities.values():
        item.stale = _is_stale(item, now)

    out = Posture(window_days=days, truncated=read.truncated, limit=limit)
    out.exposed = [e.to_json() for e in _pick(entities, "exposed")]
    out.privileged = [e.to_json() for e in _pick(entities, "privileged")]
    out.unwatched = unwatched(conn, tenant_id, entities, config)
    out.citations = [u for e in entities.values() for u in e.event_uids][:100]
    if listed:
        out.caveat = (
            f"Derived from ingested events, plus what {', '.join(sorted(listed))} list as "
            "existing. Anything else that did nothing in the window is not here."
        )
    out.counts = _counts(entities)
    if keep:
        _store(conn, tenant_id, entities, out, started)
        # Stale is read back, because an identity no event showed this window is
        # stale from an earlier survey's sighting, not from this one's.
        out.stale = [
            _row_json(r)
            for r in fetch_all(
                conn,
                """SELECT * FROM shoc.exposures WHERE tenant_id = %s AND stale
               ORDER BY events DESC, entity LIMIT 100""",
                (tenant_id,),
            )
        ]
        out.counts["stale"] = int(
            (
                fetch_one(
                    conn,
                    "SELECT count(*) AS n FROM shoc.exposures WHERE tenant_id = %s AND stale",
                    (tenant_id,),
                )
                or {}
            ).get("n")
            or 0
        )
        _snapshot_row(conn, tenant_id, out)
    else:
        out.stale = [e.to_json() for e in _pick(entities, "stale")]
    return out


def _listed(conn: Conn, tenant_id: str, entities: dict[str, Entity]) -> set[str]:
    """Add what the sources' own APIs say exists (D49). Returns the sources."""
    kinds = set(ENTITY_COLUMNS.values())
    sources: set[str] = set()
    for row in fetch_all(
        conn,
        "SELECT source, entity, kind, attributes, last_active FROM shoc.snapshots "
        "WHERE tenant_id = %s",
        (tenant_id,),
    ):
        sources.add(str(row["source"]))
        if row["kind"] not in kinds:
            continue  # a network range is an answer to "what is this address", not an entity
        item = entities.setdefault(
            str(row["entity"]), Entity(entity=str(row["entity"]), kind=str(row["kind"]))
        )
        item.listed_by.add(str(row["source"]))
        created = (row["attributes"] or {}).get("created")
        active = row["last_active"] or (_when(created) if created else None)
        if active is not None:
            item.last_active = max(item.last_active or active, active)
    return sources


def _when(text: str) -> datetime | None:
    try:
        when = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _last(item: Entity) -> datetime | None:
    """The latest sighting: in an event, or the sign-in a snapshot reports."""
    return max((t for t in (item.last_seen, item.last_active) if t is not None), default=None)


def _is_stale(item: Entity, now: datetime) -> bool:
    """Not seen for long enough to be worth asking about — or too old to still be in use."""
    if item.kind in ("user", "account"):
        seen = _last(item)
        return seen is not None and (now - seen).days >= STALE_IDENTITY_DAYS
    if item.kind == "key" and item.first_seen is not None:
        return (now - item.first_seen).days >= KEY_ROTATION_DAYS
    return False


def _row_json(row: dict[str, Any]) -> dict[str, Any]:
    """A stored exposure in the shape `Entity.to_json` gives."""
    keys = (
        "entity",
        "kind",
        "events",
        "exposed",
        "privileged",
        "stale",
        "sources",
        "countries",
        "operations",
        "first_seen",
        "last_seen",
        "present",
    )
    return {**{k: row.get(k) for k in keys}, "citations": list(row.get("event_uids") or [])[:10]}


def _counts(entities: dict[str, Entity]) -> dict[str, int]:
    counts: dict[str, int] = {"total": len(entities)}
    for item in entities.values():
        counts[item.kind] = counts.get(item.kind, 0) + 1
    for flag in ("exposed", "privileged", "stale"):
        counts[flag] = sum(1 for e in entities.values() if getattr(e, flag))
    return counts


def _pick(entities: dict[str, Entity], flag: str, limit: int = 100) -> list[Entity]:
    return sorted(
        (e for e in entities.values() if getattr(e, flag)),
        key=lambda e: e.events,
        reverse=True,
    )[:limit]


def unwatched(
    conn: Conn, tenant_id: str, entities: dict[str, Entity], config: Any = None
) -> dict[str, Any]:
    """What is producing events that no rule is looking at.

    A product we ingest and do not detect on looks like coverage from the
    outside and is not. This is deliberately the count a founder is shown.
    """

    from shoc.detect import rules as ruleset

    products = {s for e in entities.values() for s in e.sources}
    rules: dict[str, int] = {}
    with contextlib.suppress(Exception):
        for rule in ruleset.load(config, conn, tenant_id):
            for product in set(
                layout.products_for(
                    rule.logsource.get("product", ""), rule.logsource.get("service", "")
                )
            ):
                rules[product] = rules.get(product, 0) + 1
    blind = sorted(products - rules.keys())
    # Silent rules, and why, are `health.rules`' one answer (D77).
    return {
        "products_with_no_rule": blind,
        "products_seen": sorted(products),
        "rules_by_product": {**dict.fromkeys(products, 0), **rules},
    }


def _store(
    conn: Conn, tenant_id: str, entities: dict[str, Entity], posture: Posture, started: datetime
) -> None:
    for item in entities.values():
        execute(
            conn,
            """INSERT INTO shoc.exposures
                   (tenant_id, entity, kind, exposed, privileged, stale, events,
                    sources, countries, operations, event_uids, first_seen, last_seen,
                    surveyed_at, present)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, true)
               ON CONFLICT (tenant_id, entity) DO UPDATE SET
                   kind = EXCLUDED.kind, exposed = EXCLUDED.exposed,
                   privileged = EXCLUDED.privileged,
                   events = EXCLUDED.events, sources = EXCLUDED.sources,
                   countries = EXCLUDED.countries, operations = EXCLUDED.operations,
                   event_uids = EXCLUDED.event_uids,
                   first_seen = LEAST(shoc.exposures.first_seen, EXCLUDED.first_seen),
                   last_seen = GREATEST(shoc.exposures.last_seen, EXCLUDED.last_seen),
                   -- An earlier survey's sighting is still a sighting: an identity
                   -- this window shows only through a snapshot is stale by the
                   -- older of the two.
                   stale = EXCLUDED.stale AND NOT (
                       EXCLUDED.kind IN ('user', 'account')
                       AND shoc.exposures.last_seen > now() - %s * interval '1 day'),
                   surveyed_at = EXCLUDED.surveyed_at, present = true""",
            (
                tenant_id,
                item.entity,
                item.kind,
                item.exposed,
                item.privileged,
                item.stale,
                item.events,
                sorted(item.sources),
                sorted(item.countries),
                sorted(item.operations),
                item.event_uids,
                item.first_seen,
                _last(item),
                started,
                STALE_IDENTITY_DAYS,
            ),
        )
    if not posture.truncated:
        # What this survey did not see is not described by an old survey's flags.
        # An identity stays, flagged stale once its last sighting is old enough;
        # anything else is dropped. A cut window proves nothing absent.
        execute(
            conn,
            """UPDATE shoc.exposures SET present = false, exposed = false,
                   stale = kind IN ('user', 'account')
                           AND last_seen < now() - %s * interval '1 day'
               WHERE tenant_id = %s AND surveyed_at < %s""",
            (STALE_IDENTITY_DAYS, tenant_id, started),
        )
        execute(
            conn,
            "DELETE FROM shoc.exposures WHERE tenant_id = %s AND NOT present AND kind <> ALL(%s)",
            (tenant_id, list(IDENTITY_KINDS)),
        )


def _snapshot_row(conn: Conn, tenant_id: str, posture: Posture) -> None:
    import json

    uid = (
        "POS-"
        + hashlib.sha256(f"{tenant_id}|{posture.taken_at:%Y-%m-%dT%H}".encode()).hexdigest()[:20]
    )
    execute(
        conn,
        """INSERT INTO shoc.posture_snapshots
               (snapshot_uid, tenant_id, taken_at, window_days, counts, gaps, caveat)
           VALUES (%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (snapshot_uid) DO UPDATE SET
               counts = EXCLUDED.counts, gaps = EXCLUDED.gaps, taken_at = EXCLUDED.taken_at""",
        (
            uid,
            tenant_id,
            posture.taken_at,
            posture.window_days,
            json.dumps(posture.counts, default=str),
            json.dumps(
                {
                    "unwatched": posture.unwatched,
                    "truncated": posture.truncated,
                    "limit": posture.limit,
                },
                default=str,
            ),
            posture.caveat,
        ),
    )


def exposure_of(conn: Conn, tenant_id: str, entity: str) -> dict[str, Any]:
    """What we know about one entity. An entity we have never seen says so plainly.

    This is the answer the Investigator and the IR Commander ask for: is this
    identity privileged, has it been used from outside, what does suspending it
    touch? "We do not know" is a valid answer and must not read as "no".
    """
    rows = fetch_all(
        conn,
        """SELECT * FROM shoc.exposures
           WHERE tenant_id = %s AND (entity = %s OR entity LIKE %s) LIMIT 5""",
        (tenant_id, entity, f"%:{entity}"),
    )
    if not rows:
        return {
            "entity": entity,
            "known": False,
            "caveat": CAVEAT,
            "answer": (
                f"{entity} has not been seen in any ingested event in the survey window. "
                "That means it did nothing we can see, not that it does not exist."
            ),
        }
    row = dict(rows[0])
    row["known"] = True
    row["caveat"] = CAVEAT
    row["answer"] = _describe(row)
    return row


def _describe(row: dict[str, Any]) -> str:
    if row.get("present") is False:
        last = row.get("last_seen")
        return (
            (
                f"{row['entity']} was not seen in the latest survey; last seen {last:%Y-%m-%d}."
                if last
                else f"{row['entity']} was not seen in the latest survey."
            )
            + (" It is stale." if row.get("stale") else "")
            + (" It performed administrative operations before." if row.get("privileged") else "")
        )
    bits = [f"{row['entity']} was seen in {row['events']} event(s)"]
    if row.get("sources"):
        bits.append("via " + ", ".join(row["sources"][:3]))
    flags = [name for name in ("exposed", "privileged", "stale") if row.get(name)]
    bits.append("; ".join(flags) if flags else "no exposure, privilege or staleness observed")
    if row.get("operations"):
        bits.append("administrative operations: " + ", ".join(sorted(row["operations"])[:5]))
    return ". ".join(bits) + "."


def latest(conn: Conn, tenant_id: str) -> dict[str, Any] | None:
    rows = fetch_all(
        conn,
        """SELECT * FROM shoc.posture_snapshots WHERE tenant_id = %s
           ORDER BY taken_at DESC LIMIT 1""",
        (tenant_id,),
    )
    return dict(rows[0]) if rows else None


def surface(
    conn: Conn, tenant_id: str, kind: str = "", exposed_only: bool = True, limit: int = 100
) -> list[dict[str, Any]]:
    """The attack surface as the events describe it: what is reachable from outside."""
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if exposed_only:
        where.append("exposed")
    if kind:
        where.append("kind = %(kind)s")
        params["kind"] = kind
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.exposures WHERE {' AND '.join(where)} "
        "ORDER BY events DESC LIMIT %(limit)s",
        params,
    )


# -- what a target is to us, and who an identity is (D45) ---------------------
def _in_range(address: str, value: str) -> bool:
    """Whether an address is in a CIDR or an `a-b` range, as vendors write them."""
    try:
        ip = ipaddress.ip_address(address)
        if "-" in value:
            low, high = (ipaddress.ip_address(v.strip()) for v in value.split("-", 1))
            return low.version == ip.version and low <= ip <= high  # type: ignore[operator]
        net = ipaddress.ip_network(value.strip(), strict=False)
        return ip.version == net.version and ip in net
    except ValueError:
        return False


def identify(
    conn: Conn, store: Any, tenant_id: str, target: str, config: Any = None, days: int = 30
) -> dict[str, Any]:
    """What a target is to this company, from three sources in order of authority.

    What a person declared outranks what a connector says, which outranks what
    behaviour shows. Each statement says which it is. Nothing here guesses: a
    target none of them knows is `unknown`.
    """
    from shoc.agents import memory
    from shoc.cases import own

    value = own.bare(target)
    said: list[dict[str, Any]] = []
    # 1. Declared: by a person in memory, in shoc's own registry, or in policy.
    for fact in memory.search(conn, tenant_id, value, 5):
        if fact.get("source") == "human" and value.lower() in (
            f"{fact['subject']} {fact['body']}".lower()
        ):
            said.append(
                {
                    "source": "declared",
                    "ours": None,
                    "what": str(fact["body"]),
                    "cite": str(fact["memory_id"]),
                }
            )
    for row in own.listing(conn, tenant_id):
        if str(row["value"]).lower() == value.lower():
            said.append(
                {
                    "source": "declared",
                    "ours": True,
                    "what": f"shoc's registry: {row['kind']}"
                    + (f" ({row['note']})" if row["note"] else ""),
                    "cite": f"own:{row['kind']}:{row['value']}",
                }
            )
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(value)
        if not _outside(value, []):
            said.append(
                {
                    "source": "declared",
                    "ours": True,
                    "what": "a private or carrier-grade NAT address",
                    "cite": "rfc1918",
                }
            )
    if any(_in_range(value, str(n)) for n in _own_networks(config)[len(PRIVATE_NETWORKS) :]):
        said.append(
            {
                "source": "declared",
                "ours": True,
                "what": "in known_egress in content/policy.yaml",
                "cite": "policy:known_egress",
            }
        )
    # 2. Connector: what a source's own API lists.
    for row in fetch_all(
        conn,
        "SELECT source, entity, kind, attributes FROM shoc.snapshots WHERE tenant_id = %s "
        "AND (entity = ANY(%s) OR kind = 'network')",
        (tenant_id, [f"{k}:{value}" for k in ("user", "host", "account")]),
    ):
        attrs = row["attributes"] or {}
        if row["kind"] == "network":
            if not _in_range(value, str(row["entity"]).split(":", 1)[1]):
                continue
            blocked = str(attrs.get("usage") or "").upper() == "BLOCKLIST"
            said.append(
                {
                    "source": "connector",
                    "ours": not blocked,
                    "what": f"{row['source']} network zone '{attrs.get('zone')}'"
                    + (" (a blocklist)" if blocked else ""),
                    "cite": f"snapshot:{row['source']}:{row['entity']}",
                }
            )
        else:
            said.append(
                {
                    "source": "connector",
                    "ours": True,
                    "what": f"a {row['kind']} in {row['source']}, status {attrs.get('status')}",
                    "cite": f"snapshot:{row['source']}:{row['entity']}",
                }
            )
    # 3. Observed: who acts from it, or what it did.
    principals, citations = -1, []
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(value)
        since = datetime.now(UTC) - timedelta(days=days)
        actors = store.query(
            f"SELECT actor_user_name, count(*) AS n FROM {layout.EVENTS_TABLE} "
            "WHERE tenant_id = :tenant_id AND time >= :since AND src_endpoint_ip = :ip "
            "AND actor_user_name IS NOT NULL GROUP BY actor_user_name",
            {"tenant_id": tenant_id, "since": since, "ip": value},
            1000,
        ).rows
        citations = [
            str(r["event_uid"])
            for r in store.query(
                f"SELECT event_uid FROM {layout.EVENTS_TABLE} WHERE tenant_id = :tenant_id "
                "AND time >= :since AND src_endpoint_ip = :ip ORDER BY time DESC",
                {"tenant_id": tenant_id, "since": since, "ip": value},
                10,
            ).rows
        ]
        principals = len(actors)
        if actors:
            said.append(
                {
                    "source": "observed",
                    "ours": None,
                    "what": f"{len(actors)} principal(s) acted from it in {days} day(s): "
                    + ", ".join(str(a["actor_user_name"]) for a in actors[:5]),
                    "cite": ",".join(citations[:3]),
                }
            )
    seen = exposure_of(conn, tenant_id, value)
    if seen.get("known"):
        said.append(
            {
                "source": "observed",
                "ours": None,
                "what": str(seen["answer"]),
                "cite": ",".join(list(seen.get("event_uids") or [])[:3]),
            }
        )
        citations += [str(u) for u in seen.get("event_uids") or []][:10]
    top = said[0] if said else {}
    return {
        "target": value,
        "is_ours": bool(top.get("ours")),
        "what_it_is": str(top.get("what") or "unknown"),
        "source": str(top.get("source") or "unknown"),
        "principals": principals,
        "statements": said,
        "citations": list(dict.fromkeys(citations)),
    }


def resolve(conn: Conn, tenant_id: str, identity: str) -> dict[str, Any]:
    """The same actor under its other names: the keys a user used, the users a key
    belongs to, what the sources list for it, and what a person wrote down.

    A link is something two names did in the same event, or a record that names
    both. Two names nothing links stay apart, and the answer says so.
    """
    from shoc.agents import memory
    from shoc.cases import own

    value = own.bare(identity)
    nodes = [
        r["node_id"]
        for r in fetch_all(
            conn,
            "SELECT node_id FROM shoc.graph_nodes WHERE tenant_id = %s AND (node_id = %s OR label = %s) "
            "AND kind IN ('user', 'key')",
            (tenant_id, identity, value),
        )
    ]
    linked = (
        fetch_all(
            conn,
            """SELECT CASE WHEN e.src = ANY(%s) THEN e.dst ELSE e.src END AS entity,
                  e.weight, e.first_seen, e.last_seen
           FROM shoc.graph_edges e
           WHERE e.tenant_id = %s AND (e.src = ANY(%s) OR e.dst = ANY(%s))
           ORDER BY e.weight DESC LIMIT 50""",
            (nodes, tenant_id, nodes, nodes),
        )
        if nodes
        else []
    )
    linked = [r for r in linked if str(r["entity"]).split(":", 1)[0] in ("user", "key")]
    listed = fetch_all(
        conn,
        "SELECT source, entity, attributes, last_active FROM shoc.snapshots "
        "WHERE tenant_id = %s AND entity = ANY(%s)",
        (tenant_id, [f"user:{value}", identity]),
    )
    registry = [
        dict(r) for r in own.listing(conn, tenant_id) if str(r["value"]).lower() == value.lower()
    ]
    told = [m for m in memory.search(conn, tenant_id, value, 5) if m.get("source") == "human"]
    return {
        "identity": identity,
        "nodes": nodes,
        "linked": linked,
        "listed": listed,
        "registry": registry,
        "declared": told,
        "unbridged": not (linked or listed or registry),
    }


# -- the identity-provider login a name signs in as (RFC 0027) ----------------
# The platforms whose events name identity-provider logins: an M365 or Azure
# actor is an Entra principal.
IDP_PLATFORMS = ("okta", "entra", "m365", "azure")
# A local name seen on more hosts than this is a shared account (admin, root):
# no one machine says who used it.
MAX_LINK_HOSTS = 20
LINK_DAYS = 30


def _short(host: str) -> str:
    """`LAPTOP-21` to an IdP is `laptop-21.example.org` to an EDR."""
    return host.strip().lower().split(".", 1)[0]


def _in(values: list[str], prefix: str, params: dict[str, Any]) -> str:
    params.update({f"{prefix}{i}": v for i, v in enumerate(values)})
    return ", ".join(f":{prefix}{i}" for i in range(len(values)))


def logins(
    store: Any,
    tenant_id: str,
    user: str,
    platforms: tuple[str, ...] = IDP_PLATFORMS,
    days: int = LINK_DAYS,
) -> dict[str, Any]:
    """The identity-provider login a name signs in as, and the events that say so.

    Three links, strongest first; the first that finds a login decides:

    1. another platform's event names the login (GitHub's SAML identity, a
       mapping's `login`);
    2. the identity provider's events name the same name;
    3. they show a login signing in from a host the name acted on.

    A login counts only if the identity provider's events name it as an actor.
    Two logins from one link answer nothing: a shared laptop says nothing about
    who used it.
    """
    from shoc.cases import own
    from shoc.ingest import ocsf as mappings

    value = own.bare(user)
    since = datetime.now(UTC) - timedelta(days=days)
    idp = sorted({p.lower() for platform in platforms for p in layout.products_for(platform)})
    events = layout.EVENTS_TABLE
    base = {"tenant_id": tenant_id, "since": since, "user": value.lower()}
    scope = "tenant_id = :tenant_id AND time >= :since"

    def query(sql: str, params: dict[str, Any], limit: int) -> Any:
        return store.query(sql, {**base, **params}, limit)

    def signed_in(names: dict[str, tuple[str, list[str]]]) -> list[dict[str, Any]]:
        if not names:
            return []
        params: dict[str, Any] = {}
        rows = query(
            f"SELECT actor_user_name, event_uid FROM {events} WHERE {scope} "
            f"AND LOWER(metadata_product) IN ({_in(idp, 'p', params)}) "
            f"AND LOWER(actor_user_name) IN ({_in(sorted(names), 'n', params)}) "
            "ORDER BY time DESC",
            params,
            200,
        ).rows
        found: dict[str, dict[str, Any]] = {}
        for r in rows:
            via, cited = names[str(r["actor_user_name"]).lower()]
            entry = found.setdefault(
                str(r["actor_user_name"]).lower(),
                {"login": str(r["actor_user_name"]), "via": via, "event_uids": list(cited)},
            )
            if len(entry["event_uids"]) < len(cited) + 3:
                entry["event_uids"].append(str(r["event_uid"]))
        return list(found.values())

    def named() -> list[dict[str, Any]]:
        names: dict[str, tuple[str, list[str]]] = {}
        for source in mappings.available_sources():
            mapping = mappings.load_mapping(source)
            product = str(mapping.constants.get("metadata_product") or "").lower()
            expr = layout.column_for(mapping.login) if mapping.login else None
            if not expr or not product or product in idp:
                continue
            for r in query(
                f"SELECT {expr} AS login, event_uid FROM {events} WHERE {scope} "
                "AND LOWER(metadata_product) = :product AND LOWER(actor_user_name) = :user "
                f"AND {expr} IS NOT NULL ORDER BY time DESC",
                {"product": product},
                20,
            ).rows:
                login = str(r["login"]).strip()
                if login and login.lower() != value.lower():
                    names.setdefault(
                        login.lower(), (f"{source} events name it", [str(r["event_uid"])])
                    )
        return signed_in(names)

    def same() -> list[dict[str, Any]]:
        return signed_in({value.lower(): ("the same name", [])})

    def device() -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        products = _in(idp, "p", params)
        hosts = query(
            f"SELECT DISTINCT device_hostname FROM {events} WHERE {scope} "
            "AND LOWER(actor_user_name) = :user AND device_hostname IS NOT NULL "
            f"AND NOT LOWER(metadata_product) IN ({products})",
            params,
            MAX_LINK_HOSTS,
        )
        shorts = sorted({_short(str(r["device_hostname"])) for r in hosts.rows} - {""})
        if hosts.truncated or not shorts:
            return []
        likes = " OR ".join(f"LOWER(device_hostname) LIKE :h{i}" for i in range(len(shorts)))
        params.update({f"h{i}": f"{h}%" for i, h in enumerate(shorts)})
        found: dict[str, dict[str, Any]] = {}
        for r in query(
            f"SELECT actor_user_name, device_hostname, event_uid FROM {events} WHERE {scope} "
            f"AND LOWER(metadata_product) IN ({products}) "
            f"AND actor_user_name IS NOT NULL AND ({likes}) ORDER BY time DESC",
            params,
            500,
        ).rows:
            host = str(r["device_hostname"])
            if _short(host) not in shorts:
                continue
            entry = found.setdefault(
                str(r["actor_user_name"]).lower(),
                {
                    "login": str(r["actor_user_name"]),
                    "via": f"signed in from {host}",
                    "event_uids": [],
                },
            )
            if len(entry["event_uids"]) < 3:
                entry["event_uids"].append(str(r["event_uid"]))
        return list(found.values())

    if value and idp:
        for link in (named, same, device):
            found = link()
            if len(found) == 1:
                return {"user": value, "logins": found, "why": ""}
            if found:
                names = ", ".join(f"{f['login']} ({f['via']})" for f in found[:5])
                return {
                    "user": value,
                    "logins": found,
                    "why": f"{value} links to {names}: no single login to act on",
                }
    return {
        "user": value,
        "logins": [],
        "why": f"nothing links {value or 'an empty name'} to an identity-provider login",
    }


# -- the agent above the queries (D47) ----------------------------------------
# How much of the Surveyor's reading code acts on: the list it hands the
# Detection Engineer has to be short to be real.
MAX_UNWATCHED_ITEMS = 5
MAX_CHANGES = 10
CHANGE_FACT_DAYS = 30


def read(
    conn: Conn,
    store: Any,
    tenant_id: str,
    posture: dict[str, Any],
    config: Any = None,
    client: Any = None,
) -> dict[str, Any]:
    """The Surveyor's model turn over a survey it did not compute (D47).

    The five answers are already stored and do not change here. The model says
    what they mean (kept on the snapshot as `reading`), which unwatched products
    matter (each a Detection Engineer coverage item, only for a product the
    query named), and what changed (a fact on an entity the survey holds, never
    a finding). With no model, or a failed one, the survey stands alone.
    """
    from shoc.agents import detection_engineer as engineer
    from shoc.agents import loop, memory, ops, roles, safety
    from shoc.agents.llm import NoLLM, from_config

    client = client if client is not None else from_config(config, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return {"read": False, "why": "no model is configured"}
    earlier = fetch_all(
        conn,
        """SELECT taken_at, counts FROM shoc.posture_snapshots
           WHERE tenant_id = %s AND taken_at < %s ORDER BY taken_at DESC LIMIT 1""",
        (tenant_id, posture["taken_at"]),
    )
    try:
        said, usage = loop._ask(
            client,
            roles.SURVEYOR,
            "Today's survey is below, with the one before it. Say what it means for this "
            "company, which unwatched products matter here, and what changed.\n\n"
            + safety.quote("survey", posture)
            + "\n\n"
            + safety.quote("previous_survey", earlier[0] if earlier else {}),
            roles.SurveyorOutput,
            config,
            conn,
            tenant_id,
            store,
        )
    except Exception as exc:
        ops.record_failure(
            conn, tenant_id, getattr(client, "model", "none"), f"{type(exc).__name__}: {exc}"
        )
        return {"read": False, "why": f"the model failed: {type(exc).__name__}"}
    loop._charge(conn, tenant_id, usage)

    blind = list((posture.get("unwatched") or {}).get("products_with_no_rule") or [])
    items: list[str] = []
    for text in said.unwatched_matters[:MAX_UNWATCHED_ITEMS]:
        product = next((p for p in blind if p.lower() in str(text).lower()), "")
        if not product:
            continue  # a product the query did not name is the model's, not the survey's
        items.append(
            engineer.add(
                conn,
                tenant_id,
                engineer.BacklogItem(
                    item_uid=engineer.item_uid(tenant_id, "posture", product),
                    kind="coverage",
                    intake="posture",
                    title=f"no rule reads {product}",
                    reason=str(text)[:500],
                    priority=engineer.PRIORITY["coverage"],
                    observability="have",
                    evidence={"product": product},
                ),
            )
        )
    changes = said.changes[:MAX_CHANGES]
    known = {
        str(r["entity"])
        for r in fetch_all(
            conn,
            "SELECT entity FROM shoc.exposures WHERE tenant_id = %s AND entity = ANY(%s)",
            (tenant_id, [c.entity for c in changes]),
        )
    }
    facts: list[str] = []
    for change in changes:
        if change.entity not in known or not change.change.strip():
            continue  # a fact on something the survey does not hold is not one
        facts.append(
            memory.add(
                conn,
                tenant_id,
                f"{change.entity}: {change.change.strip()[:300]} "
                f"(Surveyor, {str(posture['taken_at'])[:10]})",
                subject=change.entity,
                kind="episodic",
                source="Surveyor",
                confidence=0.6,
                expires_at=datetime.now(UTC) + timedelta(days=CHANGE_FACT_DAYS),
            )
        )
    reading = said.exposure_story.strip()[:2000]
    if reading:
        import json

        execute(
            conn,
            """UPDATE shoc.posture_snapshots SET gaps = gaps || %s::jsonb
               WHERE tenant_id = %s AND snapshot_uid = (
                   SELECT snapshot_uid FROM shoc.posture_snapshots
                   WHERE tenant_id = %s ORDER BY taken_at DESC LIMIT 1)""",
            (json.dumps({"reading": reading}), tenant_id, tenant_id),
        )
    return {
        "read": True,
        "items": items,
        "facts": facts,
        "reading": reading,
        "tokens": usage.tokens,
    }
