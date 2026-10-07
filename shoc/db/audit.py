"""Hash-chained audit log (SEC-1).

Each row commits to the one before it in the same tenant's chain:

    hash = HMAC-SHA256(key, [prev_hash, tenant, ts, principal, capability,
                             input_hash, output_hash, error])

The key is derived from SHOC_MASTER_KEY, which never reaches the database.
Appends take a per-tenant advisory lock, so two writers cannot both chain onto
the same row. `shoc migrate` records a fingerprint of the key in
`shoc.audit_key`, and a process whose key is empty or does not match refuses to
append, so one misconfigured shell cannot write a row that never verifies.
`verify` walks the whole chain and reports every row that does not match; the
worker runs it every hour in `ops.check` and pages once for each new break.

What this protects, and what it does not:

- Without the master key, nobody can edit a row, insert one, or re-chain the
  log from some point on and have it verify. That includes the database role
  shoc runs as.
- `serve` and `worker` should run as a role that does not own the schema
  (RFC 0024): `shoc migrate` connects as the owner (SHOC_MIGRATE_DSN) and grants
  the runtime role (SHOC_DSN) SELECT and INSERT here and nothing else, so it
  cannot disable the triggers, delete or truncate. The owner still can, and the
  chain left behind verifies; each webhook delivery carries the tenant's chain
  head, and `health.audit` checks a head kept that way (`head`).
- Anyone who holds the master key and can write to the table can rewrite the
  log. `shoc rotate-key` moves the chain to a new key: the retired key is kept
  in `shoc.audit_epochs`, sealed with the new one, so older rows still verify.

Rows written before migration 025 were chained with plain SHA-256 and without
`ts`. Migration 025 closes each tenant's older chain with an `audit.checkpoint`
row, keyed like every row after it, so those rows cannot be changed or replaced
afterwards either. Rows before a tenant's first checkpoint are checked the old
way; every other row must be keyed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from shoc.errors import ConfigError
from shoc.jsonschema import to_json

GENESIS = "0" * 64

# The reserved capability name of the row migration 025 writes (see above).
CHECKPOINT = "audit.checkpoint"

# The row `shoc rotate-key` writes on each chain, the first keyed with the new key.
REKEY = "audit.rekey"

# The migration that switches the chain to the keyed scheme.
KEYED_FROM = "025_audit_keyed"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def hash_payload(value: Any) -> str:
    return _sha(json.dumps(to_json(value), sort_keys=True, default=str))


def chain_key(master: str | None = None) -> bytes:
    """The chain's HMAC key, kept apart from the key that seals secrets."""
    from shoc.config import Config

    master = Config.load().master_key if master is None else master
    if not master:
        raise ConfigError("SHOC_MASTER_KEY is not set; the audit log cannot be written or verified")
    return hashlib.sha256(b"shoc audit chain\0" + master.encode()).digest()


def fingerprint(key: bytes) -> str:
    """What `shoc.audit_key` holds: names the key without revealing it."""
    return hmac.new(key, b"shoc audit key", hashlib.sha256).hexdigest()


def _key(conn: Any) -> bytes:
    """This process's key, once it is known to be the one the chain is keyed with."""
    from shoc.db.pool import fetch_one

    key = chain_key()
    held = fetch_one(conn, "SELECT fingerprint FROM shoc.audit_key")
    if not held or held["fingerprint"] != fingerprint(key):
        raise ConfigError(
            "SHOC_MASTER_KEY is not the key `shoc migrate` keyed the audit log with; "
            "nothing was written to the audit log or checked against it"
        )
    return key


def _ts(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def chain_hash(
    key: bytes,
    prev_hash: str,
    tenant_id: str,
    ts: datetime,
    principal: str,
    capability: str,
    input_hash: str,
    output_hash: str | None,
    error: str | None,
) -> str:
    parts = [
        prev_hash,
        tenant_id,
        _ts(ts),
        principal,
        capability,
        input_hash,
        output_hash or "",
        error or "",
    ]
    return hmac.new(key, json.dumps(parts).encode(), hashlib.sha256).hexdigest()


def legacy_hash(
    prev_hash: str,
    tenant_id: str,
    principal: str,
    capability: str,
    input_hash: str,
    output_hash: str | None,
    error: str | None,
) -> str:
    """How rows were chained before migration 025."""
    parts = [
        prev_hash,
        tenant_id,
        principal,
        capability,
        input_hash,
        output_hash or "",
        error or "",
    ]
    return _sha("|".join(parts))


def append(
    conn: Any,
    tenant_id: str,
    principal_kind: str,
    principal_id: str,
    capability: str,
    input_hash: str,
    output_hash: str | None = None,
    error: str | None = None,
    key: bytes | None = None,
) -> str:
    """Append one row to a tenant's chain. Returns its hash.

    `key` is for `rotate` alone, which appends with the key it is moving to.
    """
    from shoc.db.pool import fetch_one

    key = key or _key(conn)
    with conn.transaction(), conn.cursor() as cur:
        # Held until the enclosing transaction ends, so the row read below is
        # the last one committed and nobody else can chain onto it meanwhile.
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtext('shoc.audit_log'), hashtext(%s))",
            (tenant_id,),
        )
        row = fetch_one(
            conn,
            "SELECT hash FROM shoc.audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
            (tenant_id,),
        )
        prev = row["hash"] if row else GENESIS
        ts = datetime.now(UTC)
        digest = chain_hash(
            key,
            prev,
            tenant_id,
            ts,
            f"{principal_kind}:{principal_id}",
            capability,
            input_hash,
            output_hash,
            error,
        )
        cur.execute(
            """INSERT INTO shoc.audit_log
               (tenant_id, ts, principal_kind, principal_id, capability,
                input_hash, output_hash, error, prev_hash, hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                tenant_id,
                ts,
                principal_kind,
                principal_id,
                capability,
                input_hash,
                output_hash,
                error,
                prev,
                digest,
            ),
        )
    return digest


def record(
    ctx: Any, capability: str, inp: Any, result: Any = None, error: str | None = None
) -> str:
    """Append the row for one capability call. Returns its hash."""
    return append(
        ctx.db,
        ctx.tenant_id,
        ctx.caller.kind,
        ctx.caller.id,
        capability,
        hash_payload(inp),
        hash_payload(result.data) if result is not None else None,
        error,
    )


def seal_legacy(conn: Any) -> int:
    """Record the key's fingerprint and close every tenant's pre-025 chain. Run by migration 025."""
    from shoc.db.pool import fetch_all

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO shoc.audit_key (fingerprint) VALUES (%s)", (fingerprint(chain_key()),)
        )
    tenants = fetch_all(conn, "SELECT DISTINCT tenant_id FROM shoc.audit_log")
    for row in tenants:
        append(conn, row["tenant_id"], "service", "migrate", CHECKPOINT, hash_payload({}))
    return len(tenants)


def _retired(conn: Any, master: str | None = None) -> list[tuple[int, bytes]]:
    """The keys earlier rows were chained with, oldest first (`rotate`)."""
    from shoc.config import Config
    from shoc.db.pool import fetch_all
    from shoc.db.secrets import open_secret

    master = Config.load().master_key if master is None else master
    return [
        (
            int(r["until_seq"]),
            bytes.fromhex(
                open_secret(master, r["sealed"], "", "audit_epochs", str(r["until_seq"]))["key"]
            ),
        )
        for r in fetch_all(
            conn, "SELECT until_seq, sealed FROM shoc.audit_epochs ORDER BY until_seq"
        )
    ]


def rotate(conn: Any, old_master: str, new_master: str) -> int:
    """Move every chain to the key `new_master` derives. Returns the chains re-anchored.

    Run as the schema owner inside the caller's transaction (`shoc rotate-key`).
    The retiring key is sealed with the new master key into `shoc.audit_epochs`
    beside the first row it no longer covers, and every key already there is
    sealed again, so each older row still verifies with the key it was chained
    with. Each tenant's chain then gets an `audit.rekey` row, keyed with the new
    key and chained onto the old head.
    """
    from shoc.db.pool import execute, fetch_all, fetch_one
    from shoc.db.secrets import seal

    old, new = chain_key(old_master), chain_key(new_master)
    held = fetch_one(conn, "SELECT fingerprint FROM shoc.audit_key")
    if not held or held["fingerprint"] != fingerprint(old):
        raise ConfigError(
            "SHOC_MASTER_KEY is not the key the audit log is keyed with; nothing was rotated"
        )
    # Waits for appends in flight and holds new ones until this commits, so no
    # row lands between the boundary and the re-anchor.
    execute(conn, "LOCK TABLE shoc.audit_log IN EXCLUSIVE MODE")

    def sealed(until: int, key: bytes) -> bytes:
        return seal(new_master, {"key": key.hex()}, "", "audit_epochs", str(until))

    for until, key in _retired(conn, old_master):
        execute(
            conn,
            "UPDATE shoc.audit_epochs SET sealed = %s WHERE until_seq = %s",
            (sealed(until, key), until),
        )
    row = fetch_one(conn, "SELECT coalesce(max(seq), 0) + 1 AS n FROM shoc.audit_log")
    until = int(row["n"]) if row else 1
    # Two rotations with no row between them: the first epoch already covers it.
    execute(
        conn,
        """INSERT INTO shoc.audit_epochs (until_seq, fingerprint, sealed) VALUES (%s,%s,%s)
           ON CONFLICT (until_seq) DO NOTHING""",
        (until, fingerprint(old), sealed(until, old)),
    )
    execute(conn, "UPDATE shoc.audit_key SET fingerprint = %s", (fingerprint(new),))
    tenants = fetch_all(conn, "SELECT DISTINCT tenant_id FROM shoc.audit_log")
    for t in tenants:
        append(conn, t["tenant_id"], "service", "rotate-key", REKEY, hash_payload({}), key=new)
    return len(tenants)


def chain_head(conn: Any, tenant_id: str) -> str:
    """The newest row of a tenant's chain as `seq:hash`, to keep outside Postgres."""
    from shoc.db.pool import fetch_one

    row = fetch_one(
        conn,
        "SELECT seq, hash FROM shoc.audit_log WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
        (tenant_id,),
    )
    return f"{row['seq']}:{row['hash']}" if row else ""


def verify(conn: Any, tenant_id: str, batch: int = 5000, head: str = "") -> tuple[bool, int, str]:
    """Walk the whole chain. Returns (ok, rows_checked, message).

    A row that does not match is counted and the walk goes on from its stored
    hash, so a later change elsewhere still shows. While nothing new breaks,
    the message stays the same. `head` is a `seq:hash` kept outside Postgres (a
    webhook delivery carries one), and the chain must still hold that row.
    """
    from shoc.db.pool import fetch_all, fetch_one

    key = _key(conn)
    retired = _retired(conn)
    first = fetch_one(
        conn,
        "SELECT min(seq) AS seq FROM shoc.audit_log WHERE tenant_id = %s AND capability = %s",
        (tenant_id, CHECKPOINT),
    )
    keyed_from = int(first["seq"]) if first and first["seq"] is not None else 0
    head_seq, _, head_hash = head.partition(":")
    held = not head
    prev, count, last = GENESIS, 0, 0
    broken, first_bad, last_bad = 0, 0, 0
    while True:
        rows = fetch_all(
            conn,
            """SELECT seq, tenant_id, ts, principal_kind, principal_id, capability,
                      input_hash, output_hash, error, prev_hash, hash
               FROM shoc.audit_log WHERE tenant_id = %s AND seq > %s ORDER BY seq LIMIT %s""",
            (tenant_id, last, batch),
        )
        if not rows:
            break
        for r in rows:
            principal = f"{r['principal_kind']}:{r['principal_id']}"
            fields = (r["capability"], r["input_hash"], r["output_hash"], r["error"])
            keyed = next((k for until, k in retired if r["seq"] < until), key)
            expect = (
                legacy_hash(r["prev_hash"], r["tenant_id"], principal, *fields)
                if r["seq"] < keyed_from
                else chain_hash(keyed, r["prev_hash"], r["tenant_id"], r["ts"], principal, *fields)
            )
            if r["prev_hash"] != prev or expect != r["hash"]:
                broken += 1
                first_bad, last_bad = first_bad or r["seq"], r["seq"]
            held = held or (str(r["seq"]) == head_seq and r["hash"] == head_hash)
            prev = r["hash"]
            count += 1
        last = rows[-1]["seq"]
    if not held:
        return (
            False,
            count,
            (
                f"the chain no longer holds row {head_seq} as it was recorded outside the "
                "database: rows were removed or replaced"
            ),
        )
    if not broken:
        return True, count, f"{count} audit rows verified"
    return (
        False,
        count,
        (
            f"{broken} audit row(s) do not match the chain, the first at row {first_bad} "
            f"and the last at row {last_bad}"
        ),
    )
