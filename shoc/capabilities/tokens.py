"""Bearer tokens, issued and revoked through the registry (API-1, SEC-1, RFC 0019).

`SHOC_TOKENS` still works and is how the first admin gets in; everything after
that is a capability, so issuing a token is audited, confirmed by the person
when it comes over MCP, and revoked without a restart. The token is shown once
and only its SHA-256 is kept.

A signed-in browser is a row here too (RFC 0028), tied to its account by
`user_id`; `token.list` leaves those out, since `user.update` ends them.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal

from shoc.capabilities.registry import Context, Result, capability
from shoc.db.pool import Conn, fetch_all, fetch_one
from shoc.errors import NotFound, ValidationError
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json

PREFIX = "shoc_"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def find(conn: Conn, token: str) -> dict[str, Any] | None:
    """The live entry behind a presented token, in `SHOC_TOKENS`' shape.

    A signed-in browser's row (RFC 0028) has a `user_id` and no role: the role
    is the account's, read on every request, and a disabled account's rows
    find nothing.
    """
    row = fetch_one(
        conn,
        """SELECT t.tenant_id, t.who, COALESCE(t.role, u.role) AS role, t.kind, t.scopes,
                  t.user_id
           FROM shoc.api_tokens t
           LEFT JOIN shoc.users u ON u.tenant_id = t.tenant_id AND u.user_id = t.user_id
           WHERE t.hash = %s AND t.revoked_at IS NULL
             AND (t.expires_at IS NULL OR t.expires_at > now())
             AND (t.user_id IS NULL OR (u.user_id IS NOT NULL AND u.disabled_at IS NULL))""",
        (digest(token),),
    )
    if row is None:
        return None
    entry: dict[str, Any] = {"id": row["who"], "tenant": row["tenant_id"]}
    if row["user_id"]:
        entry["user_id"] = row["user_id"]
    if row["role"]:
        entry["role"] = row["role"]
    else:
        entry.update(kind=row["kind"], scopes=list(row["scopes"]))
    return entry


def issued(conn: Conn) -> bool:
    """Whether any token or account was ever made, revoked or not: that ends single-user mode."""
    row = fetch_one(
        conn,
        """SELECT EXISTS (SELECT 1 FROM shoc.api_tokens)
                  OR EXISTS (SELECT 1 FROM shoc.users) AS made""",
    )
    return bool(row and row["made"])


@dataclass
class TokenCreate:
    who: str = f(doc="The person or machine the token is for, e.g. alice@example.com or ci")
    role: Literal["", "admin", "operator", "deployer", "reader"] = f(
        "", doc="A person's role; leave empty for a machine token"
    )
    kind: Literal["service", "agent", "external_agent"] = f(
        "service", doc="A machine token's principal; ignored when a role is set"
    )
    scopes: list[str] = f(doc="A machine token's scopes, e.g. events:write", factory=list)
    expires_days: int = f(0, doc="Days until it stops working; 0 never expires")


@dataclass
class TokenIssued:
    token_id: str = ""
    token: str = f("", doc="Shown once; shoc keeps only its hash")
    who: str = ""
    role: str = ""
    expires_at: str | None = None


@capability(
    name="token.create",
    summary="Issue a bearer token for a person or a machine; the token is returned once",
    input=TokenCreate,
    output=TokenIssued,
    scope="tokens:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("tokens", "write"),
)
def create(ctx: Context, inp: TokenCreate) -> Result:
    from shoc.api.auth import ROLES

    who = inp.who.strip()
    if not who:
        raise ValidationError("who: name the person or machine the token is for")
    if inp.role and inp.role not in ROLES:
        raise ValidationError(f"role: one of {', '.join(ROLES)}")
    if not inp.role and not inp.scopes:
        raise ValidationError("a machine token needs scopes, and a person's token a role")
    if inp.expires_days < 0:
        raise ValidationError("expires_days: 0 or more")
    token = PREFIX + secrets.token_urlsafe(32)
    token_id = "tok_" + secrets.token_hex(6)
    row = (
        fetch_one(
            ctx.db,
            """INSERT INTO shoc.api_tokens
               (tenant_id, token_id, hash, who, role, kind, scopes, created_by, expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,
                   CASE WHEN %s > 0 THEN now() + make_interval(days => %s) END)
           RETURNING expires_at""",
            (
                ctx.tenant_id,
                token_id,
                digest(token),
                who,
                inp.role or None,
                "human" if inp.role else inp.kind,
                [] if inp.role else inp.scopes,
                ctx.caller.id,
                inp.expires_days,
                inp.expires_days,
            ),
        )
        or {}
    )
    expires = row.get("expires_at")
    return Result(
        data=TokenIssued(
            token_id=token_id,
            token=token,
            who=who,
            role=inp.role,
            expires_at=expires.isoformat() if expires else None,
        ),
        summary=(
            f"Token {token_id} for {who} ({inp.role or inp.kind}). Copy it now; "
            "shoc will not show it again."
        ),
        citations=[token_id],
    )


@dataclass
class TokenQuery:
    revoked: bool = f(False, doc="Include revoked and expired tokens")


@dataclass
class TokenList:
    tokens: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="token.list",
    summary="List issued bearer tokens: who, role or scopes, and when they end",
    input=TokenQuery,
    output=TokenList,
    scope="tokens:read",
    principals=("human",),
    tags=("tokens", "read"),
)
def list_tokens(ctx: Context, inp: TokenQuery) -> Result:
    rows = fetch_all(
        ctx.db,
        """SELECT token_id, who, role, kind, scopes, created_by, created_at, expires_at,
                  revoked_at, revoked_by
           FROM shoc.api_tokens
           WHERE tenant_id = %s AND user_id IS NULL AND (%s OR (revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > now())))
           ORDER BY created_at DESC""",
        (ctx.tenant_id, inp.revoked),
    )
    return Result(
        data=TokenList(tokens=[to_json(r) for r in rows]),
        summary=f"{len(rows)} token(s).",
        citations=[r["token_id"] for r in rows],
    )


@dataclass
class TokenRevoke:
    token_id: str = f(doc="The token's id, tok_…, from token.list")


@dataclass
class TokenRevoked:
    token_id: str = ""
    who: str = ""


@capability(
    name="token.revoke",
    summary="Revoke a bearer token; it stops working on the next request",
    input=TokenRevoke,
    output=TokenRevoked,
    scope="tokens:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("tokens", "write"),
)
def revoke(ctx: Context, inp: TokenRevoke) -> Result:
    row = fetch_one(
        ctx.db,
        """UPDATE shoc.api_tokens SET revoked_at = now(), revoked_by = %s
           WHERE tenant_id = %s AND token_id = %s AND revoked_at IS NULL
           RETURNING who""",
        (ctx.caller.id, ctx.tenant_id, inp.token_id),
    )
    if row is None:
        raise NotFound(f"no live token '{inp.token_id}'")
    return Result(
        data=TokenRevoked(token_id=inp.token_id, who=row["who"]),
        summary=f"Revoked {inp.token_id} ({row['who']}).",
        citations=[inp.token_id],
    )
