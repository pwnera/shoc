"""shoc's own footprint and the people who run it (AGT-13, RFC 0021, D78)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from shoc.capabilities.registry import Context, Result, capability
from shoc.cases import own
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json


@dataclass
class Empty:
    pass


@dataclass
class OwnPage:
    rows: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0


@capability(
    name="own.list",
    summary="What shoc knows is its own: its credentials and addresses, the operator's and the company's automation accounts",
    input=Empty,
    output=OwnPage,
    scope="own:read",
    # An outside assistant is not told which credentials are shoc's own.
    principals=("human", "agent"),
    tags=("own", "read"),
)
def list_own(ctx: Context, inp: Empty) -> Result:
    rows = own.listing(ctx.db, ctx.tenant_id)
    return Result(
        data=OwnPage(rows=[to_json(r) for r in rows], count=len(rows)),
        summary=f"{len(rows)} identit(y/ies) shoc treats as its own or the operator's.",
    )


@dataclass
class OwnIdentity:
    kind: Literal["credential", "address", "operator", "automation"] = f(
        "operator",
        doc="credential: a credential id shoc reads with; address: an address shoc calls "
        "out from; operator: an account of the person who runs shoc; automation: an "
        "account of the company's own automation",
    )
    value: str = f("", doc="The id, address or account, exactly as the logs show it")
    source: str = f("", doc="The source a credential belongs to, e.g. google_workspace")
    scope: str = f("", doc="What a credential was granted, space-separated")
    note: str = f("", doc="Why, in one sentence")


@dataclass
class OwnRef:
    kind: str = ""
    value: str = ""


@capability(
    name="own.add",
    summary="Record a credential, address or account as shoc's own or the operator's",
    input=OwnIdentity,
    output=OwnRef,
    scope="own:write",
    principals=("human",),
    # A credential or address recorded here makes the activity it explains read
    # as shoc's own, so the person confirms it over MCP (D65).
    autonomy="L2",
    audit=True,
    tags=("own", "write"),
)
def add_own(ctx: Context, inp: OwnIdentity) -> Result:
    from shoc.errors import ValidationError

    if not inp.value.strip():
        raise ValidationError("an identity needs a value")
    own.register(
        ctx.db,
        ctx.tenant_id,
        inp.kind,
        inp.value,
        source=inp.source,
        scope=inp.scope,
        note=inp.note,
        by=f"{ctx.caller.kind}:{ctx.caller.id}",
    )
    return Result(
        data=OwnRef(kind=inp.kind, value=inp.value.strip()),
        summary=f"Recorded {inp.value.strip()} as {inp.kind}.",
    )


@dataclass
class OwnRemove:
    kind: str = f(doc="credential, address, operator or automation")
    value: str = f(doc="The value to forget")


@capability(
    name="own.remove",
    summary="Forget one of shoc's own identities",
    input=OwnRemove,
    output=OwnRef,
    scope="own:write",
    principals=("human",),
    audit=True,
    tags=("own", "write"),
)
def remove_own(ctx: Context, inp: OwnRemove) -> Result:
    from shoc.errors import NotFound

    if not own.forget(ctx.db, ctx.tenant_id, inp.kind, inp.value):
        raise NotFound(f"no {inp.kind} '{inp.value}'")
    return Result(
        data=OwnRef(kind=inp.kind, value=inp.value),
        summary=f"{inp.value} is no longer recorded as {inp.kind}.",
    )
