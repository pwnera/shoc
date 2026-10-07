"""Platform lookups: read the live state of a connected tool (RFC 0014, AGT-1).

The event store says what happened. Some questions are about what is true now:
which admin roles this user holds, which inbox rules forward mail, who owns this
access key, which hosts have seen this file. A lookup asks the platform, with
the credentials its actions use, and never changes anything there.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, capability
from shoc.jsonschema import field as f


@dataclass
class LookupFilter:
    platform: str = f("", doc="Only lookups for this platform, e.g. okta, m365, edr, aws")


@dataclass
class LookupCatalogue:
    lookups: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="platform.lookups",
    summary="List the live reads available on connected platforms, and their parameters",
    input=LookupFilter,
    output=LookupCatalogue,
    scope="platforms:read",
    tags=("platforms", "read"),
)
def catalogue(ctx: Context, inp: LookupFilter) -> Result:
    from shoc.actions import lookups
    from shoc.cases import credentials

    configured = {credentials.provider_of(p) for p in credentials.providers(ctx.db, ctx.tenant_id)}
    rows = [
        {
            "lookup": lk.type,
            "does": lk.summary,
            "platforms": list(lk.platforms),
            "params": list(lk.required_params),
            "configured": lk.provider in configured,
        }
        for lk in sorted(lookups().values(), key=lambda lk: lk.type)
        if not inp.platform or inp.platform in lk.platforms
    ]
    ready = sum(1 for r in rows if r["configured"])
    return Result(
        data=LookupCatalogue(lookups=rows),
        summary=f"{len(rows)} lookup(s), {ready} with credentials configured.",
    )


@dataclass
class LookupInput:
    lookup: str = f(doc="Lookup name from platform.lookups, e.g. okta.get_user")
    params: dict[str, Any] = f(
        doc="Its parameters, e.g. {'user': 'alice@example.com'}", factory=dict
    )
    case_uid: str = f("", doc="The case it is for: the read goes to the tenant the case saw")
    credential: str = f("", doc="One of the provider's credentials, e.g. entra:emea")


@dataclass
class LookupAnswer:
    lookup: str = ""
    platforms: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    read_from: str = ""  # the credential's name, e.g. entra:emea


@capability(
    name="platform.lookup",
    summary="Read live state from a connected platform: a user, a mailbox, a key, a host",
    input=LookupInput,
    output=LookupAnswer,
    scope="platforms:lookup",
    # Not an external agent: what it looks up comes from log content an attacker
    # wrote, and it acts with shoc's credentials. The MCP gate keeps
    # `intel:read` out for the same reason.
    principals=("human", "agent", "service"),
    audit=True,
    tags=("platforms", "read"),
)
def lookup(ctx: Context, inp: LookupInput) -> Result:
    from shoc.actions import get_lookup
    from shoc.cases import credentials
    from shoc.errors import NotFound, ValidationError

    lk = get_lookup(inp.lookup)
    lk.check(inp.params)
    # A read goes to one tenant: the one the target was seen in (RFC 0025).
    chosen, gaps = credentials.route(
        ctx.db,
        ctx.tenant_id,
        lk,
        inp.params,
        inp.case_uid,
        config=ctx.config,
        named=inp.credential,
    )
    if len(chosen) > 1:
        raise ValidationError(
            f"{lk.type} could read from {', '.join(chosen)}: name one as `credential`",
            code="credential_ambiguous",
        )
    if gaps and not chosen:
        raise NotFound("; ".join(gaps))
    name = chosen[0] if chosen else lk.provider
    creds = credentials.load(ctx.db, ctx.tenant_id, name, ctx.config.master_key)
    data = lk.run(creds, inp.params)
    return Result(
        data=LookupAnswer(lookup=lk.type, platforms=list(lk.platforms), data=data, read_from=name),
        summary=f"{lk.type} answered from {name}, live.",
    )
