"""Self-description: the registry explains itself to clients and agents (API-1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc.capabilities.registry import Context, Result, all_capabilities, capability, get
from shoc.jsonschema import field as f


@dataclass
class CapabilityFilter:
    area: str = f("", doc="Only capabilities in this area, e.g. events, finding, rule")
    principal: str = f("", doc="Only capabilities this principal kind may call")


@dataclass
class CapabilityList:
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    count: int = 0
    version: str = ""


@capability(
    name="capability.list",
    summary="List every capability, with its schemas and how each surface exposes it",
    input=CapabilityFilter,
    output=CapabilityList,
    scope="meta:read",
    tags=("meta", "read"),
)
def list_capabilities(ctx: Context, inp: CapabilityFilter) -> Result:
    from shoc import __version__

    caps = all_capabilities()
    if inp.area:
        caps = [c for c in caps if c.area == inp.area]
    if inp.principal:
        caps = [c for c in caps if inp.principal in c.principals]
    data = [c.describe() for c in caps]
    return Result(
        data=CapabilityList(capabilities=data, count=len(data), version=__version__),
        summary=f"{len(data)} capability(ies) registered in shoc {__version__}.",
    )


@dataclass
class CapabilityRef:
    name: str = f(doc="Capability name, e.g. events.query")


@dataclass
class CapabilityDoc:
    capability: dict[str, Any] = field(default_factory=dict)


@capability(
    name="capability.describe",
    summary="Describe one capability: schemas, scope, autonomy and surfaces",
    input=CapabilityRef,
    output=CapabilityDoc,
    scope="meta:read",
    tags=("meta", "read"),
)
def describe_capability(ctx: Context, inp: CapabilityRef) -> Result:
    cap = get(inp.name)
    return Result(
        data=CapabilityDoc(capability=cap.describe()),
        summary=f"{cap.name}: {cap.summary} (scope {cap.scope}, autonomy {cap.autonomy}).",
    )
