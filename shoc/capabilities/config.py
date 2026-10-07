"""Config-as-code capabilities (API-4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shoc import configcode
from shoc.capabilities.registry import Context, Result, capability
from shoc.jsonschema import field as f


@dataclass
class ConfigInput:
    config: dict[str, Any] = f(
        doc="The deployment config, as `shoc.yaml` parses. `shoc plan -f` reads the file "
        "and sends it here; the server reads no path a caller names",
        factory=dict,
    )


@dataclass
class PlanOutput:
    changes: list[dict[str, Any]] = field(default_factory=list)
    to_change: int = 0
    invalid: int = 0
    missing_env: list[str] = field(default_factory=list)
    rendered: str = ""


@capability(
    name="config.plan",
    summary="Show what applying this deployment config would change",
    input=ConfigInput,
    output=PlanOutput,
    scope="config:read",
    principals=("human", "service"),
    tags=("config", "read"),
)
def plan(ctx: Context, inp: ConfigInput) -> Result:
    result = configcode.plan(
        ctx.db, ctx.tenant_id, configcode.Desired.from_dict(inp.config), ctx.config
    )
    payload = configcode.to_json(result)
    return Result(
        data=PlanOutput(rendered=result.render(), **payload),
        summary=result.render().rsplit("\n\n", 1)[-1],
    )


@capability(
    name="config.apply",
    summary="Make the deployment match the config file",
    input=ConfigInput,
    output=PlanOutput,
    scope="config:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("config", "write"),
)
def apply(ctx: Context, inp: ConfigInput) -> Result:
    result = configcode.apply(ctx, configcode.Desired.from_dict(inp.config))
    payload = configcode.to_json(result)
    return Result(
        data=PlanOutput(rendered=result.render(), **payload),
        summary=(
            f"Applied {len(result.changes)} change(s)."
            if result.changes
            else "Nothing to do; the deployment already matches the file."
        ),
    )
