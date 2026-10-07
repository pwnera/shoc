"""The crew's model, changed at runtime (RFC 0007, AGT-5, API-1, SEC-1).

Stored per tenant in `connector_config` under `source='llm'`, the way Slack is,
and read on the next case; SHOC_LLM_* stays the default for anything not stored.
The crew's budgets live in the same row (`agents.llm.BUDGETS`).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

from shoc.capabilities.health import Empty
from shoc.capabilities.registry import Context, Result, capability
from shoc.errors import ConfigError
from shoc.jsonschema import field as f

PROVIDERS = ("anthropic", "openai", "openai-responses", "none")
DEFAULT_HOSTS = ("api.anthropic.com", "api.openai.com")


@dataclass
class LLMConfig:
    """Change the provider, models, endpoint or key. Empty fields keep what is there."""

    provider: str = f(
        "",
        doc="anthropic, openai (any /chat/completions endpoint), openai-responses (a /responses endpoint) or none",
    )
    model: str = f("", doc="The model every role uses")
    model_cheap: str = f("", doc="The model for the narrow roles; empty runs them on `model`")
    base_url: str = f("", doc="The endpoint; its host must be in SHOC_LLM_BASE_URL_ALLOWLIST")
    api_key: str = f("", doc="The provider key; stored encrypted, never returned")
    spend_usd_per_day: float = f(
        0.0, doc="Raise cost.over_budget when a day's spend passes this; 0 keeps what is stored"
    )
    hunt_tokens_per_day: int = f(
        0, doc="Ceiling of the Hunter's daily triage turn, in tokens; 0 keeps what is stored"
    )
    intel_reports_per_day: int = f(
        0, doc="Threat reports CTI reads in a day; 0 keeps what is stored"
    )
    intel_tokens_per_day: int = f(
        0, doc="Tokens CTI spends reading reports in a day; 0 keeps what is stored"
    )
    clear: bool = f(False, doc="Remove the stored settings and fall back to SHOC_LLM_*")


@dataclass
class LLMState:
    provider: str = ""
    model: str = ""
    model_cheap: str = ""
    base_url: str = ""
    key: str = ""  # "set" or "unset", never the key
    spend_usd_per_day: float = 0.0
    hunt_tokens_per_day: int = 0
    intel_reports_per_day: int = 0
    intel_tokens_per_day: int = 0
    # The fields that come from llm.configure rather than SHOC_LLM_*.
    stored: list[str] = field(default_factory=list)


def allowed_hosts() -> set[str]:
    """Where a stored base URL may point: the deployment's own choice, never the caller's."""
    raw = os.environ.get("SHOC_LLM_BASE_URL_ALLOWLIST", "")
    hosts = {h.strip().lower() for h in raw.split(",") if h.strip()}
    env = urlparse(os.environ.get("SHOC_LLM_BASE_URL", "")).hostname
    return hosts or {*DEFAULT_HOSTS, *([env] if env else [])}


def _state(ctx: Context) -> LLMState:
    from shoc.agents.llm import BUDGETS, STORED_FIELDS, budget, stored
    from shoc.db.pool import fetch_one

    cfg = stored(ctx.config, ctx.db, ctx.tenant_id)
    row = fetch_one(
        ctx.db,
        "SELECT settings, secret FROM shoc.connector_config WHERE tenant_id=%s AND source='llm'",
        (ctx.tenant_id,),
    )
    settings = dict(row["settings"] or {}) if row else {}
    from_row = [k for k in (*STORED_FIELDS, *BUDGETS) if settings.get(k)]
    if row and row["secret"]:
        from_row.append("api_key")
    return LLMState(
        provider=cfg.llm_provider,
        model=cfg.llm_model,
        model_cheap=cfg.llm_model_cheap,
        base_url=cfg.llm_base_url,
        key="set" if cfg.llm_api_key else "unset",
        spend_usd_per_day=budget(ctx.db, ctx.tenant_id, "spend_usd_per_day"),
        hunt_tokens_per_day=int(budget(ctx.db, ctx.tenant_id, "hunt_tokens_per_day")),
        intel_reports_per_day=int(budget(ctx.db, ctx.tenant_id, "intel_reports_per_day")),
        intel_tokens_per_day=int(budget(ctx.db, ctx.tenant_id, "intel_tokens_per_day")),
        stored=from_row,
    )


def _said(state: LLMState) -> str:
    cheap = f", narrow roles on {state.model_cheap}" if state.model_cheap else ""
    where = state.base_url or "the provider's default endpoint"
    return f"The crew uses {state.provider}/{state.model or 'default'}{cheap} at {where}."


@capability(
    name="llm.show",
    summary="Show the crew's model, endpoint and where each setting comes from",
    input=Empty,
    output=LLMState,
    scope="llm:read",
    principals=("human", "service"),
    tags=("llm", "read"),
)
def show(ctx: Context, inp: Empty) -> Result:
    state = _state(ctx)
    return Result(data=state, summary=_said(state))


@capability(
    name="llm.configure",
    summary="Change the crew's model, or what it may spend, without a restart",
    input=LLMConfig,
    output=LLMState,
    scope="llm:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("llm", "write", "security"),
)
def configure(ctx: Context, inp: LLMConfig) -> Result:
    from shoc.agents.llm import STORED_FIELDS
    from shoc.db.pool import execute, fetch_one
    from shoc.db.secrets import open_secret, seal

    if inp.clear:
        execute(
            ctx.db,
            "DELETE FROM shoc.connector_config WHERE tenant_id=%s AND source='llm'",
            (ctx.tenant_id,),
        )
        state = _state(ctx)
        return Result(data=state, summary="Stored settings removed. " + _said(state))
    if inp.provider and inp.provider.lower() not in PROVIDERS:
        raise ConfigError(f"unknown provider '{inp.provider}' (use {', '.join(PROVIDERS)})")
    # Whoever can set the endpoint receives every case's evidence, so the
    # deployment names the hosts and a token alone cannot add one (RFC 0007).
    host = (urlparse(inp.base_url).hostname or "").lower() if inp.base_url else ""
    if inp.base_url and host not in allowed_hosts():
        raise ConfigError(
            f"{host or inp.base_url} is not in SHOC_LLM_BASE_URL_ALLOWLIST "
            f"({', '.join(sorted(allowed_hosts()))})"
        )
    row = fetch_one(
        ctx.db,
        "SELECT settings, secret FROM shoc.connector_config WHERE tenant_id=%s AND source='llm'",
        (ctx.tenant_id,),
    )
    settings = dict(row["settings"] or {}) if row else {}
    given = {
        "provider": inp.provider.lower(),
        "model": inp.model,
        "model_cheap": inp.model_cheap,
        "base_url": inp.base_url,
    }
    settings.update({k: given[k] for k in STORED_FIELDS if given[k]})
    for name in (
        "spend_usd_per_day",
        "hunt_tokens_per_day",
        "intel_reports_per_day",
        "intel_tokens_per_day",
    ):
        value = getattr(inp, name)
        if value < 0:
            raise ConfigError(f"{name} cannot be negative")
        if value:
            settings[name] = value
    key = inp.api_key or (
        open_secret(
            ctx.config.master_key, row["secret"], ctx.tenant_id, "connector_config", "llm"
        ).get("api_key", "")
        if row and row["secret"]
        else ""
    )
    execute(
        ctx.db,
        """INSERT INTO shoc.connector_config (tenant_id, source, enabled, settings, secret)
           VALUES (%s, 'llm', true, %s, %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET
               settings = EXCLUDED.settings, secret = EXCLUDED.secret""",
        (
            ctx.tenant_id,
            json.dumps(settings),
            seal(ctx.config.master_key, {"api_key": key}, ctx.tenant_id, "connector_config", "llm")
            if key
            else None,
        ),
    )
    state = _state(ctx)
    return Result(data=state, summary=_said(state) + " The next case picks it up.")
