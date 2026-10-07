"""The capability registry (API-1).

Every operation shoc can perform is declared once here, with a typed input and
output, a scope, the principals allowed to call it and an autonomy level. REST
routes, the OpenAPI document, MCP tools, CLI commands and (later) Slack
callbacks are generated from these declarations — nothing is hand-written per
surface, and nothing bypasses the checks in `Capability.invoke`.
"""

from __future__ import annotations

import dataclasses
import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from shoc.errors import Denied, NotFound, ShocError
from shoc.jsonschema import coerce_dataclass, dataclass_schema, to_json

Principal = Literal["human", "agent", "external_agent", "service"]
Autonomy = Literal["L0", "L1", "L2"]


@dataclass
class Result:
    """The AI-first answer envelope: machine data, a short summary, citations.

    `citations` holds event UIDs (or other stable record IDs) that back the
    answer. Principle 6 — evidence or nothing — is enforced by the callers that
    produce verdicts: an uncited verdict is downgraded, never published.
    """

    data: Any
    summary: str = ""
    citations: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "data": to_json(self.data),
            "summary": self.summary,
            "citations": [str(c) for c in self.citations],
        }


@dataclass
class Caller:
    """Who is calling. Scopes are checked against the capability's `scope`."""

    kind: Principal = "human"
    id: str = "local"
    scopes: tuple[str, ...] = ("*",)

    def allows(self, scope: str) -> bool:
        if "*" in self.scopes:
            return True
        if scope in self.scopes:
            return True
        area, _, verb = scope.partition(":")
        return f"{area}:*" in self.scopes or f"*:{verb}" in self.scopes


@dataclass
class Context:
    """Everything a capability body is allowed to reach."""

    tenant_id: str
    caller: Caller
    config: Any = None
    _db: Any = None
    _store: Any = None

    def __post_init__(self) -> None:
        from shoc.db.pool import ALL_TENANTS

        # Row-level security reads `shoc:all` as every tenant (migration 026).
        # Only operational sessions set it, directly and never through a
        # Context, so a caller who names it in X-Shoc-Tenant is refused.
        if self.tenant_id == ALL_TENANTS:
            raise Denied(f"'{ALL_TENANTS}' is not a tenant")

    @property
    def db(self):
        if self._db is None:
            from shoc.db.pool import connect

            # The connection is per thread and outlives this Context, so it may
            # still carry the previous caller's tenant: pin it before first use.
            self._db = connect(self.config)
            self.scope_connection()
        return self._db

    def scope_connection(self) -> None:
        """Pin this connection to this tenant for row-level security (SEC-1).

        Called on every capability invocation and when `db` first opens, so
        whichever comes first scopes the connection the body will use. A
        capability that never touches the database does not open one.
        """
        from shoc.db.pool import set_tenant

        if self._db is not None:
            set_tenant(self._db, self.tenant_id)

    @property
    def store(self):
        if self._store is None:
            from shoc.store import open_store

            self._store = open_store(self.config, self.tenant_id, readonly=self.reads_only)
        return self._store

    @property
    def reads_only(self) -> bool:
        """Agents read through the read-only role when one is configured (SEC-1)."""
        return self.caller.kind in ("agent", "external_agent")


@dataclass(frozen=True)
class Capability:
    name: str
    summary: str
    input: type
    output: type
    scope: str
    fn: Callable[[Context, Any], Result]
    principals: tuple[Principal, ...] = ("human", "agent", "external_agent", "service")
    autonomy: Autonomy = "L0"
    audit: bool = False
    tags: tuple[str, ...] = ()

    @property
    def area(self) -> str:
        return self.name.split(".", 1)[0]

    @property
    def rest_path(self) -> str:
        """`events.query` -> `/v1/events/query`."""
        return "/v1/" + self.name.replace(".", "/")

    @property
    def mcp_name(self) -> str:
        """`events.query` -> `events_query` (MCP tool names are identifiers)."""
        return self.name.replace(".", "_")

    @property
    def cli_words(self) -> list[str]:
        return self.name.split(".")

    def input_schema(self) -> dict[str, Any]:
        return dataclass_schema(self.input)

    def output_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "data": dataclass_schema(self.output)
                if dataclasses.is_dataclass(self.output)
                else {},
                "summary": {"type": "string"},
                "citations": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["data", "summary", "citations"],
        }

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "scope": self.scope,
            "autonomy": self.autonomy,
            "principals": list(self.principals),
            "audit": self.audit,
            "tags": list(self.tags),
            "rest": {"method": "POST", "path": self.rest_path},
            "mcp_tool": self.mcp_name,
            "cli": "shoc " + " ".join(self.cli_words),
            "input_schema": self.input_schema(),
            "output_schema": self.output_schema(),
        }

    def check(self, caller: Caller) -> None:
        """The one permission rule: principal -> scope -> autonomy. Every surface asks here."""
        if caller.kind not in self.principals:
            raise Denied(f"{self.name}: principal '{caller.kind}' may not call this capability")
        if not caller.allows(self.scope):
            raise Denied(f"{self.name}: caller lacks scope '{self.scope}'")
        if self.autonomy == "L2" and caller.kind != "human":
            # D8: an L2 capability needs a human principal, never an agent.
            raise Denied(f"{self.name}: L2 capabilities require a human principal")

    def permits(self, caller: Caller) -> bool:
        try:
            self.check(caller)
        except Denied:
            return False
        return True

    def invoke(self, ctx: Context, payload: dict[str, Any] | Any) -> Result:
        """The one call path: permission check -> validate -> audit."""
        self.check(ctx.caller)
        inp = coerce_dataclass(self.input, payload)
        ctx.scope_connection()
        if not self.audit:
            return self.fn(ctx, inp)
        from shoc.db.audit import record

        try:
            result = self.fn(ctx, inp)
        except ShocError as exc:
            record(ctx, self.name, inp, error=str(exc))
            raise
        record(ctx, self.name, inp, result=result)
        return result


_REGISTRY: dict[str, Capability] = {}


def capability(
    *,
    name: str,
    summary: str,
    input: type,
    output: type,
    scope: str,
    principals: tuple[Principal, ...] = ("human", "agent", "external_agent", "service"),
    autonomy: Autonomy = "L0",
    audit: bool = False,
    tags: tuple[str, ...] = (),
) -> Callable[[Callable[[Context, Any], Result]], Capability]:
    def wrap(fn: Callable[[Context, Any], Result]) -> Capability:
        cap = Capability(
            name=name,
            summary=summary,
            input=input,
            output=output,
            scope=scope,
            fn=fn,
            principals=principals,
            autonomy=autonomy,
            audit=audit,
            tags=tags,
        )
        if name in _REGISTRY:
            raise RuntimeError(f"duplicate capability '{name}'")
        _REGISTRY[name] = cap
        return cap

    return wrap


_loaded = False


def load() -> dict[str, Capability]:
    """Import every module in `shoc.capabilities` so decorators run."""
    global _loaded
    if not _loaded:
        import shoc.capabilities as pkg

        for mod in pkgutil.iter_modules(pkg.__path__):
            if not mod.name.startswith("_") and mod.name != "registry":
                importlib.import_module(f"{pkg.__name__}.{mod.name}")
        _loaded = True
    return _REGISTRY


def all_capabilities() -> list[Capability]:
    return sorted(load().values(), key=lambda c: c.name)


def get(name: str) -> Capability:
    caps = load()
    if name not in caps:
        raise NotFound(f"unknown capability '{name}'")
    return caps[name]


def call(name: str, ctx: Context, payload: dict[str, Any]) -> Result:
    return get(name).invoke(ctx, payload)
