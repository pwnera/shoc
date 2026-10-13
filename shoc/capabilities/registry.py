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
import logging
import pkgutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from shoc.errors import Denied, NotFound, ShocError
from shoc.jsonschema import coerce_dataclass, dataclass_schema, to_json

log = logging.getLogger("shoc.registry")

Principal = Literal["human", "agent", "external_agent", "service"]
Autonomy = Literal["L0", "L1", "L2"]

# Reads that return events, cases or what the crew remembers about people:
# audited when a token calls them (`Capability.audits_read`).
AUDITED_READS = frozenset(
    {"events.query", "search", "timeline.build", "case.get", "finding.get", "memory.search"}
)

# A caller refused the same capability again within this many seconds leaves
# no second row: a page polling what its role may not read would fill the chain.
REFUSAL_EVERY_SECONDS = 60.0
# (tenant, principal, capability) -> when its refusal was last audited, in this process.
_refused: dict[tuple[str, str, str], float] = {}


def _first_refusal(ctx: Context, name: str) -> bool:
    """Whether this refusal is the first of its kind in REFUSAL_EVERY_SECONDS."""
    key = (ctx.tenant_id, f"{ctx.caller.kind}:{ctx.caller.id}", name)
    now = time.monotonic()
    if now - _refused.get(key, float("-inf")) < REFUSAL_EVERY_SECONDS:
        return False
    if len(_refused) > 10_000:
        _refused.clear()
    _refused[key] = now
    return True


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
    _opened_store: bool = field(default=False, init=False, repr=False)

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
            self._opened_store = True
        return self._store

    def close(self) -> None:
        """Close the event store this Context opened (STO-4).

        Called where a Context is made and owned: the end of a REST, MCP or
        Slack request and of a worker job. Never inside `Capability.invoke`,
        since capabilities call each other on one Context. A store handed in
        as `_store` belongs to whoever handed it in.
        """
        if self._opened_store:
            store, self._store, self._opened_store = self._store, None, False
            # A session close lost on a network blip must not turn a finished
            # call into a failure: a REST 500 after a committed write, or a
            # worker job retried that already took effect.
            try:
                store.close()
            except Exception as exc:
                log.warning("could not close the event store: %s", exc)

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

    def audits_read(self, caller: Caller, inp: Any) -> bool:
        """Whether this read of people's data leaves an audit row (SEC-1).

        A token's reads do, and a person's bulk or raw read of events. The
        crew's reads do not: they run on the read-only role and the case's
        openspace already holds them. Nor a person's console views, which
        would write a row on every click.
        """
        if self.audit or self.name not in AUDITED_READS or caller.kind == "agent":
            return False
        if caller.kind in ("external_agent", "service"):
            return True
        raw = bool(getattr(inp, "include_raw", False))
        return self.name == "events.query" and (raw or getattr(inp, "limit", 0) > 100)

    def invoke(self, ctx: Context, payload: dict[str, Any] | Any) -> Result:
        """The one call path: permission check -> validate -> audit."""
        from shoc.db.audit import record

        ctx.scope_connection()
        try:
            self.check(ctx.caller)
        except Denied as exc:
            # A refusal is how a stolen token or a probe shows. The caller has
            # authenticated already, so nobody can flood the chain anonymously.
            try:
                if _first_refusal(ctx, self.name):
                    record(ctx, self.name, payload, error=str(exc))
            except Exception:
                log.warning("could not audit a refused call to %s", self.name, exc_info=True)
            raise
        inp = coerce_dataclass(self.input, payload)
        if self.audits_read(ctx.caller, inp):
            result = self.fn(ctx, inp)
            record(ctx, self.name, inp)  # the filters, never the rows read
            return result
        if not self.audit:
            return self.fn(ctx, inp)

        # An L2 or security change commits with its audit row or not at all. A
        # call that acts on a vendor is left out: what it did there cannot be
        # rolled back, so the row that records it must not be either. Mail a
        # capability sends (user.invite, user.reset) leaves before the commit:
        # if the row then fails, the link it carries was never stored and opens nothing.
        acts = self.scope in ("actions:run", "playbooks:run")
        together = (self.autonomy == "L2" or "security" in self.tags) and not acts
        try:
            if together:
                with ctx.db.transaction():
                    result = self.fn(ctx, inp)
                    record(ctx, self.name, inp, result=result)
                return result
            result = self.fn(ctx, inp)
        except Exception as exc:
            # Any other exception's message may hold data; its class says what failed.
            said = str(exc) if isinstance(exc, ShocError) else type(exc).__name__
            record(ctx, self.name, inp, error=said)
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
