"""The stores, queries and jobs guidelines (DAT-G1 to DAT-G10) that need no database.

The event-store checks read every statement shoc ships, built by the compiler,
`events.query`, `events.summarize`, `timeline.build` and the detection cycle
with fake stores, as SQLGlot trees. The rest read `shoc/` and the migrations as
syntax trees or text, or drive one function with fakes. Where code breaks a
rule today it is listed in a `KNOWN` dict with the reason: a violation not
listed fails, and so does a listed one that no longer violates, so each list
only shrinks. An `ALLOW` dict lists what the rule leaves out on purpose, and is
held to the code the same way.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import sqlglot
from sqlglot import exp

from shoc.detect import rules as ruleset
from shoc.errors import StoreError
from shoc.store import ocsf, sql
from shoc.store.base import QueryResult, StoreHealth
from tests.support import ROOT

SHOC = ROOT / "shoc"
MIGRATIONS = SHOC / "db" / "migrations"
DIALECTS = sorted(sql.PARAM_STYLE)


# -- helpers ----------------------------------------------------------------
def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _modules(*roots: Path) -> list[Path]:
    out: list[Path] = []
    for root in roots:
        out += [root] if root.suffix == ".py" else sorted(root.rglob("*.py"))
    return out


def _scoped(tree: ast.AST) -> Iterator[tuple[str, ast.AST]]:
    """Every node of a module with the qualified name of the def it sits in."""

    def walk(node: ast.AST, scope: str) -> Iterator[tuple[str, ast.AST]]:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = f"{scope}.{child.name}" if scope else child.name
            yield inner, child
            yield from walk(child, inner)

    return walk(tree, "")


def _defs(tree: ast.AST) -> Iterator[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    for scope, node in _scoped(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield scope, node


def _own(fn: ast.AST) -> Iterator[ast.AST]:
    """The nodes of `fn`, leaving out the functions and classes defined inside it."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _text(node: ast.AST) -> str | None:
    """A string literal's text; an f-string's, with `{}` for each value."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}"
            for v in node.values
        )
    return None


def _strings(tree: ast.AST) -> Iterator[tuple[str, int, str]]:
    """(scope, line, text) of every string and f-string, docstrings and f-string parts aside."""
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    for scope, node in _scoped(tree):
        text = _text(node)
        if text is None or isinstance(parents.get(node), (ast.Expr, ast.JoinedStr)):
            continue
        yield scope, getattr(node, "lineno", 0), text


def _called(node: ast.AST) -> str:
    """The name a call calls: `f` for `f(...)` and `x.f(...)`, else ''."""
    if not isinstance(node, ast.Call):
        return ""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _ratchet(found: Mapping[str, str], listed: Mapping[str, str], rule: str) -> None:
    """`found` (key -> where) must be exactly what `listed` names."""
    new = {k: v for k, v in found.items() if k not in listed}
    assert not new, f"{rule}: " + "; ".join(f"{k} at {v}" for k, v in sorted(new.items()))
    gone = sorted(set(listed) - set(found))
    assert not gone, f"{rule}: no longer found, take out of its list: {gone}"


def _trees() -> dict[str, ast.Module]:
    return {_rel(p): ast.parse(p.read_text(), str(p)) for p in _modules(SHOC)}


TREES = _trees()


# -- the statements shoc sends to the event store ---------------------------
class _Recorder:
    """An event store that answers nothing and keeps what it was asked."""

    def __init__(self, dialect: str = "databricks") -> None:
        self.dialect = dialect
        self.tenant_id = "t1"
        self.sent: list[str] = []

    def query(self, canonical: str, params: Any = None, limit: int = 1000) -> QueryResult:
        self.sent.append(canonical)
        return QueryResult(rows=[])

    def health(self) -> StoreHealth:
        return StoreHealth(dialect=self.dialect)


def _corpus(mp: pytest.MonkeyPatch) -> list[tuple[str, str, str]]:
    """(path:symbol, detail, canonical SQL) for each statement the event store is sent."""
    from shoc.capabilities import events, timeline
    from shoc.cases import own
    from shoc.detect import engine, hunts
    from shoc.detect.compiler import compile_pack, compile_rule, evidence_sql, page_sql

    out: list[tuple[str, str, str]] = []
    rules = ruleset.load()
    for rule in rules:
        c = compile_rule(rule)
        width = len(c.group_exprs)
        scans = [c.select_sql, c.agg_sql, c.buckets_sql, page_sql(c.select_sql, True, 1000)]
        scans += [evidence_sql(c, ["x"] * width), evidence_sql(c, [None] * width)]
        out += [("shoc/detect/compiler.py:compile_rule", rule.id, s) for s in scans if s]
    for pack in hunts.load():
        for accounts in (None, ["123456789012"]):
            compiled = compile_pack(pack, 500, accounts)
            out.append(("shoc/detect/compiler.py:compile_pack", pack.id, compiled.select_sql))

    now = datetime(2026, 10, 12, tzinfo=UTC)
    store = _Recorder()
    ranges = [(r, now - timedelta(hours=1), now) for r in rules]
    engine._unmatched(store, "t1", ranges)  # type: ignore[arg-type]
    out += [("shoc/detect/engine.py:_unmatched", "every rule", s) for s in store.sent]

    asked = [
        events.EventQuery(),
        events.EventQuery(include_raw=True, contains="C:\\Users\\x_1%"),
        events.EventQuery(
            actor="alice",
            src_ip="203.0.113.7",
            class_uid=6003,
            q='GetObject "two words" actor.user.name!=bob api.operation~List '
            "status!~fail severity_id>=3 raw.userIdentity.arn=x",
        ),
        events.EventQuery(event_uids=["e1", "e2"]),
    ]
    for inp in asked:
        canonical = events.build_query(inp, "t1")[0]
        out.append(("shoc/capabilities/events.py:build_query", "", canonical))
    for by in ("time", "actor.user.name", "raw.userIdentity.arn", *sorted(ocsf.JSON_COLUMNS)):
        canonical = events.build_summary(events.SummarizeInput(by=by), "t1")[0]
        out.append(("shoc/capabilities/events.py:build_summary", f"by={by}", canonical))

    store = _Recorder()
    events.by_uid(store, "t1", [f"e{i}" for i in range(300)], include_raw=True)
    own._events(store, "t1", ["e1", "e2", "e1"])
    out += [("shoc/capabilities/events.py:by_uid", "300 uids", s) for s in store.sent]

    cited = [
        {"event_uid": f"e{i}", "time": now + timedelta(minutes=i), "metadata_product": "okta"}
        for i in range(3)
    ]
    entities = [f"{kind}:v{i}" for kind in timeline.PIVOTS for i in range(3)]
    mp.setattr(timeline, "_cited", lambda ctx, case_uid: (cited, entities))
    store = _Recorder()
    ctx: Any = SimpleNamespace(tenant_id="t1", store=store)
    timeline.build.fn(ctx, timeline.BuildInput(case_uid="c1"))
    out += [("shoc/capabilities/timeline.py:build", "", s) for s in store.sent]
    return out


SENDERS = {
    "shoc/detect/compiler.py:compile_rule",
    "shoc/detect/compiler.py:compile_pack",
    "shoc/detect/engine.py:_unmatched",
    "shoc/capabilities/events.py:build_query",
    "shoc/capabilities/events.py:build_summary",
    "shoc/capabilities/events.py:by_uid",
    "shoc/capabilities/timeline.py:build",
}


@pytest.fixture(scope="module")
def corpus() -> list[tuple[str, str, str]]:
    with pytest.MonkeyPatch.context() as mp:
        statements = _corpus(mp)
    assert {key for key, _, _ in statements} == SENDERS, "a sender sent nothing"
    return statements


def _is_json(node: exp.Expression) -> bool:
    return isinstance(node, exp.Star) or (
        isinstance(node, exp.Column) and node.name in ocsf.JSON_COLUMNS
    )


def _json_grouped(tree: exp.Expression) -> list[str]:
    """DISTINCT or GROUP BY over a JSON column, which BigQuery refuses (wh-3)."""
    bad: list[str] = []
    for node in tree.find_all(exp.Distinct):
        values = list(node.expressions)
        if not values and isinstance(node.parent, exp.Select):
            values = [e.unalias() for e in node.parent.expressions]
        bad += [f"DISTINCT {v.sql()}" for v in values if _is_json(v)]
    for node in tree.find_all(exp.Group):
        bad += [f"GROUP BY {v.sql()}" for v in node.expressions if _is_json(v)]
    return bad


def _unescaped(tree: exp.Expression) -> list[str]:
    """A LIKE without `ESCAPE '!'`: Databricks and Postgres read a backslash as one."""
    return [
        node.sql()
        for node in tree.find_all(exp.Like, exp.ILike)
        if not (isinstance(node.parent, exp.Escape) and node.parent.expression.name == "!")
    ]


# What a caller can ask for today that breaks DAT-G1.
KNOWN_DIALECT = {
    "shoc/capabilities/events.py:build_summary": (
        "events.summarize takes `by` raw, unmapped or observables and groups by the JSON "
        "column itself, which BigQuery refuses (wh-3); resolve() should refuse a JSON column"
    ),
}


def test_every_shipped_statement_translates_safely(corpus):
    """DAT-G1: every shipped event-store statement translates, groups no JSON column and
    escapes each LIKE with '!'."""
    found: dict[str, str] = {}
    for key, detail, canonical in corpus:
        for dialect in DIALECTS:
            try:
                sql.translate(canonical, dialect)
            except Exception as exc:
                found.setdefault(key, f"{detail} does not translate to {dialect}: {exc}")
        tree = sqlglot.parse_one(canonical)
        bad = _json_grouped(tree) + _unescaped(tree)
        if bad:
            found.setdefault(key, f"{detail}: {bad[0]}")
    _ratchet(found, KNOWN_DIALECT, "DAT-G1")


# -- DAT-G2: a statement is bound in full and within budget ------------------
# `sql.bind` has no budget guard yet: each caller spreads its values itself.
KNOWN_BUDGET = {
    "shoc/store/sql.py:bind": "no guard past sql.max_params; callers chunk by hand (wh-7)",
}


def test_a_statement_past_the_dialect_budget_is_refused():
    """DAT-G2: a statement past the dialect's parameter budget is refused before the store."""
    over = sql.max_params("databricks") + 1
    params = {f"u{i}": f"e{i}" for i in range(over)}
    canonical = (
        "SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id AND event_uid IN ("
        + ", ".join(f":{k}" for k in params)
        + ")"
    )
    params["tenant_id"] = "t1"
    sql.prepare(canonical, params, "postgres")  # within the budget there
    try:
        sql.prepare(canonical, params, "databricks")
    except StoreError:
        found = {}
    else:
        found = {"shoc/store/sql.py:bind": f"{over + 1} values bound on databricks"}
    _ratchet(found, KNOWN_BUDGET, "DAT-G2")


_PLACEHOLDER = r"%(?:\([a-z_][a-z0-9_]*\))?s"
_BARE = re.compile(_PLACEHOLDER)
_BUILDER = re.compile(r"\b(jsonb_build_object|json_build_object|coalesce)\s*\(", re.I)
_CASE_WORD = re.compile(r"\b(CASE|WHEN|THEN|ELSE|END)\b", re.I)


def _args(text: str, open_at: int) -> list[str]:
    """The top-level arguments of the call whose `(` is at `open_at`."""
    args: list[str] = []
    depth, current = 0, ""
    for ch in text[open_at + 1 :]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
    return [*args, current.strip()]


def _case_branches(text: str) -> list[list[str]]:
    """The THEN and ELSE values of each CASE, nested ones apart."""
    out: list[list[str]] = []
    stack: list[tuple[list[str], str, int]] = []  # (branches, open word, its end)
    for m in _CASE_WORD.finditer(text):
        word = m.group(1).upper()
        if word == "CASE":
            stack.append(([], "", m.end()))
            continue
        if not stack:
            continue
        branches, open_word, start = stack[-1]
        if open_word in ("THEN", "ELSE"):
            branches.append(text[start : m.start()].strip())
        if word == "END":
            out.append(stack.pop()[0])
        else:
            stack[-1] = (branches, word, m.end())
    return out


def _untyped(text: str) -> list[str]:
    """Placeholders whose type nothing around them fixes."""
    out: list[str] = []
    for m in _BUILDER.finditer(text):
        args = _args(text, m.end() - 1)
        name = m.group(1).lower()
        if name == "coalesce":
            if any(_BARE.fullmatch(a) for a in args) and all(
                _BARE.fullmatch(a) or a.upper() == "NULL" for a in args
            ):
                out.append(f"coalesce({', '.join(args)})")
        else:
            out += [f"{name}(... {a} ...)" for a in args if _BARE.fullmatch(a)]
    for branches in _case_branches(text):
        if any(_BARE.fullmatch(b) for b in branches) and all(
            _BARE.fullmatch(b) or b.upper() == "NULL" for b in branches
        ):
            out.append(f"CASE ... {' / '.join(branches)} END")
    return out


# Each works today because the column's own type matches what Postgres guesses.
KNOWN_CASTS = {
    "shoc/cases/engine.py:transition": (
        "closed_by = CASE WHEN %s = 'closed' THEN %s ELSE NULL END resolves to text only "
        "because closed_by is text; write %s::text"
    ),
}


def test_a_parameter_inside_a_json_builder_is_cast():
    """DAT-G2: a control-plane placeholder in jsonb_build_object, or in a coalesce or CASE
    whose every value is a placeholder or NULL, carries a ::type cast."""
    found: dict[str, str] = {}
    for path, tree in TREES.items():
        for scope, line, text in _strings(tree):
            if not _BARE.search(text):
                continue
            bad = _untyped(text)
            if bad:
                found.setdefault(f"{path}:{scope}", f"line {line}: {bad[0]}")
    _ratchet(found, KNOWN_CASTS, "DAT-G2")


# -- DAT-G3: every session has a deadline and is closed ---------------------
POOL_HOMES = {
    "shoc/db/pool.py",
    "shoc/store/postgres.py",
    "shoc/store/redshift.py",
    "shoc/store/snowflake.py",
    "shoc/store/databricks.py",
}
DRIVERS = ("psycopg", "snowflake.connector", "databricks.sql")

# Sessions opened outside the pool on purpose.
ALLOW_SESSIONS = {
    "shoc/worker.py:listen": "a LISTEN session that runs no statement",
    "shoc/api/rest.py:build_app.database_answers": (
        "the readiness probe: SELECT 1 with connect_timeout=2, closed by `with`"
    ),
}
# Poll loops in the BigQuery adapter that need no deadline.
ALLOW_LOOPS = {
    "shoc/store/bigquery.py:BigQueryStore._run:resp.get('pageToken') and len(rows) <= limit": (
        "pages the rows of a job that already finished, at most `limit`"
    ),
}


def _driver_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Names bound to a database driver module, and to a driver's own `connect`."""
    modules: set[str] = {"psycopg"}
    connects: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in DRIVERS or alias.name.startswith("psycopg."):
                    modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            package = node.module.split(".")[0]
            for alias in node.names:
                if f"{node.module}.{alias.name}" in DRIVERS:
                    modules.add(alias.asname or alias.name)
                if package in ("psycopg", "snowflake", "databricks") and alias.name == "connect":
                    connects.add(alias.asname or alias.name)
    return modules, connects


def _root(node: ast.expr) -> ast.expr:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node


def test_sessions_open_only_through_the_pool():
    """DAT-G3: a database session opens only in shoc/db/pool.py or an adapter, and every
    BigQuery poll loop watches a deadline."""
    found: dict[str, str] = {}
    for path, tree in TREES.items():
        if path in POOL_HOMES:
            continue
        modules, connects = _driver_names(tree)
        for scope, node in _scoped(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            driver = isinstance(func, ast.Name) and func.id in connects
            if isinstance(func, ast.Attribute) and func.attr == "connect":
                root = _root(func.value)
                driver = isinstance(root, ast.Name) and root.id in modules
            if driver:
                found.setdefault(f"{path}:{scope}", f"line {node.lineno}: {ast.unparse(func)}")
    _ratchet(found, ALLOW_SESSIONS, "DAT-G3 sessions")

    loops: dict[str, str] = {}
    path = "shoc/store/bigquery.py"
    for scope, node in _scoped(TREES[path]):
        if isinstance(node, ast.While):
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            if not any("deadline" in n for n in names):
                key = f"{path}:{scope}:{ast.unparse(node.test)}"
                loops[key] = f"line {node.lineno}"
    _ratchet(loops, ALLOW_LOOPS, "DAT-G3 deadlines")


class _Closable:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def test_a_job_closes_every_store_it_opens(monkeypatch):
    """DAT-G3: a worker job closes the event store its Context opened, whether it
    finished or raised."""
    from shoc import worker
    from shoc.config import Config

    opened: list[_Closable] = []

    def open_store(*args: Any, **kwargs: Any) -> _Closable:
        opened.append(_Closable())
        return opened[-1]

    def reads(job: dict, config: Any, ctx: Any) -> str:
        assert ctx.store is opened[-1]
        return "ok"

    def raises(job: dict, config: Any, ctx: Any) -> str:
        assert ctx.store is opened[-1]
        raise RuntimeError("the job failed")

    monkeypatch.setattr("shoc.store.open_store", open_store)
    monkeypatch.setattr(worker, "connect", lambda config: None)
    monkeypatch.setattr(worker, "set_tenant", lambda conn, tenant: None)
    job = {"tenant_id": "acme", "kind": "detect.run", "job_id": 1, "payload": {}}
    monkeypatch.setattr(worker, "_handle", reads)
    assert worker.handle(job, Config()) == "ok"
    monkeypatch.setattr(worker, "_handle", raises)
    with pytest.raises(RuntimeError, match="the job failed"):
        worker.handle(job, Config())
    assert [s.closed for s in opened] == [1, 1]


# Stores opened and never closed.
KNOWN_OPEN_STORES = {
    "shoc/cases/actions.py:_gates": "opens one when none is passed in and never closes it",
    "shoc/cases/actions.py:_resolve": "opens one per looked-up field in a loop, never closed",
    "shoc/cli.py:cmd_migrate": "the CLI process ends right after, and the session with it",
}
# Opened stores whose owner closes them elsewhere.
ALLOW_OPEN_STORES = {
    "shoc/capabilities/registry.py:Context.store": (
        "Context.close closes it (tests/unit/test_lifecycle.py)"
    ),
}


def _closes(fn: ast.AST, name: str) -> bool:
    """`name.close()` sits in a `finally` of `fn`."""
    for node in _own(fn):
        if isinstance(node, ast.Try):
            for call in (c for s in node.finalbody for c in ast.walk(s)):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "close"
                    and ast.unparse(call.func.value) == name
                ):
                    return True
    return False


def _returns(fn: ast.AST, name: str) -> bool:
    return any(
        isinstance(n, ast.Return) and n.value is not None and ast.unparse(n.value) == name
        for n in _own(fn)
    )


def _is_property(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(d, ast.Name) and d.id == "property" for d in fn.decorator_list)


def test_every_store_opened_is_closed_where_it_was_opened():
    """DAT-G3: a function that opens an event store closes it in a `finally`, or returns
    it to a caller that does."""
    openers = {"open_store"}
    for _ in range(3):  # a factory of a factory
        for tree in TREES.values():
            for _scope, fn in _defs(tree):
                for node in _own(fn):
                    if not isinstance(node, ast.Assign) or _is_property(fn):
                        continue
                    opens = any(_called(c) in openers for c in ast.walk(node.value))
                    if opens and _returns(fn, ast.unparse(node.targets[0])):
                        openers.add(fn.name)
    found: dict[str, str] = {}
    for path, tree in TREES.items():
        for scope, fn in _defs(tree):
            for node in _own(fn):
                if not isinstance(node, ast.Assign):
                    continue
                if not any(_called(c) in openers for c in ast.walk(node.value)):
                    continue
                name = ast.unparse(node.targets[0])
                if not (_closes(fn, name) or (_returns(fn, name) and not _is_property(fn))):
                    found.setdefault(f"{path}:{scope}", f"line {node.lineno}: {name}")
    _ratchet(found, {**KNOWN_OPEN_STORES, **ALLOW_OPEN_STORES}, "DAT-G3 stores")


# -- DAT-G4: every staged name has a random part ----------------------------
STAGING = _modules(SHOC / "store", SHOC / "ingest", SHOC / "db" / "pool.py")
CLOCKS = {"os.getpid", "threading.get_ident", "socket.gethostname", "time.time", "time.time_ns"}
RANDOM = re.compile(r"\b(?:uuid\.uuid4|uuid4|batch_name|os\.urandom|token_hex|secrets\.\w+)\(")
REPLACES = re.compile(r"\bOVERWRITE\b|\bWRITE_TRUNCATE\b")

ALLOW_STAGED = {
    "shoc/store/postgres.py:PostgresStore._insert": (
        "a TEMP table ON COMMIT DROP lives in its own session and transaction"
    ),
}
KNOWN_STAGED = {
    "shoc/store/databricks.py:DatabricksStore.load_batch": (
        "PUT ... OVERWRITE onto a batch_name() path; without OVERWRITE a collision would "
        "fail instead of replacing a batch (wh-1)"
    ),
}


def _clocked(node: ast.AST) -> bool:
    calls = {ast.unparse(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)}
    return bool(calls & CLOCKS) and not RANDOM.search(ast.unparse(node))


def test_staged_names_carry_a_random_part():
    """DAT-G4: no staged name is built from the time, pid, thread or host alone, and no
    remote object is written with OVERWRITE or WRITE_TRUNCATE."""
    found: dict[str, str] = {}
    for module in STAGING:
        path, tree = _rel(module), TREES[_rel(module)]
        tainted = {
            (scope, target.id)
            for scope, node in _scoped(tree)
            if isinstance(node, ast.Assign) and _clocked(node.value)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for scope, node in _scoped(tree):
            if not isinstance(node, ast.JoinedStr) or RANDOM.search(ast.unparse(node)):
                continue
            names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            if _clocked(node) or any((scope, n) in tainted for n in names):
                found.setdefault(f"{path}:{scope}", f"line {node.lineno}: {ast.unparse(node)}")
        for scope, line, text in _strings(tree):
            if REPLACES.search(text):
                found.setdefault(f"{path}:{scope}", f"line {line}: {text.strip()[:80]}")
    _ratchet(found, {**ALLOW_STAGED, **KNOWN_STAGED}, "DAT-G4")


# -- DAT-G5: every event read filters on the tenant -------------------------
def _conjuncts(node: exp.Expression | None) -> Iterator[exp.Expression]:
    while isinstance(node, exp.Paren):
        node = node.this
    if isinstance(node, exp.And):
        yield from _conjuncts(node.this)
        yield from _conjuncts(node.expression)
    elif node is not None:
        yield node


def _is_tenant_mark(node: exp.Expression) -> bool:
    return isinstance(node, exp.Placeholder) and node.name == "tenant_id"


def _unscoped(tree: exp.Expression) -> list[str]:
    """Each reference to the events table no WHERE or JOIN pins to `:tenant_id`."""
    missing: list[str] = []
    for select in tree.find_all(exp.Select):
        sources = [t for t in select.find_all(exp.Table) if t.find_ancestor(exp.Select) is select]
        events = [t for t in sources if t.name == ocsf.EVENTS_TABLE]
        if not events:
            continue
        only = sources[0].alias_or_name if len(sources) == 1 else ""
        where = select.args.get("where")
        clauses = list(_conjuncts(where.this if where else None))
        for join in select.args.get("joins") or []:
            clauses += list(_conjuncts(join.args.get("on")))
        pinned: set[str] = set()
        links: list[tuple[str, str]] = []
        for clause in clauses:
            if not isinstance(clause, exp.EQ):
                continue
            sides = (clause.this, clause.expression)
            cols = [s for s in sides if isinstance(s, exp.Column) and s.name == "tenant_id"]
            owners = [c.table or only for c in cols]
            if len(cols) == 1 and any(_is_tenant_mark(s) for s in sides):
                pinned.add(owners[0])
            elif len(cols) == 2:
                links.append((owners[0], owners[1]))
        grew = True
        while grew:
            grew = False
            for a, b in links:
                if (a in pinned) != (b in pinned):
                    pinned |= {a, b}
                    grew = True
        missing += [t.alias_or_name for t in events if t.alias_or_name not in pinned]
    return missing


def test_every_events_read_filters_on_the_tenant(corpus):
    """DAT-G5: each reference to ocsf_events, subqueries and joins included, is filtered on
    tenant_id = :tenant_id."""
    found: dict[str, str] = {}
    for key, detail, canonical in corpus:
        loose = _unscoped(sqlglot.parse_one(canonical))
        if loose:
            found.setdefault(key, f"{detail}: {', '.join(loose)} has no tenant filter")
    _ratchet(found, {}, "DAT-G5")


def test_every_load_goes_through_the_batch():
    """DAT-G5: only shoc.ingest.batch.load hands a batch to a store, after its tenant check."""
    found: dict[str, str] = {}
    for path, tree in TREES.items():
        for scope, node in _scoped(tree):
            if _called(node) == "load_batch" and path != "shoc/ingest/batch.py":
                found.setdefault(f"{path}:{scope}", f"line {getattr(node, 'lineno', 0)}")
    _ratchet(found, {}, "DAT-G5 loads")


# -- DAT-G6: every job kind has a tier --------------------------------------
# The kinds `jobs.TIER` leaves at 2: model work and housekeeping that may wait
# behind a page, a detection cycle or a playbook.
ROUTINE = frozenset(
    {
        "graph.refresh",
        "posture.survey",
        "detection.backlog",
        "hunt.daily",
        "ops.check",
        "case.sweep",
        "unattended",
        "intel.refresh",
        "source.onboard",
        "retention",
        "case.recheck",
        "report.weekly",
        "report.exec",
        "report.exception",
    }
)


def _tiers(tier_sql: str) -> dict[str, int]:
    """{kind: tier} for each kind `jobs.TIER` names."""
    out: dict[str, int] = {}
    for m in re.finditer(r"\bWHEN\b(?P<branch>.*?)\bTHEN\s+(?P<tier>\d)", tier_sql, re.S):
        branch, tier = m.group("branch"), int(m.group("tier"))
        for listed in re.findall(r"q\.kind\s+IN\s*\(([^)]*)\)", branch):
            for kind in re.findall(r"'([^']+)'", listed):
                out.setdefault(kind, tier)
        for kind in re.findall(r"q\.kind\s*=\s*'([^']+)'", branch):
            out.setdefault(kind, tier)
    return out


def test_every_job_kind_has_a_tier():
    """DAT-G6: each job kind the worker handles has a deliberate place in jobs.TIER, with
    pages, approved actions and webhooks first and detection, syncs and playbooks next."""
    from shoc.db import jobs
    from shoc.worker import JOB_CAPABILITIES

    tiers = _tiers(jobs.TIER)
    handled = set(JOB_CAPABILITIES)
    assert set(tiers) <= handled, f"TIER names unhandled kinds: {sorted(set(tiers) - handled)}"
    assert not set(tiers) & ROUTINE, f"listed twice: {sorted(set(tiers) & ROUTINE)}"
    unplaced = handled - set(tiers) - ROUTINE
    assert not unplaced, f"give these a tier in jobs.TIER or add them to ROUTINE: {unplaced}"
    stale = ROUTINE - handled
    assert not stale, f"ROUTINE names kinds the worker no longer handles: {sorted(stale)}"
    first = {k for k, t in tiers.items() if t == 0}
    second = {k for k, t in tiers.items() if t == 1}
    assert {"manager.deliver", "action.run", "stream.deliver"} <= first
    assert {"detect.run", "source.sync", "playbook.run", "playbook.resume"} <= second
    assert "case.investigate" in second, "a high or critical case's crew run is tier 1"
    assert jobs.URGENT == 1


# Calls whose kind is not a literal, and where their kinds come from.
INDIRECT_KINDS = {
    "shoc/cases/engine.py:wake": "engine.WAKES",
    "shoc/db/jobs.py:tick": "the schedules, queued by the upsert_schedule calls",
}


def test_every_queued_job_kind_is_handled():
    """DAT-G6: every kind shoc queues or schedules is one the worker handles."""
    from shoc.cases import engine
    from shoc.worker import JOB_CAPABILITIES

    queued: dict[str, str] = {}
    indirect: dict[str, str] = {}
    for path, tree in TREES.items():
        for scope, node in _scoped(tree):
            name = _called(node)
            if not isinstance(node, ast.Call) or name not in ("enqueue", "upsert_schedule"):
                continue
            at = 2 if name == "enqueue" else 3
            keywords = {k.arg: k.value for k in node.keywords}
            arg = node.args[at] if len(node.args) > at else keywords.get("kind")
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                queued.setdefault(arg.value, f"{path}:{node.lineno}")
            else:
                indirect.setdefault(f"{path}:{scope}", f"line {node.lineno}")
    _ratchet(indirect, INDIRECT_KINDS, "DAT-G6 indirect kinds")
    for wakes in engine.WAKES.values():
        for kind, _seconds in wakes:
            queued.setdefault(kind, "shoc/cases/engine.py:WAKES")
    unhandled = {k: v for k, v in queued.items() if k not in JOB_CAPABILITIES}
    assert not unhandled, f"DAT-G6: queued but not in worker.JOB_CAPABILITIES: {unhandled}"


# -- DAT-G7: a job leaves `running` only through jobs.py ---------------------
_UPDATE_JOBS = re.compile(
    r"\bUPDATE\s+shoc\.jobs\b.*?\bSET\b(?P<set>.*?)(?:\bWHERE\b|\bFROM\b|\bRETURNING\b|$)",
    re.I | re.S,
)
_SETS_STATE = re.compile(r"(?:^|,)\s*state\s*=", re.I)
_DELETE_JOBS = re.compile(r"\bDELETE\s+FROM\s+shoc\.jobs\b(?P<rest>[^;]*)", re.I | re.S)


def _job_writes(text: str) -> list[str]:
    bad: list[str] = []
    for m in _UPDATE_JOBS.finditer(text):
        if _SETS_STATE.search(m.group("set")):
            bad.append("UPDATE shoc.jobs SET state")
    for m in _DELETE_JOBS.finditer(text):
        if not re.search(r"\bstate\s*=\s*'pending'", m.group("rest"), re.I):
            bad.append("DELETE FROM shoc.jobs of a job that may be running")
    return bad


def test_jobs_change_state_only_in_jobs_py():
    """DAT-G7: only shoc/db/jobs.py moves a job between states, so every failure counts an
    attempt, and nothing else deletes a job that may be running."""
    from shoc.worker import PRUNE

    found: dict[str, str] = {}
    for path, tree in TREES.items():
        for scope, line, text in _strings(tree):
            bad = [b for b in _job_writes(text) if path != "shoc/db/jobs.py" or "DELETE" in b]
            if bad:
                found.setdefault(f"{path}:{scope}", f"line {line}: {bad[0]}")
    for migration in sorted(MIGRATIONS.glob("*.sql")):
        bad = _job_writes(re.sub(r"--[^\n]*", "", migration.read_text()))
        if bad:
            found.setdefault(_rel(migration), bad[0])
    _ratchet(found, {}, "DAT-G7")
    assert "'running'" not in PRUNE["jobs"], "the nightly prune deletes a running job"


# -- DAT-G8: every table has a retention ------------------------------------
# Tables a write path keeps bounded itself, and the file that deletes from it.
PRUNED_WHERE_WRITTEN = {
    "iocs": "shoc/detect/intel.py",
    "intel_queue": "shoc/capabilities/intel.py",
    "push_deliveries": "shoc/api/ingest.py",
    "own_token_requests": "shoc/cases/own.py",
    "store_loads": "shoc/ingest/batch.py",
    "exposures": "shoc/agents/surveyor.py",
    "snapshots": "shoc/ingest/connectors/base.py",
}
# Tables kept for good, and why. worker.KEPT does not exist yet; this is its list.
KEPT = {
    "tenants": "configuration",
    "connector_config": "configuration",
    "connector_state": "configuration: one cursor row per source",
    "schedules": "configuration",
    "rule_state": "configuration: one row per rule",
    "webhooks": "configuration",
    "intel_feeds": "configuration",
    "suppressions": "configuration: each carries its own expiry",
    "hunt_packs": "configuration: one row per pack",
    "merged_rules": "configuration: merged content",
    "merged_hunts": "configuration: merged content",
    "merged_playbooks": "configuration: merged content",
    "source_onboarding": "configuration: one row per source",
    "mapping_overrides": "configuration",
    "own_identities": "configuration",
    "source_history": "configuration: kept when a source is removed, so learning holds",
    "sso_providers": "configuration",
    "store_reads": "one row per kept read, replaced in place",
    "action_credentials": "credential",
    "lookup_sources": "credential",
    "api_tokens": "credential: revoked, never deleted (migration 027)",
    "users": "people: disabled, never deleted (migration 039)",
    "user_links": "credential: ends by use or expiry, never deleted (migration 039)",
    "findings": "incident record",
    "cases": "incident record",
    "case_entities": "incident record",
    "case_routing": "incident record: where each closure went",
    "openspace_messages": "incident record: the crew's case discussion",
    "actions": "incident record",
    "playbook_runs": "incident record",
    "playbook_steps": "incident record",
    "hunts": "incident record: an indicator retro-hunt and the findings it raised",
    "hunt_runs": "incident record: why each pack ran, which coverage debt reads",
    "reports": "incident record: what shoc told the operator",
    "rule_proposals": "decision record",
    "detection_backlog": "decision record",
    "hunt_backlog": "decision record",
    "audit_log": "audit chain",
    "audit_key": "audit chain",
    "audit_epochs": "audit chain",
    "audit_checkpoints": "audit chain",
    "notices": "told-once guard: the page gate reads it to send one page per incident",
    "intel_reports": "told-once guard: raw_sha256 keeps a report from being read twice",
    "llm_spend": "cost record: one row per day and model, no personal data",
    "lookup_usage": "quota counter: one row per source and day, no personal data",
    "posture_snapshots": "daily counts and gaps, no personal data",
    "rehearsals": "unread since migration 018, and migrations never drop a table",
}


def _tables() -> set[str]:
    """Every table the migrations leave in the shoc schema."""
    tables: set[str] = set()
    for migration in sorted(MIGRATIONS.glob("*.sql")):
        text = re.sub(r"--[^\n]*", "", migration.read_text())
        tables |= set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?shoc\.(\w+)", text, re.I))
        for old, new in re.findall(
            r"ALTER TABLE (?:IF EXISTS )?shoc\.(\w+) RENAME TO (\w+)", text, re.I
        ):
            tables = (tables - {old}) | {new}
        tables -= set(re.findall(r"DROP TABLE (?:IF EXISTS )?shoc\.(\w+)", text, re.I))
    return tables


def test_every_table_has_a_retention():
    """DAT-G8: every table the migrations create is pruned nightly, pruned where it is
    written, or kept for a stated reason."""
    from shoc.worker import PRUNE

    tables = _tables()
    classified = [set(PRUNE), set(PRUNED_WHERE_WRITTEN), set(KEPT)]
    for i, a in enumerate(classified):
        for b in classified[i + 1 :]:
            assert not a & b, f"classified twice: {sorted(a & b)}"
    every = set().union(*classified)
    assert not tables - every, f"give these a retention or a reason: {sorted(tables - every)}"
    assert not every - tables, f"no migration creates: {sorted(every - tables)}"
    assert all(KEPT.values())
    for table, path in PRUNED_WHERE_WRITTEN.items():
        assert f"DELETE FROM shoc.{table}" in (ROOT / path).read_text(), f"{path} keeps {table}"


# Idempotency-key prefixes a purge may forget: each carries the job id or the
# time bucket it was queued for, so a purged key cannot let the effect repeat.
PURGEABLE_KEYS = {
    "sweep": "sweep:after:<job id>, one per finished job",
    "onboard": "onboard:<source>:<hour> and onboard:drift:<day>",
    "resume": "resume:<run>:<minute>",
    "wake": "wake:<tenant>:<kind>:<due time>",
    "<schedule>": "<schedule id>@<run time>, from jobs.tick",
}
# Keys that are not a literal, and the prefixes they carry.
INDIRECT_KEYS = {
    "shoc/cases/playbooks.py:_wait": ("timer", "retry"),
    "shoc/worker.py:_start_playbooks": ("playbook",),
    "shoc/db/jobs.py:tick": ("<schedule>",),
}


def _prefix(node: ast.expr) -> str | None:
    """The `prefix` of an f"prefix:..." key, or None when it cannot be read."""
    while isinstance(node, ast.BinOp):
        node = node.left
    text = _text(node)
    if text is None or ":" not in text.split("{}", 1)[0]:
        return None
    return text.split(":", 1)[0]


def test_every_idempotency_prefix_is_classified():
    """DAT-G8: each idempotency-key prefix shoc queues is a guard the jobs purge keeps
    (worker.GUARD_KEYS) or one it may forget (PURGEABLE_KEYS)."""
    from shoc.worker import GUARD_KEYS

    used: dict[str, str] = {}
    indirect: dict[str, str] = {}
    for path, tree in TREES.items():
        for scope, node in _scoped(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "idempotency_key":
                    continue
                prefix = _prefix(keyword.value)
                if prefix is None:
                    indirect.setdefault(f"{path}:{scope}", f"line {node.lineno}")
                else:
                    used.setdefault(prefix, f"{path}:{node.lineno}")
    _ratchet(indirect, {k: ", ".join(v) for k, v in INDIRECT_KEYS.items()}, "DAT-G8 keys")
    for site, prefixes in INDIRECT_KEYS.items():
        for prefix in prefixes:
            used.setdefault(prefix, site)
    guards = {g.split(":", 1)[0] for g in GUARD_KEYS}
    purgeable = set(PURGEABLE_KEYS)
    assert not guards & purgeable, f"both kept and purgeable: {sorted(guards & purgeable)}"
    loose = {p: at for p, at in used.items() if p not in guards | purgeable}
    assert not loose, f"DAT-G8: add to worker.GUARD_KEYS or PURGEABLE_KEYS: {loose}"
    stale = purgeable - set(used)
    assert not stale, f"PURGEABLE_KEYS names prefixes nothing queues: {sorted(stale)}"


# -- DAT-G10: warehouse layout follows the ingestion-time read --------------
KNOWN_LAYOUT = {
    "redshift": (
        'SORTKEY ("time"): a cycle reads by ingested_at, so its zone maps prune little '
        "(wh-6); amend D131 with the change"
    ),
}
_KEYS = re.compile(r"\b(?:PARTITION BY|CLUSTER BY|SORTKEY|DISTKEY)\b", re.I)


def _warehouse_statements(monkeypatch) -> dict[str, list[str]]:
    """What each warehouse adapter sends to create and migrate its events table."""
    from shoc.store.bigquery import BigQueryStore
    from shoc.store.databricks import DatabricksStore
    from shoc.store.redshift import RedshiftStore
    from shoc.store.snowflake import SnowflakeStore

    sent: dict[str, list[str]] = {}

    bigquery = BigQueryStore("proj", {"k": "v"}, "acme", "shoc_acme")

    def call(method: str, url: str, **kwargs: Any) -> httpx.Response:
        sent.setdefault("bigquery", []).append((kwargs.get("json") or {}).get("query", ""))
        return httpx.Response(200, json={"jobReference": {"jobId": "j1"}, "jobComplete": True})

    monkeypatch.setattr(bigquery, "_call", call)
    bigquery.create_tenant()

    databricks = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")

    def dbx(statement: str, params: Any = None) -> list[dict[str, Any]]:
        sent.setdefault("databricks", []).append(statement)
        if statement.startswith("DESCRIBE"):
            return [{"col_name": n} for n, _ in ocsf.COLUMNS]
        return []

    monkeypatch.setattr(databricks, "_execute", dbx)
    databricks.migrate()

    snowflake = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME")
    monkeypatch.setattr(
        snowflake, "_execute", lambda s, p=None: sent.setdefault("snowflake", []).append(s) or []
    )
    snowflake.create_tenant()

    redshift = RedshiftStore("postgresql://u@h/db", "acme", "t_acme")
    monkeypatch.setattr(
        redshift,
        "_execute",
        lambda s, p=None: sent.setdefault("redshift", []).append(s) or ([], 0),
    )
    redshift.create_tenant()
    return sent


def test_each_warehouse_prunes_on_ingested_at(monkeypatch):
    """DAT-G10: each warehouse events table that declares a key prunes on ingested_at, by
    key or by kept statistics, and no key holds the constant tenant_id."""
    sent = _warehouse_statements(monkeypatch)
    assert set(sent) == {"bigquery", "databricks", "redshift", "snowflake"}
    found: dict[str, str] = {}
    for warehouse, statements in sent.items():
        tables = [s for s in statements if "CREATE TABLE" in s and ocsf.EVENTS_TABLE in s.lower()]
        assert len(tables) == 1, f"{warehouse} creates its events table once"
        layout = tables[0].rsplit("\n)", 1)[-1].lower()
        stats = " ".join(s.lower() for s in statements if "dataSkippingStatsColumns" in s)
        if "tenant_id" in layout:
            found[warehouse] = f"a key holds tenant_id: {layout.strip()}"
        elif _KEYS.search(layout) and "ingested_at" not in layout + stats:
            found[warehouse] = f"keyed without ingested_at: {layout.strip()}"
    _ratchet(found, KNOWN_LAYOUT, "DAT-G10")
