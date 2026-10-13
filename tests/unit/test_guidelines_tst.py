"""Checks for the tests-and-simplicity guidelines (TST-G1 to TST-G7) that need no database.

Each walks the tree as text or as an AST. Code that breaks a rule today is listed
in a KNOWN map with why; a new break fails, and so does a KNOWN entry that no
longer breaks the rule, so each map only shrinks.
"""

from __future__ import annotations

import ast
import inspect
import itertools
import json
import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from functools import cache
from pathlib import Path
from typing import Any, TypeGuard

import pytest

from shoc.detect import rules as ruleset
from shoc.ingest.replay import DAY_OFFSET_KEY, expand
from tests.support import FIXTURES, ROOT, load_fixture

SHOC = ROOT / "shoc"
TESTS = ROOT / "tests"
SCENARIOS = ROOT / "evals" / "scenarios"

Found = dict[str, list[str]]


@cache
def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _walk(tree: ast.AST) -> Iterator[tuple[str, ast.AST, tuple[ast.AST, ...]]]:
    """Every node, with the dotted name of the def it sits in and the nodes above it."""

    def visit(node: ast.AST, names: tuple[str, ...], above: tuple[ast.AST, ...]):
        for child in ast.iter_child_nodes(node):
            inner = names
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                inner = (*names, child.name)
            yield ".".join(inner) or "<module>", child, above
            yield from visit(child, inner, (*above, child))

    yield from visit(tree, (), ())


def _enclosing(above: tuple[ast.AST, ...]) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    defs = [a for a in above if isinstance(a, ast.FunctionDef | ast.AsyncFunctionDef)]
    return defs[-1] if defs else None


def _is_call(node: ast.AST, owner: str, name: str) -> TypeGuard[ast.Call]:
    """`owner.name(...)`."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == name
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == owner
    )


def _known(by_file: dict[str, dict[str, str]]) -> dict[str, str]:
    """A KNOWN map keyed `path:def`, written file by file."""
    return {f"{path}:{name}": why for path, names in by_file.items() for name, why in names.items()}


def _ratchet(found: Found, known: dict[str, str], what: str) -> None:
    """Fail on a break KNOWN does not list, and on a KNOWN entry that is fixed."""
    new = {k: v for k, v in found.items() if k not in known}
    assert not new, f"{what}:\n" + "\n".join(f"  {k} ({', '.join(v)})" for k, v in new.items())
    fixed = sorted(set(known) - set(found))
    assert not fixed, f"these no longer break the rule; take them out of KNOWN: {fixed}"


# -- TST-G1: fixture order is stated in time ---------------------------------
RULES = ruleset.load()
SEQUENCES = [r for r in RULES if r.detection.sequence]
# `expand` stamps a file's records this many seconds apart, the first nearest now.
SPREAD = int(inspect.signature(expand).parameters["spread_seconds"].default)

_BY_POSITION = "the file's order says which event came first; give each record a _day_offset"
KNOWN_UNORDERED = dict.fromkeys(
    [
        "anthropic_admin_added_then_admin_key",
        "aws_bedrock_models_listed_then_invoked",
        "aws_federation_token_used",
        "aws_ses_identity_verified_then_deleted",
        "aws_ssm_parameters_listed_then_decrypted",
        "entra_device_registered_after_device_code",
        "entra_mfa_registered_after_risky_sign_in",
        "entra_sign_in_after_mfa_denial",
        "google_sign_in_after_prompt_denial",
        "okta_push_approved_after_denial",
        "okta_sign_in_after_attack_from_address",
    ],
    _BY_POSITION,
)


def _unordered(rule_id: str) -> list[str]:
    """Records whose place in time a sequence fixture leaves to file position."""
    out: list[str] = []
    for kind in ("positive", "negative"):
        offsets: set[float] = set()
        for index, record in enumerate(load_fixture(rule_id, kind)):
            if DAY_OFFSET_KEY in record:
                offsets.add(float(record[DAY_OFFSET_KEY]))
            else:
                out.append(f"{kind}.json record {index} has no {DAY_OFFSET_KEY}")
        steps = sorted(offsets)
        out += [
            f"{kind}.json offsets {a} and {b} are within the {SPREAD} s replay spread"
            for a, b in itertools.pairwise(steps)
            if (b - a) * 86400 <= SPREAD
        ]
    return out


def test_known_unordered_lists_only_sequence_rules():
    """TST-G1: KNOWN_UNORDERED names sequence rules only."""
    assert not set(KNOWN_UNORDERED) - {r.id for r in SEQUENCES}


@pytest.mark.parametrize("rule", SEQUENCES, ids=lambda r: r.id)
def test_a_sequence_fixture_states_its_order(rule):
    """TST-G1: every record of a sequence rule's fixtures carries its own _day_offset.

    Replay stamps the first record of a file latest, and a vendor timestamp falls
    outside the detect window, so only an offset more than the replay spread
    apart says which event came first.
    """
    problems = _unordered(rule.id)
    if rule.id in KNOWN_UNORDERED:
        assert problems, f"{rule.id} states its order now; take it out of KNOWN_UNORDERED"
    else:
        assert not problems, f"tests/fixtures/rules/{rule.id}: " + "; ".join(problems)


# -- TST-G2: fakes keep the real signature, threads are waited on ------------
def _polls(above: tuple[ast.AST, ...]) -> bool:
    """Is the nearest loop around this node, inside its def, a `while`?"""
    for node in reversed(above):
        if isinstance(node, ast.While):
            return True
        if isinstance(node, ast.For | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            return False
    return False


def _fixed_sleeps() -> Found:
    found: Found = defaultdict(list)
    for path in sorted(TESTS.rglob("*.py")):
        for name, node, above in _walk(_parse(path)):
            if _is_call(node, "time", "sleep") and not _polls(above):
                found[f"{_rel(path)}:{name}"].append(f"line {node.lineno}")
    return found


_STARTED = "gives the queued resets time to start before it counts them"
_BLOCKED = "proves the second writer waits; nothing signals a wait that has not ended"
_CLOCK = "lets the clock move so a new window would differ from the first"
_STALL = "the fake gateway stalls for real so the client's read timeout fires"
_TICK = "waits a second so each tick's job would have a key of its own"
KNOWN_SLEEPS = _known(
    {
        "tests/unit/test_signin_guards.py": {
            "test_forgotten_passwords_are_handled_two_at_a_time": _STARTED,
        },
        "tests/unit/test_audit.py": {
            "test_concurrent_appends_do_not_fork_the_chain": _BLOCKED,
        },
        "tests/unit/test_connectors.py": {
            "test_sentinelone_alert_pages_keep_the_window_they_were_issued_for": _CLOCK,
        },
        "tests/conformance/test_pages.py": {
            "test_a_slow_model_does_not_hold_the_page.stalled": _STALL,
        },
        "tests/conformance/test_worker.py": {
            "test_a_schedule_queues_nothing_while_its_last_job_waits.due_again": _TICK,
        },
    }
)


def test_no_new_fixed_sleeps():
    """TST-G2: a test waits on an event or polls a condition, never on a fixed sleep.

    A `time.sleep` inside a `while` that polls with a deadline is a wait on a
    condition; any other sleep guesses how long a thread takes.
    """
    _ratchet(_fixed_sleeps(), KNOWN_SLEEPS, "a fixed sleep; wait on a threading.Event instead")


# The shoc modules whose functions worker-loop and connector tests stand in for,
# by the name a test reaches each through.
PATCHED = {"jobs": "shoc.db.jobs", "worker": "shoc.worker", "batchwriter": "shoc.ingest.batch"}
Shape = tuple[int, frozenset[str]]


def _aliases(tree: ast.Module, path: Path, module: str) -> set[str]:
    """The names a shoc file reaches `module` by."""
    package = list(path.relative_to(ROOT).with_suffix("").parts[:-1])
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.asname for a in node.names if a.name == module and a.asname}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = package[: len(package) - node.level + 1]
                base = ".".join([*parent, *([node.module] if node.module else [])])
            out |= {a.asname or a.name for a in node.names if f"{base}.{a.name}" == module}
    return out


@cache
def _calls(module: str, name: str) -> frozenset[Shape]:
    """How shoc calls `module.name`: (positional count, keyword names) of each call
    a monkeypatch on the module reaches."""
    home = ROOT / (module.replace(".", "/") + ".py")
    shapes: set[Shape] = set()
    for path in sorted(SHOC.rglob("*.py")):
        tree = _parse(path)
        names = _aliases(tree, path, module)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            direct = path == home and isinstance(func, ast.Name) and func.id == name
            via = (
                isinstance(func, ast.Attribute)
                and func.attr == name
                and isinstance(func.value, ast.Name)
                and func.value.id in names
            )
            starred = any(isinstance(a, ast.Starred) for a in node.args)
            if (direct or via) and not starred and all(k.arg for k in node.keywords):
                shapes.add((len(node.args), frozenset(str(k.arg) for k in node.keywords)))
    return frozenset(shapes)


def _binds(args: ast.arguments, positional: int, keywords: frozenset[str]) -> bool:
    """Would a call with this shape bind to a def with these arguments?"""
    names = [a.arg for a in (*args.posonlyargs, *args.args)]
    if positional > len(names) and args.vararg is None:
        return False
    taken = set(names[:positional])
    kwonly = {a.arg for a in args.kwonlyargs}
    for key in keywords:
        if key in taken or (key not in names and key not in kwonly and args.kwarg is None):
            return False
    required = names[: len(names) - len(args.defaults)]
    required += [a.arg for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True) if d is None]
    return set(required) <= taken | keywords


def _fake_args(value: ast.expr, above: tuple[ast.AST, ...], tree: ast.Module):
    """The arguments of a stand-in passed to monkeypatch.setattr: a lambda, or a
    def in the test (or the module) by its name. None for anything else."""
    if isinstance(value, ast.Lambda):
        return value.args
    if not isinstance(value, ast.Name):
        return None
    scopes = [a for a in above if isinstance(a, ast.FunctionDef | ast.AsyncFunctionDef)]
    for scope in reversed(scopes):
        for node in ast.walk(scope):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == value.id:
                return node.args
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == value.id:
            return node.args
    return None


def _patched(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id if target.id in PATCHED else None
    if isinstance(target, ast.Attribute):
        return target.attr if target.attr in PATCHED else None
    return None


def _unfit_fakes() -> Found:
    found: Found = defaultdict(list)
    for path in sorted(TESTS.rglob("*.py")):
        tree = _parse(path)
        for name, node, above in _walk(tree):
            if not _is_call(node, "monkeypatch", "setattr") or len(node.args) < 3:
                continue
            target, attribute, value = node.args[:3]
            key = _patched(target)
            args = _fake_args(value, above, tree)
            if key is None or args is None or not isinstance(attribute, ast.Constant):
                continue
            attr = str(attribute.value)
            for positional, keywords in sorted(_calls(PATCHED[key], attr), key=str):
                if not _binds(args, positional, keywords):
                    shape = f"{positional} positional and {sorted(keywords)}"
                    found[f"{_rel(path)}:{name}:{key}.{attr}"].append(
                        f"line {node.lineno} cannot take {shape}"
                    )
    return found


_THREE = "takes (conn, cfg); the leader's pass over a new tenant passes three and would raise"
KNOWN_FAKES = _known(
    {
        "tests/conformance/test_worker.py": {
            "test_a_queued_job_wakes_an_idle_worker:worker.ensure_default_schedules": _THREE,
        },
    }
)


def test_fakes_keep_the_real_signature():
    """TST-G2: a stand-in for a worker, queue or loader function takes every call shoc makes.

    When jobs.claim gained most_tier, a fixed-signature fake raised TypeError
    in the worker thread and a test failed for an unrelated reason (qa-20).
    """
    _ratchet(_unfit_fakes(), KNOWN_FAKES, "a fake that cannot take a call shoc makes")


def test_the_signature_check_sees_a_missing_keyword():
    """TST-G2: the check above catches the fake qa-20 tripped over, and finds call sites."""
    old = ast.parse("def claim(conn, limit=1): ...").body[0]
    assert isinstance(old, ast.FunctionDef)
    assert _binds(old.args, 1, frozenset())
    assert not _binds(old.args, 1, frozenset({"most_tier"}))
    assert _calls("shoc.db.jobs", "claim"), "found no call to jobs.claim in shoc/"


# -- TST-G3: an assertion compares an exact value ----------------------------
def _envelope(test: ast.expr) -> bool:
    """`x["data"]`, `x.data`, or either `is not None`, with nothing compared."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        test = test.operand
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.IsNot):
        right = test.comparators[0]
        if isinstance(right, ast.Constant) and right.value is None:
            test = test.left
    if isinstance(test, ast.Attribute):
        return test.attr == "data"
    return (
        isinstance(test, ast.Subscript)
        and isinstance(test.slice, ast.Constant)
        and test.slice.value == "data"
    )


def test_no_assertion_on_the_envelope_alone():
    """TST-G3: no assert checks only that a capability's `data` came back.

    The GitHub redelivery assertion checked that a dict was truthy, which any
    answer is (qa-15). Compare a value inside it instead.
    """
    found: Found = defaultdict(list)
    for path in sorted(TESTS.rglob("*.py")):
        for name, node, _ in _walk(_parse(path)):
            if not isinstance(node, ast.Assert):
                continue
            parts = node.test.values if isinstance(node.test, ast.BoolOp) else [node.test]
            if any(_envelope(p) for p in parts):
                found[f"{_rel(path)}:{name}"].append(f"line {node.lineno}")
    _ratchet(found, {}, "an assert on the envelope alone")


# -- TST-G4: the session fixtures are read-only ------------------------------
SESSION_FIXTURES = ("config", "store", "conn")


def _is_fixture(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any("fixture" in ast.unparse(d) for d in func.decorator_list)


def _assigned_fixtures() -> Found:
    found: Found = defaultdict(list)
    for path in sorted(TESTS.rglob("*.py")):
        if path.name == "conftest.py":
            continue
        conformance = "conformance" in path.parts
        for name, node, above in _walk(_parse(path)):
            func = _enclosing(above)
            if func is None:
                continue
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AugAssign | ast.AnnAssign):
                targets = [node.target]
            else:
                continue
            # In conformance every `config`, `store` or `conn` is the session's;
            # elsewhere only a test's or a fixture's own parameter is.
            if not (conformance or func.name.startswith("test_") or _is_fixture(func)):
                continue
            params = {a.arg for a in (*func.args.posonlyargs, *func.args.args)}
            for target in targets:
                for t in target.elts if isinstance(target, ast.Tuple) else [target]:
                    if (
                        isinstance(t, ast.Attribute)
                        and isinstance(t.value, ast.Name)
                        and t.value.id in SESSION_FIXTURES
                        and t.value.id in params
                    ):
                        found[f"{_rel(path)}:{name}"].append(
                            f"line {node.lineno} sets {t.value.id}.{t.attr}"
                        )
    return found


_PROVIDER = "sets config.llm_provider and puts it back by hand; use monkeypatch.setattr"
_BY_QUEUE = "sets config.llm_provider; the module's queue fixture puts it back"
KNOWN_ASSIGNED = _known(
    {
        "tests/conformance/test_autonomy.py": {"with_a_crew": _PROVIDER},
        "tests/conformance/test_crew.py": {
            "test_more_of_the_same_within_the_hour_waits_for_the_hour": _PROVIDER,
        },
        "tests/conformance/test_worker.py": {
            "queue": _PROVIDER,
            "_failed_tries": _BY_QUEUE,
            "test_the_sweep_sends_the_crew_back_at_a_case_nobody_worked": _BY_QUEUE,
            "test_the_sweep_is_not_silenced_by_the_jobs_it_queued_before": _BY_QUEUE,
            "test_the_sweep_leaves_a_case_the_crew_is_already_on": _BY_QUEUE,
            "test_the_sweep_does_nothing_without_a_model": _BY_QUEUE,
            "test_the_sweep_stands_down_while_the_provider_is_failing": _BY_QUEUE,
        },
    }
)


def test_session_fixtures_are_not_assigned():
    """TST-G4: a test changes the session's config, store or conn only through monkeypatch.

    `config.max_request_bytes = 1024` stayed set for the rest of the session and
    made later tests depend on order (qa-16).
    """
    _ratchet(_assigned_fixtures(), KNOWN_ASSIGNED, "a session fixture assigned in a test")


# -- TST-G5: config is loaded at entry points only ---------------------------
ENTRY_POINTS = {
    "shoc/cli.py:main",
    "shoc/worker.py:run",
    "shoc/api/rest.py:build_app",
    "shoc/api/mcp.py:serve_stdio",
    "shoc/api/mcp.py:session_manager",
}


def _fresh_config(node: ast.AST) -> bool:
    """`Config.load()` or `Config()`."""
    if _is_call(node, "Config", "load"):
        return True
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Config"
    )


def _config_loads() -> Found:
    found: Found = defaultdict(list)
    for path in sorted(SHOC.rglob("*.py")):
        for name, node, _ in _walk(_parse(path)):
            site = f"{_rel(path)}:{name}"
            if _fresh_config(node) and site not in ENTRY_POINTS:
                found[site].append(f"line {getattr(node, 'lineno', 0)}")
    return found


_FALLBACK = "loads Config itself when the caller passes none; take config as required"
_DEFAULTS = "builds a Config to read one default from it"
KNOWN_LOADS = {
    **dict.fromkeys(
        [
            "shoc/agents/detection_engineer.py:_technique_platforms",
            "shoc/agents/detection_engineer.py:work",
            "shoc/agents/hunter.py:triaged",
            "shoc/agents/hunter.py:work_backlog",
            "shoc/agents/integrator.py:work",
            "shoc/agents/llm.py:stored",
            "shoc/agents/loop.py:_ask",
            "shoc/agents/manager.py:_page",
            "shoc/agents/manager.py:reachable",
            "shoc/agents/reporter.py:_dry_run_switch",
            "shoc/cases/actions.py:decide",
            "shoc/cases/actions.py:_follow_link",
            "shoc/cases/actions.py:_resolve",
            "shoc/cases/credentials.py:signed_in",
            "shoc/cases/credentials.py:owners",
            "shoc/cases/credentials.py:products_behind",
            "shoc/cases/credentials.py:split_legacy",
            "shoc/cases/playbooks.py:load",
            "shoc/cases/playbooks.py:start",
            "shoc/cases/policy.py:Policy.load",
            "shoc/cases/review.py:review_action",
            "shoc/configcode.py:plan",
            "shoc/db/audit.py:chain_key",
            "shoc/db/audit.py:_retired",
            "shoc/db/migrate.py:migrate",
            "shoc/db/pool.py:connect",
            "shoc/db/pool.py:connect_owner",
            "shoc/db/pool.py:connect_readonly",
            "shoc/detect/hunts.py:load",
            "shoc/detect/osint.py:_keys",
            "shoc/detect/rules.py:load",
            "shoc/store/__init__.py:open_store",
        ],
        _FALLBACK,
    ),
    "shoc/scaffold.py:_playbooks_for": _DEFAULTS,
    "shoc/store/bigquery.py:BigQueryStore.__init__": _DEFAULTS,
}


def test_config_is_loaded_only_at_entry_points():
    """TST-G5: library code takes config as an argument; only entry points load it.

    A replay that loaded its own config wrote into the backend SHOC_BACKEND named
    instead of the one under test (qa-2).
    """
    _ratchet(_config_loads(), KNOWN_LOADS, "Config loaded outside an entry point")


# -- TST-G6: one home per helper ---------------------------------------------
_ID_PREFIX = re.compile(r"^[A-Z]+-$")


def _hashes(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Attribute) and n.attr == "hexdigest" for n in ast.walk(node))


def _prefixed_id(node: ast.AST) -> bool:
    """`"XX-" + sha256(...).hexdigest()[:n]`, or the same as an f-string."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = node.left
        return (
            isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and bool(_ID_PREFIX.match(left.value))
            and _hashes(node.right)
        )
    if isinstance(node, ast.JoinedStr) and node.values:
        first = node.values[0]
        return (
            isinstance(first, ast.Constant)
            and bool(_ID_PREFIX.match(str(first.value)))
            and _hashes(node)
        )
    return False


def _iso_parse(node: ast.AST) -> bool:
    """`text.replace("Z", "+00:00")` before a fromisoformat."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    args = [a.value for a in node.args if isinstance(a, ast.Constant)]
    return node.func.attr == "replace" and args == ["Z", "+00:00"]


def _staging(node: ast.AST) -> bool:
    """A name led by the time in ms, or a temporary directory of its own."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        sides = (node.left, node.right)
        thousand = any(isinstance(s, ast.Constant) and s.value == 1000 for s in sides)
        return thousand and any(_is_call(s, "time", "time") for s in sides)
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return called == "mkdtemp"


def _token_cache(node: ast.AST) -> bool:
    if isinstance(node, ast.AnnAssign):
        return isinstance(node.target, ast.Name) and node.target.id == "_TOKENS"
    if not isinstance(node, ast.Assign):
        return False
    return any(isinstance(t, ast.Name) and t.id == "_TOKENS" for t in node.targets)


def _documentation_range(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and "192.0.2.0/24" in str(node.value)


# (what, its home as path or path:def, the paths it is looked for in, how to see it)
HOMES: list[tuple[str, str, tuple[str, ...], Callable[[ast.AST], bool]]] = [
    ("the documentation ranges", "shoc/detect/osint.py", ("shoc/",), _documentation_range),
    ("ISO time parsing", "shoc/ingest/ocsf.py", ("shoc/",), _iso_parse),
    (
        "a staging name or directory",
        "shoc/ingest/batch.py:batch_name",
        ("shoc/store/", "shoc/ingest/batch.py"),
        _staging,
    ),
    ("a vendor token cache", "shoc/ingest/connectors/base.py", ("shoc/",), _token_cache),
    ("a prefixed id hash", "shoc/ids.py", ("shoc/",), _prefixed_id),
]


def _strays() -> Found:
    found: Found = defaultdict(list)
    for path in sorted(SHOC.rglob("*.py")):
        rel = _rel(path)
        for name, node, _ in _walk(_parse(path)):
            site = f"{rel}:{name}"
            for what, home, scope, seen in HOMES:
                at_home = site == home or (":" not in home and rel == home)
                if rel.startswith(scope) and not at_home and seen(node):
                    found[site].append(f"{what} at line {getattr(node, 'lineno', 0)}")
    return found


_ISO = "parses ISO time itself; use base.utc or ocsf's iso8601 transform (ING-G8)"
_STAGE = "names or makes its staging on its own; one helper in store/base.py (lean-1, DAT-G4)"
_ID = "hashes a prefixed id itself; use shoc.ids.make_id"
# Away from home on purpose, with the reason DAT-G4 gives (ALLOW_STAGED there).
ALLOWED_STRAYS = {
    "shoc/store/postgres.py:PostgresStore._insert": (
        "a TEMP table ON COMMIT DROP lives in its own session and transaction"
    ),
}
KNOWN_STRAYS = {
    **dict.fromkeys(
        [
            "shoc/actions/base.py:_created",
            "shoc/agents/hunter.py:_when",
            "shoc/agents/surveyor.py:_when",
            "shoc/detect/intel.py:_when",
            "shoc/detect/osint.py:rdap",
            "shoc/ingest/connectors/aws_cloudtrail.py:_epoch",
            "shoc/ingest/connectors/aws_guardduty.py:_epoch_ms",
            "shoc/ingest/connectors/awssig.py:assumed",
            "shoc/jsonschema.py:coerce",
            "shoc/store/postgres.py:_parse_ts",
        ],
        _ISO,
    ),
    **dict.fromkeys(
        [
            "shoc/store/databricks.py:_staging_dir",
            "shoc/store/snowflake.py:_staging_dir",
        ],
        _STAGE,
    ),
    **dict.fromkeys(
        [
            "shoc/agents/hunter.py:group",
            "shoc/agents/manager.py:tell",
            "shoc/capabilities/intel.py:_digest",
            "shoc/capabilities/intel.py:run_hunt",
            "shoc/capabilities/stream.py:subscribe",
        ],
        _ID,
    ),
}


def test_each_helper_has_one_home():
    """TST-G6: behaviour that siblings share lives in one function, not in each sibling.

    D162 gave Databricks a shared staging directory and thread-unique names
    while Snowflake, Redshift and BigQuery kept the old ones (lean-1).
    """
    _ratchet(_strays(), {**ALLOWED_STRAYS, **KNOWN_STRAYS}, "a helper away from its home")


# -- TST-G7: fixtures use visibly fake vendor ids ----------------------------
# A Stripe object id: the prefix, then "1" and the id's own characters.
STRIPE_ID = re.compile(r"(?<![A-Za-z0-9_])(?:acct|mk|accact)_1[A-Za-z0-9]{4,}")
HEX_ID = re.compile(r"^[0-9a-f]{32}$")
ACCOUNT_URL = re.compile(r"accounts/([0-9a-f]{32})(?![0-9a-f])")
ACCOUNT_KEY = re.compile(r"(?i)^account_?(id|tag)$")


def _fixture_files() -> list[Path]:
    return sorted([*FIXTURES.rglob("*.json"), *SCENARIOS.rglob("*.json")])


def _account_ids(value: Any, key: str = "", parent: str = "") -> Iterator[str]:
    """32-hex account ids, Cloudflare's shape, under an account key or in a URL."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _account_ids(v, str(k), key)
    elif isinstance(value, list):
        for v in value:
            yield from _account_ids(v, key, parent)
    elif isinstance(value, str):
        named = ACCOUNT_KEY.match(key) or (key == "id" and parent.lower() == "account")
        if named and HEX_ID.match(value):
            yield value
        yield from ACCOUNT_URL.findall(value)


def _real_looking_ids() -> Found:
    found: Found = defaultdict(list)
    for path in _fixture_files():
        text = path.read_text()
        for value in STRIPE_ID.findall(text):
            if "fake" not in value.lower():
                found[value].append(_rel(path))
        for value in _account_ids(json.loads(text)):
            if not value.startswith("0" * 16):
                found[value].append(_rel(path))
    return {k: sorted(set(v)) for k, v in found.items()}


_STRIPE = "shares the 1Sdey prefix of the Stripe account qa-13 replaced; use an mk_1Pfake id"
_CLOUDFLARE = "not known to be real, but not visibly fake; use a zero-padded id (qa-13)"
KNOWN_IDS = {
    "mk_1Sdey": _STRIPE,
    "mk_1SdeyOld": _STRIPE,
    "mk_1SdezNew": _STRIPE,
    "4bb334f7c94c4a29a045f03944f072e5": _CLOUDFLARE,
    "9f42c6e2a0b44ed0b6e5d1258f8b1a22": _CLOUDFLARE,
}


def test_fixtures_use_fake_vendor_ids():
    """TST-G7: Stripe ids in fixtures say fake, and account ids are zero-padded.

    A Stripe account id marked livemode and a 32-hex Cloudflare account id came
    from real exports and shipped in every wheel through _rule_fixtures (qa-13).
    """
    _ratchet(_real_looking_ids(), KNOWN_IDS, "a vendor id that does not look fake")
