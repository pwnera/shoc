"""The ingest and connector guidelines (ING-G1 to ING-G11) no single connector's tests hold.

Static checks read the connector modules, the mappings and the rules as syntax
trees or text; the rest drive `base.run`, `Streams` and the mapping engine with
fakes. Where code breaks a rule today it is listed in a `KNOWN` dict with the
reason: a violation not listed fails, and so does a listed one that no longer
violates, so each list only shrinks. An `ALLOW` dict lists what the rule leaves
out on purpose, and is held to the code the same way.
"""

from __future__ import annotations

import ast
import copy
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from shoc.detect import rules as ruleset
from shoc.detect.engine import ENTITY_COLUMNS
from shoc.ingest import connectors, ocsf
from shoc.ingest.connectors import base
from shoc.store import ocsf as layout
from shoc.store.base import LoadStats
from tests.support import FIXTURES, ROOT
from tests.unit.test_connectors import AWS, query, s3_file, s3_list, transport

CONNECTORS = ROOT / "shoc" / "ingest" / "connectors"


def _modules() -> list[Path]:
    return sorted(p for p in CONNECTORS.glob("*.py") if p.name != "__init__.py")


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


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _ratchet(found: dict[str, str], listed: dict[str, str], rule: str) -> None:
    """`found` (key -> where) must be exactly what `listed` names."""
    new = {k: v for k, v in found.items() if k not in listed}
    assert not new, f"{rule}: " + "; ".join(f"{k} at {v}" for k, v in sorted(new.items()))
    gone = sorted(set(listed) - set(found))
    assert not gone, f"{rule}: no longer found, take out of its list: {gone}"


def _is_call(node: ast.AST | None, owner: str, name: str) -> bool:
    """`owner.name(...)`, or `name(...)` when owner is empty."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr == name and (
            not owner or (isinstance(func.value, ast.Name) and func.value.id == owner)
        )
    return isinstance(func, ast.Name) and func.id == name and not owner


# -- ING-G1: re-read a look-back where the vendor publishes no lag ----------


def test_since_default_applies_the_overlap():
    """ING-G1: a new walk starts OVERLAP before the newest event read, and only once."""
    since = "2026-09-20T09:00:00+00:00"
    start = base.since_default({"since": since}, {})
    assert base.utc(start) == base.utc(since) - base.OVERLAP
    held = {"start": start, "newest": "2026-09-20T09:30:00+00:00", "next_link": "x"}
    assert base.since_default(held, {}) == start, "a walk still paging keeps its start"
    old = {"since": since, "newest": "2026-09-20T09:30:00+00:00", "page_token": "x"}
    assert base.since_default(old, {}) == since, "a walk held before D164 keeps its filter"
    assert base.since_default({"since": since}, {}, timedelta(0)) == since, "a lag read"
    first = base.utc(base.since_default({}, {"backfill_hours": 2}))
    assert abs(first - (datetime.now(UTC) - timedelta(hours=2))) < timedelta(minutes=1)


# A strict lower bound on the vendor's time: OData `gt`, Django `__gt`, Stripe
# `[gt]`, Falcon FQL `:>'`, Cloud Logging `> "`, OpenSearch and Anthropic `gt`,
# GuardDuty `GreaterThan`.
STRICT = re.compile(r"""\bgt\s+\{|__gt\b|\[gt\]|:>'|>\s*"\{|^gt$|\.gt$|^GreaterThan$""")

# Reads that stop at the vendor's published lag start at the newest event read,
# and D164 gives them no overlap.
ALLOW_STRICT = {
    "gcp_audit.py:GCPAuditConnector.fetch": "entries.list stops at Logging's 10-minute lag",
    "anthropic.py:_activities": "the activity feed stops at Anthropic's one-minute lag",
}
KNOWN_STRICT = {
    "defender.py:DefenderConnector.fetch": "detect-3: `gt` on since - OVERLAP, not `ge`",
    "entra.py:EntraConnector.fetch": "detect-3: the risk streams read `gt`",
    "crowdstrike.py:CrowdStrikeConnector.fetch": "detect-3: FQL `>` on since - OVERLAP",
    "sentinelone.py:_threats": "detect-3: `updatedAt__gt` on since - OVERLAP",
    "wazuh.py:WazuhConnector.fetch": "detect-3: range `gt` on since - OVERLAP",
    "aws_guardduty.py:AwsGuardDutyConnector.fetch": "detect-3: `GreaterThan` on since - OVERLAP",
}
# A cursor's `since` read anywhere but `base.since_default` skips the overlap.
# Counting late rows (`late = ...`, `since=`) reads it as a bound, not a start.
ALLOW_SINCE = {
    "llmusage.py:read": "reads closed hourly buckets once they settle, never one hour twice",
    "updates.py:upgrade": "turns a cursor from before `created` into today's shape (ING-G3)",
}


def _strict_bounds() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _modules():
        if path.name == "base.py":
            continue
        source = path.read_text()
        tree = ast.parse(source)
        parents = _parents(tree)
        for scope, node in _scoped(tree):
            text = ""
            if isinstance(node, ast.JoinedStr):
                text = ast.get_source_segment(source, node) or ""
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and not isinstance(parents.get(node), (ast.Expr, ast.JoinedStr))
            ):
                text = node.value
            if text and STRICT.search(text):
                found[f"{path.name}:{scope}"] = f"{path.name}:{getattr(node, 'lineno', 0)}"
    return found


def _since_reads() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _modules():
        if path.name == "base.py":
            continue
        tree = ast.parse(path.read_text())
        parents = _parents(tree)
        for scope, node in _scoped(tree):
            read = (
                isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "since"
            ) or (
                _is_call(node, "", "get")
                and isinstance(node, ast.Call)
                and bool(node.args)
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "since"
            )
            if read and not _counts_late(node, parents):
                found[f"{path.name}:{scope}"] = f"{path.name}:{getattr(node, 'lineno', 0)}"
    return found


def _counts_late(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Whether `node` feeds `late = ...` or a `since=` keyword, its nearest owner."""
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.keyword):
            return node.arg == "since"
        if isinstance(node, ast.Assign):
            return [ast.unparse(t) for t in node.targets] == ["late"]
        if isinstance(node, ast.stmt):
            return False
    return False


def test_no_connector_filters_strictly_after_its_cursor():
    """ING-G1: a poll by event time starts at an inclusive bound that since_default set."""
    _ratchet(_strict_bounds(), {**ALLOW_STRICT, **KNOWN_STRICT}, "a strict start bound")
    _ratchet(_since_reads(), ALLOW_SINCE, "a cursor's since read past since_default")


def test_stored_keys_cover_the_overlap_across_streams(monkeypatch):
    """ING-G1: a re-read never reaches the store, whichever streams the last run read."""
    now = datetime.now(UTC)

    def event(uid: str, minutes: int) -> dict[str, Any]:
        published = (now - timedelta(minutes=minutes)).isoformat()
        return {"uuid": uid, "published": published, "eventType": "user.session.start"}

    a1, a2, b1, b2 = event("a1", 10), event("a2", 5), event("b1", 10), event("b2", 2)
    # Each run, the page per stream; the second run reads stream A alone.
    runs = [{"A": [a1], "B": [b1]}, {"A": [a1, a2]}, {"A": [a1, a2], "B": [b1, b2]}]

    class TwoStreams:
        source = "okta"

        def fetch(self, settings, secret, cursor, limit):
            page = runs.pop(0)
            return base.FetchResult(
                records=[r for records in page.values() for r in records],
                cursor={"read": len(runs)},
                parts=[(name, len(records), "") for name, records in page.items()],
            )

    kept: dict[str, Any] = {"keys": b""}
    loaded: list[list[str]] = []

    def write_state(*args: Any, **kwargs: Any) -> None:
        if args[6] is not None:
            kept["keys"] = args[6]

    def load(store: Any, rows: list[dict[str, Any]]) -> LoadStats:
        loaded[-1] += [str(r["event_uid"]) for r in rows]
        return LoadStats(len(rows))

    monkeypatch.setattr(connectors, "get", lambda source: TwoStreams())
    monkeypatch.setattr(base, "fetch_one", lambda *a: {"stored_keys": kept["keys"]})
    monkeypatch.setattr(base, "write_state", write_state)
    monkeypatch.setattr(base.batchwriter, "load", load)
    for _ in range(3):
        loaded.append([])
        stats = base.run(None, None, "t1", "okta", {}, {}, cursor={})  # type: ignore[arg-type]
        assert stats.error is None, stats.detail
    assert loaded == [["a1", "b1"], ["a2"], ["b2"]], "a stream not read last run kept its keys"


# -- ING-G2: page the vendor its own way and stop at the limit ---------------

# A vendor whose API has no continuation, where a short page is the last.
ALLOW_PAGE_SIZE = {
    "wazuh.py:WazuhConnector.fetch": (
        "OpenSearch `search_after` has no continuation token, and a search answers a "
        "full page while hits remain"
    ),
}
KNOWN_PAGE_SIZE = {
    "stripe.py:_activity": "integ-5: reads more from the page size, not `next_page_url`",
    "crowdstrike.py:CrowdStrikeConnector.fetch": (
        "integ-5: a full page means more; `meta.pagination.total` is not read"
    ),
}


def _from_page_size(node: ast.AST) -> bool:
    """`len(x) >= n` or `len(x) == n` against anything but the run's `limit`."""
    return (
        isinstance(node, ast.Compare)
        and _is_call(node.left, "", "len")
        and isinstance(node.ops[0], (ast.GtE, ast.Gt, ast.Eq))
        and not any(
            isinstance(n, ast.Name) and n.id == "limit"
            for c in node.comparators
            for n in ast.walk(c)
        )
    )


def _says_more(body: list[ast.stmt]) -> bool:
    """Whether a block returns or sets `more` as True."""
    for node in (n for stmt in body for n in ast.walk(stmt)):
        if (isinstance(node, ast.keyword) and node.arg == "more") or (
            isinstance(node, ast.Assign) and [ast.unparse(t) for t in node.targets] == ["more"]
        ):
            return isinstance(node.value, ast.Constant) and node.value.value is True
    return False


def _page_size_more() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _modules():
        for scope, node in _scoped(ast.parse(path.read_text())):
            value: ast.AST | None = None
            if (isinstance(node, ast.keyword) and node.arg == "more") or (
                isinstance(node, ast.Assign) and [ast.unparse(t) for t in node.targets] == ["more"]
            ):
                value = node.value
            elif isinstance(node, ast.If) and _says_more(node.body):
                value = node.test
            if value is not None and _from_page_size(value):
                found[f"{path.name}:{scope}"] = f"{path.name}:{getattr(value, 'lineno', 0)}"
    return found


def test_more_never_comes_from_the_page_size():
    """ING-G2: FetchResult.more comes from the vendor's continuation, never len(page)."""
    _ratchet(_page_size_more(), {**ALLOW_PAGE_SIZE, **KNOWN_PAGE_SIZE}, "more from page size")


KNOWN_WHOLE = {
    "cloudtrail_s3.py:fetch": "integ-6: a trail's log file is decompressed whole",
    "cloudflare_logs.py:CloudflareLogsConnector.fetch": "integ-6: a Logpush batch read whole",
    "sentinelone_cloudfunnel.py:read": "integ-6: a Cloud Funnel object read whole",
}


def _read_whole() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _modules():
        for scope, node in _scoped(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            whole = _is_call(node, "gzip", "decompress") or _is_call(node, "zlib", "decompress")
            if _is_call(node, "json", "loads") and node.args:
                arg = node.args[0]
                whole = whole or (isinstance(arg, ast.Attribute) and arg.attr == "content")
                whole = whole or _is_call(arg, "bucket", "get")
            if whole:
                found[f"{path.name}:{scope}"] = f"{path.name}:{node.lineno}"
    return found


def test_no_vendor_object_is_read_whole():
    """ING-G2: a vendor object is streamed line by line, never decompressed whole."""
    _ratchet(_read_whole(), KNOWN_WHOLE, "a vendor object read whole")


def test_a_listing_connector_stops_at_its_limit(monkeypatch):
    """ING-G2: a trail bucket read stops at `limit` and the next call reads on from its cursor.

    The other listings hold this in their own tests: Logpush, Cloud Funnel and
    the Streaming API in tests/unit/test_connector_*.py, M365 and FDR in
    tests/unit/test_connectors.py and tests/unit/test_connector_crowdstrike_fdr.py.
    """
    account = "AWSLogs/111122223333/"
    east = f"{account}CloudTrail/us-east-1/"
    t = (datetime.now(UTC) - timedelta(hours=2)).replace(second=0, microsecond=0)
    keys = tuple(
        f"{east}{w:%Y/%m/%d}/111122223333_CloudTrail_us-east-1_{w:%Y%m%dT%H%M}Z_x.json.gz"
        for w in (t, t + timedelta(minutes=20), t + timedelta(minutes=40))
    )
    seen = transport(
        monkeypatch,
        [
            s3_list(prefixes=(account,)),
            s3_list(prefixes=(east,)),
            s3_list(keys),
            s3_file("e1"),
            s3_list(keys),
            s3_file("e2"),
        ],
    )
    connector = connectors.get("aws_cloudtrail")
    settings = {"bucket": "trail-bucket", "bucket_region": "us-east-1"}
    first = connector.fetch(settings, AWS, {}, 1)
    assert [r["eventID"] for r in first.records] == ["e1"] and first.more is True
    assert len(seen) == 4, "the files past the limit are not fetched"

    second = connector.fetch(settings, AWS, first.cursor, 1)
    assert [r["eventID"] for r in second.records] == ["e2"] and second.more is True
    assert query(seen[4])["start-after"] == first.cursor["prefixes"][east]["after"]
    fetched = [r.url.path for r in seen[4:] if r.url.path.endswith(".json.gz")]
    assert fetched == [f"/{keys[1]}"], "the next call reads on from where the last stopped"


# -- ING-G4: raise on every vendor refusal ----------------------------------

# What a connector may let pass without raising, and why it is no refusal.
ALLOW_SWALLOW = {
    "base.py:history:suppress(Exception)": (
        "the store probe for a source's first event; history is kept either way"
    ),
    "gcp_audit.py:_acknowledge:suppress(httpx.HTTPError)": (
        "an ack after the page is stored; an unacknowledged message loads once again"
    ),
    "gcp_audit.py:_pull:except httpx.ReadTimeout": "Pub/Sub holds a pull on an empty queue",
    "defender_hunting.py:DefenderHuntingConnector.fetch:except httpx.HTTPStatusError": (
        "a 404 is a table the Streaming API does not export"
    ),
    "defender_hunting.py:_record:suppress(ValueError)": "AdditionalFields that is not JSON",
    "cloudflare_logs.py:CloudflareLogsConnector.fetch:except ValueError": (
        "a key that is not a Logpush batch"
    ),
    "sentinelone_cloudfunnel.py:read:except ValueError": "a line that is not a JSON object",
    "updates.py:mark:except (TypeError, ValueError, OverflowError)": (
        "a creation time that does not parse marks no update"
    ),
    "file.py:read_records:except json.JSONDecodeError": (
        "a file that is not one object is read as NDJSON, which raises on a bad line"
    ),
}
KNOWN_SWALLOW = {
    "sentinelone.py:_alerts:graphql": "integ-4: GraphQL errors beside data pass as success",
}


def _swallows() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _modules():
        tree = ast.parse(path.read_text())
        for scope, node in _scoped(tree):
            where = f"{path.name}:{getattr(node, 'lineno', 0)}"
            if _is_call(node, "time", "sleep") or _is_call(node, "", "sleep"):
                found[f"{path.name}:{scope}:sleep"] = where
            if isinstance(node, ast.Call) and (
                _is_call(node, "contextlib", "suppress") or _is_call(node, "", "suppress")
            ):
                args = ", ".join(ast.unparse(a) for a in node.args)
                found[f"{path.name}:{scope}:suppress({args})"] = where
            if isinstance(node, ast.ExceptHandler) and _passes(node):
                caught = ast.unparse(node.type) if node.type else "BaseException"
                found[f"{path.name}:{scope}:except {caught}"] = where
        found.update(_graphql_errors_after_data(path, tree))
    return found


def _passes(handler: ast.ExceptHandler) -> bool:
    """A handler that only passes or continues, or returns a page with no error."""
    if len(handler.body) == 1 and isinstance(handler.body[0], (ast.Pass, ast.Continue)):
        return True
    return any(
        isinstance(n, ast.Return)
        and _is_call(n.value, "", "FetchResult")
        and not any(k.arg == "error" for k in getattr(n.value, "keywords", []))
        for stmt in handler.body
        for n in ast.walk(stmt)
    )


def _graphql_errors_after_data(path: Path, tree: ast.AST) -> dict[str, str]:
    """A def that calls a GraphQL endpoint and reads `data` before `errors`."""
    found: dict[str, str] = {}
    for scope, node in _scoped(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        texts = [n.value for n in ast.walk(node) if isinstance(n, ast.Constant)]
        if not any(isinstance(t, str) and "graphql" in t.lower() for t in texts):
            continue
        reads: dict[str, tuple[int, int]] = {}
        for n in ast.walk(node):
            if not isinstance(n, (ast.Subscript, ast.Call)):
                continue
            key: Any = None
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant):
                key = n.slice.value
            elif isinstance(n, ast.Call) and _is_call(n, "", "get") and n.args:
                first = n.args[0]
                key = first.value if isinstance(first, ast.Constant) else None
            if key in ("data", "errors"):
                at = (n.lineno, n.col_offset)
                reads[str(key)] = min(reads.get(str(key), at), at)
        if "data" in reads and reads["data"] < reads.get("errors", (1 << 30, 0)):
            found[f"{path.name}:{scope}:graphql"] = f"{path.name}:{reads['data'][0]}"
    return found


def test_connectors_neither_sleep_nor_swallow():
    """ING-G4: a connector raises on a refusal; it never sleeps, retries or passes it."""
    _ratchet(_swallows(), {**ALLOW_SWALLOW, **KNOWN_SWALLOW}, "a refusal not raised")


# -- ING-G5: no record can hold a cursor still --------------------------------

HOSTILE: list[Any] = [
    "\x00",
    "\ud800",
    "9999-12-31T23:59:59Z",
    "1970-01-01T00:00:00Z",
    10**30,
    {"a": [1]},
    [],
]


def _put(record: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    """A copy of `record` with `value` at `path`, written in `ocsf.dig`'s syntax:
    `[0]` and `[*]` are the first item, `[name=x]` the item named x. What the
    path needs and the record lacks is made."""
    out = copy.deepcopy(record)
    steps: list[tuple[str, str]] = []
    for part in path.split("."):
        name = part.split("[", 1)[0]
        if name:
            steps.append(("key", name))
        steps += [("item", spec) for spec in re.findall(r"\[([^\]]*)\]", part)]
    node: Any = out
    for i, (kind, spec) in enumerate(steps):
        last = i == len(steps) - 1
        fresh: Any = value if last else ([] if steps[i + 1][0] == "item" else {})
        if kind == "key":
            if not isinstance(node, dict):
                return out
            if last or not isinstance(node.get(spec), (dict, list)):
                node[spec] = fresh
            node = node[spec]
        elif not isinstance(node, list):
            return out
        elif "=" in spec:
            key, want = spec.split("=", 1)
            item = next((x for x in node if isinstance(x, dict) and str(x.get(key)) == want), None)
            if item is None:
                item = {key: want}
                node.append(item)
            node = item
        else:
            position = 0 if spec == "*" else max(int(spec), 0)
            while len(node) <= position:
                node.append(copy.deepcopy(fresh))
            if last or not isinstance(node[position], (dict, list)):
                node[position] = fresh
            node = node[position]
    return out


def _storable(row: dict[str, Any]) -> bool:
    """What Postgres takes: no NUL, and text that encodes as UTF-8."""
    text = json.dumps(row, ensure_ascii=False, default=str)
    text.encode("utf-8")  # a lone surrogate raises here, as it does in psycopg
    return "\x00" not in text and "\\u0000" not in text


@pytest.mark.parametrize("source", ocsf.available_sources())
def test_no_value_on_a_mapped_path_breaks_a_row(source):
    """ING-G5: whatever a vendor puts on a mapped path, the row is storable and in time."""
    mapping = ocsf.load_mapping(source)
    record = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())[0]
    columns = set(mapping.fields) | {c for r in mapping.derive for c in r.get("set") or {}}
    paths = sorted({p for c in columns for p in mapping.paths(c)})
    failures: list[str] = []
    for path in paths:
        for value in HOSTILE:
            try:
                rows = mapping.map_records(_put(record, path, value), "t1")
                for row in rows:
                    assert _storable(row), "not storable"
                    when = datetime.fromisoformat(row["time"])
                    ingested = datetime.fromisoformat(row["ingested_at"])
                    assert ocsf.EARLIEST <= when <= ingested + ocsf.AHEAD, row["time"]
            except Exception as exc:
                failures.append(f"{path}={value!r}: {type(exc).__name__}: {exc}")
    assert not failures, f"{source}: " + "; ".join(failures[:5])


# -- ING-G6: one tail from records to rows ----------------------------------

TAIL_FILES = [
    *sorted((ROOT / "shoc").rglob("*.py")),
    *sorted((ROOT / "evals").rglob("*.py")),
    *sorted((ROOT / "scripts").rglob("*.py")),
    ROOT / "tests" / "support.py",
]
# Each step of the tail and the files that may take it.
TAIL = {
    "map_record": (re.compile(r"\.map_record\("), {"shoc/ingest/ocsf.py"}),
    "loaded": (
        re.compile(
            r"\b(?:batchwriter|batch)\.loaded\(|from shoc\.ingest\.batch import [\w, ]*\bloaded\b"
        ),
        {"shoc/ingest/connectors/base.py", "shoc/capabilities/events.py"},
    ),
    "load_batch": (re.compile(r"\.load_batch\("), {"shoc/ingest/batch.py"}),
}
ALLOW_LOAD = {
    "shoc/ingest/connectors/base.py": "base.run, every poll's tail",
    "shoc/capabilities/events.py": "events.ingest, the tail of a push and of the API",
    "shoc/agents/detection_engineer.py": "a scratch store a proposed rule is tried on",
    "shoc/agents/hunter.py": "a scratch store a proposed hunt is tried on",
    "shoc/store/conformance.py": "the adapter conformance checks, on a throwaway tenant",
    "scripts/replay_datasets.py": "public datasets replayed into a throwaway tenant",
}
LOAD = re.compile(
    r"\b(?:batchwriter|batch)\.load\(|from shoc\.ingest\.batch import [\w, ]*\bload\b"
)


def _tail_steps() -> tuple[dict[str, str], dict[str, str]]:
    """(a step taken outside its files, every file that loads a batch)."""
    stray: dict[str, str] = {}
    loads: dict[str, str] = {}
    for path in TAIL_FILES:
        name = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for step, (pattern, allowed) in TAIL.items():
                if pattern.search(line) and name not in allowed:
                    stray[f"{name}:{step}"] = f"{name}:{number}"
            if LOAD.search(line):
                loads.setdefault(name, f"{name}:{number}")
    return stray, loads


def test_only_the_tail_loads_rows():
    """ING-G6: records reach the store through base.run or events.ingest, never another way."""
    stray, loads = _tail_steps()
    assert not stray, f"a step of the tail taken outside it: {stray}"
    _ratchet(loads, ALLOW_LOAD, "a batch loaded outside the tail")


# -- ING-G7: one row per vendor event ------------------------------------------

EVENT_COLUMNS = ("api_operation", "class_uid", "activity_id", "time")
# Lists read at their first item that are not a list of events.
ALLOW_FIRST_ITEM = {
    "crowdstrike:behaviors": "a Falcon detection's behaviors are the evidence of one alert",
    "m365:PolicyDetails": "the DLP policies one message matched, which grade one event",
    "wazuh:rule.groups": "a Wazuh rule's groups label one alert; the first names its family",
}
KNOWN_FIRST_ITEM = {
    "gcp_audit:protoPayload.metadata.event": (
        "integ-2: `explode` takes a top-level key only, so the Workspace events Cloud "
        "Logging carries are read at their first"
    ),
}
# An explode mapping whose fixture lists one item only.
KNOWN_SHORT_FIXTURE = {
    "m365": "the fixture's Teams message has one link; test_mapping_m365 builds two inline",
}


def _first_items() -> tuple[dict[str, str], dict[str, str]]:
    """(an event list read at its first item, an explode fixture with no list of two)."""
    lists: dict[str, str] = {}
    short: dict[str, str] = {}
    for source in ocsf.available_sources():
        mapping = ocsf.load_mapping(source)
        paths = [p for c in EVENT_COLUMNS for p in mapping.paths(c)]
        paths += [str(k) for rule in mapping.derive for k in rule.get("when") or {}]
        for path in paths:
            first = re.search(r"\[(?:0|\*)\]", path)
            if first and path[: first.start()] != mapping.explode:
                lists[f"{source}:{path[: first.start()]}"] = f"{source}.yaml: {path}"
        if mapping.explode:
            records = json.loads((FIXTURES / "mappings" / f"{source}.json").read_text())
            if not any(len(r.get(mapping.explode) or []) >= 2 for r in records):
                short[source] = f"tests/fixtures/mappings/{source}.json"
    return lists, short


def test_an_event_list_is_exploded_not_read_at_its_first_item():
    """ING-G7: a record that lists several events is one row per event, by `explode`."""
    lists, short = _first_items()
    _ratchet(lists, {**ALLOW_FIRST_ITEM, **KNOWN_FIRST_ITEM}, "an event list read at [0]")
    _ratchet(short, KNOWN_SHORT_FIXTURE, "an explode fixture without a list of two")


# -- ING-G8: the row's time is the cursor's field ----------------------------

SIGNED_IN = "createdDateTime"
# The record field each poll by event time moves its cursor on, by stream where
# a source reads several (a record's `_stream`). The connectors do not export
# it, so it is kept here; the first test holds the table to the connectors.
CURSOR_FIELD: dict[str, str | dict[str, str]] = {
    "anthropic": "created_at",
    "aws_cloudtrail": "eventTime",
    "aws_guardduty": "updatedAt",
    "azure_activity": "eventTimestamp",
    "cloudflare": "action.time",
    "crowdstrike": "updated_timestamp",
    "defender": "lastUpdateDateTime",
    "entra": {
        "signIns": SIGNED_IN,
        "nonInteractiveSignIns": SIGNED_IN,
        "servicePrincipalSignIns": SIGNED_IN,
        "managedIdentitySignIns": SIGNED_IN,
        "directoryAudits": "activityDateTime",
        "riskDetections": "lastUpdatedDateTime",
        "riskyUsers": "riskLastUpdatedDateTime",
    },
    "gcp_audit": "timestamp",
    "github": "@timestamp",
    "gitlab": "created_at",
    "google_workspace": "id.time",
    "okta": "published",
    "openai": "effective_at",
    "sentinelone": {"threats": "threatInfo.updatedAt", "unified_alerts": "updatedAt"},
    "stripe": "created",
    "wazuh": "timestamp",
}
# The stream a record without `_stream` belongs to.
FIRST_STREAM = {"sentinelone": "threats"}
# Polls through since_default whose cursor is not a record's time.
NOT_A_RECORD_TIME = {
    "m365": "when content became available, not when its events happened",
    "tailscale": "the end of the window it read",
}
KNOWN_UNCOVERED = {
    "sentinelone:unified_alerts": "the fixture's unified alerts carry no updatedAt",
}


def test_every_poll_by_event_time_names_its_cursor_field():
    """ING-G8: every connector that polls by event time is in CURSOR_FIELD."""
    polled = {
        p.stem for p in _modules() if p.name != "base.py" and "since_default(" in p.read_text()
    }
    assert polled == set(CURSOR_FIELD) | set(NOT_A_RECORD_TIME)


def test_the_cursor_field_is_the_rows_time():
    """ING-G8: a row's time is the field its connector's cursor advances on."""
    wrong: list[str] = []
    checked: dict[str, int] = {}
    for source, fields in CURSOR_FIELD.items():
        mapping = ocsf.load_mapping(source)
        streams = fields if isinstance(fields, dict) else {source: fields}
        for name in streams:
            checked.setdefault(f"{source}:{name}" if isinstance(fields, dict) else source, 0)
        for record in json.loads((FIXTURES / "mappings" / f"{source}.json").read_text()):
            stream = str(record.get("_stream") or FIRST_STREAM.get(source, ""))
            key = f"{source}:{stream}" if isinstance(fields, dict) else source
            field = streams.get(stream if isinstance(fields, dict) else source)
            value = ocsf.dig(record, field) if field else None
            if value in (None, ""):
                continue
            expected = ocsf._to_iso(value)
            if not ocsf.EARLIEST <= datetime.fromisoformat(expected) <= datetime.now(UTC):
                continue
            checked[key] = checked.get(key, 0) + 1
            got = mapping.map_records(record, "t1")[0]["time"]
            if got != expected:
                wrong.append(f"{key}: time {got}, {field} {expected}")
    assert not wrong, "; ".join(wrong)
    uncovered = {k: "no fixture record" for k, n in checked.items() if not n}
    _ratchet(uncovered, KNOWN_UNCOVERED, "a cursor field no fixture record carries")


ALLOW_FROMISO = {
    "base.py:utc": "the one parser: Graph's 7-digit ticks, and a naive time read as UTC",
    "base.py:_instant": "a mapped row's time, already ISO from ocsf._to_iso",
    "updates.py:mark": "reads a creation time through ocsf.TRANSFORMS, as base.utc does",
}
KNOWN_FROMISO = {
    "aws_cloudtrail.py:_epoch": "integ-11: a time with no offset reads as local time",
    "aws_guardduty.py:_epoch_ms": "integ-11: a time with no offset reads as local time",
    "awssig.py:assumed": "the STS Expiration time, parsed past base.utc",
}


def _fromisoformat() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in _modules():
        for scope, node in _scoped(ast.parse(path.read_text())):
            if _is_call(node, "", "fromisoformat"):
                found[f"{path.name}:{scope}"] = f"{path.name}:{getattr(node, 'lineno', 0)}"
    return found


def test_times_are_parsed_by_base_utc():
    """ING-G8: every vendor time a connector compares is parsed by base.utc."""
    _ratchet(_fromisoformat(), {**ALLOW_FROMISO, **KNOWN_FROMISO}, "a time parsed past base.utc")


# -- ING-G9: entity columns hold principals and objects --------------------

REQUEST_ID = re.compile(
    r"(?i)((correlation|request|trace|operation|activity)_?id|uniqueQualifier)$"
)


@pytest.mark.parametrize("source", ocsf.available_sources())
def test_no_request_id_is_an_entity(source):
    """ING-G9: no correlation, request, trace or operation id fills an entity column."""
    mapping = ocsf.load_mapping(source)
    for column in ENTITY_COLUMNS:
        for path in mapping.paths(column):
            leaf = re.sub(r"\[[^\]]*\]", "", path.rsplit(".", 1)[-1])
            assert not REQUEST_ID.search(leaf), f"{source}: {column} is read from {path}"


def _fills(mapping: ocsf.Mapping, column: str) -> bool:
    if column in mapping.fields or mapping.constants.get(column) is not None:
        return True
    return any((rule.get("set") or {}).get(column) is not None for rule in mapping.derive)


@pytest.mark.parametrize("rule", ruleset.load(), ids=lambda r: r.id)
def test_every_rule_entity_names_a_mapped_column(rule):
    """ING-G9: a rule's entity is a column its products' mappings fill, or a raw path."""
    names = layout.products_for(
        str(rule.logsource.get("product") or ""), str(rule.logsource.get("service") or "")
    )
    mappings = [
        ocsf.load_mapping(s)
        for s in ocsf.available_sources()
        if str(ocsf.load_mapping(s).constants.get("metadata_product") or "") in names
    ]
    assert mappings, f"{rule.id}: no mapping answers to its logsource"
    for entity in rule.entity:
        if layout.JSON_FIELD.match(entity):
            continue
        column = layout.column_for(entity)
        assert column and column in layout.COLUMN_NAMES, f"{rule.id}: {entity} is no column"
        assert any(_fills(m, column) for m in mappings), (
            f"{rule.id}: no mapping of its logsource fills {column}"
        )


# -- ING-G11: a new vendor tenant works on the first cycle ------------------

PULLED = [s for s in connectors.available() if s != "file"]


def _refused(status: int = 403) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://vendor.example/api")
    return httpx.HTTPStatusError(
        str(status), request=request, response=httpx.Response(status, request=request)
    )


def test_every_hint_names_a_real_connector():
    """ING-G11: PERMISSION_HINTS and WHERE name only connectors that exist."""
    assert set(base.PERMISSION_HINTS) <= set(PULLED)
    assert set(base.WHERE) <= set(connectors.available())


@pytest.mark.parametrize("source", PULLED)
def test_every_connector_says_what_it_needs(source):
    """ING-G11: every connector names its permission, where to grant it, and says so on a 403."""
    hint = base.PERMISSION_HINTS.get(source)
    assert hint, f"{source}: add what its credential needs to PERMISSION_HINTS"
    assert base.WHERE.get(source) or base.PUSH_WHERE.get(source), f"{source}: add WHERE"
    said = base.explain(source, _refused())
    assert said.endswith(f"it needs {hint}."), said


DEFAULT_STREAMS = [
    s
    for s in connectors.available()
    if isinstance(c := connectors.get(s), base.Streams) and c.default
]


@pytest.mark.parametrize("source", DEFAULT_STREAMS)
def test_every_default_stream_says_what_it_needs(monkeypatch, source):
    """ING-G11: a default stream refused names its permission and the setting that drops it."""
    streams = connectors.get(source)
    assert isinstance(streams, base.Streams)
    first = streams.default[0]

    def fetch(settings, secret, cursor, limit):
        if settings[streams.setting] == first:
            raise _refused()
        return base.FetchResult()

    monkeypatch.setattr(streams.inner, "fetch", fetch)
    page = streams.fetch({}, {}, {}, 10)
    hint = base.PERMISSION_HINTS[source]
    assert f"{first}: {source} rejected the credential (403); it needs {hint}." in page.error
    assert f"set {streams.setting} to a list without {first}" in page.error
