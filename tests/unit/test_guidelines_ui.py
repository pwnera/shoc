"""Console guidelines (UI-G) the kernel side can check without a browser.

Each test reads the console's hand-kept copies (console/src/lib) and holds them
to the code they copy: the capabilities that read the event store, the payload
of each published event type, and the case vocabularies in shoc/cases/engine.py.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "console"
CAPABILITIES = ROOT / "shoc" / "capabilities"

needs_console = pytest.mark.skipif(not CONSOLE.is_dir(), reason="no console/ in this checkout")


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


# -- UI-G6 -----------------------------------------------------------------------------------

# Capabilities that touch the event store (or call a model) and that the console calls,
# but whose deadline is the 30s default. Each is a gap this check found; the entry goes
# when the name joins SLOW in console/src/lib/api.ts.
KNOWN_FAST_STORE_READS = {
    "shoc/capabilities/findings.py:get_finding": "UI-G6 gap: finding.get reads the cited events",
    "shoc/capabilities/ops.py:cost": "UI-G6 gap: health.cost counts events per product",
    "shoc/capabilities/health.py:status": "UI-G6 gap: health.status runs store.health on a miss",
    "shoc/capabilities/hunting.py:pack": "UI-G6 gap: hunt.pack runs a whole pack on the store",
    "shoc/capabilities/hunting.py:results": "UI-G6 gap: hunt.results reads lookback readiness",
    "shoc/capabilities/intel.py:add": "UI-G6 gap: intel.add retro-hunts the new values",
    "shoc/capabilities/cases.py:openspace_post": "UI-G6 gap: openspace.post checks citations",
    "shoc/capabilities/ops.py:alerts": "UI-G6 gap: ops.alerts reads source quality",
}


def _slow_set() -> set[str]:
    text = (CONSOLE / "src/lib/api.ts").read_text()
    match = re.search(r"const SLOW = new Set\(\[(.*?)\]\)", text, re.S)
    assert match, "console/src/lib/api.ts: no `const SLOW = new Set([...])` literal"
    return set(re.findall(r'"([a-z_.]+)"', match.group(1)))


def _console_calls(names: set[str]) -> set[str]:
    """Capability names the console's code quotes; labels.ts names job kinds, api.ts SLOW."""
    found: set[str] = set()
    for path in (CONSOLE / "src").rglob("*.ts*"):
        if _rel(path) in {"console/src/lib/labels.ts", "console/src/lib/api.ts"}:
            continue
        found |= set(re.findall(r'"([a-z_]+(?:\.[a-z_]+)*)"', path.read_text())) & names
    return found


def _calls_out(fn: ast.FunctionDef) -> bool:
    """The body reads the event store or calls a model, by the names those take in shoc."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute):
            if node.attr == "store" and isinstance(node.value, ast.Name) and node.value.id == "ctx":
                return True
            if node.attr in {"open_store", "complete_typed"}:
                return True
            if (
                node.attr == "from_config"
                and isinstance(node.value, ast.Name)
                and node.value.id == "llm"
            ):
                return True
        if isinstance(node, ast.Name) and node.id in {"open_store", "complete_typed"}:
            return True
    return False


def _registered() -> dict[str, tuple[str, bool]]:
    """Capability name -> ("path:function", whether its body reads the store or a model)."""
    out: dict[str, tuple[str, bool]] = {}
    for path in sorted(CAPABILITIES.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if not (isinstance(dec, ast.Call) and getattr(dec.func, "id", "") == "capability"):
                    continue
                name = next(
                    k.value.value
                    for k in dec.keywords
                    if k.arg == "name" and isinstance(k.value, ast.Constant)
                )
                out[str(name)] = (f"{_rel(path)}:{node.name}", _calls_out(node))
    return out


@needs_console
def test_every_slow_capability_is_in_the_consoles_slow_set():
    """UI-G6: a capability that reads the store or calls a model gets the 150s deadline."""
    slow = _slow_set()
    registered = _registered()
    assert not slow - set(registered), (
        f"console/src/lib/api.ts SLOW names no capability: {sorted(slow - set(registered))}"
    )
    called = _console_calls(set(registered))
    late = {
        where: name
        for name, (where, out) in registered.items()
        if out and name in called and name not in slow
    }
    new = {where: name for where, name in late.items() if where not in KNOWN_FAST_STORE_READS}
    assert not new, (
        "the console calls these with the 30s deadline though they read the event store or a "
        f"model; add them to SLOW in console/src/lib/api.ts: {new}"
    )
    stale = sorted(set(KNOWN_FAST_STORE_READS) - set(late))
    assert not stale, f"no longer a gap, drop from KNOWN_FAST_STORE_READS: {stale}"

    api = (CONSOLE / "src/lib/api.ts").read_text()
    deadline = re.search(r"const SLOW_DEADLINE = ([\d_]+);", api)
    assert deadline, "console/src/lib/api.ts: no `const SLOW_DEADLINE = <ms>;`"
    nginx = (CONSOLE / "deploy/nginx.conf").read_text()
    v1 = re.search(r"location ~ \^/\(v1\|[^{]*\{(.*?)\n    \}", nginx, re.S)
    assert v1, "console/deploy/nginx.conf: no location block for /v1"
    timeout = re.search(r"proxy_read_timeout (\d+)s;", v1.group(1))
    assert timeout, "console/deploy/nginx.conf: the /v1 location sets no proxy_read_timeout"
    assert int(deadline.group(1).replace("_", "")) == int(timeout.group(1)) * 1000, (
        f"SLOW_DEADLINE {deadline.group(1)}ms is not nginx's /v1 timeout {timeout.group(1)}s"
    )


# -- UI-G7 -----------------------------------------------------------------------------------

# Event types published with more than one payload shape today. Each entry goes when every
# publish of the type sends the same keys.
KNOWN_PAYLOAD_SHAPES = {
    "events.loaded": "UI-G7 gap: the push endpoint (shoc/api/rest.py) adds `pushed`",
    "finding.new": "UI-G7 gap: an intel finding sends `source`, a rule finding `events`",
    "report.ready": "UI-G7 gap: a held report sends `held` where a sent one sends `items`",
}


def _publish_shapes() -> tuple[dict[str, dict[str, frozenset[str]]], list[str]]:
    """Event type -> {"path:line": payload keys}, and every publish whose payload is no literal."""
    shapes: dict[str, dict[str, frozenset[str]]] = defaultdict(dict)
    loose: list[str] = []
    for path in sorted((ROOT / "shoc").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", getattr(node.func, "id", "")) != "publish":
                continue
            where = f"{_rel(path)}:{node.lineno}"
            keywords = {k.arg: k.value for k in node.keywords}
            kind = node.args[2] if len(node.args) >= 3 else keywords.get("type_")
            payload = node.args[4] if len(node.args) >= 5 else keywords.get("payload")
            choices = [kind.body, kind.orelse] if isinstance(kind, ast.IfExp) else [kind]
            types = [str(c.value) for c in choices if isinstance(c, ast.Constant)]
            if len(types) != len(choices):
                continue  # f"health.{kind}": an OpsAlert, one dataclass for every kind
            if not (
                isinstance(payload, ast.Dict)
                and all(isinstance(k, ast.Constant) for k in payload.keys)
            ):
                loose.append(where)
                continue
            keys = frozenset(str(k.value) for k in payload.keys if isinstance(k, ast.Constant))
            for type_ in types:
                shapes[type_][where] = keys
    return shapes, loose


def test_every_publish_of_an_event_type_sends_the_same_payload_keys():
    """UI-G7: each event type reaches subscribers with one payload shape."""
    shapes, loose = _publish_shapes()
    assert shapes, "found no publish() call under shoc/"
    assert not loose, f"publish a payload as a dict literal with literal keys: {loose}"
    mixed = {t: s for t, s in shapes.items() if len(set(s.values())) > 1}
    new = {
        t: {where: sorted(keys) for where, keys in s.items()}
        for t, s in mixed.items()
        if t not in KNOWN_PAYLOAD_SHAPES
    }
    assert not new, f"event types published with different payload keys: {new}"
    stale = sorted(set(KNOWN_PAYLOAD_SHAPES) - set(mixed))
    assert not stale, f"one payload shape now, drop from KNOWN_PAYLOAD_SHAPES: {stale}"


def _ts_keys(text: str, name: str) -> list[str]:
    """The keys of `name`'s object literal, or the strings of its array literal, in labels.ts."""
    match = re.search(rf"\b(?:const|let) {name}\b[^=]*=\s*([\[{{])", text)
    assert match, f"console/src/lib/labels.ts: no `{name}` literal"
    close = "]" if match.group(1) == "[" else "}"
    depth, start, end = 0, match.end(1) - 1, -1
    for i in range(start, len(text)):
        depth += {match.group(1): 1, close: -1}.get(text[i], 0)
        if depth == 0:
            end = i
            break
    assert end > 0, f"console/src/lib/labels.ts: `{name}` never closes"
    body = text[start + 1 : end]
    if close == "]":
        return re.findall(r'"([a-z_]+)"', body)
    return re.findall(r"^\s*([a-z_]+):", body, re.M)


@needs_console
def test_the_consoles_case_vocabularies_match_the_engine():
    """UI-G7: every case state, verdict and disposition the engine knows has a console label."""
    from shoc.cases import engine

    labels = (CONSOLE / "src/lib/labels.ts").read_text()
    assert _ts_keys(labels, "CASE_STATES") == list(engine.STATES), (
        "CASE_STATES in console/src/lib/labels.ts is not engine.STATES in order"
    )
    for name, kernel in [
        ("CASE_STATE_LABELS", set(engine.STATES)),
        ("CASE_STATE_TIPS", set(engine.STATES)),
        ("DISPOSITIONS", set(engine.DISPOSITIONS)),
        ("VERDICTS", set(engine.VERDICTS) | set(engine.LEGACY_VERDICTS)),
    ]:
        console = set(_ts_keys(labels, name))
        assert console == kernel, (
            f"{name} in console/src/lib/labels.ts: missing {sorted(kernel - console)}, "
            f"unknown to shoc/cases/engine.py {sorted(console - kernel)}"
        )
