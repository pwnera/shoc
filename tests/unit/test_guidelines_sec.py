"""API, auth, secrets and privacy (SEC-G1 to SEC-G11), checked without a database.

Each test names the guideline it enforces in its first docstring line. Where code
breaks a rule today, a KNOWN dict names it and says why; the test fails on any
other violation, and on a KNOWN entry that no longer breaks the rule, so each
list only shrinks.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import ipaddress
import json
import re
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from shoc.capabilities.registry import Capability, all_capabilities
from shoc.config import Config
from tests.support import ROOT

CAPABILITIES = all_capabilities()
SHOC = sorted((ROOT / "shoc").rglob("*.py"))
API = sorted((ROOT / "shoc" / "api").glob("*.py"))
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _owned(tree: ast.AST, owner: str = "") -> Iterator[tuple[str, ast.AST]]:
    """Every node below `tree`, with the dotted name of the function or class it sits in."""
    for child in ast.iter_child_nodes(tree):
        yield owner, child
        inner = owner
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            inner = f"{owner}.{child.name}" if owner else child.name
        yield from _owned(child, inner)


def _defs(tree: ast.AST) -> dict[str, FunctionNode]:
    """Every function in a module by its dotted name: `build_app.lifespan`."""
    return {
        f"{owner}.{node.name}" if owner else node.name: node
        for owner, node in _owned(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _names(node: ast.AST) -> set[str]:
    """Every name and attribute a piece of code mentions, nested functions included."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)
    }


def _called(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _text(node: ast.AST) -> str:
    """A string literal's text, an f-string's with `{}` for each value; else ''."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(str(v.value) if isinstance(v, ast.Constant) else "{}" for v in node.values)
    return ""


def _ratchet(found: dict[str, str], known: dict[str, str]) -> None:
    """Fail on a violation `known` does not name, and on a `known` entry that is fixed."""
    new = sorted(f"{key}: {why}" for key, why in found.items() if key not in known)
    assert not new, "\n".join(new)
    fixed = sorted(set(known) - set(found))
    assert not fixed, f"these no longer break the rule; take them out of KNOWN: {fixed}"


# -- SEC-G1 ---------------------------------------------------------------------
def test_call_tool_knows_an_l2_tool_only_by_its_mcp_name(monkeypatch):
    """SEC-G1: MCP's call_tool finds an L2 tool by its MCP name, never another surface's.

    `action.approve` with dots once reached the capability with no confirmation
    (appsec-1). Any spelling but `action_approve` must be unknown, before
    confirmation or invocation is reached.
    """
    import mcp.types as types

    from shoc.api import mcp as surface
    from shoc.api.auth import role_caller

    asked: list[str] = []

    def ran(self: Capability, *_args: Any) -> Any:
        raise AssertionError(f"{self.name} ran under a name that is not its tool name")

    async def confirm(_session: Any, _request_id: Any, cap: Any, *_args: Any) -> str | None:
        asked.append(cap.name)
        return None

    monkeypatch.setattr(Capability, "invoke", ran)
    monkeypatch.setattr(surface, "confirmed", confirm)
    server = surface.build_server(Config(), role_caller("admin", "ann"))
    handle = server.request_handlers[types.CallToolRequest]
    l2 = [c for c in CAPABILITIES if c.autonomy == "L2"]
    assert l2, "the registry has L2 capabilities to check"
    for cap in l2:
        for name in (cap.name, cap.rest_path, " ".join(cap.cli_words)):
            params = types.CallToolRequestParams(name=name, arguments={})
            answer = asyncio.run(handle(types.CallToolRequest(method="tools/call", params=params)))
            result = answer.root
            assert isinstance(result, types.CallToolResult) and result.isError, name
            content = result.content[0]
            assert isinstance(content, types.TextContent), name
            code = json.loads(content.text)["error"]["code"]
            assert code == "unknown_tool", f"{name} answered {content.text}"
    assert asked == [], "nothing was put to the person either"


# -- SEC-G2 ---------------------------------------------------------------------
# Every route build_app serves that the registry does not generate, and why it exists.
HAND_WRITTEN = {
    "/": "what this is, for whoever opens it in a browser; reads nothing",
    "/healthz": "liveness; reads nothing",
    "/readyz": "readiness; one Postgres probe every READY_SECONDS, one at a time",
    "/v1/openapi.json": "the generated document; reads nothing",
    "/metrics": "Prometheus GETs metrics.export, authenticated first",
    "/v1/stream": "server-sent stream.tail, authenticated first",
    "/mcp": "the MCP server, behind the same bearer token check",
    "/slack/commands": "Slack signs its body; verified before it is parsed",
    "/slack/interactions": "Slack signs its body; verified before it is parsed",
    "/ingest/{source}": "GitHub's signed webhook (ING-2)",
    "/auth/start": "sign-in before there is a caller (RFC 0028)",
    "/auth/login": "sign-in before there is a caller (RFC 0028)",
    "/auth/token": "sign-in before there is a caller (RFC 0028)",
    "/auth/link": "sign-in before there is a caller (RFC 0028)",
    "/auth/link/accept": "sign-in before there is a caller (RFC 0028)",
    "/auth/forgot": "sign-in before there is a caller (RFC 0028)",
    "/auth/logout": "sign-in before there is a caller (RFC 0028)",
    "/auth/sso/callback": "the identity provider's redirect back (RFC 0028)",
}


def test_every_hand_written_route_is_listed():
    """SEC-G2: a route not generated from the registry is one HAND_WRITTEN names, with why."""
    from shoc.api.rest import build_app

    app = build_app(Config())
    paths = {str(getattr(route, "path", "")) for route in app.routes}
    generated = {cap.rest_path for cap in CAPABILITIES}
    assert generated <= paths, f"not served: {sorted(generated - paths)}"
    assert paths - generated == set(HAND_WRITTEN), (
        f"unlisted: {sorted(paths - generated - set(HAND_WRITTEN))}; "
        f"listed but gone: {sorted(set(HAND_WRITTEN) - paths)}"
    )


# The two places a body is read, each counting bytes as they arrive.
BODY_READERS = ("shoc/api/rest.py:_body", "shoc/api/signin.py:_post.handle")
RESPONSES = {"JSONResponse", "PlainTextResponse", "HTMLResponse", "RedirectResponse", "Response"}


def _repeats_exception(call: ast.Call, caught: set[str]) -> bool:
    """A response built from str(exc), repr(exc) or an f-string of exc."""
    for node in ast.walk(call):
        if (
            isinstance(node, ast.Call)
            and _called(node) in ("str", "repr")
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in caught
        ):
            return True
        if (
            isinstance(node, ast.FormattedValue)
            and isinstance(node.value, ast.Name)
            and node.value.id in caught
        ):
            return True
    return False


def test_routes_read_bodies_only_through_rest_body():
    """SEC-G2: a route reads its body only through a capped reader and never answers exc text.

    `/slack` and `/ingest` read unbounded chunked bodies before authentication,
    and every route returned `str(exc)` with the database host and role (appsec-9).
    """
    found: dict[str, str] = {}
    readers: set[str] = set()
    for path in API:
        tree = _tree(path)
        caught = {h.name for h in ast.walk(tree) if isinstance(h, ast.ExceptHandler) and h.name}
        for owner, node in _owned(tree):
            if not isinstance(node, ast.Call):
                continue
            where = f"{_rel(path)}:{owner or '<module>'}"
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "request"
            ):
                if func.attr in ("body", "json", "form"):
                    found[f"{where}:request.{func.attr}"] = f"line {node.lineno} reads uncapped"
                elif func.attr == "stream" and where in BODY_READERS:
                    readers.add(where)
                elif func.attr == "stream":
                    found[f"{where}:request.stream"] = f"line {node.lineno}: use rest._body"
            if _called(node) in RESPONSES and _repeats_exception(node, caught):
                found[f"{where}:{_called(node)}"] = f"line {node.lineno} answers with exc text"
    assert readers == set(BODY_READERS), f"a capped reader moved: {sorted(readers)}"
    _ratchet(found, {})


# One thread per process, started once; not a thread per request.
PER_PROCESS = {
    "shoc/api/rest.py:build_app.lifespan": "the scheduler watcher, started once as serve starts",
}
KNOWN_THREADS = {
    "shoc/mail.py:send_later": "a thread per mail; sign-in reaches it only when an account "
    "locks, which takes the account's password (SEC-G2 gap)",
}
MAX_WORKERS = 8


def test_no_unbounded_threads():
    """SEC-G2: what a client can trigger runs on a fixed module-level pool, never a new thread.

    `/auth/forgot` opened a thread and a Postgres connection per request.
    """
    found: dict[str, str] = {}
    for path in [*API, ROOT / "shoc" / "mail.py"]:
        for owner, node in _owned(_tree(path)):
            if not isinstance(node, ast.Call):
                continue
            where = f"{_rel(path)}:{owner or '<module>'}"
            if _called(node) == "Thread":
                found[where] = f"line {node.lineno} starts a thread"
            if _called(node) == "ThreadPoolExecutor":
                workers = {k.arg: k.value for k in node.keywords}.get("max_workers")
                fixed = (
                    isinstance(workers, ast.Constant)
                    and isinstance(workers.value, int)
                    and workers.value <= MAX_WORKERS
                )
                if owner or not fixed:
                    found[where] = f"line {node.lineno}: a pool per call, or no fixed max_workers"
    _ratchet(found, PER_PROCESS | KNOWN_THREADS)


# -- SEC-G3 ---------------------------------------------------------------------
HTTPX_CALLS = {
    "Client",
    "AsyncClient",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "request",
    "stream",
}
# Headers httpx drops on a cross-origin redirect, or that carry no credential.
SAFE_HEADERS = {"authorization", "accept", "content-type", "user-agent", "range", "stripe-version"}
KNOWN_REDIRECTS = {
    "shoc/ingest/connectors/base.py:client": "follows redirects with the caller's headers, so "
    "Anthropic's x-api-key, GitLab's PRIVATE-TOKEN and AWS's x-amz-security-token would ride a "
    "redirect to another host (SEC-G3 gap)",
}


def test_every_http_client_vets_or_refuses_redirects():
    """SEC-G3: an HTTP client that follows redirects vets each hop and carries no key header.

    httpx strips only Authorization on a cross-origin redirect, so a key in
    `Auth-Key`, `x-apikey` or the query rode the redirect (appsec-2, priv-18).
    """
    found: dict[str, str] = {}
    for path in SHOC:
        for owner, node in _owned(_tree(path)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            where = f"{_rel(path)}:{owner or '<module>'}"
            if _called(node) == "PyJWKClient":
                found[where] = f"line {node.lineno}: PyJWKClient fetches with urllib, which follows"
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            builds = (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "httpx"
                and func.attr in HTTPX_CALLS
            )
            follow = kw.get("follow_redirects")
            if not (builds or follow is not None):
                continue
            if follow is None or (isinstance(follow, ast.Constant) and follow.value is False):
                continue  # httpx follows none by default
            hooks, transport = kw.get("event_hooks"), kw.get("transport")
            vetted = (hooks is not None and "vet_redirect" in ast.unparse(hooks)) or (
                transport is not None and "Pinned" in ast.unparse(transport)
            )
            headers = kw.get("headers")
            keyed = (
                sorted(
                    str(k.value)
                    for k in headers.keys
                    if isinstance(k, ast.Constant) and str(k.value).lower() not in SAFE_HEADERS
                )
                if isinstance(headers, ast.Dict)
                else []
            )
            if not vetted or keyed:
                said = f"carries {keyed}" if keyed else "follows unvetted"
                found[where] = f"line {node.lineno} {said}"
    _ratchet(found, KNOWN_REDIRECTS)


# -- SEC-G4 ---------------------------------------------------------------------
# Configure paths that keep a stored secret by other means than the two patterns
# `_reuses` finds.
REUSES_ELSEWHERE = ("shoc/capabilities/llm.py:configure", "shoc/capabilities/users.py:configure")
KNOWN_REUSE = {
    "shoc/capabilities/llm.py:configure": "compares the provider and the base_url host itself "
    "instead of calling credentials.same_host (SEC-G4 gap)",
    "shoc/capabilities/users.py:configure": "keeps the SSO client secret only for the same issuer "
    "and client id, its own check instead of credentials.same_host (SEC-G4 gap)",
}


def _reuses(node: ast.AST) -> bool:
    """`COALESCE(EXCLUDED.secret, ...)` in SQL, or a `{**stored, ...}` merge."""
    if "COALESCE(EXCLUDED.secret" in _text(node):
        return True
    return isinstance(node, ast.Dict) and any(
        key is None and isinstance(value, ast.Name) and value.id == "stored"
        for key, value in zip(node.keys, node.values, strict=True)
    )


def test_every_secret_reuse_calls_the_host_check():
    """SEC-G4: every path that keeps a stored secret asks credentials.same_host first.

    `source.configure` with a new `org_url` and no secret sent the stored Okta
    token to the new host on the next sync (appsec-3).
    """
    found: dict[str, str] = {}
    seen: set[str] = set()
    for path in SHOC:
        tree, rel = _tree(path), _rel(path)
        defs = _defs(tree)
        # The check, and any function of this module that calls it directly.
        helpers = {"same_host"} | {name for name, fn in defs.items() if "same_host" in _names(fn)}
        reusing = {f"{rel}:{owner}" for owner, node in _owned(tree) if _reuses(node)}
        reusing |= {key for key in REUSES_ELSEWHERE if key.startswith(f"{rel}:")}
        for key in reusing:
            fn = defs.get(key.partition(":")[2])
            assert fn is not None, f"{key}: a stored secret is kept outside a function"
            seen.add(key)
            if not _names(fn) & helpers:
                found[key] = "keeps a stored secret without credentials.same_host"
    assert set(REUSES_ELSEWHERE) <= seen, "a path REUSES_ELSEWHERE names is gone"
    assert len(seen) > len(REUSES_ELSEWHERE), "the COALESCE and **stored patterns still match"
    _ratchet(found, KNOWN_REUSE)


# -- SEC-G5 ---------------------------------------------------------------------
# Verbs writing capabilities use that mcp.py classifies neither way yet: with no
# ADDITIVE vocabulary their destructiveHint is still guessed from DESTRUCTIVE alone.
UNCLASSIFIED = (
    "acknowledge",
    "add",
    "add_fact",
    "approve",
    "chase",
    "close",
    "create",
    "daily",
    "decide",
    "deliver",
    "digest",
    "expire",
    "ingest",
    "investigate",
    "invite",
    "merge",
    "notify",
    "onboard",
    "pack",
    "post",
    "propose",
    "push_key",
    "recheck",
    "refresh",
    "reject",
    "resume",
    "run",
    "send",
    "set_state",
    "set_status",
    "subscribe",
    "sync",
    "work",
    "write",
)
KNOWN_VERBS = {
    f"shoc/api/mcp.py:{verb}": "mcp.py has no ADDITIVE vocabulary yet (SEC-G5 gap)"
    for verb in UNCLASSIFIED
}


def test_every_write_verb_is_classified():
    """SEC-G5: every verb a writing capability uses is in mcp.DESTRUCTIVE or mcp.ADDITIVE.

    `retain` was missing from DESTRUCTIVE because the hint was guessed from a suffix.
    """
    from shoc.api import mcp as surface

    destructive = set(surface.DESTRUCTIVE)
    additive = set(getattr(surface, "ADDITIVE", ()))
    assert not destructive & additive, f"both ways: {sorted(destructive & additive)}"
    found: dict[str, str] = {}
    for cap in CAPABILITIES:
        if cap.scope.endswith(":read") or "read" in cap.tags:
            continue
        verb = cap.name.rsplit(".", 1)[-1]
        if verb not in destructive | additive:
            found[f"shoc/api/mcp.py:{verb}"] = f"{cap.name} writes with an unclassified verb"
    _ratchet(found, KNOWN_VERBS)


# Capabilities that blind shoc or add a destination outside the deployment.
WEAKENS = {
    "source.remove": "stops a source",
    "source.configure": "disables a source, or points its credential at another host",
    "credential.remove": "takes away what the runner acts with",
    "stream.subscribe": "adds a receiver of every finding",
    "intel.configure": "adds a URL shoc fetches, with a key",
    "slack.configure": "adds a channel that gets case cards",
    "llm.configure": "points case evidence at a model endpoint",
    "config.apply": "may do any of the above",
    "events.retain": "deletes events",
}
# A service may call these (D100) because they refuse any value below the configured one.
FLOORED = {
    "events.retain": "tests/conformance/test_lifecycle.py::"
    "test_retention_never_keeps_less_than_configured",
}
KNOWN_WEAKENING = {
    "source.remove": "L0: a client holding a person's role removes a source unconfirmed (appsec-4)",
    "source.configure": "L0: enabled false or a new org_url goes through unconfirmed (appsec-4)",
    "stream.subscribe": "L0: a client holding a person's role adds a webhook unconfirmed "
    "(appsec-4)",
    "intel.configure": "L0: a client holding a person's role adds a feed URL unconfirmed "
    "(appsec-4)",
}


def test_egress_and_blinding_need_a_person():
    """SEC-G5: a capability that blinds shoc or adds a destination is L2 and human-only.

    `source.remove`, `stream.subscribe`, `intel.configure` and `events.retain`
    were L0, so a prompt-injected assistant could blind shoc or add a webhook
    without a person seeing a prompt (appsec-4).
    """
    by_name = {c.name: c for c in CAPABILITIES}
    assert set(WEAKENS) <= set(by_name), f"gone: {sorted(set(WEAKENS) - set(by_name))}"
    for name, test in FLOORED.items():
        file, _, function = test.partition("::")
        assert f"def {function}(" in (ROOT / file).read_text(), f"{name}: {test} is gone"
    found: dict[str, str] = {}
    for name, why in WEAKENS.items():
        cap = by_name[name]
        confirmed = cap.autonomy == "L2" and cap.principals == ("human",)
        if not (confirmed or name in FLOORED):
            found[name] = f"{why}, yet {cap.autonomy} for {cap.principals}"
    _ratchet(found, KNOWN_WEAKENING)


# -- SEC-G7 ---------------------------------------------------------------------
CANARY = "CANARY-7f3a"
SECRET_NAME = re.compile(r"secret|token|key|password")
SAMPLE = {
    "ip": "203.0.113.7",
    "domain": "evil.example.test",
    "url": "https://evil.example.test/login",
    "email": "ana@evil.example.test",
    "sha256": "a" * 64,
    "md5": "a" * 32,
    "cve": "CVE-2026-1234",
}


def _setting(name: str) -> str:
    if name.endswith("url"):
        return "https://vendor.example.test"
    return {"cloud": "us-1", "admin_email": "admin@example.com"}.get(name, "acme")


def _secret(name: str) -> str:
    """The canary in every field that holds a secret; ids and emails stay plausible."""
    if SECRET_NAME.search(name) and not name.endswith("_id"):
        return CANARY
    return "svc@example.test" if name.endswith("email") else "00000000-0000-0000-0000-000000000001"


def _answer(monkeypatch, status: int | None) -> None:
    """Every client shoc opens gets `status`, with a body that repeats the request's URL and
    headers, or (None) cannot connect. Every name resolves to a documentation address."""
    real = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        if status is None:
            raise httpx.ConnectError("[Errno 111] Connection refused", request=request)
        return httpx.Response(status, text=f"{request.url} {dict(request.headers)}")

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        httpx, "Client", lambda *a, **kw: real(*a, **{**kw, "transport": transport})
    )

    def resolve(_host: str, port: Any, *_args: Any, **_kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.5", port))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)


@pytest.mark.parametrize("status", [401, 500, None], ids=["refused", "failed", "unreachable"])
def test_no_error_repeats_a_secret(monkeypatch, status):
    """SEC-G7: no stored error, lookup answer or cache row repeats a secret.

    httpx puts the whole URL in its message, so Shodan's and ipapi.is's
    query-string keys reached `intel.lookup` answers, the cache and the model's
    prompt (priv-1). Not covered here: jobs.last_error and a Result's to_json.
    """
    from shoc.detect import intel, osint
    from shoc.ingest import connectors
    from shoc.ingest.connectors import base

    _answer(monkeypatch, status)
    said: list[tuple[str, Any]] = []

    for name in connectors.available():
        if name == "file":
            continue  # reads a local path and holds no secret
        settings, secret = base.FIELDS.get(name, ((), ("api_key", "token")))
        stats = base.run(
            None,
            cast(Any, None),
            "t1",
            name,
            {key: _setting(key) for key in settings},
            {key: _secret(key) for key in secret},
            cursor={},
            limit=1,
            max_pages=1,
            persist=False,
        )
        said += [(f"{name} error", stats.error), (f"{name} detail", stats.detail)]

    observations = []
    for source in osint.SOURCES.values():
        if not source.key:
            continue
        field = osint.KEYED[source.key].secret_field
        kind = source.kinds[0]
        obs = osint._run_source(source, SAMPLE.get(kind, "203.0.113.7"), kind, {field: CANARY})
        observations.append(obs)
        said.append((f"{source.name} observation", obs.error))
    assert observations, "keyed lookups were checked"
    written: list[Any] = []
    monkeypatch.setattr(osint, "execute", lambda _conn, _sql, params: written.append(params))
    answer = osint.Observation(source="rdap", summary="registered to EXAMPLE-NET")
    osint._to_cache(cast(Any, None), "t1", "203.0.113.7", "ip", [*observations, answer])
    said += [("intel_lookups row", json.dumps(row, default=str)) for row in written]

    results: list[Any] = []
    monkeypatch.setattr(intel, "record_run", lambda *args: results.append(args[-1]))
    for parser in intel.FEEDS:
        intel.refresh(
            cast(Any, None),
            "t1",
            parser,
            {"url": "https://feed.example.test/list"},
            {"api_key": CANARY, "auth_key": CANARY, "key": CANARY},
            parser,
        )
    said += [(f"{r.feed} feed error", r.error) for r in results]

    leaked = [where for where, text in said if text and CANARY in str(text)]
    assert not leaked, f"the secret is repeated in: {leaked}"


# -- SEC-G8 ---------------------------------------------------------------------
HOSTILE = (
    "hxxps://a[.]b[.]test/x",
    "http://[",
    "http://[::1",
    "\x00",
    "a" * 10_000,
    "\ud800",
    "https://u:p@h.test/?token=x",
)


@pytest.mark.parametrize("cap", CAPABILITIES, ids=lambda c: c.name)
def test_any_input_gives_a_bounded_subject_or_none(cap):
    """SEC-G8: the audit subject is None or a bounded string for any input, and never fails.

    `hxxps://evil[.]example[.]test` read as a bad IPv6 URL, and the raise failed
    `intel.remove` itself (priv-7). A refused call is audited with its raw
    payload, so non-object payloads are tried too.
    """
    from shoc.db.audit import SUBJECT_LIMIT, subject_of

    names: list[str] = []
    if dataclasses.is_dataclass(cap.input):
        names = [f.name for f in dataclasses.fields(cap.input)]
    for value in (*HOSTILE, *([v] for v in HOSTILE)):
        cites = [value] if isinstance(value, str) else value
        every_field = subject_of({n: value for n in names}, cites)
        for said in (every_field, subject_of(value), subject_of(None)):
            if said is None:
                continue
            assert isinstance(said, str) and len(said) <= SUBJECT_LIMIT, cap.name
            assert "u:p" not in said and "token=x" not in said, f"{cap.name}: {said[:200]}"


# Input fields whose name reads like a credential and which hold none.
NOT_SECRET = {
    "LLMConfig.hunt_tokens_per_day": "a model-token budget",
    "LLMConfig.intel_tokens_per_day": "a model-token budget",
    "LookupInput.credential": "names a stored credential, such as aws:staging; never its value",
    "ProposeInput.credential": "names a stored credential, such as aws:staging; never its value",
    "TokenRevoke.token_id": "a token's public id; the token itself is never an input",
}
CREDENTIAL = re.compile(r"key|token|secret|password|credential")


def test_no_input_field_hides_a_secret_from_the_mask():
    """SEC-G8: an input field that may carry a credential is named so the audit mask hides it.

    A secret in a field named `routing_key` or `access_key` would land in an
    undeletable audit row in clear.
    """
    from shoc.db.audit import SECRET_FIELDS

    found: dict[str, str] = {}
    for cap in CAPABILITIES:
        if not dataclasses.is_dataclass(cap.input):
            continue
        for field in dataclasses.fields(cap.input):
            masked = field.name in SECRET_FIELDS or field.name.endswith("_secret")
            if CREDENTIAL.search(field.name) and not masked:
                found[f"{cap.input.__name__}.{field.name}"] = (
                    f"{cap.name} takes {field.name}, which the audit row shows in clear"
                )
    _ratchet(found, NOT_SECRET)


# -- SEC-G9 ---------------------------------------------------------------------
ENTRY_POINTS = ("cmd_serve", "cmd_worker", "cmd_mcp", "cmd_apply", "cmd_migrate", "cmd_rotate_key")
# Entry points with a reason not to call audit.check_key, and the name that shows
# they check the chain's key another way ("" for none needed).
AUDIT_KEY_ELSEWHERE = {
    "cmd_migrate": "",  # migrate keys the audit log with this key
    "cmd_rotate_key": "fingerprint",  # audit.rotate compares the chain's key before moving it
}
KNOWN_ENTRY_POINTS = {
    "shoc/cli.py:cmd_mcp": "serves tools that open secrets and append to the audit log with no "
    "key check (appsec-11)",
    "shoc/cli.py:cmd_apply": "runs config.apply, which seals secrets and appends to the audit "
    "log, with no key check (appsec-11)",
}


def _mentions(path: Path, name: str) -> set[str]:
    fn = _defs(_tree(path)).get(name)
    return _names(fn) if fn else set()


def _reach(path: Path, name: str) -> set[str]:
    """What a function mentions, and what each shoc function it calls mentions, one call deep."""
    defs = _defs(_tree(path))
    fn = defs[name]
    said = _names(fn)
    modules: dict[str, Path] = {}
    functions: dict[str, tuple[Path, str]] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("shoc"):
            base = ROOT.joinpath(*(node.module or "").split("."))
            for alias in node.names:
                local = alias.asname or alias.name
                if (base / f"{alias.name}.py").exists():
                    modules[local] = base / f"{alias.name}.py"
                elif base.with_suffix(".py").exists():
                    functions[local] = (base.with_suffix(".py"), alias.name)
    reached = set(said)
    for local, (where, target) in functions.items():
        if local in said:
            reached |= _mentions(where, target)
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in modules
        ):
            reached |= _mentions(modules[node.value.id], node.attr)
    for local in said & set(defs):
        reached |= _names(defs[local])
    return reached


def test_every_entry_point_checks_the_keys():
    """SEC-G9: each process command checks the master key and the audit chain's key first.

    A process with a mismatched key could commit a token or role change and then
    fail to write its audit row (appsec-11).
    """
    cli = ROOT / "shoc" / "cli.py"
    found: dict[str, str] = {}
    for command in ENTRY_POINTS:
        said = _reach(cli, command)
        missing = [] if "check_master_key" in said else ["secrets.check_master_key"]
        instead = AUDIT_KEY_ELSEWHERE.get(command)
        if instead is None and "check_key" not in said:
            missing.append("audit.check_key")
        elif instead and instead not in said:
            missing.append(f"a {instead} check")
        if missing:
            found[f"shoc/cli.py:{command}"] = f"calls no {' or '.join(missing)}"
    _ratchet(found, KNOWN_ENTRY_POINTS)


SECRET_COLUMN = re.compile(r"secret|password_hash|\w+_secret")
INSERT = re.compile(r"INSERT\s+INTO\s+([\w.{}\"]+)\s*\(([^)]*)\)", re.I)
UPDATE = re.compile(
    r"\bUPDATE\s+([\w.{}\"]+)\s+SET\b(.*?)(?=\bWHERE\b|\bRETURNING\b|$)", re.I | re.S
)
SEALERS = {"seal", "hash_password"}


def _secret_writes(sql: str) -> list[tuple[str, str]]:
    """(table, column) for each secret column an INSERT or UPDATE writes, NULL aside."""
    writes = [
        (table, column.strip())
        for table, columns in INSERT.findall(sql)
        for column in columns.split(",")
    ]
    for table, assignments in UPDATE.findall(sql):
        for column, value in re.findall(r"(\w+)\s*=\s*([^,]+)", assignments):
            if not value.strip().upper().startswith("NULL"):
                writes.append((table, column))
    return [(t, c) for t, c in writes if SECRET_COLUMN.fullmatch(c)]


def test_every_secret_column_is_sealed():
    """SEC-G9: every write of a secret column seals it with the master key, or hashes it.

    A sealed column's table is one `shoc rotate-key` reseals (secrets.SEALED).
    """
    from shoc.db.secrets import SEALED

    sealed_tables = {table for table, _ in SEALED}
    found: dict[str, str] = {}
    writers = 0
    for path in SHOC:
        tree = _tree(path)
        defs = _defs(tree)
        sealers = SEALERS | {name for name, fn in defs.items() if _names(fn) & SEALERS}
        for owner, node in _owned(tree):
            writes = _secret_writes(_text(node))
            if not writes:
                continue
            writers += 1
            where = f"{_rel(path)}:{owner or '<module>'}"
            fn = defs.get(owner)
            if fn is None or not _names(fn) & sealers:
                found[where] = f"line {getattr(node, 'lineno', 0)} writes {writes} unsealed"
            for table, column in writes:
                name = table.removeprefix("shoc.")
                if column != "password_hash" and "{" not in name and name not in sealed_tables:
                    found[f"{where}:{name}"] = f"{name}.{column} is not in secrets.SEALED"
    assert writers, "the SQL patterns still find the secret writes"
    _ratchet(found, {})


FALLBACK = re.compile(r"\$\{(\w*PASSWORD\w*):?-([^}]*)\}")
BARE = re.compile(r"\$\{(\w*PASSWORD\w*)\}")
REQUIRED = re.compile(r"\$\{(\w*PASSWORD\w*):\?")
KNOWN_PASSWORD_DEFAULTS = {
    f"deploy/postgres-init/10-shoc-role.sh:{name}": "compose requires the variable, so this "
    "default applies only when the script runs outside compose; drop it (SEC-G9)"
    for name in ("SHOC_DB_PASSWORD", "SHOC_APP_DB_PASSWORD", "SHOC_AGENT_DB_PASSWORD")
}


def test_compose_password_fallbacks_are_refused():
    """SEC-G9: no deploy file falls back to a well-known database password.

    Compose fell back to well-known passwords, which let anything on the network
    reach the superuser who can disable the audit triggers.
    """
    compose = ROOT / "deploy" / "docker-compose.yml"
    found: dict[str, str] = {}
    for path in [compose, *sorted((ROOT / "deploy" / "postgres-init").glob("*"))]:
        for name, default in FALLBACK.findall(path.read_text()):
            if default.strip():
                found[f"{_rel(path)}:{name}"] = f"falls back to {default!r}"
    text = compose.read_text()
    unset = set(BARE.findall(text)) - set(REQUIRED.findall(text))
    assert not unset, f"used with no default and never required with :? : {sorted(unset)}"
    assert REQUIRED.findall(text), "compose still requires the database passwords"
    _ratchet(found, KNOWN_PASSWORD_DEFAULTS)


# -- SEC-G10 --------------------------------------------------------------------
def test_slack_answers_ephemerally_and_strangers_get_no_scope():
    """SEC-G10: Slack replies only to the asker, and anyone not granted gets no scope.

    Every Slack member, guests included, could ask about any employee's sign-ins
    and have the cited answer posted to the whole channel (priv-5).
    """
    from shoc.api.slack import SlackApp, caller_for

    path = ROOT / "shoc" / "api" / "slack.py"
    public = {
        owner
        for owner, node in _owned(_tree(path))
        if isinstance(node, ast.Constant) and node.value == "in_channel"
    }
    assert public == {"handle_interaction"}, f"posted to the channel from {sorted(public)}"

    assert caller_for(SlackApp(), "U-ANY", "T-ACME").scopes == ()
    app = SlackApp(approvers={"U-SAM": "sam"}, readers={"U-RITA": "rita"}, team_id="T-ACME")
    assert caller_for(app, "U-RITA", "T-ACME").scopes, "a listed reader can read"
    strangers = (("U-SAM", "T-OTHER"), ("U-RITA", "T-OTHER"), ("U-RITA", ""), ("U-EVE", "T-ACME"))
    for user, team in strangers:
        assert caller_for(app, user, team).scopes == (), (user, team)


# -- SEC-G11 --------------------------------------------------------------------
# Each host the code sends to, and the words that name it under "## Data and privacy".
DESTINATIONS = {
    "api.openai.com": "The model provider",
    "api.anthropic.com": "The model provider",
    "data.iana.org": "IANA",
    "rdap.org": "rdap.org",
    "api.first.org": "FIRST EPSS",
    "services.nvd.nist.gov": "NVD",
    "threatfox-api.abuse.ch": "abuse.ch",
    "urlhaus-api.abuse.ch": "abuse.ch",
    "mb-api.abuse.ch": "abuse.ch",
    "api.ipapi.is": "ipapi.is",
    "api.abuseipdb.com": "AbuseIPDB",
    "api.greynoise.io": "GreyNoise",
    "api.shodan.io": "Shodan",
    "app.netlas.io": "Netlas",
    "www.virustotal.com": "VirusTotal",
    "urlscan.io": "urlscan.io",
    "slack.com": "Slack",
    "hooks.slack.com": "Slack",
    "events.pagerduty.com": "PagerDuty",
    "events.eu.pagerduty.com": "PagerDuty",
    "login.microsoftonline.com": "Your identity provider",
}
# Feeds, lists and report sources: a download that gets a request and no company
# data, which the section says once ("are downloads").
DOWNLOADS = frozenset(
    {
        "api.fastly.com",
        "api.github.com",
        "check.torproject.org",
        "digitalocean.com",
        "docs.oracle.com",
        "download.db-ip.com",
        "download.microsoft.com",
        "ip-ranges.amazonaws.com",
        "raw.githubusercontent.com",
        "www.cloudflare.com",
        "www.gstatic.com",
        "www.microsoft.com",
        "www.spamhaus.org",
        "feodotracker.abuse.ch",
        "urlhaus.abuse.ch",
        "otx.alienvault.com",
        "blog.talosintelligence.com",
        "cloudblog.withgoogle.com",
        "pushsecurity.com",
        "securitylabs.datadoghq.com",
        "thedfirreport.com",
        "www.cert.ssi.gouv.fr",
        "www.huntress.com",
        "www.proofpoint.com",
        "www.stepsecurity.io",
        "www.wiz.io",
    }
)
OUTBOUND = (
    "shoc/agents/llm.py",
    "shoc/detect/osint.py",
    "shoc/detect/intel.py",
    "shoc/actions/notify.py",
    "shoc/api/slack.py",
    "shoc/capabilities/slack.py",
    "shoc/api/oidc.py",
    "shoc/mail.py",
)
HOST = re.compile(r"https?://([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)
EXAMPLE = re.compile(r"(^|\.)example\.(com|net|org)$|\.(test|example|invalid|localhost)$")


def _documentation_address(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(
        address in ipaddress.ip_network(net)
        for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    )


def test_every_outbound_host_is_documented():
    """SEC-G11: every host shoc sends to is named under "Data and privacy" in the security model.

    Full records went to the model provider and URLs with reset tokens to
    VirusTotal and urlscan, and no document told a DPO any of it (priv-4).
    """
    hosts: set[str] = set()
    for name in OUTBOUND:
        for node in ast.walk(_tree(ROOT / name)):
            for match in HOST.finditer(_text(node).replace("\\.", ".")):
                host = match.group(1).lower()
                if not (EXAMPLE.search(host) or _documentation_address(host)):
                    hosts.add(host)
    classified = set(DESTINATIONS) | DOWNLOADS
    assert hosts == classified, (
        f"name these in docs/security-model.md and here: {sorted(hosts - classified)}; "
        f"no longer sent to: {sorted(classified - hosts)}"
    )
    doc = (ROOT / "docs" / "security-model.md").read_text()
    section = doc.partition("\n## Data and privacy")[2].partition("\n## ")[0]
    assert section, "docs/security-model.md has a Data and privacy section"
    missing = sorted({words for words in DESTINATIONS.values() if words not in section})
    assert not missing, f"not under Data and privacy: {missing}"
    assert "are downloads" in section, "the section says what a download receives"
