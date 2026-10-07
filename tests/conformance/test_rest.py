"""The generated REST surface, including signed push ingest (API-1, ING-2)."""

from __future__ import annotations

import json
import time

import pytest
from starlette.testclient import TestClient

from shoc.api import rest
from shoc.api.rest import build_app, openapi_document
from shoc.capabilities.registry import all_capabilities, call
from shoc.db.pool import ALL_TENANTS, execute, fetch_all, set_tenant
from shoc.errors import ConfigError

pytestmark = pytest.mark.postgres

# Single-user mode answers requests addressed to localhost only (D63).
LOCAL = "http://localhost"


@pytest.fixture
def api(config, conn, store, clean):
    with TestClient(build_app(config), base_url=LOCAL) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        yield client


def test_serve_pages_when_no_worker_ticks_the_schedule(config, conn, store, clean, monkeypatch):
    """With every worker down, nothing scheduled could report it (OPS-1)."""
    monkeypatch.setattr(rest, "SCHEDULER_CHECK_SECONDS", 0.1)
    execute(
        conn,
        """INSERT INTO shoc.schedules (schedule_id, tenant_id, kind, next_run_at, enabled)
           VALUES (%s, %s, 'detect.run', now() - interval '2 hours', true)""",
        (f"{config.tenant_id}:stalled", config.tenant_id),
    )

    def paged() -> list[dict]:
        return fetch_all(
            conn,
            """SELECT outcome FROM shoc.notices
               WHERE tenant_id = %s AND group_key = 'scheduler' AND outcome = 'paged'""",
            (config.tenant_id,),
        )

    try:
        with TestClient(build_app(config)):
            deadline = time.time() + 15
            while time.time() < deadline and not paged():
                time.sleep(0.2)
    finally:
        execute(conn, "DELETE FROM shoc.schedules WHERE tenant_id = %s", (config.tenant_id,))
    assert paged(), "serve checks the schedule on its own and pages"


def test_every_capability_has_a_route(api):
    document = openapi_document()
    for cap in all_capabilities():
        assert cap.rest_path in document["paths"]
    assert document["openapi"].startswith("3.1")


def test_healthz_and_openapi(api):
    assert api.get("/healthz").text == "ok"
    document = api.get("/v1/openapi.json").json()
    assert document["info"]["title"] == "shoc"
    answers = document["paths"]["/v1/finding/list"]["post"]["responses"]
    assert set(answers) == {"200", "400", "401", "403", "404", "409", "500"}
    error = answers["401"]["content"]["application/json"]["schema"]["$ref"].rpartition("/")[2]
    assert document["components"]["schemas"][error]["required"] == ["error"]


def test_a_capability_call_returns_the_envelope(api):
    body = api.post("/v1/finding/list", json={"since": "-1h"}).json()
    assert set(body) == {"data", "summary", "citations"}
    assert body["data"]["count"] == 0


def test_a_bad_body_is_a_validation_error(api):
    resp = api.post("/v1/finding/list", json={"nope": 1})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "validation_error"
    listed = api.post("/v1/finding/list", json=[1])
    assert listed.status_code == 400 and listed.json()["error"]["code"] == "validation_error"


def test_a_gate_refusal_lists_every_reason(api):
    book = {
        "id": "x",
        "title": "t",
        "rules": ["no_such_rule"],
        "steps": [{"name": "wait", "wait_minutes": 5}],
    }
    resp = api.post("/v1/playbook/merge", json={"playbook": book, "dry_run": True})
    error = resp.json()["error"]
    assert resp.status_code == 400 and error["code"] == "gate_refused" and error["stage"] == "lint"
    assert error["message"] == "not merged: " + "; ".join(error["reasons"])
    for words in ("lower_snake_case", "two questions", "no_such_rule"):
        assert sum(words in r for r in error["reasons"]) == 1, words


def test_a_missing_finding_is_a_404(api):
    resp = api.post("/v1/finding/get", json={"finding_uid": "F-nope"})
    assert resp.status_code == 404


def test_single_user_mode_refuses_proxies_and_web_pages(api):
    """Principle 5: with no tokens, reaching the port must not be enough to approve.

    A proxy in front of loopback, or a page in the operator's browser, reaches it.
    """
    refused = [
        {"x-forwarded-for": "203.0.113.7"},
        {"forwarded": "for=203.0.113.7"},
        {"x-real-ip": "203.0.113.7"},
        {"host": "shoc.example.com"},  # a proxy that keeps Host, or DNS rebinding
        {"origin": "https://attacker.example", "content-type": "text/plain"},
        {"origin": "null"},
    ]
    for headers in refused:
        assert api.post("/v1/finding/list", content=b"{}", headers=headers).status_code == 403
        assert api.get("/v1/stream", headers=headers).status_code == 403
        assert api.post("/mcp/", headers={**MCP_HEADERS, **headers}, json={}).status_code == 403
    # The console's dev server proxies from its own loopback origin.
    for headers in ({}, {"origin": "http://localhost:5173"}, {"host": "127.0.0.1:8080"}):
        assert api.post("/v1/finding/list", json={}, headers=headers).status_code == 200


def test_tokens_gate_scopes(config, conn, store, clean, monkeypatch):
    monkeypatch.setenv(
        "SHOC_TOKENS",
        json.dumps({"tok-read": {"kind": "service", "id": "ci", "scopes": ["findings:read"]}}),
    )
    with TestClient(build_app(config), base_url=LOCAL) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        missing = client.post("/v1/finding/list", json={})
        assert missing.status_code == 401
        assert missing.json()["error"]["code"] == "unauthenticated"
        allowed = client.post(
            "/v1/finding/list", json={}, headers={"authorization": "Bearer tok-read"}
        )
        assert allowed.status_code == 200
        denied = client.post(
            "/v1/events/ingest",
            json={"source": "github", "records": []},
            headers={"authorization": "Bearer tok-read"},
        )
        assert denied.status_code == 403
        assert (
            client.post(
                "/v1/finding/list", json={}, headers={"authorization": "Bearer wrong"}
            ).status_code
            == 401
        )
        # SEC-1: a token acts on its own tenant; the header cannot move it.
        assert (
            client.post(
                "/v1/finding/list",
                json={},
                headers={"authorization": "Bearer tok-read", "x-shoc-tenant": "someone-else"},
            ).status_code
            == 403
        )


def _webhook(key: str, body: bytes, delivery: str = "72d3162e-cb52-11e3-8bc7-4c9367dc0958"):
    import hashlib
    import hmac

    return {
        "content-type": "application/json",
        "x-github-event": "repository",
        "x-github-delivery": delivery,
        "x-hub-signature-256": "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest(),
    }


def test_a_github_webhook_loads_on_its_own_signature(config, ctx, store, clean):
    """GitHub sends no bearer token: the signature is what authenticates it (ING-2)."""
    from shoc.capabilities.registry import call

    key = call("source.push_key", ctx, {"source": "github", "rotate": True}).data.push_key
    body = json.dumps(
        {
            "action": "publicized",
            "repository": {"full_name": "acme/payments"},
            "organization": {"login": "acme"},
            "sender": {"login": "mallory", "id": 4242},
        }
    ).encode()
    url = f"/ingest/github?tenant={config.tenant_id}"
    # Not addressed to localhost and carrying no token, as GitHub's request is.
    with TestClient(build_app(config), base_url="https://shoc.example.com") as github:
        resp = github.post(url, content=body, headers=_webhook(key, body))
        assert resp.status_code == 200 and resp.json()["data"]["loaded"] == 1
        # Redelivered: the same delivery id is the same event.
        assert github.post(url, content=body, headers=_webhook(key, body)).json()["data"]
        assert github.post(url, content=body, headers=_webhook("wrong", body)).status_code == 403
        assert (
            github.post(
                f"/ingest/wazuh?tenant={config.tenant_id}",
                content=body,
                headers=_webhook(key, body),
            ).status_code
            == 403
        ), "only /ingest/github takes GitHub's signature"
    rows = store.query(
        "SELECT api_operation FROM ocsf_events WHERE tenant_id = :t", {"t": config.tenant_id}
    ).rows
    assert [r["api_operation"] for r in rows] == ["repo.access"]
    # A push key is no poll credential, and each delivery shows on the source.
    (src,) = [r for r in call("source.list", ctx, {}).data.configured if r["source"] == "github"]
    assert src["has_secret"] is False and src["last_ok_at"] and src["events_seen"] >= 1


def test_a_github_webhook_is_refused_before_a_push_key_exists(config, conn, store, clean):
    body = b'{"action": "publicized"}'
    with TestClient(build_app(config), base_url="https://shoc.example.com") as github:
        resp = github.post(
            f"/ingest/github?tenant={config.tenant_id}", content=body, headers=_webhook("", body)
        )
    assert resp.status_code == 403 and "push-key" in resp.json()["error"]["message"]


def test_nothing_but_githubs_webhook_is_pushed(api, ctx, config):
    """Every other source is polled; there is no push shoc invented (ING-2)."""
    from shoc.capabilities.registry import call

    body = json.dumps([{"id": "wz-1", "rule": {"level": 12}}]).encode()
    assert api.post("/ingest/wazuh", content=body).status_code == 403
    assert api.post("/ingest/github", content=body).status_code == 403, "unsigned"
    with pytest.raises(ConfigError, match="polled"):
        call("source.push_key", ctx, {"source": "crowdstrike"})


def test_rotating_the_key_invalidates_the_old_one(config, ctx, store, clean):
    from shoc.capabilities.registry import call

    first = call("source.push_key", ctx, {"source": "github", "rotate": True}).data.push_key
    second = call("source.push_key", ctx, {"source": "github", "rotate": True}).data.push_key
    assert first != second
    body = b'{"action": "publicized", "repository": {"full_name": "acme/x"}}'
    url = f"/ingest/github?tenant={config.tenant_id}"
    with TestClient(build_app(config), base_url="https://shoc.example.com") as github:
        assert github.post(url, content=body, headers=_webhook(first, body)).status_code == 403
        assert github.post(url, content=body, headers=_webhook(second, body)).status_code == 200


def test_metrics_are_served_as_text(api):
    resp = api.get("/metrics")
    assert resp.status_code == 200
    assert "shoc_findings" in resp.text


def test_metrics_are_a_capability(ctx):
    """API-1: /metrics checked `health:read` by hand; now the registry does."""
    from shoc.capabilities.registry import get

    cap = get("metrics.export")
    assert cap.scope == "health:read"
    assert "# TYPE shoc_jobs gauge" in call("metrics.export", ctx, {}).data.text


def test_metrics_need_a_token_and_show_its_tenant_only(config, conn, store, clean, monkeypatch):
    """SEC-1: /metrics used to answer anyone, for every tenant."""
    other = f"other{config.tenant_id}"
    set_tenant(conn, ALL_TENANTS)  # an earlier test's ctx may have pinned it
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO shoc.connector_state (tenant_id, source) VALUES (%s, 'okta'), (%s, 'okta')",
            (config.tenant_id, other),
        )
    monkeypatch.setenv(
        "SHOC_TOKENS",
        json.dumps(
            {
                "tok-prom": {"kind": "service", "id": "prometheus", "scopes": ["health:read"]},
                "tok-ci": {"kind": "service", "id": "ci", "scopes": ["events:write"]},
            }
        ),
    )
    try:
        with TestClient(build_app(config), base_url=LOCAL) as client:
            assert client.get("/metrics").status_code == 401
            assert (
                client.get("/metrics", headers={"authorization": "Bearer tok-ci"}).status_code
                == 403
            )
            resp = client.get("/metrics", headers={"authorization": "Bearer tok-prom"})
            assert resp.status_code == 200
            assert f'tenant="{config.tenant_id}",source="okta"' in resp.text
            assert other not in resp.text
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM shoc.connector_state WHERE tenant_id = %s", (other,))


# -- server-sent events (API-2) ----------------------------------------------
STREAM_TOKENS = {
    "tok-ci": {"kind": "service", "id": "ci", "scopes": ["events:write"]},
    "tok-tail": {"kind": "service", "id": "tail", "scopes": ["stream:read"]},
}


def test_the_stream_answers_a_refused_caller_with_401_or_403_not_500(
    config, conn, store, clean, monkeypatch
):
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(STREAM_TOKENS))
    with TestClient(build_app(config), base_url=LOCAL) as client:
        assert client.get("/v1/stream").status_code == 401
        assert (
            client.get("/v1/stream", headers={"authorization": "Bearer tok-ci"}).status_code == 403
        )
        assert (
            client.get(
                "/v1/stream",
                headers={"authorization": "Bearer tok-tail", "x-shoc-tenant": "someone-else"},
            ).status_code
            == 403
        )
        assert (
            client.get(
                "/v1/stream?since=abc", headers={"authorization": "Bearer tok-tail"}
            ).status_code
            == 400
        )


def _first_sse_chunks(app, headers: dict[str, str]) -> list[str]:
    """Call the stream route over raw ASGI and hang up after its first event.

    TestClient waits for a response to finish, and an event stream never does.
    """
    import anyio

    chunks: list[str] = []

    async def run() -> None:
        first_event = anyio.Event()
        requested = False

        async def receive():
            nonlocal requested
            if not requested:
                requested = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await first_event.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                chunks.append(str(message["status"]))
            elif message.get("body"):
                chunks.append(message["body"].decode())
                first_event.set()

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/v1/stream",
            "raw_path": b"/v1/stream",
            "query_string": b"",
            "root_path": "",
            "client": ("127.0.0.1", 1),
            "server": ("testserver", 80),
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
        with anyio.fail_after(20):
            await app(scope, receive, send)

    anyio.run(run)
    return chunks


def test_the_stream_reads_the_callers_tenant_through_the_registry(
    config, conn, store, clean, monkeypatch
):
    from shoc.cases.engine import publish

    other = f"other{config.tenant_id}"
    set_tenant(conn, ALL_TENANTS)
    publish(conn, other, "case.opened", "CASE-theirs", {})
    publish(conn, config.tenant_id, "case.opened", "CASE-ours", {})
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(STREAM_TOKENS))
    try:
        chunks = _first_sse_chunks(build_app(config), {"authorization": "Bearer tok-tail"})
    finally:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM shoc.stream_events WHERE tenant_id = %s", (other,))
    assert chunks[0] == "200"
    body = "".join(chunks[1:])
    assert "event: case.opened" in body and "CASE-ours" in body
    assert "CASE-theirs" not in body


# -- MCP over HTTP (API-1) --------------------------------------------------
MCP_HEADERS = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def _session(api) -> None:
    """Sessions are stateful (RFC 0018), so a client opens one before anything else."""
    if "mcp-session-id" in api.headers:
        return
    hello = {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"},
    }
    resp = api.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": hello},
    )
    assert resp.status_code == 200, resp.text
    api.headers["mcp-session-id"] = resp.headers["mcp-session-id"]
    api.post(
        "/mcp/", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )


def _mcp(api, method: str, params: dict | None = None, request_id: int = 1):
    if method != "initialize":
        _session(api)
    resp = api.post(
        "/mcp/",
        headers=MCP_HEADERS,
        json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}},
    )
    assert resp.status_code == 200, resp.text
    # Streamable HTTP answers as server-sent events.
    payload = [line for line in resp.text.splitlines() if line.startswith("data: ")]
    assert payload, resp.text
    return json.loads(payload[-1][len("data: ") :])


def test_a_remote_mcp_client_can_initialize(api):
    result = _mcp(
        api,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    )["result"]
    assert result["serverInfo"]["name"] == "shoc"
    assert "tools" in result["capabilities"]


def test_mcp_over_http_lists_the_same_tools_as_stdio(api):
    listed = {t["name"]: t for t in _mcp(api, "tools/list", request_id=2)["result"]["tools"]}
    from shoc.api.mcp import EXTERNAL_AGENT, tool_definitions

    assert set(listed) == {t["name"] for t in tool_definitions(EXTERNAL_AGENT)}
    assert "source_configure" not in listed, "a remote agent gets no write tools"
    assert listed["finding_list"]["annotations"] == {"readOnlyHint": True}
    added = listed["memory_add_fact"]
    assert added["annotations"] == {"readOnlyHint": False, "destructiveHint": False}
    assert added["description"].endswith("Writes.")


def test_a_tool_call_over_http_returns_the_envelope(api, ctx, config, store):
    from evals.run import SCENARIOS, replay

    replay(SCENARIOS / "leaked_aws_key", tenant_id=config.tenant_id, store=store)
    result = _mcp(api, "tools/call", {"name": "finding_list", "arguments": {"since": "-1h"}}, 3)
    body = json.loads(result["result"]["content"][0]["text"])
    assert set(body) == {"data", "summary", "citations"}
    assert body["data"]["count"] >= 5 and body["citations"]


def test_a_tool_the_caller_may_not_use_answers_with_an_error_not_a_crash(api):
    result = _mcp(
        api, "tools/call", {"name": "action_approve", "arguments": {"action_uid": "x"}}, 4
    )["result"]
    assert result["isError"] is True
    assert json.loads(result["content"][0]["text"])["error"]["code"] == "denied"


def test_the_serve_process_principal_does_not_reach_http_mcp(
    config, conn, store, clean, monkeypatch
):
    """SHOC_MCP_ROLE is for stdio. Over HTTP it would make every caller an admin."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    monkeypatch.setenv("SHOC_MCP_ROLE", "admin")
    with TestClient(build_app(config), base_url=LOCAL) as client:
        tools = {t["name"] for t in _mcp(client, "tools/list")["result"]["tools"]}
    assert "action_approve" not in tools


def test_mcp_over_http_checks_the_token_and_takes_its_principal(
    config, conn, store, clean, monkeypatch
):
    from shoc.api.mcp import tool_definitions
    from shoc.capabilities.registry import Caller

    monkeypatch.setenv("SHOC_MCP_ROLE", "admin")
    monkeypatch.setenv(
        "SHOC_TOKENS",
        json.dumps({"tok-read": {"kind": "service", "id": "ci", "scopes": ["findings:read"]}}),
    )
    listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    with TestClient(build_app(config), base_url=LOCAL) as client:
        assert client.post("/mcp/", headers=MCP_HEADERS, json=listing).status_code == 401
        wrong = {**MCP_HEADERS, "authorization": "Bearer wrong"}
        assert client.post("/mcp/", headers=wrong, json=listing).status_code == 401
        elsewhere = {**MCP_HEADERS, "authorization": "Bearer tok-read", "x-shoc-tenant": "x"}
        assert client.post("/mcp/", headers=elsewhere, json=listing).status_code == 403

        client.headers["authorization"] = "Bearer tok-read"
        tools = {t["name"] for t in _mcp(client, "tools/list")["result"]["tools"]}
        token = Caller(kind="service", id="ci", scopes=("findings:read",))
        assert tools == {t["name"] for t in tool_definitions(token)}
        assert "finding_list" in tools and "action_approve" not in tools
        result = _mcp(client, "tools/call", {"name": "finding_list", "arguments": {}}, 2)
        body = json.loads(result["result"]["content"][0]["text"])
        assert set(body) == {"data", "summary", "citations"}


# -- limits -----------------------------------------------------------------
def test_an_oversized_body_is_refused_before_it_is_read(config, conn, store, clean):
    config.max_request_bytes = 1024
    with TestClient(build_app(config), base_url=LOCAL) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        resp = client.post(
            "/v1/finding/list", content=b"x" * 2048, headers={"content-type": "application/json"}
        )
        assert resp.status_code == 413
        assert "batches" in resp.json()["error"]["message"]


def test_the_ingest_endpoint_has_the_same_limit(config, conn, store, clean, monkeypatch):
    monkeypatch.setattr(config, "max_request_bytes", 1024)
    with TestClient(build_app(config), base_url=LOCAL) as client:
        client.headers["x-shoc-tenant"] = config.tenant_id
        assert client.post("/ingest/github", content=b"[]" + b" " * 2048).status_code == 413


def test_too_many_records_in_one_call_is_refused(ctx, config, clean, monkeypatch):
    from shoc.capabilities.registry import call
    from shoc.errors import ValidationError

    # The config is the session's; a limit left behind breaks later ingests.
    monkeypatch.setattr(config, "max_ingest_records", 3)
    with pytest.raises(ValidationError, match="the limit is 3"):
        call("events.ingest", ctx, {"source": "github", "records": [{}, {}, {}, {}]})


def test_the_store_sets_a_statement_timeout(config, conn, store):
    if store.dialect != "postgres":
        pytest.skip("postgres-specific")
    with store.conn.cursor() as cur:
        cur.execute("SHOW statement_timeout")
        row = cur.fetchone()
    assert row and row["statement_timeout"] not in ("0", ""), (
        "one runaway query must not pin the database"
    )


@pytest.mark.parametrize(
    "path,body",
    [
        ("/v1/health/status", {}),
        ("/v1/health/sources", {}),
        ("/v1/health/rules", {}),
        ("/v1/health/cost", {"days": 7}),
        ("/v1/ops/alerts", {}),
        ("/v1/case/list", {}),
        ("/v1/action/list", {}),
        ("/v1/playbook/list", {}),
        ("/v1/playbook/runs", {}),
        ("/v1/rule/list", {}),
        ("/v1/intel/list", {}),
        ("/v1/source/list", {}),
        ("/v1/policy/show", {}),
        ("/v1/capability/list", {}),
        ("/v1/stream/tail", {}),
        ("/v1/report/get", {"kind": "shift"}),
        ("/v1/hunt/suggest", {}),
        ("/v1/memory/search", {}),
        ("/v1/graph/neighbours", {"node": "user:nobody"}),
        ("/v1/events/query", {"since": "-1h"}),
        ("/v1/finding/list", {}),
        ("/v1/ask", {"question": "anything?"}),
        ("/v1/search", {"question": "anything?"}),
    ],
)
def test_every_read_capability_returns_serialisable_json(api, path, body):
    """A Decimal from Postgres broke health.status in production; nothing else may."""
    resp = api.post(path, json=body)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert set(payload) == {"data", "summary", "citations"}
    assert isinstance(payload["summary"], str)


def test_the_root_says_what_this_is_rather_than_404(api):
    """shoc is headless; opening it in a browser should explain that, not 404."""
    resp = api.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "shoc"
    assert "no web UI" in body["description"]
    assert body["endpoints"]["openapi"].endswith("/v1/openapi.json")
    assert body["endpoints"]["mcp"].endswith("/mcp")
    assert body["capabilities"] == len(all_capabilities())


def test_the_browsable_endpoints_are_get_requests(api):
    for path in ("/healthz", "/metrics", "/v1/openapi.json", "/"):
        assert api.get(path).status_code == 200, path
