"""Bearer tokens, principals, scopes and tenants on the generated surfaces."""

from __future__ import annotations

import json

import pytest

from shoc.api.auth import ROLES, SINGLE_USER, authenticate, check_bind, token_table
from shoc.errors import ConfigError, Denied, Unauthenticated

TOKENS = {
    "sk-ci": {"kind": "service", "id": "ci", "scopes": ["events:write"]},
    "sk-bot": {"kind": "external_agent", "id": "bot", "scopes": ["findings:read"]},
    "sk-acme": {"kind": "human", "id": "ann", "scopes": ["*"], "tenant": "acme"},
    "sk-alice": {"role": "operator", "id": "alice"},
    "sk-dan": {"role": "deployer", "id": "dan"},
    "sk-rita": {"role": "reader", "id": "rita"},
}


def caller_for(authorization: str | None, tenant: str | None = None):
    headers = {"host": "127.0.0.1:8080"}
    if authorization is not None:
        headers["authorization"] = authorization
    if tenant:
        headers["x-shoc-tenant"] = tenant
    return authenticate(headers, "default")


def test_with_no_tokens_configured_it_is_single_user(monkeypatch):
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    assert caller_for(None) == (SINGLE_USER, "default")
    assert caller_for(None, "other") == (SINGLE_USER, "other")
    assert SINGLE_USER.kind == "human" and SINGLE_USER.allows("anything:at:all")


@pytest.mark.parametrize(
    "headers",
    [
        {"host": "localhost"},
        {"host": "localhost:8080", "origin": "http://localhost:5173"},
        {"host": "[::1]:8080", "origin": "http://127.0.0.1:8080"},
    ],
)
def test_single_user_mode_answers_this_machine(monkeypatch, headers):
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    assert authenticate(headers, "default") == (SINGLE_USER, "default")


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"host": "shoc.example.com"},
        {"host": "attacker.example:8080"},
        {"host": "[::1"},
        {"host": "127.0.0.1:8080", "x-forwarded-for": "203.0.113.7"},
        {"host": "127.0.0.1:8080", "forwarded": "for=203.0.113.7"},
        {"host": "127.0.0.1:8080", "x-real-ip": "203.0.113.7"},
        {"host": "127.0.0.1:8080", "origin": "https://attacker.example"},
        {"host": "127.0.0.1:8080", "origin": "null"},
    ],
)
def test_single_user_mode_refuses_proxies_and_web_pages(monkeypatch, headers):
    """Principle 5: a proxy or a web page reaching loopback is not the operator."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    with pytest.raises(Denied):
        authenticate(headers, "default")


def test_a_configured_token_becomes_its_principal(monkeypatch):
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(TOKENS))
    caller, tenant = caller_for("Bearer sk-ci")
    assert caller.kind == "service" and caller.id == "ci" and tenant == "default"
    assert caller.allows("events:write") and not caller.allows("actions:approve")


def test_a_missing_or_wrong_token_is_unauthenticated(monkeypatch):
    """401, not 403: the caller is unknown, not short of a permission."""
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(TOKENS))
    for header in (None, "", "Basic sk-ci", "Bearer nope", "Bearer sk-c"):
        with pytest.raises(Unauthenticated) as refused:
            caller_for(header)
        assert (refused.value.status, refused.value.code) == (401, "unauthenticated")


def test_token_matching_is_not_a_prefix_match(monkeypatch):
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(TOKENS))
    with pytest.raises(Unauthenticated):
        caller_for("Bearer sk-cix")


def test_a_broken_token_table_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("SHOC_TOKENS", "{not json")
    with pytest.raises(Denied, match="not valid JSON"):
        token_table()


def test_a_token_without_scopes_can_do_nothing(monkeypatch):
    """A forgotten `scopes` field used to become every scope."""
    monkeypatch.setenv("SHOC_TOKENS", json.dumps({"sk-x": {"kind": "service", "id": "x"}}))
    caller = caller_for("Bearer sk-x")[0]
    assert not caller.allows("events:write") and not caller.allows("findings:read")


def test_an_unknown_kind_or_role_is_refused(monkeypatch):
    monkeypatch.setenv(
        "SHOC_TOKENS",
        json.dumps(
            {
                "sk-k": {"kind": "humam", "id": "k", "scopes": ["*"]},
                "sk-r": {"role": "root", "id": "r"},
            }
        ),
    )
    for token in ("sk-k", "sk-r"):
        with pytest.raises(Denied, match="unknown"):
            caller_for(f"Bearer {token}")


def test_a_role_token_is_a_human_with_that_role(monkeypatch):
    """RFC 0018: the four roles, and which of them may approve or configure."""
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(TOKENS))
    alice, dan, rita = (caller_for(f"Bearer sk-{n}")[0] for n in ("alice", "dan", "rita"))
    assert {alice.kind, dan.kind, rita.kind} == {"human"}
    assert alice.id == "alice" and alice.scopes == ROLES["operator"]
    assert alice.allows("actions:approve") and alice.allows("actions:run")
    assert not alice.allows("config:write") and not alice.allows("actions:configure")
    assert dan.allows("config:write") and dan.allows("actions:configure")
    assert not dan.allows("actions:approve") and not dan.allows("actions:run")
    for caller in (alice, dan, rita):
        assert caller.allows("findings:read") and caller.allows("audit:read")
        assert not caller.allows("events:write")
    assert not any(rita.allows(s) for s in ("cases:write", "memory:write", "intel:write"))


def test_a_token_acts_on_its_own_tenant_only(monkeypatch):
    """SEC-1: the tenant header cannot move a token onto another tenant."""
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(TOKENS))
    assert caller_for("Bearer sk-acme")[1] == "acme"
    assert caller_for("Bearer sk-acme", "acme")[1] == "acme"
    assert caller_for("Bearer sk-ci", "default")[1] == "default"
    with pytest.raises(Denied, match="tenant"):
        caller_for("Bearer sk-acme", "default")
    with pytest.raises(Denied, match="tenant"):
        caller_for("Bearer sk-ci", "acme")


def test_serve_refuses_single_user_mode_off_loopback(monkeypatch):
    """Principle 5: without tokens, reaching the port would be enough to approve."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    monkeypatch.delenv("SHOC_BIND", raising=False)
    for host in ("127.0.0.1", "localhost", "::1", "127.0.0.2"):
        check_bind(host)
    for host in ("0.0.0.0", "::", "192.0.2.10", "shoc.example.com"):
        with pytest.raises(ConfigError, match="SHOC_TOKENS"):
            check_bind(host)


def test_under_compose_the_published_address_is_the_one_checked(monkeypatch):
    """serve listens on 0.0.0.0 in its container; SHOC_BIND is what others reach."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    monkeypatch.setenv("SHOC_BIND", "127.0.0.1")
    check_bind("0.0.0.0")
    for published in ("100.64.0.7", "0.0.0.0"):
        monkeypatch.setenv("SHOC_BIND", published)
        with pytest.raises(ConfigError, match=published):
            check_bind("0.0.0.0")


def test_serve_binds_anywhere_once_tokens_are_set(monkeypatch):
    monkeypatch.setenv("SHOC_BIND", "0.0.0.0")
    monkeypatch.setenv("SHOC_TOKENS", json.dumps(TOKENS))
    check_bind("0.0.0.0")


def test_the_serve_command_checks_the_bind_before_it_listens(monkeypatch, capsys):
    import uvicorn

    from shoc.cli import main

    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    monkeypatch.delenv("SHOC_BIND", raising=False)
    monkeypatch.delenv("SHOC_DSN", raising=False)  # no stored tokens to consult
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("serve started"))
    assert main(["serve", "--host", "0.0.0.0"]) == 1
    assert "SHOC_TOKENS" in capsys.readouterr().err
