"""Tokens issued through the registry: hashed, revocable, and the end of single-user mode (RFC 0019)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from shoc.api import auth
from shoc.api.rest import build_app
from shoc.capabilities.registry import call
from shoc.db.pool import execute, fetch_all
from shoc.errors import Denied, Unauthenticated

pytestmark = pytest.mark.postgres


@pytest.fixture
def issuing(config, conn, clean, monkeypatch):
    """Each test starts in single-user mode and leaves it that way for the next."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)

    def forget() -> None:
        execute(conn, "DELETE FROM shoc.api_tokens WHERE tenant_id = %s", (config.tenant_id,))
        auth._issued = False

    forget()
    yield
    forget()


def bearer(token: str, host: str = "shoc.example.com") -> dict[str, str]:
    return {"host": host, "authorization": f"Bearer {token}"}


def test_a_token_is_shown_once_and_kept_as_a_hash(ctx, config, conn, issuing):
    out = call("token.create", ctx, {"who": "alice", "role": "operator"}).data
    assert out.token.startswith("shoc_") and out.token_id.startswith("tok_")
    rows = fetch_all(
        conn, "SELECT * FROM shoc.api_tokens WHERE tenant_id = %s", (config.tenant_id,)
    )
    assert len(rows) == 1 and out.token not in str(rows[0])
    listed = call("token.list", ctx, {}).data.tokens
    assert [t["who"] for t in listed] == ["alice"] and "hash" not in listed[0]


def test_a_stored_token_is_its_role_on_its_tenant(ctx, config, issuing):
    token = call("token.create", ctx, {"who": "alice", "role": "operator"}).data.token
    caller, tenant = auth.authenticate(bearer(token), "default", config)
    assert (caller.kind, caller.id, caller.scopes) == ("human", "alice", auth.ROLES["operator"])
    assert tenant == config.tenant_id
    with pytest.raises(Denied, match="tenant"):
        auth.authenticate({**bearer(token), "x-shoc-tenant": "other"}, "default", config)


def test_a_machine_token_carries_its_scopes_only(ctx, config, issuing):
    token = call(
        "token.create", ctx, {"who": "ci", "kind": "service", "scopes": ["events:write"]}
    ).data.token
    caller, _ = auth.authenticate(bearer(token), "default", config)
    assert caller.kind == "service" and caller.allows("events:write")
    assert not caller.allows("findings:read")


def test_a_token_needs_a_role_or_scopes(ctx, issuing):
    from shoc.errors import ValidationError

    for payload in ({"who": "x"}, {"who": "", "role": "reader"}, {"who": "x", "role": "root"}):
        with pytest.raises(ValidationError):
            call("token.create", ctx, payload)


def test_revoking_or_expiry_ends_a_token_on_the_next_request(ctx, config, conn, issuing):
    token = call("token.create", ctx, {"who": "alice", "role": "reader"}).data
    auth.authenticate(bearer(token.token), "default", config)
    call("token.revoke", ctx, {"token_id": token.token_id})
    with pytest.raises(Unauthenticated, match="unknown or revoked token"):
        auth.authenticate(bearer(token.token), "default", config)

    later = call("token.create", ctx, {"who": "bob", "role": "reader", "expires_days": 1}).data
    execute(
        conn,
        "UPDATE shoc.api_tokens SET expires_at = now() - interval '1 minute' WHERE token_id = %s",
        (later.token_id,),
    )
    with pytest.raises(Unauthenticated, match="unknown or revoked token"):
        auth.authenticate(bearer(later.token), "default", config)
    assert [t["token_id"] for t in call("token.list", ctx, {}).data.tokens] == []
    assert len(call("token.list", ctx, {"revoked": True}).data.tokens) == 2


def test_the_first_token_ends_single_user_mode_for_good(ctx, config, issuing, monkeypatch):
    """Principle 5: revoking every token must lock the API, not open it again."""
    monkeypatch.delenv("SHOC_BIND", raising=False)
    local = {"host": "127.0.0.1:8080"}
    assert auth.authenticate(local, "default", config)[0] is auth.SINGLE_USER
    token = call("token.create", ctx, {"who": "rettila", "role": "admin"}).data
    auth.check_bind("0.0.0.0", config)
    call("token.revoke", ctx, {"token_id": token.token_id})
    auth._issued = False  # a fresh process asks the table again
    with pytest.raises(Unauthenticated, match="no credential"):
        auth.authenticate(local, "default", config)
    auth.check_bind("0.0.0.0", config)


def test_rest_takes_a_stored_token(ctx, config, store, issuing):
    token = call("token.create", ctx, {"who": "rita", "role": "reader"}).data.token
    with TestClient(build_app(config), base_url="https://shoc.example.com") as client:
        assert client.post("/v1/finding/list", json={}).status_code == 401
        answer = client.post(
            "/v1/finding/list", json={}, headers={"authorization": f"Bearer {token}"}
        )
        assert answer.status_code == 200, answer.text
        denied = client.post(
            "/v1/token/create",
            json={"who": "x", "role": "admin"},
            headers={"authorization": f"Bearer {token}"},
        )
        assert denied.status_code == 403
