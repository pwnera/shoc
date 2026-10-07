"""People sign in through a browser: accounts, links, sessions and SSO (SEC-3, RFC 0028).

Each test starts with no token and no account in its tenant, so single-user
mode is back on for the tests after it. The browser is a TestClient on
https://shoc.example.com, which is also SHOC_PUBLIC_URL, so the session cookie
is `__Host-shoc_session` and the client's cookie jar sends it back. Mail, the
identity provider and the clock the routes read are replaced by fakes.
"""

from __future__ import annotations

import base64
import hashlib
import re
import threading
import time
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.requests import Request
from starlette.testclient import TestClient

from shoc import mail
from shoc.api import auth, credentials, oidc, people, signin
from shoc.api.rest import build_app
from shoc.capabilities.registry import call
from shoc.config import Config
from shoc.db.pool import execute, fetch_all, fetch_one
from shoc.errors import ConfigError, Conflict, Unauthenticated, ValidationError
from tests.support import audit_seq

pytestmark = pytest.mark.postgres

PUBLIC = "https://shoc.example.com"
COOKIE = "__Host-shoc_session"
SSO_COOKIE = "__Host-shoc_sso"
PASSWORD = "correct horse battery"
NEW_PASSWORD = "a brand new passphrase"
ISSUER = "https://idp.example.com"
CLIENT = "shoc-client"
MS_TENANT = "11111111-2222-3333-4444-555555555555"


# -- fixtures --------------------------------------------------------------------
@pytest.fixture
def signing(config, conn, clean, monkeypatch):
    """No token, no account and empty throttles before and after each test."""
    monkeypatch.delenv("SHOC_TOKENS", raising=False)
    monkeypatch.delenv("SHOC_BIND", raising=False)
    monkeypatch.setattr(config, "public_url", PUBLIC)
    monkeypatch.setattr(config, "smtp_url", "")
    monkeypatch.setattr(config, "mail_from", "")

    def forget() -> None:
        for table in ("user_links", "users", "sso_providers", "api_tokens"):
            execute(conn, f"DELETE FROM shoc.{table} WHERE tenant_id = %s", (config.tenant_id,))
        auth._issued = False
        signin.ADDRESSES._hits.clear()
        signin.WRONG_PASSWORDS._hits.clear()

    forget()
    yield
    forget()


class Clock:
    """The time the sign-in routes read, moved one 30-second step at a time."""

    def __init__(self) -> None:
        self.now = (time.time() // 30) * 30 + 1

    def time(self) -> float:
        return self.now

    def advance(self) -> None:
        self.now += 30

    def code(self, seed: bytes, ahead: int = 0) -> str:
        return credentials._code(seed, int(self.now // 30) + ahead)

    def wrong(self, seed: bytes) -> str:
        """A code no step in the window has."""
        right = {self.code(seed, d) for d in (-1, 0, 1)}
        return next(c for c in ("000000", "111111", "222222", "333333") if c not in right)


@pytest.fixture
def clock(monkeypatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(signin, "time", SimpleNamespace(time=c.time, monotonic=time.monotonic))
    return c


class Mailbox:
    """Mail as it would leave: captured, never sent. Off until `enable`."""

    def __init__(self, config, monkeypatch) -> None:
        self.sent: list[tuple[str, str, str]] = []
        self.arrived = threading.Event()
        self.done = threading.Event()
        self._config, self._monkeypatch = config, monkeypatch

    def send(self, cfg, to: str, subject: str, body: str) -> None:
        self.sent.append((to, subject, body))
        self.arrived.set()

    def enable(self) -> None:
        smtp = "smtps://mailer:pw@mail.example.com:465"
        self._monkeypatch.setattr(self._config, "smtp_url", smtp)
        self._monkeypatch.setattr(self._config, "mail_from", "shoc@example.com")

    def forgot(self, browser: TestClient, email: str) -> httpx.Response:
        """POST /auth/forgot and wait for its background thread to finish."""
        self.done.clear()
        answer = browser.post("/auth/forgot", json={"email": email})
        if answer.status_code == 200 and answer.json().get("sent"):
            assert self.done.wait(10), "the forgot-password thread did not finish"
        return answer

    def link(self, index: int = -1) -> str:
        match = re.search(r"/welcome#(shoc_link_[\w-]+)", self.sent[index][2])
        assert match, self.sent[index][2]
        return match.group(1)


@pytest.fixture
def mailbox(config, monkeypatch) -> Mailbox:
    box = Mailbox(config, monkeypatch)
    monkeypatch.setattr(mail, "send", box.send)
    original = signin._forgot

    def tracked(*args: Any) -> None:
        try:
            original(*args)
        finally:
            box.done.set()

    monkeypatch.setattr(signin, "_forgot", tracked)
    return box


@pytest.fixture
def browser(config, store, signing, clock, mailbox):
    # The peer is in a trusted network, as the console's proxy is, so the
    # X-Forwarded-For a test sends is the client address the throttles see.
    with TestClient(build_app(config), base_url=PUBLIC, client=("172.18.0.9", 50000)) as client:
        client.headers["origin"] = PUBLIC
        yield client


# -- helpers ---------------------------------------------------------------------
def link_of(out: Any) -> str:
    assert out.link.startswith(f"{PUBLIC}/welcome#shoc_link_"), out.link
    return out.link.rpartition("#")[2]


def enrol(browser: TestClient, ctx, clock: Clock, email: str, role: str = "operator") -> bytes:
    """Invite, open the link and accept it, as /welcome does. Returns the authenticator's seed."""
    link = link_of(call("user.invite", ctx, {"email": email, "role": role}).data)
    assert browser.post("/auth/link", json={"link": link}).status_code == 200
    seed = credentials.link_seed(ctx.config.master_key, link)
    accepted = browser.post(
        "/auth/link/accept", json={"link": link, "password": PASSWORD, "code": clock.code(seed)}
    )
    assert accepted.status_code == 200, accepted.text
    return seed


def login(
    browser: TestClient,
    clock: Clock,
    email: str,
    seed: bytes,
    password: str = PASSWORD,
    code: str | None = None,
    **headers: str,
) -> httpx.Response:
    """Sign in with the next step's code unless given one."""
    if code is None:
        clock.advance()
        code = clock.code(seed)
    body = {"email": email, "password": password, "code": code}
    return browser.post("/auth/login", json=body, headers=headers)


def me(browser: TestClient, **headers: str) -> httpx.Response:
    return browser.post("/v1/user/me", json={}, headers=headers)


def error(answer: httpx.Response) -> str:
    return answer.json()["error"]["code"]


def audited(conn, tenant: str, after: int, capability: str) -> list[str]:
    rows = fetch_all(
        conn,
        """SELECT principal_kind || ':' || principal_id AS who FROM shoc.audit_log
           WHERE tenant_id = %s AND seq > %s AND capability = %s ORDER BY seq""",
        (tenant, after, capability),
    )
    return [r["who"] for r in rows]


def user_row(conn, tenant: str, email: str) -> dict[str, Any]:
    row = fetch_one(
        conn,
        """SELECT *, extract(epoch FROM locked_until - now()) AS locked_for
           FROM shoc.users WHERE tenant_id = %s AND email = %s""",
        (tenant, email),
    )
    assert row is not None
    return row


def an_admin_token(ctx) -> str:
    return call("token.create", ctx, {"who": "root", "role": "admin"}).data.token


# -- invitation, password and code -------------------------------------------------
def test_an_invitation_enrols_the_person_and_signs_the_browser_in(browser, ctx, clock, conn):
    tenant = ctx.tenant_id
    before = audit_seq(conn, tenant)
    out = call("user.invite", ctx, {"email": "Ann@Example.com", "role": "admin"}).data
    assert (out.email, out.role, out.emailed) == ("ann@example.com", "admin", False)
    link = link_of(out)
    stored = fetch_one(conn, "SELECT hash FROM shoc.user_links WHERE tenant_id = %s", (tenant,))
    assert stored and stored["hash"] == credentials.digest(link)

    opened = browser.post("/auth/link", json={"link": link})
    assert opened.headers["cache-control"] == "no-store"
    seed = credentials.link_seed(ctx.config.master_key, link)
    assert opened.json() == {
        "email": "ann@example.com",
        "enrol": True,
        "otpauth": credentials.otpauth(seed, "ann@example.com"),
    }
    assert browser.cookies.get(COOKIE) is None

    accepted = browser.post(
        "/auth/link/accept", json={"link": link, "password": PASSWORD, "code": clock.code(seed)}
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json() == {"email": "ann@example.com"}
    set_cookie = accepted.headers["set-cookie"].lower()
    assert set_cookie.startswith(COOKIE.lower() + "=")
    for part in ("httponly", "secure", "samesite=strict", "path=/", "max-age=43200"):
        assert part in set_cookie
    assert browser.cookies.get(COOKIE)

    answer = me(browser)
    assert answer.status_code == 200, answer.text
    data = answer.json()["data"]
    assert (data["id"], data["kind"], data["role"]) == ("ann@example.com", "human", "admin")
    assert (data["email"], data["tenant"]) == ("ann@example.com", tenant)

    # The link is spent, and nothing secret is kept in clear.
    assert browser.post("/auth/link", json={"link": link}).status_code == 410
    row = user_row(conn, tenant, "ann@example.com")
    assert row["password_hash"].startswith("scrypt$32768$8$1$")
    assert PASSWORD not in row["password_hash"] and seed not in bytes(row["secret"])
    assert row["last_login_at"] is not None
    assert audited(conn, tenant, before, "auth.link_accepted") == ["human:ann@example.com"]
    listed = call("user.list", ctx, {}).data.users
    assert [(u["email"], u["method"]) for u in listed] == [("ann@example.com", "password")]
    assert not {"password_hash", "secret", "totp_step"} & set(listed[0])


def test_a_weak_password_is_refused_and_the_link_still_works(browser, ctx, clock):
    link = link_of(call("user.invite", ctx, {"email": "ann@example.com"}).data)
    seed = credentials.link_seed(ctx.config.master_key, link)
    for password in ("too short", "ANN@example.com"):
        answer = browser.post(
            "/auth/link/accept", json={"link": link, "password": password, "code": clock.code(seed)}
        )
        assert answer.status_code == 400 and error(answer) == "validation_error"
    assert browser.post("/auth/link", json={"link": link}).status_code == 200


def test_password_and_code_sign_in(browser, ctx, clock, conn):
    seed = enrol(browser, ctx, clock, "ann@example.com", role="admin")
    browser.cookies.clear()
    assert me(browser).status_code == 401  # no credential, and single-user mode is over
    before = audit_seq(conn, ctx.tenant_id)
    answer = login(browser, clock, "ann@example.com", seed)
    assert answer.status_code == 200, answer.text
    assert answer.json() == {"email": "ann@example.com"}
    assert answer.headers["cache-control"] == "no-store"
    assert me(browser).json()["data"]["role"] == "admin"
    assert audited(conn, ctx.tenant_id, before, "auth.signin") == ["human:ann@example.com"]
    # The email is matched whatever its case.
    browser.cookies.clear()
    assert login(browser, clock, "ANN@example.com", seed).status_code == 200


def test_a_code_works_once(browser, ctx, clock):
    seed = enrol(browser, ctx, clock, "ann@example.com")
    browser.cookies.clear()
    clock.advance()
    code = clock.code(seed)
    assert login(browser, clock, "ann@example.com", seed, code=code).status_code == 200
    browser.cookies.clear()
    replayed = login(browser, clock, "ann@example.com", seed, code=code)
    assert replayed.status_code == 401 and error(replayed) == "bad_credentials"
    # The step before the last accepted one is no good either.
    older = login(browser, clock, "ann@example.com", seed, code=clock.code(seed, -1))
    assert older.status_code == 401
    assert browser.cookies.get(COOKIE) is None


def test_a_lock_set_meanwhile_stops_a_right_code(browser, ctx, clock, conn):
    enrol(browser, ctx, clock, "ann@example.com")
    row = user_row(conn, ctx.tenant_id, "ann@example.com")
    lock = """UPDATE shoc.users SET locked_until = now() + %s * interval '1 minute'
              WHERE tenant_id = %s AND user_id = %s"""
    step = row["totp_step"] + 1
    execute(conn, lock, (15, ctx.tenant_id, row["user_id"]))
    assert not people.advance_step(conn, ctx.tenant_id, row["user_id"], step)
    execute(conn, lock, (-1, ctx.tenant_id, row["user_id"]))
    assert people.advance_step(conn, ctx.tenant_id, row["user_id"], step)


def test_five_wrong_codes_lock_the_account_and_the_lock_doubles(browser, ctx, clock, conn, mailbox):
    email, tenant = "ann@example.com", ctx.tenant_id
    seed = enrol(browser, ctx, clock, email)
    browser.cookies.clear()
    mailbox.enable()
    before = audit_seq(conn, tenant)
    wrong_password = login(browser, clock, email, seed, password="not the password")
    assert wrong_password.status_code == 401
    for _ in range(5):
        answer = login(browser, clock, email, seed, code=clock.wrong(seed))
        # A wrong code answers exactly as a wrong password does.
        assert answer.status_code == 401 and answer.json() == wrong_password.json()
    row = user_row(conn, tenant, email)
    assert row["code_failures"] == 5 and 14 * 60 < row["locked_for"] <= 15 * 60
    assert audited(conn, tenant, before, "auth.locked") == [f"human:{email}"]
    assert mailbox.arrived.wait(10)
    assert [(to, subject) for to, subject, _ in mailbox.sent] == [
        (email, "Your shoc account is locked")
    ]

    # The right password and code still get the same answer while it is locked.
    locked = login(browser, clock, email, seed)
    assert locked.status_code == 401 and locked.json() == wrong_password.json()
    assert browser.cookies.get(COOKIE) is None

    execute(
        conn,
        """UPDATE shoc.users SET locked_until = now() - interval '1 second'
           WHERE tenant_id = %s AND email = %s""",
        (tenant, email),
    )
    for _ in range(5):
        assert login(browser, clock, email, seed, code=clock.wrong(seed)).status_code == 401
    row = user_row(conn, tenant, email)
    assert row["code_failures"] == 10 and 29 * 60 < row["locked_for"] <= 30 * 60

    # Only a completed sign-in resets the count.
    execute(
        conn,
        """UPDATE shoc.users SET locked_until = now() - interval '1 second'
           WHERE tenant_id = %s AND email = %s""",
        (tenant, email),
    )
    assert login(browser, clock, email, seed).status_code == 200
    row = user_row(conn, tenant, email)
    assert row["code_failures"] == 0 and row["locked_until"] is None


def test_wrong_passwords_are_throttled_and_never_lock(browser, ctx, clock, conn):
    email = "ann@example.com"
    seed = enrol(browser, ctx, clock, email)
    browser.cookies.clear()
    for _ in range(10):
        answer = login(browser, clock, email, seed, password="not the password")
        assert answer.status_code == 401 and error(answer) == "bad_credentials"
    throttled = login(browser, clock, email, seed, password="not the password")
    assert throttled.status_code == 429 and error(throttled) == "slow_down"
    assert throttled.headers["retry-after"] == "900"
    # Throttled per account and address: the right password waits too here...
    assert login(browser, clock, email, seed).status_code == 429
    # ...but the account is not locked, and another address signs in.
    row = user_row(conn, ctx.tenant_id, email)
    assert row["code_failures"] == 0 and row["locked_until"] is None
    elsewhere = login(browser, clock, email, seed, **{"x-forwarded-for": "198.51.100.7"})
    assert elsewhere.status_code == 200, elsewhere.text
    browser.cookies.clear()
    signin.WRONG_PASSWORDS._hits.clear()
    assert login(browser, clock, email, seed).status_code == 200


def test_an_unknown_email_answers_like_a_wrong_password(browser, ctx, clock):
    seed = enrol(browser, ctx, clock, "ann@example.com")
    browser.cookies.clear()
    wrong = login(browser, clock, "ann@example.com", seed, password="not the password")
    unknown = login(browser, clock, "nobody@example.com", seed)
    invited = call("user.invite", ctx, {"email": "bob@example.com"}).data
    assert invited.link  # invited, no password yet
    pending = login(browser, clock, "bob@example.com", seed)
    garbled = login(browser, clock, "not an email", seed)
    for answer in (unknown, pending, garbled):
        assert answer.status_code == 401 and answer.json() == wrong.json()


# -- what a browser may send ---------------------------------------------------------
def test_sign_in_posts_must_be_json_from_the_console(browser):
    body = {"email": "ann@example.com", "password": PASSWORD, "code": "000000"}
    refused = [
        browser.post("/auth/login", json=body, headers={"origin": "https://evil.example"}),
        browser.post("/auth/login", json=body, headers={"origin": f"{PUBLIC}:8443"}),
        browser.post("/auth/login", json=body, headers={"origin": "http://shoc.example.com"}),
        browser.post("/auth/login", json=body, headers={"origin": "null"}),
        browser.post(
            "/auth/login",
            content=b'{"email": "ann@example.com"}',
            headers={"content-type": "text/plain"},
        ),
        browser.post(
            "/auth/login",
            content=b"email=ann%40example.com",
            headers={"content-type": "application/x-www-form-urlencoded"},
        ),
    ]
    del browser.headers["origin"]
    refused.append(browser.post("/auth/login", json=body))
    for answer in refused:
        assert answer.status_code == 403 and error(answer) == "cross_site"
        assert answer.headers["cache-control"] == "no-store"


def test_a_body_over_the_limit_is_refused(browser):
    big = b'{"email": "' + b"a" * signin.MAX_BODY + b'"}'
    json_type = {"content-type": "application/json"}
    declared = browser.post("/auth/login", content=big, headers=json_type)
    streamed = browser.post("/auth/login", content=iter([big]), headers=json_type)  # chunked
    for answer in (declared, streamed):
        assert answer.status_code == 413 and error(answer) == "payload_too_large"


def test_a_cookie_post_must_be_json_from_the_console(browser, ctx, clock):
    enrol(browser, ctx, clock, "ann@example.com", role="reader")
    assert me(browser).status_code == 200
    for headers in (
        {"origin": "https://evil.example"},
        {"origin": "http://shoc.example.com"},
        {"origin": f"{PUBLIC}:8443"},
    ):
        answer = me(browser, **headers)
        assert answer.status_code == 403 and error(answer) == "cross_site"
        assert f"Origin {headers['origin']} is not {PUBLIC}" in answer.json()["error"]["message"]
    as_text = browser.post("/v1/user/me", content=b"{}", headers={"content-type": "text/plain"})
    assert as_text.status_code == 403 and error(as_text) == "cross_site"
    assert "Content-Type: application/json" in as_text.json()["error"]["message"]
    del browser.headers["origin"]
    assert error(me(browser)) == "cross_site"

    # A bearer token is not sent by the browser on its own, so it needs no Origin.
    token = an_admin_token(ctx)
    browser.cookies.clear()
    answer = browser.post("/v1/user/me", json={}, headers={"authorization": f"Bearer {token}"})
    assert answer.status_code == 200 and answer.json()["data"]["id"] == "root"


def test_sign_in_needs_a_public_url(browser, ctx, clock, config, monkeypatch):
    enrol(browser, ctx, clock, "ann@example.com")
    monkeypatch.setattr(config, "public_url", "")
    for path in (
        "/auth/start",
        "/auth/login",
        "/auth/token",
        "/auth/link",
        "/auth/link/accept",
        "/auth/forgot",
        "/auth/logout",
    ):
        answer = browser.post(path, json={})
        assert answer.status_code == 503 and error(answer) == "sign_in_not_configured", path
    # Without it, no cookie is read at all.
    assert me(browser).status_code == 401


def test_a_cookie_with_no_live_session_is_signed_out(browser, ctx):
    call("user.invite", ctx, {"email": "ann@example.com"})
    answer = me(browser, cookie=f"{COOKIE}=shoc_not-a-session")
    assert answer.status_code == 401 and error(answer) == "signed_out"
    two = me(browser, cookie=f"{COOKIE}=shoc_one; {COOKIE}=shoc_two")
    assert two.status_code == 403


def test_signing_out_revokes_the_session(browser, ctx, clock, conn):
    enrol(browser, ctx, clock, "ann@example.com")
    value = browser.cookies.get(COOKIE)
    assert value
    answer = browser.post("/auth/logout", json={})
    assert answer.status_code == 200 and answer.json() == {"signed_out": True}
    assert browser.cookies.get(COOKIE) is None
    gone = me(browser, cookie=f"{COOKIE}={value}")
    assert gone.status_code == 401 and error(gone) == "signed_out"
    row = fetch_one(
        conn,
        "SELECT revoked_at, revoked_by FROM shoc.api_tokens WHERE hash = %s",
        (credentials.digest(value),),
    )
    assert row and row["revoked_at"] is not None and row["revoked_by"] == "sign-out"


def test_a_session_acts_on_its_own_tenant_only(browser, ctx, clock):
    enrol(browser, ctx, clock, "ann@example.com")
    assert me(browser, **{"x-shoc-tenant": ctx.tenant_id}).status_code == 200
    elsewhere = me(browser, **{"x-shoc-tenant": "someone-else"})
    assert elsewhere.status_code == 403 and error(elsewhere) == "denied"


def test_a_session_is_a_token_row_that_token_list_leaves_out(browser, ctx, clock, conn):
    enrol(browser, ctx, clock, "ann@example.com")
    assert call("token.list", ctx, {"revoked": True}).data.tokens == []
    rows = fetch_all(
        conn,
        """SELECT who, role, kind, user_id, created_by,
                  extract(epoch FROM expires_at - now()) AS lasts
           FROM shoc.api_tokens WHERE tenant_id = %s""",
        (ctx.tenant_id,),
    )
    assert len(rows) == 1
    row = rows[0]
    assert (row["who"], row["role"], row["kind"]) == ("ann@example.com", None, "human")
    assert row["user_id"].startswith("usr_") and row["created_by"] == "sign-in"
    assert 11.9 * 3600 < row["lasts"] <= 12 * 3600
    token = call("token.create", ctx, {"who": "ci", "scopes": ["events:write"]}).data
    assert [t["token_id"] for t in call("token.list", ctx, {}).data.tokens] == [token.token_id]


# -- what an admin changes takes effect on the next request ----------------------------
def test_a_role_change_applies_on_the_next_request(browser, ctx, clock):
    enrol(browser, ctx, clock, "ann@example.com", role="admin")
    an_admin_token(ctx)  # so ann is not the last admin
    invited = browser.post("/v1/user/invite", json={"email": "dan@example.com"})
    assert invited.status_code == 200, invited.text
    call("user.update", ctx, {"email": "ann@example.com", "role": "reader"})
    data = me(browser).json()["data"]
    assert (data["role"], data["email"]) == ("reader", "ann@example.com")
    refused = browser.post("/v1/user/invite", json={"email": "eve@example.com"})
    assert refused.status_code == 403 and error(refused) == "denied"


def test_disabling_a_person_ends_their_sessions_links_and_role_tokens(browser, ctx, clock, config):
    email = "bob@example.com"
    seed = enrol(browser, ctx, clock, email)
    old = browser.cookies.get(COOKIE)
    role_token = call("token.create", ctx, {"who": "Bob@Example.com", "role": "operator"}).data
    machine = call("token.create", ctx, {"who": email, "scopes": ["events:write"]}).data
    link = link_of(call("user.reset", ctx, {"email": email}).data)

    out = call("user.update", ctx, {"email": email, "disabled": True}).data
    assert out.disabled is True
    signed_out = me(browser)
    assert signed_out.status_code == 401 and error(signed_out) == "signed_out"
    with_token = browser.post(
        "/v1/user/me", json={}, headers={"authorization": f"Bearer {role_token.token}"}
    )
    assert with_token.status_code == 401
    assert browser.post("/auth/link", json={"link": link}).status_code == 410
    browser.cookies.clear()
    assert login(browser, clock, email, seed).status_code == 401
    # A machine token is not the person's way in, so it stays.
    host = {"host": "shoc.example.com", "authorization": f"Bearer {machine.token}"}
    assert auth.authenticate(host, "default", config)[0].kind == "service"
    assert [u["email"] for u in call("user.list", ctx, {}).data.users] == []
    assert [u["email"] for u in call("user.list", ctx, {"disabled": True}).data.users] == [email]

    # Enabled again: they sign in anew; nothing that ended comes back.
    call("user.update", ctx, {"email": email, "disabled": False})
    assert me(browser, cookie=f"{COOKIE}={old}").status_code == 401
    assert login(browser, clock, email, seed).status_code == 200


def test_the_last_admin_cannot_be_demoted_or_disabled(ctx, signing, monkeypatch):
    call("user.invite", ctx, {"email": "ann@example.com", "role": "admin"})
    with pytest.raises(ValidationError, match="last admin"):
        call("user.update", ctx, {"email": "ann@example.com", "role": "reader"})
    with pytest.raises(ValidationError, match="last admin"):
        call("user.update", ctx, {"email": "ann@example.com", "disabled": True})
    # An admin token issued to her own address does not count as someone else.
    call("token.create", ctx, {"who": "ann@example.com", "role": "admin"})
    with pytest.raises(ValidationError, match="last admin"):
        call("user.update", ctx, {"email": "ann@example.com", "role": "reader"})
    # SHOC_TOKENS' admin does.
    monkeypatch.setenv("SHOC_TOKENS", '{"break-glass": {"role": "admin", "id": "root"}}')
    out = call("user.update", ctx, {"email": "ann@example.com", "role": "reader"}).data
    assert (out.role, out.disabled) == ("reader", False)


def test_links_need_a_public_url_and_a_master_key(ctx, signing, config, monkeypatch):
    monkeypatch.setattr(config, "public_url", "")
    with pytest.raises(ConfigError, match="SHOC_PUBLIC_URL"):
        call("user.invite", ctx, {"email": "ann@example.com"})
    with pytest.raises(ConfigError, match="SHOC_PUBLIC_URL"):
        call("sso.configure", ctx, {"issuer": ISSUER, "client_id": CLIENT, "domains": ["x.io"]})
    assert call("user.list", ctx, {"disabled": True}).data.users == []
    monkeypatch.setattr(config, "public_url", PUBLIC)
    call("user.invite", ctx, {"email": "ann@example.com"})
    monkeypatch.setattr(config, "master_key", "")
    with pytest.raises(ConfigError, match="SHOC_MASTER_KEY"):
        call("user.reset", ctx, {"email": "ann@example.com"})


def test_one_address_has_one_account(ctx, signing, conn):
    call("user.invite", ctx, {"email": "ann@example.com"})
    with pytest.raises(Conflict, match="already has an account"):
        call("user.invite", ctx, {"email": "Ann@example.com"})
    # Two invitations at once: the second insert finds the first.
    with pytest.raises(Conflict, match="already has an account"):
        people.create(conn, ctx.tenant_id, "ann@example.com", "reader", "test")


# -- links ---------------------------------------------------------------------------
def test_a_reset_link_replaces_the_password_and_the_authenticator(browser, ctx, clock):
    email = "ann@example.com"
    old_seed = enrol(browser, ctx, clock, email)
    old_session = browser.cookies.get(COOKIE)
    out = call("user.reset", ctx, {"email": email}).data
    assert out.expires_at and not out.emailed
    link = link_of(out)
    new_seed = credentials.link_seed(ctx.config.master_key, link)
    assert new_seed != old_seed
    opened = browser.post("/auth/link", json={"link": link}).json()
    assert opened["enrol"] is True and opened["otpauth"] == credentials.otpauth(new_seed, email)

    clock.advance()
    accepted = browser.post(
        "/auth/link/accept",
        json={"link": link, "password": NEW_PASSWORD, "code": clock.code(new_seed)},
    )
    assert accepted.status_code == 200, accepted.text
    # Accepting it ends every other session the person had.
    assert me(browser, cookie=f"{COOKIE}={old_session}").status_code == 401
    assert me(browser).status_code == 200
    browser.cookies.clear()
    assert login(browser, clock, email, new_seed).status_code == 401  # the old password
    assert login(browser, clock, email, old_seed, password=NEW_PASSWORD).status_code == 401
    assert login(browser, clock, email, new_seed, password=NEW_PASSWORD).status_code == 200


def test_a_forgotten_password_link_keeps_the_authenticator(browser, ctx, clock, conn, mailbox):
    email = "ann@example.com"
    seed = enrol(browser, ctx, clock, email)
    browser.cookies.clear()
    mailbox.enable()
    assert mailbox.forgot(browser, email).json() == {"sent": True}
    assert [(to, s) for to, s, _ in mailbox.sent] == [(email, "Set a new shoc password")]
    link = mailbox.link()
    assert f"{PUBLIC}/welcome#{link}" in mailbox.sent[0][2]
    opened = browser.post("/auth/link", json={"link": link})
    assert opened.json() == {"email": email, "enrol": False, "otpauth": ""}

    # A wrong code on such a link counts against the account too.
    clock.advance()
    wrong = browser.post(
        "/auth/link/accept",
        json={"link": link, "password": NEW_PASSWORD, "code": clock.wrong(seed)},
    )
    assert wrong.status_code == 401 and error(wrong) == "bad_code"
    assert user_row(conn, ctx.tenant_id, email)["code_failures"] == 1

    # The code comes from the authenticator the person already has.
    accepted = browser.post(
        "/auth/link/accept", json={"link": link, "password": NEW_PASSWORD, "code": clock.code(seed)}
    )
    assert accepted.status_code == 200, accepted.text
    assert user_row(conn, ctx.tenant_id, email)["code_failures"] == 0
    browser.cookies.clear()
    assert login(browser, clock, email, seed).status_code == 401  # the old password
    assert login(browser, clock, email, seed, password=NEW_PASSWORD).status_code == 200


def test_forgot_answers_the_same_and_mails_only_an_account(browser, ctx, clock, mailbox):
    no_mail = browser.post("/auth/forgot", json={"email": "ann@example.com"})
    assert no_mail.status_code == 200 and no_mail.json() == {"sent": False}

    enrol(browser, ctx, clock, "ann@example.com")
    call("user.invite", ctx, {"email": "bob@example.com"})  # no password yet
    mailbox.enable()
    for email in ("nobody@example.com", "bob@example.com"):
        answer = mailbox.forgot(browser, email)
        assert answer.status_code == 200 and answer.json() == {"sent": True}
    assert mailbox.sent == []
    # One link per five minutes.
    assert mailbox.forgot(browser, "ann@example.com").json() == {"sent": True}
    assert mailbox.forgot(browser, "ann@example.com").json() == {"sent": True}
    assert [to for to, _, _ in mailbox.sent] == ["ann@example.com"]


def test_forgot_leaves_an_admins_live_link_alone(browser, ctx, clock, mailbox):
    email = "ann@example.com"
    enrol(browser, ctx, clock, email)
    browser.cookies.clear()
    reset = link_of(call("user.reset", ctx, {"email": email}).data)
    mailbox.enable()
    assert mailbox.forgot(browser, email).json() == {"sent": True}
    assert mailbox.sent == []
    assert browser.post("/auth/link", json={"link": reset}).status_code == 200


def test_a_new_link_ends_the_earlier_ones(browser, ctx, mailbox):
    email = "ann@example.com"
    first = link_of(call("user.invite", ctx, {"email": email}).data)
    second = link_of(call("user.reset", ctx, {"email": email}).data)
    expired = browser.post("/auth/link", json={"link": first})
    assert expired.status_code == 410 and error(expired) == "link_expired"
    assert browser.post("/auth/link", json={"link": second}).status_code == 200

    # With mail set up the link is emailed, not returned.
    mailbox.enable()
    out = call("user.reset", ctx, {"email": email}).data
    assert out.emailed is True and out.link == ""
    assert mailbox.arrived.wait(10)
    assert mailbox.sent[0][0] == email and mailbox.sent[0][1] == "Reset your shoc sign-in"
    assert browser.post("/auth/link", json={"link": second}).status_code == 410
    assert browser.post("/auth/link", json={"link": mailbox.link()}).status_code == 200


def test_a_mail_that_cannot_be_sent_returns_the_link(browser, ctx, mailbox, monkeypatch):
    mailbox.enable()

    def refuse(cfg, to: str, subject: str, body: str) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(mail, "send", refuse)
    result = call("user.invite", ctx, {"email": "ann@example.com"})
    assert result.data.emailed is False
    assert "could not be sent (OSError: connection refused)" in result.summary
    assert browser.post("/auth/link", json={"link": link_of(result.data)}).status_code == 200


def test_five_wrong_codes_end_a_link(browser, ctx, clock):
    link = link_of(call("user.invite", ctx, {"email": "ann@example.com"}).data)
    seed = credentials.link_seed(ctx.config.master_key, link)
    body = {"link": link, "password": PASSWORD}
    for _ in range(5):
        answer = browser.post("/auth/link/accept", json={**body, "code": clock.wrong(seed)})
        assert answer.status_code == 401 and error(answer) == "bad_code"
    ended = browser.post("/auth/link/accept", json={**body, "code": clock.code(seed)})
    assert ended.status_code == 410 and error(ended) == "link_expired"
    assert browser.post("/auth/link", json={"link": link}).status_code == 410


def test_an_unknown_link_is_expired(browser):
    answer = browser.post("/auth/link", json={"link": "shoc_link_not-a-link"})
    assert answer.status_code == 410 and error(answer) == "link_expired"


# -- tokens and single-user mode -------------------------------------------------------
def test_a_persons_token_becomes_the_session_cookie(browser, ctx, config):
    token = call("token.create", ctx, {"who": "rita@example.com", "role": "operator"}).data.token
    answer = browser.post("/auth/token", json={"token": token})
    assert answer.status_code == 200 and answer.json() == {"id": "rita@example.com"}
    assert browser.cookies.get(COOKIE) == token
    assert me(browser).json()["data"]["role"] == "operator"
    # Signing out clears the cookie and leaves the person's own token working.
    browser.post("/auth/logout", json={})
    assert browser.cookies.get(COOKIE) is None
    bearer = {"host": "shoc.example.com", "authorization": f"Bearer {token}"}
    assert auth.authenticate(bearer, "default", config)[0].id == "rita@example.com"


def test_a_machine_or_unknown_token_cannot_sign_a_browser_in(browser, ctx, clock):
    machine = call("token.create", ctx, {"who": "ci", "scopes": ["events:write"]}).data.token
    person = call("token.create", ctx, {"who": "rita", "role": "reader"}).data.token
    enrol(browser, ctx, clock, "ann@example.com")
    session = browser.cookies.get(COOKIE)
    browser.cookies.clear()
    for value in (machine, "shoc_not-a-token", "", session):
        answer = browser.post("/auth/token", json={"token": value})
        assert answer.status_code == 401 and error(answer) == "bad_credentials"
        assert browser.cookies.get(COOKIE) is None
    elsewhere = browser.post(
        "/auth/token", json={"token": person}, headers={"x-shoc-tenant": "someone-else"}
    )
    assert elsewhere.status_code == 401


def test_the_first_account_ends_single_user_mode(ctx, config, signing):
    local = {"host": "127.0.0.1:8080"}
    assert auth.authenticate(local, "default", config)[0] is auth.SINGLE_USER
    with pytest.raises(ConfigError, match="user invite"):
        auth.check_bind("0.0.0.0", config)
    call("user.invite", ctx, {"email": "ann@example.com", "role": "admin"})
    auth._issued = False  # a fresh process asks the tables again
    with pytest.raises(Unauthenticated, match="no credential"):
        auth.authenticate(local, "default", config)
    auth.check_bind("0.0.0.0", config)


# -- SSO -----------------------------------------------------------------------------
RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Provider:
    """A fake OpenID provider: discovery, the token endpoint and its signing key."""

    def __init__(self, issuer: str = ISSUER) -> None:
        self.issuer = issuer
        self.id_token = ""
        self.query: dict[str, str] = {}
        self.posted: list[dict[str, str]] = []

    def get_json(self, url: str) -> dict[str, Any]:
        assert url == f"{self.issuer}/.well-known/openid-configuration"
        return {
            "issuer": self.issuer,
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/keys",
        }

    def post_form(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        assert url == "https://idp.example.com/token"
        self.posted.append(data)
        return {"id_token": self.id_token}


@pytest.fixture
def idp(monkeypatch) -> Provider:
    fake = Provider()
    key = SimpleNamespace(key=RSA_KEY.public_key())
    monkeypatch.setattr(oidc, "_get_json", fake.get_json)
    monkeypatch.setattr(oidc, "_post_form", fake.post_form)
    monkeypatch.setattr(
        oidc, "_keys", lambda uri: SimpleNamespace(get_signing_key_from_jwt=lambda token: key)
    )
    return fake


def configure_sso(ctx, fake: Provider, domains: tuple[str, ...] = ("example.com",)) -> Any:
    payload = {
        "issuer": fake.issuer,
        "client_id": CLIENT,
        "client_secret": "client-secret",
        "domains": list(domains),
    }
    return call("sso.configure", ctx, payload).data


def sso_round(
    browser: TestClient, fake: Provider, address: str, return_to: str = "/", **claims: Any
) -> httpx.Response:
    """/auth/start for `address`, then the provider's answer: an ID token for it with
    `claims` changed (None drops one, so `email=None` sends no email)."""
    started = browser.post("/auth/start", json={"email": address, "return_to": return_to})
    assert started.status_code == 200 and started.json()["method"] == "sso", started.text
    fake.query = {k: v[0] for k, v in parse_qs(urlsplit(started.json()["url"]).query).items()}
    now = int(time.time())
    found: dict[str, Any] = {
        "iss": fake.issuer,
        "aud": CLIENT,
        "sub": f"sub-{address}",
        "iat": now,
        "exp": now + 300,
        "nonce": fake.query["nonce"],
        "email": address,
        "email_verified": True,
    }
    found.update(claims)
    found = {k: v for k, v in found.items() if v is not None}
    fake.id_token = jwt.encode(found, RSA_KEY, algorithm="RS256", headers={"kid": "k1"})
    return browser.get(
        "/auth/sso/callback",
        params={"code": "the-code", "state": fake.query["state"]},
        follow_redirects=False,
    )


def signin_code(answer: httpx.Response) -> str:
    assert answer.status_code == 303, answer.text
    location = answer.headers["location"]
    assert location.startswith(f"{PUBLIC}/?signin="), location
    return location.rpartition("=")[2]


def test_sso_configure_needs_an_admin_first(ctx, signing, idp):
    with pytest.raises(ValidationError, match="admin"):
        configure_sso(ctx, idp)
    an_admin_token(ctx)
    state = configure_sso(ctx, idp, ("Example.com",))
    assert state.configured and state.issuer == ISSUER and state.domains == ["example.com"]
    assert state.key == "set" and state.redirect_uri == f"{PUBLIC}/auth/sso/callback"
    shown = call("sso.show", ctx, {})
    assert "client-secret" not in str(shown.data) and "client-secret" not in shown.summary
    # An empty secret keeps the stored one; clear turns SSO off.
    again = call("sso.configure", ctx, {"domains": ["example.com", "example.org"]}).data
    assert again.key == "set" and again.domains == ["example.com", "example.org"]
    # Another issuer or client never gets the stored secret.
    for changed in ({"client_id": "another-client"}, {"issuer": "https://other.example.com"}):
        with pytest.raises(ValidationError, match="client_secret"):
            call("sso.configure", ctx, changed)
    assert call("sso.configure", ctx, {"clear": True}).data.configured is False


def test_sso_signs_a_new_person_in_as_reader(browser, ctx, idp, conn):
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    # An address outside the domains signs in with a password; nothing says who exists.
    other = browser.post("/auth/start", json={"email": "ann@example.org"})
    assert other.json() == {"method": "password"}

    before = audit_seq(conn, ctx.tenant_id)
    answer = sso_round(browser, idp, "bob@example.com", return_to="/cases?open=1")
    query = idp.query
    assert query["client_id"] == CLIENT and query["login_hint"] == "bob@example.com"
    assert query["redirect_uri"] == f"{PUBLIC}/auth/sso/callback"
    assert query["code_challenge_method"] == "S256" and query["state"] and query["nonce"]
    assert answer.status_code == 303 and answer.headers["location"] == f"{PUBLIC}/cases?open=1"
    posted = idp.posted[-1]
    assert posted["code"] == "the-code" and posted["client_secret"] == "client-secret"
    verifier = posted["code_verifier"].encode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).decode().rstrip("=")
    assert challenge == query["code_challenge"]

    data = me(browser).json()["data"]
    assert (data["email"], data["role"]) == ("bob@example.com", "reader")
    row = user_row(conn, ctx.tenant_id, "bob@example.com")
    assert (row["sso_issuer"], row["sso_subject"]) == (ISSUER, "sub-bob@example.com")
    assert row["password_hash"] is None
    assert audited(conn, ctx.tenant_id, before, "auth.signin") == ["human:bob@example.com"]
    listed = call("user.list", ctx, {}).data.users
    assert [(u["email"], u["method"]) for u in listed] == [("bob@example.com", "sso")]

    # The state cookie went with the callback, so the same answer cannot be replayed.
    replay = browser.get(
        "/auth/sso/callback",
        params={"code": "the-code", "state": query["state"]},
        follow_redirects=False,
    )
    assert signin_code(replay) == "sso_state"


def test_sso_links_an_invited_person_and_then_the_subject_decides(browser, ctx, idp):
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    out = call("user.invite", ctx, {"email": "carol@example.com", "role": "operator"}).data
    assert out.sso is True and out.link == "" and not out.emailed
    with pytest.raises(ValidationError, match="provider"):
        call("user.reset", ctx, {"email": "carol@example.com"})

    answer = sso_round(browser, idp, "carol@example.com")
    assert answer.headers["location"] == f"{PUBLIC}/"
    assert me(browser).json()["data"]["role"] == "operator"
    browser.cookies.clear()

    # Another subject with the same address is someone else.
    impostor = sso_round(browser, idp, "carol@example.com", sub="sub-someone-else")
    assert signin_code(impostor) == "sso_failed"
    # A disabled person is told so.
    call("user.update", ctx, {"email": "carol@example.com", "disabled": True})
    assert signin_code(sso_round(browser, idp, "carol@example.com")) == "disabled"
    assert browser.cookies.get(COOKIE) is None


def test_a_new_issuer_relinks_people_by_email(browser, ctx, idp, conn):
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    sso_round(browser, idp, "bob@example.com")
    idp.issuer = "https://login.example.net"
    configure_sso(ctx, idp)
    answer = sso_round(browser, idp, "bob@example.com")
    assert answer.headers["location"] == f"{PUBLIC}/"
    row = user_row(conn, ctx.tenant_id, "bob@example.com")
    assert (row["sso_issuer"], row["sso_subject"]) == (idp.issuer, "sub-bob@example.com")
    # The same issuer with another subject is still someone else.
    other = sso_round(browser, idp, "bob@example.com", sub="sub-someone-else")
    assert signin_code(other) == "sso_failed"


def test_sso_links_an_account_made_meanwhile(browser, ctx, idp, monkeypatch):
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    call("user.invite", ctx, {"email": "carol@example.com", "role": "operator"})
    # The first lookup misses it, as if the invitation landed during the sign-in.
    real, answers = people.by_email, iter([None])
    monkeypatch.setattr(people, "by_email", lambda *args: next(answers, real(*args)))
    sso_round(browser, idp, "carol@example.com")
    monkeypatch.setattr(people, "by_email", real)
    assert me(browser).json()["data"]["role"] == "operator"


def test_sso_refuses_what_the_provider_does_not_vouch_for(browser, ctx, idp):
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    cases = {
        "sso_unverified": {"email_verified": False},
        "sso_domain": {"email": "eve@example.org"},
        "sso_failed": {"nonce": "another-nonce"},
    }
    for code, claims in cases.items():
        assert signin_code(sso_round(browser, idp, "eve@example.com", **claims)) == code
    assert signin_code(sso_round(browser, idp, "eve@example.com", email=None)) == "sso_unverified"
    assert signin_code(sso_round(browser, idp, "eve@example.com", aud="other")) == "sso_failed"
    assert browser.cookies.get(COOKIE) is None
    assert call("user.list", ctx, {"disabled": True}).data.users == []


def test_sso_refuses_a_microsoft_guest_or_another_tenant(browser, ctx, idp):
    idp.issuer = f"https://login.microsoftonline.com/{MS_TENANT}/v2.0"
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    member = {"tid": MS_TENANT, "email_verified": None}
    guest = {**member, "idp": "https://sts.windows.net/99999999-0000-0000-0000-000000000000/"}
    assert signin_code(sso_round(browser, idp, "eve@example.com", **guest)) == "sso_unverified"
    other_tenant = {**member, "tid": "99999999-0000-0000-0000-000000000000"}
    assert signin_code(sso_round(browser, idp, "eve@example.com", **other_tenant)) == (
        "sso_unverified"
    )
    answer = sso_round(browser, idp, "bob@example.com", **member)
    assert answer.status_code == 303 and answer.headers["location"] == f"{PUBLIC}/"
    assert me(browser).json()["data"]["email"] == "bob@example.com"


def test_a_tampered_or_missing_sso_state_is_refused(browser, ctx, idp):
    an_admin_token(ctx)
    configure_sso(ctx, idp)

    def start() -> str:
        answer = browser.post("/auth/start", json={"email": "bob@example.com"})
        return parse_qs(urlsplit(answer.json()["url"]).query)["state"][0]

    def back(params: dict[str, str], **headers: str) -> httpx.Response:
        return browser.get(
            "/auth/sso/callback", params=params, headers=headers, follow_redirects=False
        )

    assert signin_code(back({"code": "c", "state": "forged"})) == "sso_state"  # no cookie
    start()
    assert signin_code(back({"code": "c", "state": "forged"})) == "sso_state"
    state = start()
    assert signin_code(back({"code": "c", "state": state, "iss": "https://evil.example"})) == (
        "sso_state"
    )
    state = start()
    assert signin_code(back({"state": state, "error": "access_denied"})) == "sso_failed"

    state = start()
    sealed = (browser.cookies.get(SSO_COOKIE) or "").strip('"')  # quoted: it ends in =
    assert sealed
    raw = bytearray(base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4)))
    raw[-1] ^= 1
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode()
    browser.cookies.clear()
    answer = back({"code": "c", "state": state}, cookie=f"{SSO_COOKIE}={tampered}")
    assert signin_code(answer) == "sso_state"
    assert idp.posted == []  # nothing reached the provider's token endpoint


def test_an_sso_state_works_once(browser, ctx, idp, monkeypatch):
    an_admin_token(ctx)
    configure_sso(ctx, idp)
    started = browser.post("/auth/start", json={"email": "bob@example.com"})
    set_cookie = started.headers["set-cookie"].lower()
    assert set_cookie.startswith(SSO_COOKIE.lower() + "=") and "path=/;" in set_cookie
    state = parse_qs(urlsplit(started.json()["url"]).query)["state"][0]
    sealed = (browser.cookies.get(SSO_COOKIE) or "").strip('"')  # quoted: it ends in =
    cookie = f"{SSO_COOKIE}={sealed}"
    browser.cookies.clear()

    def back() -> httpx.Response:
        return browser.get(
            "/auth/sso/callback",
            params={"code": "the-code", "state": state},
            headers={"cookie": cookie},
            follow_redirects=False,
        )

    assert signin_code(back()) == "sso_failed"  # the fake provider has no ID token ready
    assert signin_code(back()) == "sso_state"  # a script that kept the cookie
    assert len(idp.posted) == 1
    # The callback counts against the client address like every sign-in request.
    monkeypatch.setattr(signin, "ADDRESSES", signin.Throttle(0, 60))
    assert signin_code(back()) == "sso_failed"
    assert len(idp.posted) == 1


def test_sso_takes_over_password_accounts_in_its_domains(browser, ctx, clock, idp):
    seed = enrol(browser, ctx, clock, "ann@example.com", role="admin")
    pending = link_of(call("user.invite", ctx, {"email": "dan@example.com"}).data)
    configure_sso(ctx, idp)
    browser.cookies.clear()
    # The provider is how the company takes access away, so the password stops working...
    assert login(browser, clock, "ann@example.com", seed).status_code == 401
    assert browser.post("/auth/link", json={"link": pending}).status_code == 410
    assert browser.post("/auth/start", json={"email": "ann@example.com"}).json()["method"] == "sso"
    # ...and the provider signs her in with the role she had.
    sso_round(browser, idp, "ann@example.com")
    assert me(browser).json()["data"]["role"] == "admin"


# -- pure helpers --------------------------------------------------------------------
@pytest.mark.parametrize(
    "value, kept",
    [
        ("/cases?open=1", True),
        ("/", True),
        ("//evil.example/", False),
        ("/\\evil.example", False),
        ("https://evil.example/", False),
        ("cases", False),
        ("/a\nb", False),
        (None, False),
        (7, False),
    ],
)
def test_return_to_stays_on_this_origin(value, kept):
    assert signin._return_to(value) == (value if kept else "/")


def test_the_origin_a_browser_sends():
    assert auth.origin_of("https://shoc.example.com/") == "https://shoc.example.com"
    assert auth.origin_of("https://shoc.example.com:443") == "https://shoc.example.com"
    assert auth.origin_of("http://shoc.example.com:8080") == "http://shoc.example.com:8080"
    assert auth.origin_of("https://Shoc.Example.com") == "https://shoc.example.com"
    assert auth.origin_of("") == ""


def asked(peer: str, forwarded: str) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({"type": "http", "headers": headers, "client": (peer, 1234)})


@pytest.mark.parametrize(
    ("peer", "forwarded", "seen"),
    [
        ("172.18.0.5", "203.0.113.9", "203.0.113.9"),  # the console's proxy
        ("127.0.0.1", "198.51.100.1, 203.0.113.9", "203.0.113.9"),
        ("172.18.0.5", "203.0.113.9, 172.17.0.1", "203.0.113.9"),  # a TLS proxy via Docker
        ("172.18.0.5", "172.17.0.1", "172.17.0.1"),  # every hop trusted: the first
        ("172.18.0.5", "", "172.18.0.5"),
        ("172.18.0.5", "198.51.100.1, not-an-address", "not-an-address"),
        ("10.0.0.5", "203.0.113.9", "10.0.0.5"),  # a LAN client cannot pick its address
        ("100.64.1.2", "203.0.113.9", "100.64.1.2"),  # a tailnet client reaching serve itself
        ("203.0.113.7", "", "203.0.113.7"),
    ],
)
def test_the_client_address_believes_only_trusted_proxies(peer, forwarded, seen, monkeypatch):
    monkeypatch.delenv("SHOC_TRUSTED_PROXIES", raising=False)
    assert signin._address(asked(peer, forwarded), Config()) == seen


def test_the_trusted_proxies_are_a_setting(monkeypatch):
    monkeypatch.setenv("SHOC_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.1/32")
    cfg = Config()
    assert signin._address(asked("10.0.0.5", "203.0.113.9, 192.0.2.1"), cfg) == "203.0.113.9"
    assert signin._address(asked("172.18.0.5", "203.0.113.9"), cfg) == "172.18.0.5"


def test_the_sso_state_cookie_is_host_only_on_https():
    assert signin._sso_cookie(Config(public_url=PUBLIC)) == (SSO_COOKIE, "/")
    http = Config(public_url="http://shoc.lan:8089")
    assert signin._sso_cookie(http) == ("shoc_sso", "/auth/sso")


def test_a_throttle_counts_hits_per_key_in_its_window(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(signin, "time", SimpleNamespace(monotonic=lambda: now[0]))
    throttle = signin.Throttle(2, 60)
    throttle.hit("a")
    throttle.hit("a")
    assert throttle.full("a") and not throttle.full("b")
    now[0] += 61
    assert not throttle.full("a")


def test_a_throttle_forgets_the_least_recently_hit_keys(monkeypatch):
    monkeypatch.setattr(signin, "time", SimpleNamespace(monotonic=lambda: 1000.0))
    throttle = signin.Throttle(1, 60, keys=2)
    for key in ("a", "b", "a", "c"):
        throttle.hit(key)
    assert throttle.full("a") and throttle.full("c") and not throttle.full("b")
