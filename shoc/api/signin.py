"""The browser's way in: the /auth/* routes (SEC-3, RFC 0028).

Signing in cannot be a capability: it sets cookies, follows redirects and runs
before there is a caller. These routes do that and nothing else; managing
people is the user.* and sso.* capabilities. They are not part of the frozen
contract. Answers are JSON with `Cache-Control: no-store`, errors are
{"error": {code, message}}, and every POST must be JSON from SHOC_PUBLIC_URL's
origin. Blocking work runs off the event loop, and password hashing on the two
threads `credentials.hashing` keeps for it.

A request that is not signed in yet acts on the tenant X-Shoc-Tenant names,
else SHOC_TENANT, as Slack's callbacks do.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hmac
import ipaddress
import json
import logging
import secrets
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from shoc import mail
from shoc.api import credentials, oidc, people
from shoc.api.auth import check_browser_post, entry_for, session_cookie, session_cookies
from shoc.config import Config
from shoc.db import pool
from shoc.db.secrets import open_secret, seal
from shoc.errors import ShocError, SignInError, ValidationError

log = logging.getLogger("shoc.signin")

COOKIE_SECONDS = int(people.SESSION.total_seconds())
SSO_SECONDS = 600
MAX_BODY = 16 * 1024
# The codes a failed SSO round trip redirects with: `/?signin=<code>`.
SSO_CODES = {"sso_state", "sso_failed", "sso_domain", "sso_unverified", "disabled"}


class Throttle:
    """At most `limit` hits per `window` seconds for each key, in this process.

    It keeps the `keys` most recently hit; older ones are forgotten.
    """

    def __init__(self, limit: int, window: float, keys: int = 10_000) -> None:
        self.limit, self.window, self.keys = limit, window, keys
        self._hits: dict[Any, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: Any, now: float) -> int:
        hits = self._hits.get(key)
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        return len(hits or ())

    def full(self, key: Any) -> bool:
        with self._lock:
            return self._recent(key, time.monotonic()) >= self.limit

    def hit(self, key: Any) -> None:
        now = time.monotonic()
        with self._lock:
            hits = self._hits.pop(key, None) or deque()
            hits.append(now)
            self._hits[key] = hits  # last in the dict's order: the oldest go first
            if len(self._hits) > self.keys:
                del self._hits[next(iter(self._hits))]


# Every sign-in POST from one client address, and wrong passwords for one
# account from one address. A wrong password never locks the account, so
# knowing the admin's email is not enough to lock them out.
WINDOW = 15 * 60
ADDRESSES = Throttle(100, WINDOW)
WRONG_PASSWORDS = Throttle(10, WINDOW)


def _bad() -> SignInError:
    return SignInError("bad_credentials", 401, "wrong email, password or code")


def _bad_code() -> SignInError:
    return SignInError("bad_code", 401, "wrong code")


def _expired() -> SignInError:
    return SignInError("link_expired", 410, "this link has expired or was used")


def _slow() -> SignInError:
    return SignInError("slow_down", 429, "too many attempts; try again later", WINDOW)


def _too_large() -> SignInError:
    return SignInError("payload_too_large", 413, f"the body is over {MAX_BODY} bytes")


def _error(exc: ShocError) -> JSONResponse:
    response = JSONResponse({"error": exc.to_json()}, exc.status)
    if retry := getattr(exc, "retry_after", 0):
        response.headers["retry-after"] = str(retry)
    return response


@functools.cache
def _networks(cidrs: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    cleaned = (c.strip() for c in cidrs.split(","))
    return tuple(ipaddress.ip_network(c, strict=False) for c in cleaned if c)


def _address(request: Request, cfg: Config) -> str:
    """The client: the socket, or behind SHOC_TRUSTED_PROXIES the first hop they did not add.

    X-Forwarded-For is read from the right, skipping trusted hops, and only
    when the peer itself is trusted; anyone reaching serve directly could
    otherwise pick a new address for every guess.
    """
    networks = _networks(cfg.trusted_proxies)

    def trusted(value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(ip in network for network in networks)

    peer = request.client.host if request.client else ""
    if not trusted(peer):
        return peer
    forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
    hops = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
    return next((hop for hop in reversed(hops) if not trusted(hop)), hops[0] if hops else peer)


def _tenant(request: Request, cfg: Config) -> str:
    return request.headers.get("x-shoc-tenant") or cfg.tenant_id


def _secure(cfg: Config) -> bool:
    return cfg.public_url.startswith("https://")


def _redirect_uri(cfg: Config) -> str:
    return f"{cfg.public_url}/auth/sso/callback"


def _set_session(response: Response, cfg: Config, value: str) -> None:
    response.set_cookie(
        session_cookie(cfg),
        value,
        max_age=COOKIE_SECONDS,
        path="/",
        secure=_secure(cfg),
        httponly=True,
        samesite="strict",
    )


def _string(body: dict[str, Any], name: str, limit: int) -> str:
    value = body.get(name, "")
    if not isinstance(value, str) or len(value) > limit:
        raise ValidationError(f"{name}: a string of at most {limit} characters")
    return value


def _return_to(value: Any) -> str:
    """A path on this origin to come back to: `/…`, never `//…` or `/\\…`."""
    if (
        isinstance(value, str)
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and value.isprintable()
        and len(value) <= 2048
    ):
        return value
    return "/"


type Handler = Callable[[Request, dict[str, Any], Config], Awaitable[Response]]


def _post(fn: Handler, cfg: Config) -> Callable[[Request], Awaitable[Response]]:
    """The checks every sign-in POST shares, then `fn`; errors become JSON."""

    async def handle(request: Request) -> Response:
        try:
            if not cfg.public_url:
                raise SignInError(
                    "sign_in_not_configured", 503, "set SHOC_PUBLIC_URL to let people sign in"
                )
            check_browser_post(request.headers, cfg)
            address = _address(request, cfg)
            if ADDRESSES.full(address):
                raise _slow()
            ADDRESSES.hit(address)
            length = request.headers.get("content-length", "0")
            if not length.isdigit() or int(length) > MAX_BODY:
                raise _too_large()
            raw = b""
            async for chunk in request.stream():
                raw += chunk
                if len(raw) > MAX_BODY:
                    raise _too_large()
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValidationError("request body must be a JSON object")
            response = await fn(request, body, cfg)
        except ShocError as exc:
            response = _error(exc)
        except json.JSONDecodeError as exc:
            response = _error(ValidationError(f"bad JSON: {exc}"))
        except Exception:
            log.exception("sign-in route failed")
            response = _error(ShocError("sign-in failed"))
        response.headers["cache-control"] = "no-store"
        return response

    return handle


# -- password, code, token -------------------------------------------------------
def _wrong_code(cfg: Config, conn: pool.Conn, tenant: str, user: dict[str, Any]) -> None:
    """Count a wrong code; a lock is audited once and the person told."""
    minutes = people.code_failed(conn, tenant, user["user_id"])
    if minutes:
        people.audit_person(conn, tenant, user["email"], "auth.locked", {"minutes": minutes})
        if mail.configured(cfg):
            mail.send_later(cfg, user["email"], *mail.locked(cfg, minutes))


def _account(cfg: Config, tenant: str, email: str) -> dict[str, Any] | None:
    with people.pinned(cfg, tenant) as conn:
        user = people.by_email(conn, tenant, email)
        if user is not None:
            user["sso"] = people.in_sso_domain(conn, tenant, email)
        return user


def _second_factor(cfg: Config, tenant: str, user: dict[str, Any], code: str) -> str:
    with people.pinned(cfg, tenant) as conn:
        seed = people.seed_of(cfg.master_key, tenant, user)
        step = credentials.totp_step(seed, code, time.time(), user["totp_step"]) if seed else None
        if step is None:
            _wrong_code(cfg, conn, tenant, user)
            raise _bad()
        if not people.advance_step(conn, tenant, user["user_id"], step):
            raise _bad()  # the same code, used meanwhile
        people.signed_in(conn, tenant, user["user_id"])
        session = people.create_session(conn, tenant, user)
        people.audit_person(conn, tenant, user["email"], "auth.signin", {"method": "password"})
        return session


async def login(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    """Email, password and code in one request, so no answer says which of them was wrong."""
    password, code = _string(body, "password", 1024), _string(body, "code", 16)
    try:
        email = people.clean_email(body.get("email"))
    except ValidationError as exc:
        raise _bad() from exc
    tenant, address = _tenant(request, cfg), _address(request, cfg)
    key = (tenant, email, address)
    if WRONG_PASSWORDS.full(key):
        raise _slow()
    user = await asyncio.to_thread(_account, cfg, tenant, email)
    stored = user["password_hash"] if user else None
    if not await credentials.hashing(credentials.check_password, password, stored):
        WRONG_PASSWORDS.hit(key)
        raise _bad()
    if user is None or user["disabled_at"] or user["locked"] or user["sso"]:
        raise _bad()
    session = await asyncio.to_thread(_second_factor, cfg, tenant, user, code)
    response = JSONResponse({"email": user["email"]})
    _set_session(response, cfg, session)
    return response


def _token_signin(cfg: Config, value: str, asked: str | None) -> str:
    entry = entry_for(value, cfg)[1] if value else None
    # A person's token, not a machine's and not another browser's session.
    if not entry or "role" not in entry or entry.get("user_id"):
        raise _bad()
    tenant = entry.get("tenant") or cfg.tenant_id
    if asked and asked != tenant:
        raise _bad()
    who = str(entry.get("id", "token"))
    with people.pinned(cfg, tenant) as conn:
        people.audit_person(conn, tenant, who, "auth.signin", {"method": "token"})
    return who


async def token(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    """A person's token becomes the session cookie itself; revoking it signs the browser out."""
    value = _string(body, "token", 512).strip()
    asked = request.headers.get("x-shoc-tenant")
    who = await asyncio.to_thread(_token_signin, cfg, value, asked)
    response = JSONResponse({"id": who})
    _set_session(response, cfg, value)
    return response


def _logout(cfg: Config, values: list[str]) -> None:
    conn = pool.connect(cfg)
    pool.set_tenant(conn, pool.ALL_TENANTS)  # the cookie names the tenant
    try:
        for value in values:
            people.end_session(conn, value, "sign-out")
    finally:
        pool.set_tenant(conn, "")


async def logout(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    values = [v for v in session_cookies(request.headers, cfg) if v]
    if values:
        await asyncio.to_thread(_logout, cfg, values)
    response = JSONResponse({"signed_out": True})
    response.delete_cookie(
        session_cookie(cfg), path="/", secure=_secure(cfg), httponly=True, samesite="strict"
    )
    return response


# -- links -----------------------------------------------------------------------
def _open(cfg: Config, tenant: str, value: str) -> dict[str, Any] | None:
    with people.pinned(cfg, tenant) as conn:
        found = people.open_link(conn, tenant, value)
        # A link cannot sign in a password account the provider now answers for.
        if found and people.in_sso_domain(conn, tenant, found["email"]):
            return None
        return found


async def link(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    value = _string(body, "link", 256)
    found = await asyncio.to_thread(_open, cfg, _tenant(request, cfg), value)
    if found is None:
        raise _expired()
    uri = ""
    if found["enrol"]:
        uri = credentials.otpauth(credentials.link_seed(cfg.master_key, value), found["email"])
    return JSONResponse({"email": found["email"], "enrol": found["enrol"], "otpauth": uri})


def _link_code(
    cfg: Config, tenant: str, found: dict[str, Any], new_seed: bytes | None, code: str
) -> int:
    """The step of a right code; a wrong one is refused and counted.

    It counts against the link, and against the account when the link keeps
    the authenticator the person already has.
    """
    with people.pinned(cfg, tenant) as conn:
        if new_seed is None and found["locked"]:
            raise _bad_code()
        seed = new_seed or people.seed_of(cfg.master_key, tenant, found)
        last = 0 if new_seed else found["totp_step"]
        step = credentials.totp_step(seed, code, time.time(), last) if seed else None
        if step is None:
            people.link_code_failed(conn, tenant, found["link_id"])
            if new_seed is None:
                _wrong_code(cfg, conn, tenant, found)
            raise _bad_code()
        return step


def _accept(
    cfg: Config, tenant: str, found: dict[str, Any], hashed: str, seed: bytes | None, step: int
) -> str | None:
    with people.pinned(cfg, tenant) as conn:
        return people.accept_link(conn, tenant, found, hashed, seed, step, cfg.master_key)


async def accept(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    value = _string(body, "link", 256)
    password, code = _string(body, "password", 1024), _string(body, "code", 16)
    tenant = _tenant(request, cfg)
    found = await asyncio.to_thread(_open, cfg, tenant, value)
    if found is None:
        raise _expired()
    problem = credentials.password_problem(password, found["email"])
    if problem:
        raise ValidationError(problem)
    new_seed = credentials.link_seed(cfg.master_key, value) if found["enrol"] else None
    step = await asyncio.to_thread(_link_code, cfg, tenant, found, new_seed, code)
    hashed = await credentials.hashing(credentials.hash_password, password)
    session = await asyncio.to_thread(_accept, cfg, tenant, found, hashed, new_seed, step)
    if session is None:
        raise _expired()
    response = JSONResponse({"email": found["email"]})
    _set_session(response, cfg, session)
    return response


def _forgot(cfg: Config, tenant: str, email: str) -> None:
    """Email a link that keeps the authenticator, to an active password account only."""
    try:
        with people.pinned(cfg, tenant) as conn:
            user = people.by_email(conn, tenant, email)
            if (
                user is None
                or user["disabled_at"]
                or not (user["password_hash"] and user["secret"])
                or people.in_sso_domain(conn, tenant, email)
                or people.forgot_recently(conn, tenant, user["user_id"])
            ):
                return
            value, _ = people.issue_link(
                conn, tenant, user["user_id"], False, people.FORGOT, "forgot-password"
            )
        mail.send(cfg, user["email"], *mail.forgot(cfg, value))
    except Exception as exc:
        log.warning("could not send a password link: %s", exc)
    finally:
        pool.close()  # this thread's connection ends with it


async def forgot(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    """Always the same answer, at once: the work happens on a thread of its own."""
    email = people.clean_email(body.get("email"))
    if not mail.configured(cfg):
        return JSONResponse({"sent": False})
    tenant = _tenant(request, cfg)
    threading.Thread(target=_forgot, args=(cfg, tenant, email), daemon=True).start()
    return JSONResponse({"sent": True})


# -- SSO -------------------------------------------------------------------------
def _sso_cookie(cfg: Config) -> tuple[str, str]:
    """The state cookie's name and path: `__Host-` on https, so no sibling subdomain plants one."""
    return ("__Host-shoc_sso", "/") if _secure(cfg) else ("shoc_sso", "/auth/sso")


# The states a callback has used, until they expire: each works once.
_used: dict[str, float] = {}
_used_lock = threading.Lock()


def _first_use(state: dict[str, Any]) -> bool:
    now = time.time()
    with _used_lock:
        for value in [v for v, expires in _used.items() if expires <= now]:
            del _used[value]
        if state["state"] in _used:
            return False
        _used[state["state"]] = state["expires"]
        return True


def _state_cookie(cfg: Config, state: dict[str, Any]) -> str:
    # The tenant travels inside the sealed state: the callback has no other way to know it.
    return base64.urlsafe_b64encode(seal(cfg.master_key, state, "", "sso_state", "state")).decode()


def _open_state(cfg: Config, value: str) -> dict[str, Any] | None:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        state = open_secret(cfg.master_key, raw, "", "sso_state", "state")
    except Exception:
        return None
    return state if state.get("expires", 0) > time.time() else None


def _provider(cfg: Config, tenant: str) -> dict[str, Any] | None:
    with people.pinned(cfg, tenant) as conn:
        return people.provider(conn, tenant)


async def start(request: Request, body: dict[str, Any], cfg: Config) -> Response:
    """Which way this email signs in. Never says whether an account exists."""
    email = people.clean_email(body.get("email"))
    tenant = _tenant(request, cfg)
    provider = await asyncio.to_thread(_provider, cfg, tenant)
    if provider is None or people.domain_of(email) not in provider["domains"]:
        return JSONResponse({"method": "password"})
    verifier, challenge = oidc.pkce()
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    sealed = _state_cookie(
        cfg,
        {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "tenant": tenant,
            "issuer": provider["issuer"],
            "client_id": provider["client_id"],
            "return_to": _return_to(body.get("return_to")),
            "expires": time.time() + SSO_SECONDS,
        },
    )
    url = oidc.authorize_url(provider, state, nonce, challenge, email, _redirect_uri(cfg))
    response = JSONResponse({"method": "sso", "url": url})
    name, path = _sso_cookie(cfg)
    response.set_cookie(
        name,
        sealed,
        max_age=SSO_SECONDS,
        path=path,
        secure=_secure(cfg),
        httponly=True,
        samesite="lax",
    )
    return response


def _sso_signin(cfg: Config, state: dict[str, Any], code: str) -> str:
    tenant = state["tenant"]
    with people.pinned(cfg, tenant) as conn:
        provider = people.provider(conn, tenant, cfg.master_key)
        if provider is None or (provider["issuer"], provider["client_id"]) != (
            state["issuer"],
            state["client_id"],
        ):
            raise SignInError("sso_failed", 401, "the provider changed during sign-in")
        id_token = oidc.exchange(provider, code, state["verifier"], _redirect_uri(cfg))
        found = oidc.claims(provider, id_token, state["nonce"])
        email = oidc.email_of(provider, found)
        user = people.sso_person(conn, tenant, provider["issuer"], str(found["sub"]), email)
        people.signed_in(conn, tenant, user["user_id"])
        session = people.create_session(conn, tenant, user)
        people.audit_person(conn, tenant, user["email"], "auth.signin", {"method": "sso"})
        return session


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def callback(cfg: Config) -> Callable[[Request], Awaitable[Response]]:
    async def handle(request: Request) -> Response:
        """The provider sends the browser back here; any failure goes to `/?signin=<code>`."""
        query = request.query_params
        name, path = _sso_cookie(cfg)
        try:
            if not cfg.public_url:
                raise SignInError("sso_failed", 503, "SHOC_PUBLIC_URL is not set")
            address = _address(request, cfg)
            if ADDRESSES.full(address):
                raise _slow()
            ADDRESSES.hit(address)
            state = _open_state(cfg, request.cookies.get(name, ""))
            if (
                state is None
                or not _same(query.get("state", ""), state["state"])
                or ("iss" in query and query["iss"] != state["issuer"])  # RFC 9207
                or not _first_use(state)
            ):
                raise SignInError("sso_state", 401)
            if "error" in query or not query.get("code"):
                log.warning("SSO provider error: %r", query.get("error", "")[:100])
                raise SignInError("sso_failed", 401, "the provider returned no code")
            session = await asyncio.to_thread(_sso_signin, cfg, state, query["code"])
            response: Response = RedirectResponse(cfg.public_url + state["return_to"], 303)
            _set_session(response, cfg, session)
        except Exception as exc:
            code = exc.code if isinstance(exc, SignInError) and exc.code in SSO_CODES else ""
            log.warning("SSO sign-in failed: %s", exc)
            response = RedirectResponse(f"{cfg.public_url}/?signin={code or 'sso_failed'}", 303)
        response.delete_cookie(name, path=path, secure=_secure(cfg), httponly=True, samesite="lax")
        response.headers["cache-control"] = "no-store"
        return response

    return handle


def routes(cfg: Config) -> list[Route]:
    """The /auth/* routes `rest.build_app` serves beside the generated ones."""
    posts: dict[str, Handler] = {
        "/auth/start": start,
        "/auth/login": login,
        "/auth/token": token,
        "/auth/link": link,
        "/auth/link/accept": accept,
        "/auth/forgot": forgot,
        "/auth/logout": logout,
    }
    return [
        *(Route(path, _post(fn, cfg), methods=["POST"]) for path, fn in posts.items()),
        Route("/auth/sso/callback", callback(cfg), methods=["GET"]),
    ]
