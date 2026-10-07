"""Principals, scopes and tenants for the generated surfaces (API-1, SEC-1).

Tokens come from two places. `token.create` issues one and keeps its hash in
`shoc.api_tokens` (RFC 0019). SHOC_TOKENS, as JSON, is how the first admin gets
in: a person's entry names a role, {"<token>": {"role": "operator", "id":
"alice"}}, and a machine's names its kind and scopes, {"<token>": {"kind":
"service", "id": "ci", "scopes": ["events:write"]}}. A token acts on its own
tenant only: `tenant` when the entry names one, SHOC_TENANT otherwise, and the
tenant it was issued in for a stored token.

A person signed in through a browser (SEC-3, RFC 0028) sends no bearer token:
an HttpOnly cookie carries a session, which is an `api_tokens` row tied to the
account, so it is looked up the same way and takes the account's role. Since
the browser sends the cookie on its own, a cookie request that changes
anything must be JSON from SHOC_PUBLIC_URL's origin.

With no tokens configured shoc runs in single-user mode, which the quick start
relies on: every caller is a human with every scope. That is only for a person
on this machine (D63), so `shoc serve` refuses to publish it anywhere but
loopback, and a request that came through a proxy or from a web page is refused.
The first token `token.create` ever issues, or the first account, ends
single-user mode for good, even once it is revoked or disabled.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
from collections.abc import Mapping
from typing import Any, get_args
from urllib.parse import urlsplit

from shoc.capabilities.registry import Caller, Principal
from shoc.config import Config
from shoc.errors import ConfigError, Denied, SignInError, Unauthenticated

SINGLE_USER = Caller(kind="human", id="local", scopes=("*",))

# What the person behind a token or an MCP session may do (RFC 0018). All four
# are human principals. Most of the time the person works through an assistant,
# so an L2 call over MCP still waits for the person's own confirmation.
ROLES: dict[str, tuple[str, ...]] = {
    "admin": ("*",),
    # Works the cases: approves, runs and undoes actions, triages and tunes.
    "operator": (
        "*:read",
        "actions:propose",
        "actions:approve",
        "actions:run",
        "cases:transition",
        "cases:investigate",
        "cases:write",
        "findings:write",
        "memory:write",
        "intel:write",
        "rules:write",
        "detection:run",
        "detection:write",
        "detection:merge",
        "detection:work",
        "hunts:run",
        "hunts:work",
        "hunts:merge",
        "graph:write",
        "posture:write",
        "platforms:lookup",
        "playbooks:run",
        "playbooks:merge",
        "own:write",
    ),
    # Installs and configures shoc: sources, credentials, feeds, Slack, config as code.
    "deployer": (
        "*:read",
        "config:write",
        "sources:write",
        "sources:sync",
        "sources:onboard",
        "sources:sample",
        "actions:configure",
        "intel:configure",
        "slack:write",
        "llm:write",
        "stream:write",
        "own:write",
    ),
    "reader": ("*:read",),
}


def role_caller(role: str, who: str) -> Caller:
    if role not in ROLES:
        raise Denied(f"unknown role '{role}'; the roles are {', '.join(ROLES)}")
    return Caller(kind="human", id=who, scopes=ROLES[role])


def role_of(caller: Caller) -> str:
    """The role a human caller's scopes are, or "" for anything else."""
    if caller.kind != "human":
        return ""
    return next((role for role, scopes in ROLES.items() if caller.scopes == scopes), "")


def session_cookie(config: Config) -> str:
    """The session cookie's name. `__Host-` makes an https browser refuse one set elsewhere."""
    return "__Host-shoc_session" if config.public_url.startswith("https://") else "shoc_session"


def origin_of(url: str) -> str:
    """`scheme://host[:port]` as a browser writes it in an Origin header."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not (parts.scheme and host):
        return ""
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}.get(parts.scheme)
    port = f":{parts.port}" if parts.port and parts.port != default else ""
    return f"{parts.scheme}://{host}{port}"


def check_browser_post(headers: Mapping[str, str], config: Config) -> None:
    """A POST a browser sends with a cookie must be JSON from the console's origin.

    SameSite does not separate two ports of one host, and a cross-site form can
    post text/plain without asking first; each fails one of the two checks.
    """
    kind = headers.get("content-type", "").split(";")[0].strip().lower()
    if kind != "application/json":
        raise SignInError("cross_site", 403, "send Content-Type: application/json")
    origin, got = origin_of(config.public_url), headers.get("origin")
    if not origin or got != origin:
        raise SignInError(
            "cross_site",
            403,
            f"Origin {got or '(none)'} is not {origin or '(none)'}, the origin of SHOC_PUBLIC_URL: "
            "open the console there or set SHOC_PUBLIC_URL to the address you open it at",
        )


def session_cookies(headers: Mapping[str, str], config: Config) -> list[str]:
    """Every value of the session cookie in the request: more than one is refused."""
    name = session_cookie(config)
    getlist = getattr(headers, "getlist", None)  # Starlette's Headers keep repeated headers
    raw = getlist("cookie") if getlist else [headers.get("cookie", "")]
    values: list[str] = []
    for header in raw:
        for part in header.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key == name:
                values.append(value.strip())
    return values


def token_table() -> dict[str, dict[str, Any]]:
    raw = os.environ.get("SHOC_TOKENS", "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Denied(f"SHOC_TOKENS is not valid JSON: {exc}") from exc


# Once a stored token has been seen it stays seen: rows are never deleted, so
# there is no need to ask again on every request.
_issued = False


def _stored(config: Config | None, token: str | None) -> tuple[bool, dict[str, Any] | None]:
    """Whether any token was ever issued, and the live entry behind `token`."""
    global _issued
    if config is None or not config.dsn:
        return False, None
    from shoc.capabilities import tokens
    from shoc.db.pool import ALL_TENANTS, connect, set_tenant

    conn = connect(config)
    # The token names the tenant, so the lookup runs across tenants; the pin
    # is dropped again so nothing else on this thread inherits it.
    set_tenant(conn, ALL_TENANTS)
    try:
        _issued = _issued or tokens.issued(conn)
        return _issued, tokens.find(conn, token) if token and _issued else None
    finally:
        set_tenant(conn, "")


def entry_for(token: str | None, config: Config | None) -> tuple[bool, dict[str, Any] | None]:
    """Whether single-user mode has ended, and the live entry behind `token`."""
    table = token_table()
    # Constant-time comparison against every configured token: a dict lookup
    # leaks how much of a guess was right through timing. A stored token is
    # found by its hash, which a guess cannot steer.
    entry: dict[str, Any] | None = None
    for candidate, value in table.items():
        if token is not None and hmac.compare_digest(candidate, token):
            entry = value
    if entry is not None:
        return True, entry
    issued, stored = _stored(config, token)
    return bool(table) or issued, stored


def authenticate(
    headers: Mapping[str, str],
    default_tenant: str,
    config: Config | None = None,
    method: str = "POST",
) -> tuple[Caller, str]:
    """The caller behind one request, and the tenant it acts on.

    `method` is the request's: a cookie POST gets the browser check. It
    defaults to the strict answer for a caller that does not say.
    """
    asked = headers.get("x-shoc-tenant")
    authorization = headers.get("authorization") or ""
    token = (
        authorization.split(" ", 1)[1].strip()
        if authorization.lower().startswith("bearer ")
        else None
    )
    # A bearer token wins; the cookie counts only once SHOC_PUBLIC_URL is set,
    # since no session is ever made without it (RFC 0028).
    cookie: str | None = None
    if token is None and config is not None and config.public_url:
        cookies = [c for c in session_cookies(headers, config) if c]
        if len(cookies) > 1:
            raise Denied("more than one session cookie; clear this site's cookies and sign in")
        cookie = token = cookies[0] if cookies else None
    ended, entry = entry_for(token, config)
    if not ended:
        _only_from_this_machine(headers)
        return SINGLE_USER, asked or default_tenant
    if token is None:
        raise Unauthenticated(
            "no credential: send Authorization: Bearer <token>, or sign in through "
            "/auth/start for a session cookie",
            code="unauthenticated",
        )
    if cookie is not None and config is not None and method.upper() not in ("GET", "HEAD"):
        check_browser_post(headers, config)
    if entry is None:
        if cookie is not None:
            raise Unauthenticated("signed out; sign in again")
        raise Unauthenticated("unknown or revoked token", code="unauthenticated")
    tenant = entry.get("tenant") or default_tenant
    if asked and asked != tenant:
        raise Denied(f"this token may not act on tenant '{asked}'")
    who = entry.get("id", "token")
    if "role" in entry:
        return role_caller(entry["role"], who), tenant
    kind = entry.get("kind", "service")
    if kind not in get_args(Principal):
        raise Denied(f"token '{who}' names an unknown kind '{kind}'")
    # No scopes means no access: a forgotten field must not become every scope.
    return Caller(kind=kind, id=who, scopes=tuple(entry.get("scopes", ()))), tenant


def _loopback(host: str | None) -> bool:
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return host == "localhost"


def _names_this_machine(value: str) -> bool:
    """Whether a Host header (`host:port`) or an Origin (a URL) names loopback."""
    try:
        return _loopback(urlsplit(value if "//" in value else "//" + value).hostname)
    except ValueError:
        return False


def _only_from_this_machine(headers: Mapping[str, str]) -> None:
    """Keep single-user mode for the person at this machine (principle 5).

    A proxy in front of the port says so in a forwarding header. A web page the
    operator opens can reach loopback too, but its request names another Host
    (DNS rebinding) or carries its own Origin (a cross-site POST).
    """
    if any(h in headers for h in ("forwarded", "x-forwarded-for", "x-real-ip")):
        raise Denied("this request came through a proxy, which needs SHOC_TOKENS set")
    origin = headers.get("origin")
    if not _names_this_machine(headers.get("host", "")) or (
        origin is not None and not _names_this_machine(origin)
    ):
        raise Denied("without SHOC_TOKENS, shoc answers requests to localhost from localhost only")


def check_bind(host: str, config: Config | None = None) -> None:
    """Refuse single-user mode on an address other hosts can reach.

    Without tokens, whoever reaches the port is a human with every scope, which
    includes approving an L2 action (principle 5). Under Docker, serve listens on
    0.0.0.0 in its container and SHOC_BIND is the address the port is published
    on, so that is the one checked.
    """
    host = os.environ.get("SHOC_BIND") or host
    if token_table() or _loopback(host) or _stored(config, None)[0]:
        return
    raise ConfigError(
        f"No token or account exists, so anyone who reaches {host} would be a human with "
        "every scope. Run `shoc user invite you@example.com --role admin` or "
        "`shoc token create --who you --role admin`, set SHOC_TOKENS, or serve on 127.0.0.1."
    )
