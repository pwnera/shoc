"""People who sign in, and the company's identity provider (SEC-3, RFC 0028).

Managing people is ordinary capabilities, so inviting someone or changing a
role is audited and, over MCP, confirmed by the person. Signing in is not a
capability: that is the /auth/* routes in `shoc.api.signin`. Every write goes
through `shoc.api.people`. Only admin holds `users:write` and `sso:write`, so
no other role can give itself a wider one.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from shoc.api import oidc, people
from shoc.capabilities.health import Empty
from shoc.capabilities.registry import Context, Result, capability
from shoc.db.pool import execute, fetch_all
from shoc.errors import ConfigError, NotFound, ValidationError
from shoc.jsonschema import field as f
from shoc.jsonschema import to_json

log = logging.getLogger("shoc.users")
DOMAIN = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")


@dataclass
class UserInvite:
    email: str = f(doc="The person's address, e.g. ann@example.com")
    role: Literal["admin", "operator", "deployer", "reader"] = f(
        "reader", doc="What the person may do"
    )


@dataclass
class UserLinkOut:
    user_id: str = ""
    email: str = ""
    role: str = ""
    link: str = f("", doc="Opens /welcome to set a password and an authenticator; shown once")
    emailed: bool = f(False, doc="The link went to the person's address instead")
    expires_at: str | None = None
    sso: bool = f(False, doc="The person signs in through the company's provider, with no link")


def _can_link(ctx: Context) -> None:
    """A link opens on SHOC_PUBLIC_URL and its authenticator seed needs the master key."""
    if not ctx.config.public_url:
        raise ConfigError("set SHOC_PUBLIC_URL first: people cannot sign in without it")
    if not ctx.config.master_key:
        raise ConfigError("set SHOC_MASTER_KEY first: a link's authenticator needs it")


def _deliver(
    ctx: Context, user: dict[str, Any], lifetime: timedelta, invited: bool
) -> tuple[UserLinkOut, str]:
    """An enrolling link for the person: emailed when mail is set up, else returned once.

    The mail is sent before answering, so a failure is reported (the second
    value) and the link returned instead.
    """
    from shoc import mail

    link, expires = people.issue_link(
        ctx.db, ctx.tenant_id, user["user_id"], True, lifetime, ctx.caller.id
    )
    out = UserLinkOut(
        user_id=user["user_id"],
        email=user["email"],
        role=user["role"],
        expires_at=expires.isoformat(),
    )
    problem = ""
    if mail.configured(ctx.config):
        subject, body = (mail.invitation if invited else mail.reset)(
            ctx.config, link, lifetime.days
        )
        try:
            mail.send(ctx.config, user["email"], subject, body)
            out.emailed = True
            return out, problem
        except Exception as exc:
            log.warning("could not email %s: %s", user["email"], exc)
            problem = f"{type(exc).__name__}: {exc}"[:160]
    out.link = mail.link_url(ctx.config, link)
    return out, problem


def _said(out: UserLinkOut, days: int, problem: str) -> str:
    if out.emailed:
        return f"The link was emailed to {out.email}; it works for {days} day(s)."
    said = (
        f"The link is returned once and works for {days} day(s); give it to {out.email} yourself."
    )
    return f"The mail could not be sent ({problem}). {said}" if problem else said


@capability(
    name="user.invite",
    summary="Invite a person to sign in; the link is emailed or returned once",
    input=UserInvite,
    output=UserLinkOut,
    scope="users:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("users", "write", "security"),
)
def invite(ctx: Context, inp: UserInvite) -> Result:
    email = people.clean_email(inp.email)
    sso = people.in_sso_domain(ctx.db, ctx.tenant_id, email)
    if not sso:
        _can_link(ctx)
    user_id = people.create(ctx.db, ctx.tenant_id, email, inp.role, ctx.caller.id)
    user = {"user_id": user_id, "email": email, "role": inp.role}
    if sso:
        out = UserLinkOut(user_id=user_id, email=email, role=inp.role, sso=True)
        summary = f"Added {email} as {inp.role}; they sign in through the company's provider."
    else:
        out, problem = _deliver(ctx, user, people.INVITE, invited=True)
        summary = f"Invited {email} as {inp.role}. " + _said(out, people.INVITE.days, problem)
    return Result(data=out, summary=summary, citations=[user_id])


@dataclass
class UserRef:
    email: str = f(doc="The person's address")


def _person(ctx: Context, email: str) -> dict[str, Any]:
    user = people.by_email(ctx.db, ctx.tenant_id, people.clean_email(email))
    if user is None:
        raise NotFound(f"no account for {email}")
    return user


@capability(
    name="user.reset",
    summary="Replace a person's password and authenticator; the link is emailed or returned once",
    input=UserRef,
    output=UserLinkOut,
    scope="users:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("users", "write", "security"),
)
def reset(ctx: Context, inp: UserRef) -> Result:
    user = _person(ctx, inp.email)
    if people.in_sso_domain(ctx.db, ctx.tenant_id, user["email"]):
        raise ValidationError(
            f"{user['email']} signs in through the company's provider; reset it there"
        )
    if user["disabled_at"]:
        raise ValidationError(f"{user['email']} is disabled; enable it with user.update first")
    _can_link(ctx)
    out, problem = _deliver(ctx, user, people.RESET, invited=False)
    summary = (
        f"Reset link for {user['email']}: it replaces the password and the authenticator. "
        + _said(out, people.RESET.days, problem)
    )
    return Result(data=out, summary=summary, citations=[user["user_id"]])


@dataclass
class UserUpdate:
    email: str = f(doc="The person's address")
    role: Literal["", "admin", "operator", "deployer", "reader"] = f(
        "", doc="The new role; empty keeps it"
    )
    disabled: bool | None = f(
        None, doc="true signs the person out everywhere and keeps them out; false lets them back"
    )


@dataclass
class UserState:
    user_id: str = ""
    email: str = ""
    role: str = ""
    disabled: bool = False


@capability(
    name="user.update",
    summary="Change a person's role, or disable or enable them",
    input=UserUpdate,
    output=UserState,
    scope="users:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("users", "write", "security"),
)
def update(ctx: Context, inp: UserUpdate) -> Result:
    user = _person(ctx, inp.email)
    email, user_id = user["email"], user["user_id"]
    role = inp.role or user["role"]
    disabled = bool(user["disabled_at"]) if inp.disabled is None else inp.disabled
    was_admin = user["role"] == "admin" and not user["disabled_at"]
    if (
        was_admin
        and (role != "admin" or disabled)
        and not people.admin_exists(ctx.db, ctx.tenant_id, ctx.config.tenant_id, but=email)
    ):
        raise ValidationError(f"{email} is the last admin; make someone else admin first")
    execute(
        ctx.db,
        """UPDATE shoc.users SET role = %s,
               disabled_at = CASE WHEN %s THEN COALESCE(disabled_at, now()) END,
               disabled_by = CASE WHEN %s THEN COALESCE(disabled_by, %s) END
           WHERE tenant_id = %s AND user_id = %s""",
        (role, disabled, disabled, ctx.caller.id, ctx.tenant_id, user_id),
    )
    if disabled:
        people.revoke_person(ctx.db, ctx.tenant_id, user, ctx.caller.id)
    state = "disabled; their sessions, links and role tokens ended" if disabled else "active"
    return Result(
        data=UserState(user_id=user_id, email=email, role=role, disabled=disabled),
        summary=f"{email} is {role}, {state}.",
        citations=[user_id],
    )


@dataclass
class UserQuery:
    disabled: bool = f(False, doc="Include disabled people")


@dataclass
class UserList:
    users: list[dict[str, Any]] = field(default_factory=list)


@capability(
    name="user.list",
    summary="List the people who sign in: role, how they sign in, and when they last did",
    input=UserQuery,
    output=UserList,
    scope="users:read",
    principals=("human",),
    tags=("users", "read"),
)
def list_users(ctx: Context, inp: UserQuery) -> Result:
    found = people.provider(ctx.db, ctx.tenant_id)
    domains = found["domains"] if found else []
    rows = fetch_all(
        ctx.db,
        """SELECT user_id, email, role, created_by, created_at, last_login_at, disabled_at,
                  sso_subject IS NOT NULL AS sso_linked,
                  (locked_until IS NOT NULL AND locked_until > now()) AS locked
           FROM shoc.users
           WHERE tenant_id = %s AND (%s OR disabled_at IS NULL)
           ORDER BY email""",
        (ctx.tenant_id, inp.disabled),
    )
    for row in rows:
        sso = row.pop("sso_linked") or people.domain_of(row["email"]) in domains
        row["method"] = "sso" if sso else "password"
    return Result(
        data=UserList(users=[to_json(r) for r in rows]),
        summary=f"{len(rows)} person(s).",
        citations=[r["user_id"] for r in rows],
    )


@dataclass
class Me:
    id: str = ""
    kind: str = ""
    role: str = f("", doc="A person's role, empty for a machine")
    tenant: str = ""
    email: str = f("", doc="The account's address, when the caller is one")


@capability(
    name="user.me",
    summary="Who is calling: id, kind, role, tenant and, for an account, its email",
    input=Empty,
    output=Me,
    scope="meta:read",
    tags=("users", "read"),
)
def me(ctx: Context, inp: Empty) -> Result:
    from shoc.api.auth import role_of

    caller = ctx.caller
    user = (
        people.by_email(ctx.db, ctx.tenant_id, caller.id.lower())
        if caller.kind == "human"
        else None
    )
    email = user["email"] if user and not user["disabled_at"] else ""
    out = Me(
        id=caller.id, kind=caller.kind, role=role_of(caller), tenant=ctx.tenant_id, email=email
    )
    return Result(data=out, summary=f"{email or caller.id}, {out.role or caller.kind}.")


@dataclass
class SsoState:
    configured: bool = False
    issuer: str = ""
    client_id: str = ""
    domains: list[str] = field(default_factory=list)
    key: str = f("unset", doc="Whether a client secret is stored: set or unset")
    redirect_uri: str = f("", doc="Register this at the provider")
    updated_by: str = ""


def _sso_state(ctx: Context) -> SsoState:
    found = people.provider(ctx.db, ctx.tenant_id)
    public = ctx.config.public_url if ctx.config else ""
    state = SsoState(redirect_uri=f"{public}/auth/sso/callback" if public else "")
    if found:
        state.configured = True
        state.issuer, state.client_id = found["issuer"], found["client_id"]
        state.domains, state.updated_by = found["domains"], found["updated_by"]
        state.key = "set" if found["has_secret"] else "unset"
    return state


def _sso_said(state: SsoState) -> str:
    if not state.configured:
        return "SSO is off: everyone signs in with a password and an authenticator."
    return f"People at {', '.join(state.domains)} sign in through {state.issuer}."


@capability(
    name="sso.show",
    summary="Show the company's identity provider and the email domains that use it",
    input=Empty,
    output=SsoState,
    scope="sso:read",
    principals=("human",),
    tags=("sso", "read"),
)
def show(ctx: Context, inp: Empty) -> Result:
    state = _sso_state(ctx)
    return Result(data=state, summary=_sso_said(state))


@dataclass
class SsoConfig:
    issuer: str = f("", doc="The provider's issuer, e.g. https://accounts.google.com")
    client_id: str = f("", doc="The client id the provider gave shoc")
    client_secret: str = f(
        "", doc="Stored encrypted; empty keeps the stored one for the same issuer and client"
    )
    domains: list[str] = f(
        doc="The company's email domains that sign in there, e.g. example.com", factory=list
    )
    clear: bool = f(False, doc="Turn SSO off")


@capability(
    name="sso.configure",
    summary="Let the company's email domains sign in through its OpenID Connect provider",
    input=SsoConfig,
    output=SsoState,
    scope="sso:write",
    principals=("human",),
    autonomy="L2",
    audit=True,
    tags=("sso", "write", "security"),
)
def configure(ctx: Context, inp: SsoConfig) -> Result:
    if inp.clear:
        people.clear_provider(ctx.db, ctx.tenant_id)
        state = _sso_state(ctx)
        return Result(
            data=state,
            summary=_sso_said(state) + " People who joined through SSO need user.reset first.",
        )
    if not ctx.config.public_url:
        raise ConfigError("set SHOC_PUBLIC_URL first: the provider sends people back to it")
    # The first person through SSO joins as reader, so someone must be able to
    # raise them (RFC 0028).
    if not people.admin_exists(ctx.db, ctx.tenant_id, ctx.config.tenant_id):
        raise ValidationError("invite an admin first: shoc user invite <email> --role admin")
    current = people.provider(ctx.db, ctx.tenant_id, ctx.config.master_key) or {}
    domains = sorted({d.strip().lower() for d in inp.domains}) or current.get("domains", [])
    for domain in domains:
        if not DOMAIN.fullmatch(domain):
            raise ValidationError(f"domains: '{domain}' is not a domain such as example.com")
    issuer = inp.issuer.strip() or current.get("issuer", "")
    client_id = inp.client_id.strip() or current.get("client_id", "")
    if not (issuer and client_id and domains):
        raise ValidationError("issuer, client_id and domains are all needed")
    # The stored secret is the old provider's: it never goes to another one.
    same = (issuer, client_id) == (current.get("issuer"), current.get("client_id"))
    secret = inp.client_secret or (current.get("client_secret", "") if same else "")
    if not secret:
        raise ValidationError("client_secret: the provider's secret for this client is needed")
    settings = {**oidc.discover(issuer), "client_id": client_id, "domains": domains}
    people.store_provider(
        ctx.db, ctx.tenant_id, settings, secret, ctx.config.master_key, ctx.caller.id
    )
    state = _sso_state(ctx)
    return Result(
        data=state,
        summary=_sso_said(state) + f" Register {state.redirect_uri} at the provider.",
    )
