"""Accounts, their links and their sessions: the one place that writes them (SEC-3, RFC 0028).

The /auth/* routes and the user.* and sso.* capabilities both come here, so a
rule such as "a new link ends the person's earlier ones" is written once. Every
function takes a connection already pinned to the tenant it is given.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any

from shoc.api import credentials
from shoc.api.auth import token_table
from shoc.capabilities.tokens import PREFIX
from shoc.config import Config
from shoc.db import audit
from shoc.db.pool import Conn, connect, execute, fetch_one, set_tenant
from shoc.db.secrets import open_secret, seal
from shoc.errors import Conflict, SignInError, ValidationError

SESSION = timedelta(hours=12)
INVITE = timedelta(days=7)
RESET = timedelta(days=1)
FORGOT = timedelta(hours=1)
FORGOT_EVERY = timedelta(minutes=5)
CODES_TO_LOCK = 5  # wrong codes on an account before it locks, and on a link before it ends
LINK_PREFIX = "shoc_link_"

# A plain addr-spec: no display name, quotes, spaces, commas or line breaks, so
# an address is safe in a mail header and compares as one string.
EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+")

USER = """SELECT user_id, email, role, password_hash, secret, totp_step, sso_issuer,
                 sso_subject, code_failures, created_at, created_by, last_login_at,
                 disabled_at, (locked_until IS NOT NULL AND locked_until > now()) AS locked
          FROM shoc.users WHERE tenant_id = %s"""


def clean_email(value: Any) -> str:
    email = value.strip().lower() if isinstance(value, str) else ""
    if len(email) > 254 or not EMAIL.fullmatch(email):
        raise ValidationError("email: a plain address such as ann@example.com")
    return email


def domain_of(email: str) -> str:
    return email.rpartition("@")[2]


@contextmanager
def pinned(config: Config, tenant: str) -> Iterator[Conn]:
    """This thread's connection pinned to `tenant`, then unpinned, as auth._stored does."""
    conn = connect(config)
    set_tenant(conn, tenant)
    try:
        yield conn
    finally:
        set_tenant(conn, "")


def by_email(conn: Conn, tenant: str, email: str) -> dict[str, Any] | None:
    return fetch_one(conn, USER + " AND email = %s", (tenant, email))


def create(conn: Conn, tenant: str, email: str, role: str, by: str, **sso: str) -> str:
    """A new account with no password yet. `sso` is sso_issuer and sso_subject when known."""
    row = fetch_one(
        conn,
        """INSERT INTO shoc.users
               (tenant_id, user_id, email, role, created_by, sso_issuer, sso_subject)
           VALUES (%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, email) DO NOTHING RETURNING user_id""",
        (
            tenant,
            "usr_" + secrets.token_hex(6),
            email,
            role,
            by,
            sso.get("issuer"),
            sso.get("subject"),
        ),
    )
    if row is None:
        raise Conflict(f"{email} already has an account; use user.reset or user.update")
    return row["user_id"]


def audit_person(conn: Conn, tenant: str, email: str, what: str, detail: dict[str, Any]) -> None:
    """One audit row under the person. Never the password or the code: only `detail`."""
    audit.append(conn, tenant, "human", email, what, audit.hash_payload(detail))


# -- the authenticator ---------------------------------------------------------
def seed_of(master_key: str, tenant: str, user: dict[str, Any]) -> bytes | None:
    if not user.get("secret"):
        return None
    opened = open_secret(master_key, user["secret"], tenant, "users", user["user_id"])
    return bytes.fromhex(opened["seed"])


def sealed_seed(master_key: str, tenant: str, user_id: str, seed: bytes) -> bytes:
    return seal(master_key, {"seed": seed.hex()}, tenant, "users", user_id)


def advance_step(conn: Conn, tenant: str, user_id: str, step: int) -> bool:
    """Accept `step` only if it is above the stored one and the account is not locked,
    in one statement: a code works once, and a lock set meanwhile stops it."""
    return (
        execute(
            conn,
            """UPDATE shoc.users SET totp_step = %s
               WHERE tenant_id = %s AND user_id = %s AND totp_step < %s
                 AND (locked_until IS NULL OR locked_until <= now())""",
            (step, tenant, user_id, step),
        )
        == 1
    )


def code_failed(conn: Conn, tenant: str, user_id: str) -> int:
    """Count a wrong code against the account. Returns the minutes it is now locked for, or 0.

    Every fifth wrong code locks it: 15 minutes, then 30, 60 and so on up to a
    day. Only a completed sign-in resets the count (`signed_in`).
    """
    row = fetch_one(
        conn,
        """UPDATE shoc.users SET
               code_failures = code_failures + 1,
               locked_until = CASE WHEN mod(code_failures + 1, 5) = 0
                   THEN now() + least(power(2, (code_failures + 1) / 5 - 1), 96)
                                * interval '15 minutes'
                   ELSE locked_until END
           WHERE tenant_id = %s AND user_id = %s
           RETURNING code_failures""",
        (tenant, user_id),
    )
    failures = row["code_failures"] if row else 0
    if not failures or failures % CODES_TO_LOCK:
        return 0
    return min(15 * 2 ** (failures // CODES_TO_LOCK - 1), 24 * 60)


def signed_in(conn: Conn, tenant: str, user_id: str) -> None:
    execute(
        conn,
        """UPDATE shoc.users SET code_failures = 0, locked_until = NULL, last_login_at = now()
           WHERE tenant_id = %s AND user_id = %s""",
        (tenant, user_id),
    )


# -- sessions ------------------------------------------------------------------
def create_session(conn: Conn, tenant: str, user: dict[str, Any]) -> str:
    """An api_tokens row with the account's user_id and no role. Returns its value, once."""
    value = credentials.new_secret(PREFIX)
    execute(
        conn,
        """INSERT INTO shoc.api_tokens
               (tenant_id, token_id, hash, who, role, kind, scopes, created_by, expires_at, user_id)
           VALUES (%s,%s,%s,%s,NULL,'human','{}','sign-in',now() + %s,%s)""",
        (
            tenant,
            "tok_" + secrets.token_hex(6),
            credentials.digest(value),
            user["email"],
            SESSION,
            user["user_id"],
        ),
    )
    return value


def end_sessions(conn: Conn, tenant: str, user_id: str, by: str) -> None:
    execute(
        conn,
        """UPDATE shoc.api_tokens SET revoked_at = now(), revoked_by = %s
           WHERE tenant_id = %s AND user_id = %s AND revoked_at IS NULL""",
        (by, tenant, user_id),
    )


def end_session(conn: Conn, value: str, by: str) -> None:
    """Sign one browser out. A person's own token used as the cookie is left alone."""
    execute(
        conn,
        """UPDATE shoc.api_tokens SET revoked_at = now(), revoked_by = %s
           WHERE hash = %s AND user_id IS NOT NULL AND revoked_at IS NULL""",
        (by, credentials.digest(value)),
    )


def revoke_person(conn: Conn, tenant: str, user: dict[str, Any], by: str) -> None:
    """Everything a disabled person could still sign in with: sessions, role tokens, links."""
    end_sessions(conn, tenant, user["user_id"], by)
    execute(
        conn,
        """UPDATE shoc.api_tokens SET revoked_at = now(), revoked_by = %s
           WHERE tenant_id = %s AND role IS NOT NULL AND lower(who) = %s
             AND revoked_at IS NULL""",
        (by, tenant, user["email"]),
    )
    end_links(conn, tenant, user["user_id"])


# -- links ---------------------------------------------------------------------
def end_links(conn: Conn, tenant: str, user_id: str) -> None:
    execute(
        conn,
        """UPDATE shoc.user_links SET used_at = now()
           WHERE tenant_id = %s AND user_id = %s AND used_at IS NULL""",
        (tenant, user_id),
    )


def issue_link(
    conn: Conn, tenant: str, user_id: str, enrol: bool, lifetime: timedelta, by: str
) -> tuple[str, datetime]:
    """A new link for the person, ending their earlier ones. Returns it, once, and its expiry."""
    end_links(conn, tenant, user_id)
    link = credentials.new_secret(LINK_PREFIX)
    row = fetch_one(
        conn,
        """INSERT INTO shoc.user_links
               (tenant_id, link_id, hash, user_id, enrol, created_by, expires_at)
           VALUES (%s,%s,%s,%s,%s,%s,now() + %s) RETURNING expires_at""",
        (
            tenant,
            "lnk_" + secrets.token_hex(6),
            credentials.digest(link),
            user_id,
            enrol,
            by,
            lifetime,
        ),
    )
    return link, (row or {})["expires_at"]


def forgot_recently(conn: Conn, tenant: str, user_id: str) -> bool:
    """Whether a forgotten-password link must not go out now.

    One went out in the last five minutes, or an admin's invitation or reset
    is still live: a new link would end it, and anyone who knows the email
    could keep a person who lost their phone from ever using it.
    """
    return bool(
        fetch_one(
            conn,
            """SELECT 1 AS x FROM shoc.user_links
               WHERE tenant_id = %s AND user_id = %s
                 AND ((NOT enrol AND created_at > now() - %s)
                      OR (enrol AND used_at IS NULL AND expires_at > now()))""",
            (tenant, user_id, FORGOT_EVERY),
        )
    )


def open_link(conn: Conn, tenant: str, link: str) -> dict[str, Any] | None:
    """The live link and its person, or None for an unknown, used, expired or worn-out one."""
    return fetch_one(
        conn,
        """SELECT l.link_id, l.enrol, u.user_id, u.email, u.secret, u.totp_step,
                  (u.locked_until IS NOT NULL AND u.locked_until > now()) AS locked
           FROM shoc.user_links l
           JOIN shoc.users u ON u.tenant_id = l.tenant_id AND u.user_id = l.user_id
           WHERE l.tenant_id = %s AND l.hash = %s AND l.used_at IS NULL
             AND l.expires_at > now() AND l.wrong_codes < %s AND u.disabled_at IS NULL""",
        (tenant, credentials.digest(link), CODES_TO_LOCK),
    )


def link_code_failed(conn: Conn, tenant: str, link_id: str) -> None:
    execute(
        conn,
        """UPDATE shoc.user_links SET wrong_codes = wrong_codes + 1
           WHERE tenant_id = %s AND link_id = %s""",
        (tenant, link_id),
    )


def accept_link(
    conn: Conn,
    tenant: str,
    link: dict[str, Any],
    password_hash: str,
    new_seed: bytes | None,
    step: int,
    master_key: str,
) -> str | None:
    """Set the password, and the authenticator when `new_seed` is given, and sign in.

    One transaction: the link is used, the step accepted, the person's other
    links and sessions ended and a new session made, or none of it. None means
    the link ended meanwhile.
    """
    user_id, email = link["user_id"], link["email"]
    with conn.transaction():
        used = execute(
            conn,
            """UPDATE shoc.user_links SET used_at = now()
               WHERE tenant_id = %s AND link_id = %s AND used_at IS NULL
                 AND expires_at > now() AND wrong_codes < %s""",
            (tenant, link["link_id"], CODES_TO_LOCK),
        )
        if used != 1:
            return None
        if new_seed is not None:
            sealed = sealed_seed(master_key, tenant, user_id, new_seed)
            execute(
                conn,
                """UPDATE shoc.users SET password_hash = %s, secret = %s, totp_step = %s
                   WHERE tenant_id = %s AND user_id = %s""",
                (password_hash, sealed, step, tenant, user_id),
            )
        else:
            if not advance_step(conn, tenant, user_id, step):
                raise SignInError("bad_code", 401, "that code was already used")
            execute(
                conn,
                "UPDATE shoc.users SET password_hash = %s WHERE tenant_id = %s AND user_id = %s",
                (password_hash, tenant, user_id),
            )
        signed_in(conn, tenant, user_id)
        end_links(conn, tenant, user_id)
        end_sessions(conn, tenant, user_id, email)
        session = create_session(conn, tenant, {"user_id": user_id, "email": email})
        audit_person(conn, tenant, email, "auth.link_accepted", {"enrol": bool(link["enrol"])})
    return session


# -- SSO -----------------------------------------------------------------------
PROVIDER = """SELECT issuer, client_id, domains, authorization_endpoint, token_endpoint,
                     jwks_uri, secret, updated_by, updated_at
              FROM shoc.sso_providers WHERE tenant_id = %s AND provider = 'oidc'"""


def provider(conn: Conn, tenant: str, master_key: str = "") -> dict[str, Any] | None:
    """The tenant's identity provider. With `master_key`, `client_secret` is opened too."""
    row = fetch_one(conn, PROVIDER, (tenant,))
    if row is None:
        return None
    row["domains"] = list(row["domains"])
    secret = row.pop("secret")
    if master_key:
        opened = open_secret(master_key, secret, tenant, "sso_providers", "oidc")
        row["client_secret"] = opened.get("client_secret", "")
    else:
        row["has_secret"] = bool(secret)
    return row


def store_provider(
    conn: Conn, tenant: str, settings: dict[str, Any], client_secret: str, master_key: str, by: str
) -> None:
    execute(
        conn,
        """INSERT INTO shoc.sso_providers
               (tenant_id, provider, issuer, client_id, domains, authorization_endpoint,
                token_endpoint, jwks_uri, secret, updated_by, updated_at)
           VALUES (%s,'oidc',%s,%s,%s,%s,%s,%s,%s,%s,now())
           ON CONFLICT (tenant_id, provider) DO UPDATE SET
               issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
               domains = EXCLUDED.domains,
               authorization_endpoint = EXCLUDED.authorization_endpoint,
               token_endpoint = EXCLUDED.token_endpoint, jwks_uri = EXCLUDED.jwks_uri,
               secret = EXCLUDED.secret, updated_by = EXCLUDED.updated_by,
               updated_at = EXCLUDED.updated_at""",
        (
            tenant,
            settings["issuer"],
            settings["client_id"],
            settings["domains"],
            settings["authorization_endpoint"],
            settings["token_endpoint"],
            settings["jwks_uri"],
            seal(master_key, {"client_secret": client_secret}, tenant, "sso_providers", "oidc")
            if client_secret
            else None,
            by,
        ),
    )


def clear_provider(conn: Conn, tenant: str) -> None:
    execute(
        conn, "DELETE FROM shoc.sso_providers WHERE tenant_id = %s AND provider = 'oidc'", (tenant,)
    )


def in_sso_domain(conn: Conn, tenant: str, email: str) -> bool:
    """Whether this address signs in through the provider, never with a password."""
    found = provider(conn, tenant)
    return bool(found and domain_of(email) in found["domains"])


def sso_person(conn: Conn, tenant: str, issuer: str, subject: str, email: str) -> dict[str, Any]:
    """The account behind a provider's subject.

    Found by issuer and subject; on a first sign-in, by email, and linked; else
    a new `reader`. After that the subject decides, not the email, until the
    issuer changes: a new provider vouches for the email and relinks it.
    """
    find = USER + " AND sso_issuer = %s AND sso_subject = %s"
    user = fetch_one(conn, find, (tenant, issuer, subject))
    if user is None:
        known = by_email(conn, tenant, email)
        if known is None:
            try:
                create(conn, tenant, email, "reader", "sso", issuer=issuer, subject=subject)
            except Conflict:  # created meanwhile: link it below
                known = by_email(conn, tenant, email)
        if known and known["sso_issuer"] == issuer and known["sso_subject"] != subject:
            raise SignInError("sso_failed", 401, "this address belongs to another identity")
        if known:
            execute(
                conn,
                """UPDATE shoc.users SET sso_issuer = %s, sso_subject = %s
                   WHERE tenant_id = %s AND user_id = %s
                     AND (sso_subject IS NULL OR sso_issuer IS DISTINCT FROM %s)""",
                (issuer, subject, tenant, known["user_id"], issuer),
            )
        user = fetch_one(conn, find, (tenant, issuer, subject))
    if user is None:
        raise SignInError("sso_failed", 401, "the account could not be linked")
    if user["disabled_at"]:
        raise SignInError("disabled", 401, "this account is disabled")
    return user


# -- admins --------------------------------------------------------------------
def admin_exists(conn: Conn, tenant: str, default_tenant: str, but: str = "") -> bool:
    """Whether an active admin account or a live admin token exists, `but` (an email) aside."""
    row = fetch_one(
        conn,
        """SELECT EXISTS (SELECT 1 FROM shoc.users WHERE tenant_id = %s AND role = 'admin'
                          AND disabled_at IS NULL AND email <> %s)
               OR EXISTS (SELECT 1 FROM shoc.api_tokens WHERE tenant_id = %s
                          AND role = 'admin' AND revoked_at IS NULL
                          AND (expires_at IS NULL OR expires_at > now())
                          AND lower(who) <> %s) AS yes""",
        (tenant, but, tenant, but),
    )
    return bool(row and row["yes"]) or any(
        entry.get("role") == "admin"
        and (entry.get("tenant") or default_tenant) == tenant
        and str(entry.get("id", "")).lower() != but
        for entry in token_table().values()
    )
