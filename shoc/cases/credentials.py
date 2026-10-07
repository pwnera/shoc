"""Credentials the playbook runner acts with (RSP-4, principle 5).

Agents never read this table. The runner acts with it, `platform.lookup` reads
with it (RFC 0014), and a human writes it; no caller ever gets a secret back.

A provider is a vendor (RFC 0031) and can hold several credentials, named like
sources (D76): `aws` and `aws:staging`, `okta` and `okta:eu`. Each acts, when it
says so, only in its `accounts`: the `cloud_account_uid` the platform's events
carry (an AWS account, an Entra tenant, an Okta org). Which ones an action uses
is decided from where its target was seen (RFC 0025).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.actions.base import Credentials
from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.db.secrets import open_secret, seal
from shoc.errors import ConfigError, ValidationError


def provider_of(name: str) -> str:
    """`aws:staging` → `aws`."""
    return name.split(":", 1)[0]


@dataclass(frozen=True)
class Instance:
    name: str
    accounts: tuple[str, ...] = ()  # () acts in any account no other one claims

    @classmethod
    def of(cls, name: str, settings: dict[str, Any]) -> Instance:
        return cls(name, accounts_of(settings))


def accounts_of(settings: dict[str, Any]) -> tuple[str, ...]:
    raw = settings.get("accounts") or ()
    values = [raw] if isinstance(raw, str) else list(raw)
    return tuple(sorted({str(v).strip() for v in values if str(v).strip()}))


def store(
    conn: Conn,
    tenant_id: str,
    provider: str,
    settings: dict[str, Any],
    secret: dict[str, Any],
    master_key: str,
) -> None:
    execute(
        conn,
        """INSERT INTO shoc.action_credentials (tenant_id, provider, settings, secret)
           VALUES (%s,%s,%s,%s)
           ON CONFLICT (tenant_id, provider) DO UPDATE SET
               settings = EXCLUDED.settings,
               secret = EXCLUDED.secret,
               updated_at = now()""",
        (
            tenant_id,
            provider,
            json.dumps(settings),
            seal(master_key, secret, tenant_id, "action_credentials", provider),
        ),
    )


def load(conn: Conn, tenant_id: str, provider: str, master_key: str) -> Credentials:
    row = fetch_one(
        conn,
        "SELECT settings, secret FROM shoc.action_credentials WHERE tenant_id=%s AND provider=%s",
        (tenant_id, provider),
    )
    if not row:
        raise ConfigError(
            f"no credentials for '{provider}': a human must set them with credential.configure "
            "before shoc can act"
        )
    return Credentials(
        provider=provider,
        settings=dict(row["settings"]),
        secret=open_secret(master_key, row["secret"], tenant_id, "action_credentials", provider),
    )


def save(
    conn: Conn,
    tenant_id: str,
    name: str,
    settings: dict[str, Any],
    secret: dict[str, Any],
    master_key: str,
) -> None:
    """Store a credential. A secret field left blank keeps the stored one, as a
    source's form does, so changing a setting never means typing the key again."""
    row = fetch_one(
        conn,
        "SELECT secret FROM shoc.action_credentials WHERE tenant_id=%s AND provider=%s",
        (tenant_id, name),
    )
    given = {k: v for k, v in secret.items() if v not in (None, "")}
    if row:
        stored = open_secret(master_key, row["secret"], tenant_id, "action_credentials", name)
        given = {**stored, **given}
    elif not given:
        raise ValidationError(f"{name}: a new credential needs its secret")
    store(conn, tenant_id, name, settings, given, master_key)


def record_check(conn: Conn, tenant_id: str, name: str, ok: bool | None, detail: str) -> None:
    """What the last read with a credential said (`credential.configure`, `credential.check`)."""
    execute(
        conn,
        """UPDATE shoc.action_credentials SET checked_at = now(), check_ok = %s, check_detail = %s
           WHERE tenant_id = %s AND provider = %s""",
        (ok, detail[:500], tenant_id, name),
    )


def remove(conn: Conn, tenant_id: str, name: str) -> bool:
    return bool(
        fetch_one(
            conn,
            """DELETE FROM shoc.action_credentials WHERE tenant_id = %s AND provider = %s
               RETURNING provider""",
            (tenant_id, name),
        )
    )


def missing(name: str, settings: dict[str, Any], secret: dict[str, Any]) -> list[str]:
    """The fields its provider needs that are not stored (`NEEDS`)."""
    from shoc.actions.base import NEEDS

    need = NEEDS.get(provider_of(name))
    if need is None:
        return []
    secrets = (
        [] if need.alternative and all(secret.get(f) for f in need.alternative) else need.secret
    )
    return [f for f in need.settings if not settings.get(f)] + [
        f for f in secrets if not secret.get(f)
    ]


def listing(conn: Conn, tenant_id: str, master_key: str) -> list[dict[str, Any]]:
    """Every credential with what it is for and what it lacks, never its secret."""
    rows = fetch_all(
        conn,
        """SELECT provider, settings, secret, updated_at, checked_at, check_ok, check_detail
           FROM shoc.action_credentials WHERE tenant_id = %s ORDER BY provider""",
        (tenant_id,),
    )
    out = []
    for row in rows:
        name, settings = str(row["provider"]), dict(row["settings"])
        try:
            secret = open_secret(master_key, row["secret"], tenant_id, "action_credentials", name)
        except Exception:  # sealed under another key: as good as none
            secret = {}
        found = Instance.of(name, settings)
        out.append(
            {
                "name": name,
                "provider": provider_of(name),
                "accounts": list(found.accounts),
                "settings": {k: v for k, v in settings.items() if k != "accounts"},
                "has_secret": bool(secret),
                "missing": missing(name, settings, secret),
                "updated_at": row["updated_at"],
                # The last read made with it: when, whether it worked, what came back.
                "checked_at": row["checked_at"],
                "check_ok": row["check_ok"],
                "check_detail": row["check_detail"],
            }
        )
    return out


def coverage(conn: Conn, tenant_id: str) -> list[dict[str, Any]]:
    """One row per connected source and the response credential it calls for
    (`RESPONDS`): the credentials that act on it, and the accounts its events
    named that none of them claims. A source with no credential row is one shoc
    can see and cannot act on."""
    from shoc.actions.base import RESPONDS

    sources = fetch_all(
        conn,
        """SELECT c.source, COALESCE(h.account_uids, '{}') AS accounts
           FROM shoc.connector_config c
           LEFT JOIN shoc.source_history h ON h.tenant_id = c.tenant_id AND h.source = c.source
           WHERE c.tenant_id = %s AND c.source NOT IN ('slack', 'llm') ORDER BY c.source""",
        (tenant_id,),
    )
    configured = [
        Instance.of(str(r["provider"]), dict(r["settings"]))
        for r in fetch_all(
            conn,
            "SELECT provider, settings FROM shoc.action_credentials WHERE tenant_id = %s "
            "ORDER BY provider",
            (tenant_id,),
        )
    ]
    out = []
    for s in sources:
        accounts = [str(a) for a in s["accounts"] or []]
        for provider in RESPONDS.get(s["source"].split(":", 1)[0], ()):
            fit = [i for i in configured if provider_of(i.name) == provider]
            out.append(
                {
                    "source": s["source"],
                    "provider": provider,
                    "credentials": [
                        i.name
                        for i in fit
                        if not i.accounts or not accounts or set(i.accounts) & set(accounts)
                    ],
                    "missing": [
                        a
                        for a in accounts
                        if not any(not i.accounts or a in i.accounts for i in fit)
                    ],
                }
            )
    return out


def providers(conn: Conn, tenant_id: str) -> list[str]:
    return [
        r["provider"]
        for r in fetch_all(
            conn,
            "SELECT provider FROM shoc.action_credentials WHERE tenant_id=%s ORDER BY provider",
            (tenant_id,),
        )
    ]


def instances(conn: Conn, tenant_id: str, provider: str) -> list[Instance]:
    rows = fetch_all(
        conn,
        """SELECT provider, settings FROM shoc.action_credentials
           WHERE tenant_id = %s AND split_part(provider, ':', 1) = %s ORDER BY provider""",
        (tenant_id, provider),
    )
    return [Instance.of(str(r["provider"]), dict(r["settings"])) for r in rows]


def overlap(found: list[Instance]) -> str:
    """Why two credentials of one provider could both claim the same target, or ''."""
    for i, a in enumerate(found):
        for b in found[i + 1 :]:
            if not a.accounts and not b.accounts:
                return f"{a.name} and {b.name} would both act everywhere: give each its `accounts`"
            if both := set(a.accounts) & set(b.accounts):
                return f"{a.name} and {b.name} both claim {', '.join(sorted(both))}"
    return ""


def choose(
    found: list[Instance], provider: str, places: set[tuple[str, str]], named: str = ""
) -> tuple[list[str], list[str]]:
    """The credentials to act with, one per (platform, account) the target was seen
    in, and a sentence for each place none can act in.

    An account no credential names goes to the one that names none. A place
    with an unknown account is answered only when one credential serves it.
    Naming a credential narrows the choice and never widens it, so a name an
    attacker wrote into a log cannot send an action to another tenant.
    """
    known = {p for p, a in places if a}
    places = {(p, a) for p, a in places if a or p not in known} or {("", "")}
    chosen: set[str] = set()
    gaps: list[str] = []
    for platform, account in sorted(places):
        serving = [i for i in found if not named or i.name == named]
        if account:
            owners = [i for i in serving if account in i.accounts] or [
                i for i in serving if not i.accounts
            ]
        else:
            owners = serving
        where = f"{platform or provider} account {account}" if account else (platform or provider)
        if len(owners) == 1:
            chosen.add(owners[0].name)
        elif not owners:
            gaps.append(f"no {named or provider} credentials act in {where}")
        else:
            names = ", ".join(i.name for i in owners)
            gaps.append(
                f"{names} could each act in {where}; give each its `accounts` with credential.configure"
            )
    return sorted(chosen), gaps


def where_seen(
    conn: Conn,
    tenant_id: str,
    platforms: tuple[str, ...],
    target: str,
    case_uid: str = "",
    config: Any = None,
) -> set[tuple[str, str]]:
    """The (platform, account) pairs of the findings behind a target.

    A case's findings on the action's platforms, narrowed to those that name the
    target when any does; with no case, the last 30 days' findings that name it.
    The account is the finding's `account:` entity, '' when its events had none.
    A case with no finding on those platforms answers with the target's own
    events there: the login an EDR or Gateway case's user is linked to (RFC 0027).
    """
    from shoc.cases import engine

    if case_uid:
        rows = fetch_all(
            conn,
            "SELECT rule_id, entities FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
            (tenant_id, case_uid),
        )
    elif target:
        rows = fetch_all(
            conn,
            """SELECT rule_id, entities FROM shoc.findings
               WHERE tenant_id = %s AND last_seen > now() - interval '30 days'
                 AND lower(%s) IN (SELECT lower(substr(e, strpos(e, ':') + 1))
                                   FROM unnest(entities) AS e)""",
            (tenant_id, target),
        )
    else:
        return set()
    if not rows:
        return set()
    product = engine.products(conn, tenant_id, config)
    rows = [r for r in rows if not platforms or product.get(r["rule_id"], "") in platforms]
    if case_uid and not rows and target:
        return signed_in(tenant_id, platforms, target, config)
    wanted = target.lower()
    naming = [
        r
        for r in rows
        if wanted and any(e.split(":", 1)[-1].lower() == wanted for e in r["entities"] or [])
    ]
    out: set[tuple[str, str]] = set()
    for r in naming or rows:
        accounts = [e.split(":", 1)[1] for e in r["entities"] or [] if e.startswith("account:")]
        for account in accounts or [""]:
            out.add((product.get(r["rule_id"], ""), account))
    return out


def signed_in(
    tenant_id: str, platforms: tuple[str, ...], login: str, config: Any = None, days: int = 30
) -> set[tuple[str, str]]:
    """The (platform, account) pairs of the events that name a login as their actor."""
    from shoc.config import Config
    from shoc.store import ocsf as layout
    from shoc.store import open_store

    platform_of = {n.lower(): p for p in platforms for n in layout.products_for(p)}
    if not platform_of or not login:
        return set()
    names = sorted(platform_of)
    params: dict[str, Any] = {f"p{i}": n for i, n in enumerate(names)}
    since = datetime.now(UTC) - timedelta(days=days)
    try:
        store = open_store(config or Config.load(), tenant_id)
        try:
            rows = store.query(
                f"SELECT DISTINCT metadata_product, cloud_account_uid FROM {layout.EVENTS_TABLE} "
                "WHERE tenant_id = :tenant_id AND time >= :since "
                "AND LOWER(actor_user_name) = :login "
                f"AND LOWER(metadata_product) IN ({', '.join(f':{k}' for k in params)})",
                {**params, "tenant_id": tenant_id, "since": since, "login": login.lower()},
                50,
            ).rows
        finally:
            store.close()
    except Exception:  # unread, so no place: `choose` acts only where one credential serves
        return set()
    return {
        (platform_of[str(r["metadata_product"]).lower()], str(r["cloud_account_uid"] or ""))
        for r in rows
    }


def route(
    conn: Conn,
    tenant_id: str,
    acting: Any,
    params: dict[str, Any],
    case_uid: str = "",
    *,
    config: Any = None,
    named: str = "",
) -> tuple[list[str], list[str]]:
    """Which of the provider's credentials an action or a lookup acts with (RFC 0025).

    `([], [])` when the provider has none at all: that is the runner's error to
    report, and a dry run needs none.
    """
    found = instances(conn, tenant_id, acting.provider)
    if not found:
        return [], []
    target = str(params.get(acting.required_params[0], "")) if acting.required_params else ""
    places = where_seen(conn, tenant_id, tuple(acting.platforms), target, case_uid, config)
    return choose(found, acting.provider, places, named)


def in_use(conn: Conn, tenant_id: str) -> set[str]:
    """The providers a tenant holds a credential of or reads a source for (`RESPONDS`)."""
    from shoc.actions.base import RESPONDS

    rows = fetch_all(
        conn,
        """SELECT source FROM shoc.connector_config WHERE tenant_id = %s
           UNION SELECT source FROM shoc.source_history WHERE tenant_id = %s""",
        (tenant_id, tenant_id),
    )
    read = {p for r in rows for p in RESPONDS.get(str(r["source"]).split(":", 1)[0], ())}
    return read | {provider_of(n) for n in providers(conn, tenant_id)}


def answering(product: str) -> set[str]:
    """The providers that act on what a product's events describe: those of every
    connector whose mapping names that product."""
    from shoc.actions.base import RESPONDS
    from shoc.ingest import ocsf as mappings

    return {
        provider
        for source in mappings.available_sources()
        if mappings.load_mapping(source).constants.get("metadata_product") == product
        for provider in RESPONDS.get(source, ())
    }


def products_behind(
    conn: Conn, tenant_id: str, case_uid: str, config: Any = None
) -> set[str] | None:
    """The products a case's cited events come from; None when they cannot be read."""
    from shoc.config import Config
    from shoc.store import ocsf as layout
    from shoc.store import open_store

    uids = [
        str(r["uid"])
        for r in fetch_all(
            conn,
            """SELECT DISTINCT unnest(event_uids) AS uid FROM shoc.findings
               WHERE tenant_id = %s AND case_uid = %s LIMIT 200""",
            (tenant_id, case_uid),
        )
    ]
    if not uids:
        return None
    params: dict[str, Any] = {f"u{i}": u for i, u in enumerate(uids)}
    try:
        store = open_store(config or Config.load(), tenant_id)
        try:
            rows = store.query(
                f"SELECT DISTINCT metadata_product FROM {layout.EVENTS_TABLE} "
                "WHERE tenant_id = :tenant_id "
                f"AND event_uid IN ({', '.join(f':{k}' for k in params)})",
                {**params, "tenant_id": tenant_id},
                50,
            ).rows
        finally:
            store.close()
    except Exception:  # unread: the providers the tenant uses stand in
        return None
    return {str(r["metadata_product"]) for r in rows if r["metadata_product"]} or None


@dataclass(frozen=True)
class Scope:
    """Where a case was seen, to tell which vendor's action answers it (RFC 0031)."""

    platforms: set[str]
    products: set[str] | None  # what its cited events come from; None when unread
    using: set[str]  # the providers the tenant holds a credential of or reads a source for

    @classmethod
    def of(cls, conn: Conn, tenant_id: str, case_uid: str, config: Any = None) -> Scope:
        from shoc.cases import engine

        return cls(
            engine.platforms(conn, tenant_id, case_uid, config),
            products_behind(conn, tenant_id, case_uid, config),
            in_use(conn, tenant_id),
        )

    def excludes(self, action: Any) -> str:
        """Why an action does not answer this case, or ''.

        On the case's platform, an action acts on the vendor its events come
        from. Through a link (RFC 0027), or with those events unread, it acts on
        a vendor the tenant uses. A page answers every case.
        """
        from shoc.actions.base import follows_link, out_of_scope

        if not action.platforms:
            return ""
        linked = bool(out_of_scope(action, self.platforms))
        if linked and not follows_link(action, self.platforms):
            return out_of_scope(action, self.platforms)
        if self.products and not linked:
            if any(action.provider in answering(p) for p in self.products):
                return ""
            return f"this case's events come from {', '.join(sorted(self.products))}"
        if action.provider in self.using:
            return ""
        return f"shoc reads no {action.provider} source and holds no {action.provider} credential"


# -- migration 043: providers named after a category (RFC 0031) ---------------
LEGACY: dict[str, tuple[str, ...]] = {
    "idp": ("okta", "entra"),
    "edr": ("crowdstrike", "sentinelone", "defender"),
    "waf": ("cloudflare",),
}


def _legacy_vendor(old: str, settings: dict[str, Any]) -> str:
    """The vendor an `idp`, `edr` or `waf` credential spoke to, read as the old code read it."""
    flavour = str(settings.get("flavour") or "").lower()
    if old == "idp" and not flavour:
        flavour = "okta" if settings.get("org_url") else "entra"
    if old == "waf":
        flavour = "cloudflare"
    return flavour if flavour in LEGACY[old] else ""


def _legacy_action_vendor(
    conn: Conn,
    tenant: str,
    case_uid: str | None,
    old: str,
    acts_in: list[str],
    product: dict[str, str],
) -> str:
    """Which vendor an `idp` or `edr` action called: the credential it acted with,
    else its case's platform, else the tenant's one vendor of that kind, else the
    first. Only dry runs and unrun proposals reach the last two."""
    family = LEGACY[old]
    acted = [provider_of(n) for n in acts_in if provider_of(n) in family]
    if acted:
        return acted[0]
    if old == "idp" and case_uid:
        seen = {
            product.get(str(r["rule_id"]), "")
            for r in fetch_all(
                conn,
                "SELECT DISTINCT rule_id FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
                (tenant, case_uid),
            )
        }
        if "okta" in seen:
            return "okta"
        if seen & {"entra", "m365", "azure"}:
            return "entra"
    used = sorted(in_use(conn, tenant) & set(family))
    return used[0] if len(used) == 1 else family[0]


def split_legacy(conn: Conn, config: Any = None) -> None:
    """Give `idp`, `edr` and `waf` credentials, and the `idp` and `edr` actions and
    steps, their vendor's name. Run by migration 043, in its transaction."""
    from shoc.cases import engine
    from shoc.config import Config

    cfg = config or Config.load()
    rows = fetch_all(
        conn,
        """SELECT tenant_id, provider, settings, secret FROM shoc.action_credentials
           WHERE split_part(provider, ':', 1) IN ('idp', 'edr', 'waf')
           ORDER BY tenant_id, provider""",
    )
    if rows and not cfg.master_key:
        raise ConfigError(
            "migration 043 renames response credentials, and a secret is sealed to its "
            "name: set SHOC_MASTER_KEY and run `shoc migrate` again"
        )
    for row in rows:
        tenant, name = str(row["tenant_id"]), str(row["provider"])
        old, _, label = name.partition(":")
        settings = dict(row["settings"])
        vendor = _legacy_vendor(old, settings)
        if not vendor:
            continue  # an `edr` credential with no flavour never worked: left for a person
        taken = set(providers(conn, tenant))
        new = vendor if label in ("", vendor) else f"{vendor}:{label}"
        if new in taken:
            new = f"{vendor}:{old}" + (f"-{label}" if label and label != vendor else "")
        if new in taken:
            continue
        try:
            secret = open_secret(cfg.master_key, row["secret"], tenant, "action_credentials", name)
        except ConfigError:
            continue  # unreadable under this key, renamed or not
        settings.pop("flavour", None)
        execute(
            conn,
            """UPDATE shoc.action_credentials SET provider = %s, settings = %s, secret = %s
               WHERE tenant_id = %s AND provider = %s""",
            (
                new,
                json.dumps(settings),
                seal(cfg.master_key, secret, tenant, "action_credentials", new),
                tenant,
                name,
            ),
        )
        execute(
            conn,
            """UPDATE shoc.actions SET acts_in = array_replace(acts_in, %s, %s)
               WHERE tenant_id = %s AND %s = ANY(acts_in)""",
            (name, new, tenant, name),
        )
    products: dict[str, dict[str, str]] = {}

    def vendor_of(tenant: str, case_uid: str | None, old: str, acts_in: list[str]) -> str:
        if tenant not in products:
            products[tenant] = engine.products(conn, tenant, cfg)
        return _legacy_action_vendor(conn, tenant, case_uid, old, acts_in, products[tenant])

    for a in fetch_all(
        conn,
        """SELECT action_uid, tenant_id, case_uid, type, acts_in, fallback FROM shoc.actions
           WHERE split_part(type, '.', 1) IN ('idp', 'edr')
              OR split_part(fallback, '.', 1) IN ('idp', 'edr')""",
    ):
        old, _, verb = str(a["type"]).partition(".")
        tenant, acts_in = str(a["tenant_id"]), a["acts_in"] or []
        # A narrower action the Commander named for when nobody approves (RSP-7).
        was, _, instead = str(a["fallback"]).partition(".")
        if was in LEGACY:
            execute(
                conn,
                "UPDATE shoc.actions SET fallback = %s WHERE action_uid = %s",
                (f"{vendor_of(tenant, a['case_uid'], was, acts_in)}.{instead}", a["action_uid"]),
            )
        if old not in LEGACY:
            continue
        renamed = f"{vendor_of(tenant, a['case_uid'], old, acts_in)}.{verb}"
        execute(
            conn,
            "UPDATE shoc.actions SET type = %s WHERE action_uid = %s",
            (renamed, a["action_uid"]),
        )
        execute(
            conn,
            "UPDATE shoc.playbook_steps SET action_type = %s WHERE action_uid = %s",
            (renamed, a["action_uid"]),
        )
    # Steps that never proposed one: skipped, or not reached yet.
    for s in fetch_all(
        conn,
        """SELECT s.run_uid, s.step_index, s.action_type, r.tenant_id, r.case_uid
           FROM shoc.playbook_steps s JOIN shoc.playbook_runs r ON r.run_uid = s.run_uid
           WHERE split_part(s.action_type, '.', 1) IN ('idp', 'edr')""",
    ):
        old, _, verb = str(s["action_type"]).partition(".")
        execute(
            conn,
            "UPDATE shoc.playbook_steps SET action_type = %s WHERE run_uid = %s AND step_index = %s",
            (
                f"{vendor_of(str(s['tenant_id']), s['case_uid'], old, [])}.{verb}",
                s["run_uid"],
                s["step_index"],
            ),
        )


def check_name(name: str) -> None:
    """A credential is named after a provider that has actions or lookups, as a
    source is named after its connector (D76)."""
    import re

    from shoc.actions import load, lookups

    known = {a.provider for a in load().values()} | {lk.provider for lk in lookups().values()}
    if provider_of(name) not in known:
        raise ValidationError(
            f"unknown provider '{provider_of(name)}' (have: {', '.join(sorted(known))})"
        )
    if not re.fullmatch(r"[a-z0-9_]+(:[a-z0-9_-]{1,40})?", name):
        raise ValidationError(
            f"'{name}': another credential is provider:label, the label in "
            "lowercase letters, digits, '_' and '-'"
        )
