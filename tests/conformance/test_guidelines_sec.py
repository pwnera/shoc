"""API, auth, secrets and privacy (SEC-G4, SEC-G10), checked against Postgres.

Each test names the guideline it enforces in its first docstring line. KNOWN
names what breaks a rule today and why; a test fails on anything else, and on a
KNOWN entry that no longer breaks the rule, so the list only shrinks.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from shoc.actions.base import NEEDS
from shoc.api import people
from shoc.capabilities.registry import call
from shoc.cases.credentials import HOST_SETTINGS
from shoc.config import Config
from shoc.db.pool import fetch_all, fetch_one
from shoc.db.secrets import open_secret
from shoc.errors import ValidationError
from shoc.ingest.connectors.base import FIELDS
from tests.support import audit_seq

pytestmark = pytest.mark.postgres

CANARY = "CANARY-7f3a"


# -- SEC-G4 ---------------------------------------------------------------------
def _names_a_host(name: str) -> bool:
    """A setting that says where the stored secret is sent."""
    return name.endswith(("url", "region")) or name in HOST_SETTINGS


def _values(name: str) -> tuple[str, str]:
    """The stored value of such a setting, and one that sends the secret elsewhere."""
    if name.endswith("url"):
        return "https://a.example.test", "https://b.example.test"
    if name.endswith("region"):
        return "us", "eu"
    return "a-example", "b-example"


# (capability, table, key column, name, setting): every configure path that keeps
# a blank secret field, for every setting of it that names a host.
CASES = [
    *(
        ("source.configure", "connector_config", "source", name, setting)
        for name, (settings, _) in FIELDS.items()
        for setting in settings
        if _names_a_host(setting)
    ),
    # Optional, so FIELDS leaves it out: a self-managed GitLab.
    ("source.configure", "connector_config", "source", "gitlab", "base_url"),
    *(
        ("credential.configure", "action_credentials", "provider", name, setting)
        for name, need in NEEDS.items()
        for setting in (*need.settings, *need.optional)
        if _names_a_host(setting)
    ),
    ("intel.configure", "intel_feeds", "feed", "misp", "url"),
]
KNOWN = {
    "credential.configure:notify.region": "credentials.same_host compares URL settings and "
    "HOST_SETTINGS only, so the routing key follows a move from the US to the EU host "
    "(SEC-G4 gap)",
}


def _input(cap: str, name: str, settings: dict[str, Any], secret: dict[str, Any]) -> dict:
    if cap == "source.configure":
        return {
            "source": name,
            "settings": settings,
            "secret": secret,
            "enabled": False,
            "verify": False,
        }
    if cap == "credential.configure":
        return {"provider": name, "settings": settings, "secret": secret, "verify": False}
    return {"feed": name, "settings": settings, "secret": secret}


def _stored(conn, config: Config, table: str, key: str, name: str) -> tuple[Any, dict]:
    row = fetch_one(
        conn,
        f"SELECT settings, secret FROM shoc.{table} WHERE tenant_id = %s AND {key} = %s",
        (config.tenant_id, name),
    )
    assert row and row["secret"], f"{name} kept no secret"
    opened = open_secret(config.master_key, row["secret"], config.tenant_id, table, name)
    return row["settings"], opened


@pytest.mark.parametrize(("cap", "table", "key", "name", "setting"), CASES)
def test_a_new_host_needs_its_credential_again(
    ctx, conn, config, clean, cap, table, key, name, setting
):
    """SEC-G4: a stored secret never follows a setting to another host without being given again.

    `source.configure` with a new `org_url` and no secret sent the stored Okta
    token to the new host on the next sync (appsec-3).
    """
    stored, moved = _values(setting)
    call(cap, ctx, _input(cap, name, {setting: stored}, {"k": CANARY}))
    before = _stored(conn, config, table, key, name)
    assert before[1] == {"k": CANARY}
    call(cap, ctx, _input(cap, name, {setting: stored}, {}))
    assert _stored(conn, config, table, key, name) == before, "the same host keeps it"

    case = f"{cap}:{name}.{setting}"
    try:
        call(cap, ctx, _input(cap, name, {setting: moved}, {}))
    except ValidationError:
        assert case not in KNOWN, f"{case} is refused now; take it out of KNOWN"
        assert _stored(conn, config, table, key, name) == before, "a refusal changes nothing"
    else:
        assert case in KNOWN, f"{case} kept the stored secret for {setting}={moved}"


def test_every_host_setting_is_covered():
    """SEC-G4: the cases above still reach every kind of configure path, KNOWN ones included."""
    caps = {c[0] for c in CASES}
    assert caps == {"source.configure", "credential.configure", "intel.configure"}
    ids = {f"{c[0]}:{c[3]}.{c[4]}" for c in CASES}
    assert set(KNOWN) <= ids, f"KNOWN names a case that no longer exists: {set(KNOWN) - ids}"


# -- SEC-G10 --------------------------------------------------------------------
KNOWN_ACCOUNTS = {
    "shoc/api/people.py:sso_person": "creates the account with no audit row, and the "
    "auth.signin row after it names no role (SEC-G10 gap)",
}


def test_an_sso_account_creation_is_audited(config, conn, clean):
    """SEC-G10: an account SSO creates leaves an audit row naming the method and the role.

    Each account creation or grant writes an audit row; a first SSO sign-in
    creates a reader with none.
    """
    tenant, email = config.tenant_id, "new.hire@example.com"
    after = audit_seq(conn, tenant)
    with people.pinned(config, tenant) as db:
        user = people.sso_person(db, tenant, "https://idp.example.test", "sub-7f3a", email)
    assert user["role"] == "reader" and user["email"] == email
    rows = fetch_all(
        conn,
        "SELECT subject FROM shoc.audit_log WHERE tenant_id = %s AND seq > %s",
        (tenant, after),
    )
    said = [json.loads(r["subject"]) for r in rows if r["subject"]]
    audited = any({"sso", "reader"} <= {v for v in s.values() if isinstance(v, str)} for s in said)
    known = "shoc/api/people.py:sso_person" in KNOWN_ACCOUNTS
    assert audited != known, (
        "audited now; take it out of KNOWN_ACCOUNTS" if audited else "no audit row for the account"
    )
