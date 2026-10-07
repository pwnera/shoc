"""The master key rotates, secrets move with it, and the runtime role cannot rewrite the audit log (SEC-1, RFC 0024).

Rotation and the runtime role's grants change the whole database, so both run
in a scratch database of their own.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from cryptography.fernet import Fernet
from psycopg.rows import DictRow, dict_row

from shoc.config import Config
from shoc.db import audit, secrets
from shoc.db.pool import ALL_TENANTS, execute, fetch_one, q, set_tenant
from shoc.errors import ConfigError
from shoc.store.postgres import PostgresStore

pytestmark = pytest.mark.postgres

TENANT = "keys"


def _dsn(dsn: str, database: str) -> str:
    parts = urlsplit(dsn)
    return urlunsplit(parts._replace(path=f"/{database}"))


def _connect(dsn: str, tenant: str = ALL_TENANTS) -> psycopg.Connection[DictRow]:
    conn = psycopg.Connection[DictRow].connect(dsn, row_factory=dict_row, autocommit=True)
    set_tenant(conn, tenant)
    return conn


@pytest.fixture
def scratch(config: Config) -> Iterator[str]:
    """A migrated database nobody else uses. Yields its owner's DSN."""
    from shoc.db.migrate import migrate

    database = f"shoc_keys_{uuid.uuid4().hex[:8]}"
    admin = _connect(config.dsn)
    with admin.cursor() as cur:
        cur.execute(q(f'CREATE DATABASE "{database}"'))
    dsn = _dsn(config.dsn, database)
    try:
        db = _connect(dsn)
        migrate(db)
        db.close()
        yield dsn
    finally:
        with admin.cursor() as cur:
            cur.execute(q(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
        admin.close()


def test_migrate_reseals_a_secret_from_before_binding(conn, config):
    from shoc.db.migrate import migrate

    fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(config.master_key.encode()).digest()))
    old = fernet.encrypt(json.dumps({"token": "s3cret"}).encode())
    execute(
        conn,
        """INSERT INTO shoc.connector_config (tenant_id, source, settings, secret)
           VALUES (%s, 'okta', '{}', %s)
           ON CONFLICT (tenant_id, source) DO UPDATE SET secret = EXCLUDED.secret""",
        (config.tenant_id, old),
    )
    migrate(conn)
    row = fetch_one(
        conn,
        "SELECT secret FROM shoc.connector_config WHERE tenant_id = %s AND source = 'okta'",
        (config.tenant_id,),
    )
    assert row
    assert secrets.open_secret(
        config.master_key, row["secret"], config.tenant_id, "connector_config", "okta"
    ) == {"token": "s3cret"}


def test_rotating_the_master_key_keeps_secrets_and_every_audit_row(scratch, config, monkeypatch):
    from shoc.cli import cmd_rotate_key

    first, second, third = config.master_key, "second-master-key", "third-master-key"
    db = _connect(scratch, TENANT)
    where = (TENANT, "action_credentials", "aws")
    execute(
        db,
        "INSERT INTO shoc.action_credentials (tenant_id, provider, secret) VALUES (%s,%s,%s)",
        (TENANT, "aws", secrets.seal(first, {"key": "AKIAEXAMPLE"}, *where)),
    )
    audit.append(db, TENANT, "human", "sam", "source.configure", audit.hash_payload(1))

    def rotate(old: str, new: str) -> None:
        cfg = Config()
        cfg.migrate_dsn, cfg.master_key = scratch, old
        monkeypatch.setenv("SHOC_NEW_MASTER_KEY", new)
        assert cmd_rotate_key(argparse.Namespace(), cfg) == 0

    rotate(first, second)
    with pytest.raises(ConfigError, match="SHOC_MASTER_KEY"):
        audit.append(db, TENANT, "human", "sam", "late", audit.hash_payload(2))  # still on `first`
    monkeypatch.setenv("SHOC_MASTER_KEY", second)
    audit.append(db, TENANT, "human", "sam", "credential.configure", audit.hash_payload(3))
    rotate(second, third)
    monkeypatch.setenv("SHOC_MASTER_KEY", third)
    audit.append(db, TENANT, "human", "sam", "action.run", audit.hash_payload(4))

    ok, count, detail = audit.verify(db, TENANT)
    assert ok and count == 5, detail  # three rows and two re-anchors, under three keys
    row = fetch_one(
        db, "SELECT secret FROM shoc.action_credentials WHERE tenant_id = %s", (TENANT,)
    )
    assert row and secrets.open_secret(third, row["secret"], *where) == {"key": "AKIAEXAMPLE"}
    with pytest.raises(ConfigError):
        secrets.open_secret(first, row["secret"], *where)
    db.close()


@pytest.mark.skipif(
    not os.environ.get("SHOC_RUNTIME_TEST_DSN"), reason="no runtime role to test with"
)
def test_the_runtime_role_appends_to_the_audit_log_and_cannot_change_it(scratch, config):
    from shoc.db.migrate import grant_runtime
    from shoc.store import open_store

    runtime = urlsplit(os.environ["SHOC_RUNTIME_TEST_DSN"]).username or ""
    database = urlsplit(scratch).path.lstrip("/")
    # A tenant schema made by the owner, as on an install from before the role.
    owner = Config()
    owner.dsn, owner.tenant_id = scratch, TENANT
    open_store(owner, TENANT).migrate()

    granting = _connect(scratch)
    grant_runtime(granting, runtime, database)
    granting.close()
    app = Config()
    app.dsn, app.tenant_id = _dsn(os.environ["SHOC_RUNTIME_TEST_DSN"], database), TENANT
    events = open_store(app, TENANT)
    events.migrate()  # its tables were handed over, so it can alter them
    assert isinstance(events, PostgresStore)
    events.ensure_partition(datetime.now(UTC))  # and add partitions to them
    events.close()

    db = _connect(app.dsn, TENANT)
    audit.append(db, TENANT, "human", "sam", "source.configure", audit.hash_payload(1))
    assert audit.verify(db, TENANT)[0]
    for statement in (
        "ALTER TABLE shoc.audit_log DISABLE TRIGGER USER",
        "DELETE FROM shoc.audit_log",
        "UPDATE shoc.audit_log SET error = 'x'",
        "TRUNCATE shoc.audit_log",
        "UPDATE shoc.audit_key SET fingerprint = 'x'",
        "DELETE FROM shoc.audit_epochs",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege), db.cursor() as cur:
            cur.execute(q(statement))
    assert fetch_one(db, "SELECT count(*) AS n FROM shoc.audit_log") == {"n": 1}
    db.close()
