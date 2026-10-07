"""Forward-only migrations, run with `shoc migrate`."""

from __future__ import annotations

from pathlib import Path

from shoc.config import Config
from shoc.db import audit, secrets
from shoc.db.pool import ALL_TENANTS, Conn, q

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

BOOTSTRAP = """
CREATE SCHEMA IF NOT EXISTS shoc;
CREATE TABLE IF NOT EXISTS shoc.schema_migrations (
    version    text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
"""


def pending(conn: Conn) -> list[Path]:
    with conn.cursor() as cur:
        cur.execute(q(BOOTSTRAP))
        cur.execute("SELECT version FROM shoc.schema_migrations")
        done = {r["version"] for r in cur.fetchall()}
    return [p for p in sorted(MIGRATIONS_DIR.glob("*.sql")) if p.stem not in done]


CREATE_ROLE_SQL = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
        CREATE ROLE {role} LOGIN PASSWORD '{password}';
    ELSE
        ALTER ROLE {role} LOGIN PASSWORD '{password}';
    END IF;
END $$;
"""

READONLY_ROLE_SQL = """
GRANT CONNECT ON DATABASE {database} TO {role};
GRANT USAGE ON SCHEMA shoc TO {role};
GRANT SELECT ON ALL TABLES IN SCHEMA shoc TO {role};
ALTER DEFAULT PRIVILEGES IN SCHEMA shoc GRANT SELECT ON TABLES TO {role};
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA shoc FROM {role};
REVOKE ALL ON {private} FROM {role};
"""

# Who signs in and how (SEC-3, RFC 0028): password hashes, sealed seeds, and
# the hashes of live sessions and tokens. Agents have no reason to read them.
PRIVATE_TABLES = ("users", "user_links", "sso_providers", "api_tokens")
PRIVATE = ", ".join(f"shoc.{t}" for t in PRIVATE_TABLES)

# The read-only roles: `grant_readonly` gave each of them SELECT by default on
# every table shoc's owner creates, so a table a later migration adds is
# theirs as soon as it exists. Read from the catalog, not from
# SHOC_READONLY_DSN, so a role granted by hand is found too.
READONLY_ROLES_SQL = """
SELECT a.grantee::regrole::text AS role
FROM pg_default_acl d, aclexplode(d.defaclacl) a
WHERE d.defaclnamespace = 'shoc'::regnamespace AND d.defaclobjtype = 'r' AND a.grantee <> 0
GROUP BY a.grantee HAVING bool_and(a.privilege_type = 'SELECT')
"""

READONLY_SCHEMA_SQL = """
GRANT USAGE ON SCHEMA "{schema}" TO {role};
GRANT SELECT ON ALL TABLES IN SCHEMA "{schema}" TO {role};
ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" GRANT SELECT ON TABLES TO {role};
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA "{schema}" FROM {role};
"""


# What `serve` and `worker` need, as a role that does not own the schema
# (RFC 0024). The audit log takes rows and gives them back, and nothing else:
# without ownership, its triggers cannot be disabled either.
RUNTIME_SQL = """
GRANT CONNECT, CREATE ON DATABASE {database} TO {role};
GRANT USAGE ON SCHEMA shoc TO {role};
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shoc TO {role};
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA shoc TO {role};
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA shoc TO {role};
REVOKE INSERT, UPDATE, DELETE, TRUNCATE
    ON shoc.schema_migrations, shoc.audit_key, shoc.audit_epochs FROM {role};
REVOKE UPDATE, DELETE, TRUNCATE ON shoc.audit_log FROM {role};
"""


def grant_runtime(conn: Conn, role: str, database: str) -> None:
    """Let `role` run shoc without owning its schema. Run again after every migration.

    The runtime role loads tenant events and adds and drops their partitions,
    which takes ownership, so tenant schemas created before it existed, by
    the owner, are handed to it. That needs the owner to be a member of `role`
    (deploy/postgres-init does it).
    """
    from psycopg import sql

    from shoc.db.pool import fetch_all

    who = sql.Identifier(role)
    with conn.cursor() as cur:
        cur.execute(sql.SQL(RUNTIME_SQL).format(role=who, database=sql.Identifier(database)))
        for schema in tenant_schemas(conn):
            owned = fetch_all(
                conn,
                """SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = %s AND c.relkind IN ('r', 'p')
                     AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = %s)""",
                (schema, role),
            )
            if not owned:
                continue
            cur.execute(sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(sql.Identifier(schema), who))
            for row in owned:
                cur.execute(
                    sql.SQL("ALTER TABLE {}.{} OWNER TO {}").format(
                        sql.Identifier(schema),
                        sql.Identifier(row["relname"]),
                        who,
                    )
                )


def tenant_schemas(conn: Conn) -> list[str]:
    """Every tenant's event schema, so a grant covers all of them, not just one."""
    from shoc.db.pool import fetch_all

    rows = fetch_all(
        conn,
        """SELECT nspname AS schema FROM pg_namespace
           WHERE nspname LIKE 't\\_%' ESCAPE '\\' ORDER BY nspname""",
    )
    return [r["schema"] for r in rows]


class RoleNotCreated(Exception):
    """shoc could not create the role itself; a privileged user must."""

    def __init__(self, role: str, sql: str) -> None:
        super().__init__(
            f"shoc is not allowed to create roles (which is correct — it is not a "
            f"superuser). Ask whoever administers the database to run:\n\n{sql}\n"
            f"then run this command again to grant '{role}' the read access."
        )
        self.role = role
        self.sql = sql


def grant_readonly(
    conn: Conn, role: str, password: str, database: str, tenant_schema: str
) -> list[str]:
    """Create (or refresh) the read-only role agents query through (SEC-1).

    shoc runs as an ordinary role, so it usually cannot create another one. When
    the role already exists this only grants; when it does not, it says exactly
    what a privileged user has to run. Grants cover every tenant schema that
    exists now, so run this again after adding a tenant.
    """
    import psycopg

    from shoc.db.pool import fetch_one, q

    exists = bool(fetch_one(conn, "SELECT 1 AS yes FROM pg_roles WHERE rolname = %s", (role,)))
    # Only touch the role itself when it is missing, or when a password was
    # asked for explicitly: rotating a password needs privileges shoc should
    # not have, and an existing role usually just needs the grants.
    if not exists or password:
        create = CREATE_ROLE_SQL.format(role=role, password=(password or "").replace("'", "''"))
        try:
            with conn.cursor() as cur:
                cur.execute(q(create))
        except psycopg.errors.InsufficientPrivilege as exc:
            if not exists:
                raise RoleNotCreated(
                    role,
                    f"  CREATE ROLE {role} LOGIN PASSWORD '<a password you choose>';",
                ) from exc
            # The role is there; we simply may not rotate its password. The
            # grants below are what this command is really for.
    with conn.cursor() as cur:
        cur.execute(q(READONLY_ROLE_SQL.format(role=role, database=database, private=PRIVATE)))
        schemas = sorted({tenant_schema, *tenant_schemas(conn)})
        for schema in schemas:
            cur.execute(q(READONLY_SCHEMA_SQL.format(schema=schema, role=role)))
    return schemas


def revoke_private(conn: Conn) -> None:
    """Take the sign-in tables back from every read-only role (RFC 0028).

    `grant_readonly` revokes them too, and `shoc migrate` re-runs it for
    SHOC_READONLY_DSN's role; this covers a role it does not know about.
    """
    from shoc.db.pool import fetch_all

    for row in fetch_all(conn, READONLY_ROLES_SQL):
        with conn.cursor() as cur:
            cur.execute(q(f"REVOKE ALL ON {PRIVATE} FROM {row['role']}"))


def migrate(conn: Conn) -> list[str]:
    """Apply every pending migration. Returns the versions applied.

    A migration changes every tenant's rows, and 025 seals every tenant's audit
    chain, so each one runs as `shoc:all` whatever tenant the session is pinned
    to. The session's own pin is back once the migration commits.
    """
    applied: list[str] = []
    for path in pending(conn):
        sql = path.read_text()
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT set_config('shoc.tenant_id', %s, true)", (ALL_TENANTS,))
            cur.execute(q(sql))
            if path.stem == audit.KEYED_FROM:
                # Needs the master key, which SQL never sees (SEC-1).
                audit.seal_legacy(conn)
            if path.stem == "043_vendor_actions":
                from shoc.cases import credentials

                credentials.split_legacy(conn)
            cur.execute(
                "INSERT INTO shoc.schema_migrations (version) VALUES (%s)",
                (path.stem,),
            )
        applied.append(path.stem)
    if applied:
        # A migration that adds a table and forgets this call still gets RLS.
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT shoc.enable_tenant_rls()")
        revoke_private(conn)
    master = Config.load().master_key
    if master:
        # Secrets sealed before they were bound to their row (SEC-1) are sealed
        # again, so none is left that a copy into another row would open.
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT set_config('shoc.tenant_id', %s, true)", (ALL_TENANTS,))
            secrets.reseal(conn, master, master, unbound_only=True)
    return applied
