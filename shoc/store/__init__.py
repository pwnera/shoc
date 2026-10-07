"""Composable event store: one interface, one conformance suite, five backends.

Another backend plugs in without a change here: a package names a factory
`(config, tenant_id, readonly) -> EventStore` under the `shoc.stores` entry
point group, and `SHOC_BACKEND` selects it by that name. `shoc.store.conformance`
is the suite it has to pass (STO-1).
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import entry_points
from typing import Any, cast

from shoc.errors import ConfigError, StoreError
from shoc.store.base import EventStore, LoadStats, QueryResult, RetentionPolicy, StoreHealth

__all__ = [
    "ADAPTERS",
    "EventStore",
    "LoadStats",
    "QueryResult",
    "RetentionPolicy",
    "StoreHealth",
    "open_store",
]

Opener = Callable[[Any, str, bool], EventStore]


def _postgres(cfg: Any, tid: str, readonly: bool) -> EventStore:
    from shoc.store.postgres import PostgresStore

    dsn = cfg.readonly_dsn if readonly and cfg.readonly_dsn else cfg.dsn
    if not dsn:
        raise ConfigError("SHOC_DSN is not set")
    return PostgresStore(dsn, tid, cfg.tenant_schema(tid), cfg.statement_timeout_seconds)


def _databricks(cfg: Any, tid: str, readonly: bool) -> EventStore:
    from shoc.store.databricks import DatabricksStore

    token = cfg.databricks_token
    if readonly and cfg.databricks_readonly_token:
        token = cfg.databricks_readonly_token
    return DatabricksStore(
        cfg.databricks_host,
        cfg.databricks_http_path,
        token,
        tid,
        cfg.tenant_catalog(tid),
        reader=cfg.databricks_readonly_principal,
    )


def _snowflake(cfg: Any, tid: str, readonly: bool) -> EventStore:
    from shoc.store.snowflake import SnowflakeStore

    return SnowflakeStore(
        cfg.snowflake_account,
        cfg.snowflake_user,
        cfg.snowflake_password,
        cfg.snowflake_warehouse,
        tid,
        cfg.tenant_database(tid),
        role=(
            cfg.snowflake_readonly_role
            if readonly and cfg.snowflake_readonly_role
            else cfg.snowflake_role
        ),
        private_key=cfg.snowflake_private_key,
        reader=cfg.snowflake_readonly_role,
    )


def _redshift(cfg: Any, tid: str, readonly: bool) -> EventStore:
    from shoc.store.redshift import RedshiftStore, reader_of

    dsn = cfg.redshift_readonly_dsn if readonly and cfg.redshift_readonly_dsn else cfg.redshift_dsn
    return RedshiftStore(
        dsn,
        tid,
        cfg.tenant_schema(tid),
        stage=cfg.redshift_stage,
        access_key=cfg.redshift_access_key,
        secret_key=cfg.redshift_secret_key,
        region=cfg.redshift_region,
        iam_role=cfg.redshift_iam_role,
        reader=reader_of(cfg.redshift_readonly_dsn),
        statement_timeout_seconds=cfg.statement_timeout_seconds,
    )


def _bigquery(cfg: Any, tid: str, readonly: bool) -> EventStore:
    from shoc.store.bigquery import BigQueryStore, key_file

    reader = key_file(cfg.bigquery_readonly_credentials)
    return BigQueryStore(
        cfg.bigquery_project,
        reader if readonly and reader else key_file(cfg.bigquery_credentials),
        tid,
        cfg.tenant_catalog(tid),
        location=cfg.bigquery_location,
        reader=str(reader.get("client_email") or ""),
    )


# Backend name -> opener. An installed package adds to it through the
# `shoc.stores` entry point group; a test may add to it directly.
ADAPTERS: dict[str, Opener] = {
    "postgres": _postgres,
    "databricks": _databricks,
    "snowflake": _snowflake,
    "redshift": _redshift,
    "bigquery": _bigquery,
}

# What a read-only store refuses, whatever credential it was opened with.
WRITES = frozenset({"create_tenant", "migrate", "load_batch", "apply_retention", "reset"})


class _ReadOnly:
    """The store an agent gets: reads pass through, writes raise (SEC-1)."""

    def __init__(self, store: EventStore) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        if name in WRITES:

            def refuse(*args: Any, **kwargs: Any) -> Any:
                raise StoreError(f"this event store was opened read-only; {name} writes")

            return refuse
        return getattr(self._store, name)


def open_store(
    config: Any = None, tenant_id: str | None = None, readonly: bool = False
) -> EventStore:
    """Open the event store for a tenant.

    `readonly=True` uses the backend's reader credential when one is set
    (SHOC_READONLY_DSN, SHOC_DATABRICKS_READONLY_TOKEN,
    SHOC_SNOWFLAKE_READONLY_ROLE, SHOC_REDSHIFT_READONLY_DSN or
    SHOC_BIGQUERY_READONLY_CREDENTIALS), so an agent's queries run as a principal that
    only holds SELECT (SEC-1). Without one it falls back to the normal
    credential; either way the store refuses every write, and `query()` runs
    nothing but a single SELECT.
    """
    from shoc.config import Config

    cfg = config or Config.load()
    opener = ADAPTERS.get(cfg.backend)
    if opener is None:
        found = entry_points(group="shoc.stores", name=cfg.backend)
        if not found:
            raise ConfigError(f"unknown backend '{cfg.backend}'")
        opener = cast(Opener, next(iter(found)).load())
    store = opener(cfg, tenant_id or cfg.tenant_id, readonly)
    return cast(EventStore, _ReadOnly(store)) if readonly else store
