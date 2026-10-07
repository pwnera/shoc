"""What a rule becomes on Snowflake (STO-4).

The adapter runs in `tests/conformance` when credentials are present; this file
covers the translation and the DDL that a warehouse-less CI cannot reach.
"""

from __future__ import annotations

import pytest

from shoc.detect import rules as ruleset
from shoc.detect.compiler import compile_rule
from shoc.errors import ConfigError
from shoc.store import ocsf
from shoc.store.snowflake import _SF_TYPES, SnowflakeStore, _ddl_columns
from shoc.store.sql import translate

RULES = ruleset.load()


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_translates_to_snowflake(rule):
    compiled = compile_rule(rule)
    for sql in (compiled.select_sql, compiled.agg_sql, compiled.buckets_sql):
        if sql:
            assert "ocsf_events" in translate(sql, "snowflake")


def test_the_ocsf_layout_is_the_same_on_snowflake():
    ddl = _ddl_columns()
    for name, tp in ocsf.COLUMNS:
        assert f'"{name.upper()}" {_SF_TYPES[tp]}' in ddl


def test_json_columns_become_variants():
    assert _SF_TYPES["JSON"] == "VARIANT"
    assert _SF_TYPES["TIMESTAMPTZ"] == "TIMESTAMP_TZ"


def test_missing_credentials_say_which_ones():
    with pytest.raises(ConfigError, match="SHOC_SNOWFLAKE_ACCOUNT"):
        SnowflakeStore("", "", "", "", "t1", "SHOC_T1")


def test_tables_are_qualified_with_the_tenant_database():
    store = SnowflakeStore("acc", "user", "pw", "wh", "acme", "SHOC_ACME")
    qualified = store._qualify("SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id")
    assert '"SHOC_ACME"."SHOC".OCSF_EVENTS' in qualified


def test_a_private_key_is_accepted_instead_of_a_password():
    store = SnowflakeStore("acc", "user", "", "wh", "t1", "SHOC_T1", private_key="-----BEGIN…")
    assert store.private_key.startswith("-----BEGIN")


def test_every_backend_declares_its_dialect():
    from shoc.store.databricks import DatabricksStore
    from shoc.store.postgres import PostgresStore

    assert PostgresStore("dsn", "t", "t_t").dialect == "postgres"
    assert DatabricksStore("h", "/p", "t", "t", "c").dialect == "databricks"
    assert SnowflakeStore("a", "u", "p", "w", "t", "D").dialect == "snowflake"
