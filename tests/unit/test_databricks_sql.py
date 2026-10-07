"""What a rule becomes on Databricks SQL (STO-3).

The adapter itself is exercised by `tests/conformance` when credentials are
present; this file checks the translation and the load statements that the
conformance suite cannot reach without a warehouse.
"""

from __future__ import annotations

import pytest

from shoc.detect import rules as ruleset
from shoc.detect.compiler import compile_rule
from shoc.errors import ConfigError
from shoc.store.sql import bind, prepare, translate

RULES = ruleset.load()


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_every_rule_translates_to_databricks(rule):
    compiled = compile_rule(rule)
    for sql in (compiled.select_sql, compiled.agg_sql, compiled.buckets_sql):
        if sql:
            out = translate(sql, "databricks")
            assert "ocsf_events" in out


def test_databricks_uses_positional_parameters_in_order():
    sql, args = bind(
        "SELECT 1 FROM ocsf_events WHERE tenant_id = :tenant_id AND time >= :start",
        {"tenant_id": "t1", "start": "2026-01-01"},
        "databricks",
    )
    assert sql.count("?") == 2 and "%(" not in sql
    assert args == ["t1", "2026-01-01"]


def test_postgres_keeps_named_parameters():
    sql, args = bind(
        "SELECT 1 FROM ocsf_events WHERE tenant_id = :tenant_id", {"tenant_id": "t1"}, "postgres"
    )
    assert sql.endswith("%(tenant_id)s") and args == {"tenant_id": "t1"}


def test_the_ocsf_layout_is_the_same_on_every_backend():
    from shoc.store import ocsf
    from shoc.store.databricks import _DBX_TYPES, _ddl_columns

    ddl = _ddl_columns()
    for name, tp in ocsf.COLUMNS:
        assert f"`{name}` {_DBX_TYPES[tp]}" in ddl


def test_a_missing_credential_is_a_clear_configuration_error():
    from shoc.store.databricks import DatabricksStore

    with pytest.raises(ConfigError, match="SHOC_DATABRICKS_HOST"):
        DatabricksStore("", "", "", "t1", "shoc_t1")


def test_table_names_are_qualified_with_the_tenant_catalog():
    from shoc.store.databricks import DatabricksStore

    store = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")
    sql, _ = prepare(
        store._qualify("SELECT event_uid FROM ocsf_events WHERE tenant_id = :tenant_id"),
        {"tenant_id": "acme"},
        "databricks",
    )
    assert "`shoc_acme`.`shoc`.ocsf_events" in sql
    assert store.volume_path == "/Volumes/shoc_acme/shoc/batches"


def test_an_unknown_backend_is_refused():
    from shoc.config import Config
    from shoc.store import open_store

    cfg = Config()
    cfg.backend = "mysql"
    with pytest.raises(ConfigError, match="unknown backend"):
        open_store(cfg, "t1")


def test_migrate_keeps_file_statistics_on_ingested_at():
    """A detection cycle selects by `ingested_at`, the 39th column (DET-3)."""
    from shoc.store import ocsf
    from shoc.store.databricks import DatabricksStore

    store = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")
    sent: list[str] = []

    def execute(sql, params=None):
        sent.append(sql)
        return [{"col_name": n} for n, _ in ocsf.COLUMNS] if sql.startswith("DESCRIBE") else []

    store._execute = execute  # type: ignore[method-assign]
    store.migrate()
    (props,) = [s for s in sent if "dataSkippingStatsColumns" in s]
    columns = props.split("= '")[1].rstrip("')").split(",")
    assert "ingested_at" in columns and "time" in columns and "raw" not in columns


def test_the_ingestion_lag_is_canonical_sql():
    """ops.py once sent Postgres interval arithmetic to every backend (STO-1)."""
    from shoc.agents.ops import LAG_SECONDS

    sql = f"SELECT {LAG_SECONDS} AS lag FROM ocsf_events"
    assert "UNIX_TIMESTAMP(ingested_at) - UNIX_TIMESTAMP(time)" in translate(sql, "databricks")
    assert "EXTRACT(epoch_second FROM ingested_at)" in translate(sql, "snowflake")
    assert "DATE_PART('epoch', ingested_at)" in translate(sql, "postgres")
