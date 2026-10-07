"""How a batch reaches Databricks and Snowflake, and who reads it (STO-3, STO-4, SEC-1).

No warehouse runs in CI, so the adapters talk to a fake connection here and
the tests check the statements they send.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from shoc.config import Config
from shoc.errors import ConfigError, StoreError
from shoc.ingest import batch
from shoc.store import open_store
from shoc.store.databricks import DatabricksStore
from shoc.store.snowflake import SnowflakeStore
from shoc.store.sql import translate

EARLY, LATE = "2026-09-20T10:00:00+00:00", "2026-09-20T11:30:00+00:00"


def _batch(tmp_path):
    rows = [
        {"event_uid": uid, "time": t, "tenant_id": "acme", "unmapped": {"k": 1}}
        for uid, t in (("a", LATE), ("b", EARLY))
    ]
    path, _ = batch.write_batch(rows, str(tmp_path))
    return str(path)


def _fake(store, answers):
    sent: list[tuple[str, object]] = []

    def execute(sql, params=None):
        sent.append((" ".join(sql.split()), params))
        for prefix, rows in answers.items():
            if sent[-1][0].startswith(prefix):
                if isinstance(rows, Exception):
                    raise rows
                return rows
        return []

    store._execute = execute
    return sent


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM ocsf_events WHERE tenant_id = :t",
        "SELECT 1 FROM ocsf_events; DROP TABLE ocsf_events",
        "INSERT INTO ocsf_events (event_uid) VALUES ('x')",
    ],
)
def test_the_read_path_runs_nothing_but_one_select(sql):
    with pytest.raises(StoreError, match="one SELECT"):
        translate(sql, "databricks")


def test_a_select_a_union_and_a_cte_still_read():
    for sql in (
        "SELECT 1 FROM ocsf_events;",
        "SELECT 1 FROM ocsf_events UNION ALL SELECT 2 FROM ocsf_events",
        "WITH x AS (SELECT 1 AS n FROM ocsf_events) SELECT n FROM x",
    ):
        translate(sql, "snowflake")


def _batch_with_a_repeat(tmp_path):
    rows = [
        {"event_uid": uid, "time": t, "tenant_id": "acme", "unmapped": {"k": 1}}
        for uid, t in (("a", LATE), ("b", EARLY), ("a", LATE))
    ]
    path, _ = batch.write_batch(rows, str(tmp_path))
    return str(path)


def _staged(sent_files):
    """Record the file each PUT stages, before the adapter deletes it."""

    def hook(sql):
        if sql.startswith("PUT"):
            local = sql.split("'")[1].removeprefix("file://")
            with open(local) as fh:
                sent_files.append(fh.read().splitlines())

    return hook


def _fake_with(store, answers, hook):
    sent = _fake(store, answers)
    inner = store._execute

    def execute(sql, params=None):
        hook(" ".join(sql.split()))
        return inner(sql, params)

    store._execute = execute
    return sent


def test_databricks_merges_only_what_the_table_lacks_and_removes_the_staged_file(tmp_path):
    store = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")
    files: list[list[str]] = []
    sent = _fake_with(
        store, {"MERGE INTO": [{"num_affected_rows": 1, "num_inserted_rows": 1}]}, _staged(files)
    )
    stats = store.load_batch(_batch_with_a_repeat(tmp_path))
    assert [sql.split()[0] for sql, _ in sent] == ["PUT", "MERGE", "REMOVE"]
    assert len(files[0]) == 2, "a repeat inside the batch is staged once"
    merge, bounds = sent[1]
    staged = sent[0][0].split(" INTO ")[1].removesuffix(" OVERWRITE")
    assert f"read_files({staged}, format => 'json'" in merge
    assert "ON t.tenant_id = s.tenant_id AND t.event_uid = s.event_uid AND t.time = s.time" in merge
    assert merge.endswith("WHEN NOT MATCHED THEN INSERT *"), "never deletes a stored row"
    assert "CAST(`time` AS TIMESTAMP) AS `time`" in merge
    assert bounds == [EARLY, LATE]
    assert sent[2][0] == f"REMOVE {staged}" and staged.startswith(f"'{store.volume_path}/")
    assert stats.rows == 1


def test_databricks_removes_the_staged_file_when_the_load_fails(tmp_path):
    store = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")
    sent = _fake(store, {"MERGE INTO": RuntimeError("warehouse stopped")})
    with pytest.raises(StoreError, match="warehouse stopped"):
        store.load_batch(_batch(tmp_path))
    assert sent[-1][0].startswith("REMOVE '/Volumes/shoc_acme/shoc/batches/")


def test_delta_clusters_by_a_column_and_partitions_by_no_expression():
    """Delta's PARTITIONED BY takes column names only (STO-3)."""
    store = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")
    sent = _fake(store, {})
    store.create_tenant()
    (ddl,) = [sql for sql, _ in sent if sql.startswith("CREATE TABLE")]
    assert "PARTITIONED BY" not in ddl and ddl.endswith("USING DELTA CLUSTER BY (`time`)")


def test_snowflake_copies_into_a_temporary_table_and_merges_what_is_new(tmp_path):
    store = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME")
    files: list[list[str]] = []
    sent = _fake_with(
        store,
        {
            "COPY INTO": [{"file": "f", "rows_loaded": 2}],
            "MERGE INTO": [{"number of rows inserted": 1}],
        },
        _staged(files),
    )
    stats = store.load_batch(_batch_with_a_repeat(tmp_path))
    kinds = [sql.split()[0] for sql, _ in sent]
    assert kinds == ["PUT", "CREATE", "COPY", "MERGE", "REMOVE", "DROP"]
    assert len(files[0]) == 2, "a repeat inside the batch is staged once"
    temp = sent[1][0].split()[3]
    assert sent[1][0].startswith(f"CREATE TEMPORARY TABLE {temp} LIKE ")
    assert sent[2][0].startswith(f"COPY INTO {temp} ")
    merge, bounds = sent[3]
    assert f"USING {temp} AS s" in merge and "WHEN NOT MATCHED THEN INSERT" in merge
    assert "DELETE" not in " ".join(sql for sql, _ in sent), "never deletes a stored row"
    assert bounds == (EARLY, LATE)
    assert sent[5][0] == f"DROP TABLE IF EXISTS {temp}"
    assert stats.rows == 1


def test_snowflake_reads_columns_from_the_tenant_database():
    """The session names no database, so information_schema must be qualified (STO-4)."""
    store = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME")
    sent = _fake(store, {})
    store.migrate()
    (read,) = [sql for sql, _ in sent if "information_schema" in sql]
    assert read.startswith('SELECT column_name FROM "SHOC_ACME".information_schema.columns')


def test_snowflake_gets_a_pem_private_key_as_der():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from shoc.store.snowflake import _der

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    assert _der(pem) == key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def test_retention_counts_what_the_delete_reports():
    dbx = DatabricksStore("h", "/p", "t", "acme", "shoc_acme")
    _fake(dbx, {"DELETE": [{"num_affected_rows": 7}]})
    sf = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME")
    _fake(sf, {"DELETE": [{"number of rows deleted": 3}]})
    from shoc.store.base import RetentionPolicy

    assert dbx.apply_retention(RetentionPolicy(days=30)) == 7
    assert sf.apply_retention(RetentionPolicy(days=30)) == 3


def test_migrate_grants_the_reader_select_and_nothing_more():
    dbx = DatabricksStore("h", "/p", "t", "acme", "shoc_acme", reader="shoc-readers")
    sent = _fake(dbx, {})
    dbx.create_tenant()
    grants = [sql for sql, _ in sent if sql.startswith("GRANT")]
    assert grants == [
        "GRANT USE CATALOG ON CATALOG `shoc_acme` TO `shoc-readers`",
        "GRANT USE SCHEMA, SELECT ON SCHEMA `shoc_acme`.`shoc` TO `shoc-readers`",
    ]
    sf = SnowflakeStore("a", "u", "p", "w", "acme", "SHOC_ACME", reader="SHOC_READER")
    sent = _fake(sf, {})
    sf.create_tenant()
    grants = [sql for sql, _ in sent if sql.startswith("GRANT")]
    assert len(grants) == 3 and all(g.endswith('TO ROLE "SHOC_READER"') for g in grants)
    assert grants[-1].startswith("GRANT SELECT ON TABLE")


def test_agents_read_a_warehouse_with_the_reader_credential():
    cfg = Config()
    cfg.backend = "databricks"
    cfg.databricks_host, cfg.databricks_http_path, cfg.databricks_token = "h", "/p", "writer"
    cfg.databricks_readonly_token = "reader"
    store = cast(Any, open_store(cfg, "acme", readonly=True))
    assert isinstance(store._store, DatabricksStore) and store.access_token == "reader"
    writer = open_store(cfg, "acme")
    assert isinstance(writer, DatabricksStore) and writer.access_token == "writer"
    assert cfg.readonly_configured()

    cfg = Config()
    cfg.backend = "snowflake"
    cfg.snowflake_account, cfg.snowflake_user = "a", "u"
    cfg.snowflake_password, cfg.snowflake_warehouse = "p", "w"
    cfg.snowflake_role, cfg.snowflake_readonly_role = "SHOC", "SHOC_READER"
    store = cast(Any, open_store(cfg, "acme", readonly=True))
    assert isinstance(store._store, SnowflakeStore) and store.role == "SHOC_READER"
    writer = open_store(cfg, "acme")
    assert isinstance(writer, SnowflakeStore) and writer.role == "SHOC"


def test_a_warehouse_cycles_every_fifteen_minutes_unless_told(monkeypatch):
    monkeypatch.delenv("SHOC_CYCLE_SECONDS", raising=False)
    cfg = Config()
    assert cfg.cycle_seconds == 300
    cfg.backend = "snowflake"
    assert cfg.cycle_seconds == 900
    monkeypatch.setenv("SHOC_CYCLE_SECONDS", "1800")
    assert cfg.cycle_seconds == 1800


def test_a_read_only_store_reads_and_refuses_to_write(monkeypatch):
    """Even with no reader credential configured (SEC-1)."""
    from shoc import store as stores
    from shoc.store.base import QueryResult

    class Plain:
        dialect, tenant_id = "plain", "acme"

        def query(self, sql, params=None, limit=1000):
            return QueryResult(rows=[{"n": 1}])

        def reset(self):
            raise AssertionError("a read-only store reached the adapter's reset")

    monkeypatch.setitem(stores.ADAPTERS, "plain", lambda cfg, tid, ro: Plain())
    cfg = Config()
    cfg.backend = "plain"
    readonly = open_store(cfg, "acme", readonly=True)
    assert readonly.query("SELECT 1 FROM ocsf_events").rows == [{"n": 1}]
    for name in ("reset", "create_tenant", "migrate", "load_batch", "apply_retention"):
        with pytest.raises(StoreError, match="read-only"):
            getattr(readonly, name)()
    assert isinstance(open_store(cfg, "acme"), Plain)


def test_an_outside_adapter_is_found_by_its_entry_point(monkeypatch):
    """A package registers a backend under `shoc.stores`; shoc needs no change (STO-1)."""
    from shoc import store as stores

    class EntryPoint:
        def load(self):
            return lambda cfg, tid, ro: ("clickhouse", tid, ro)

    def entry_points(group, name):
        return [EntryPoint()] if (group, name) == ("shoc.stores", "clickhouse") else []

    monkeypatch.setattr(stores, "entry_points", entry_points)
    cfg = Config()
    cfg.backend = "clickhouse"
    assert open_store(cfg, "acme") == ("clickhouse", "acme", False)
    cfg.backend = "mysql"
    with pytest.raises(ConfigError, match="unknown backend 'mysql'"):
        open_store(cfg, "acme")
