"""The explorer's query builder: what a one-box search compiles to (STO-2)."""

from __future__ import annotations

import pytest

from shoc.capabilities.events import (
    EventQuery,
    SummarizeInput,
    build_query,
    build_summary,
    parse_terms,
)
from shoc.errors import ValidationError
from shoc.store import sql as dialect


def terms(text: str) -> tuple[list[str], dict]:
    params: dict = {}
    return parse_terms(text, params), params


def test_a_bare_word_searches_the_fields_that_identify_something():
    where, params = terms("getsecretvalue")
    assert where == [
        "(LOWER(message) LIKE :q0 ESCAPE '!' OR LOWER(api_operation) LIKE :q0 ESCAPE '!' "
        "OR LOWER(actor_user_name) LIKE :q0 ESCAPE '!' "
        "OR LOWER(src_endpoint_ip) LIKE :q0 ESCAPE '!' "
        "OR LOWER(resource_uid) LIKE :q0 ESCAPE '!')"
    ]
    assert params == {"q0": "%getsecretvalue%"}


def test_an_ocsf_path_becomes_its_column():
    where, params = terms("actor.user.name=Alice")
    assert where == ["LOWER(actor_user_name) = :q0"]
    assert params == {"q0": "alice"}


def test_a_source_path_reaches_into_the_raw_record():
    where, _ = terms("raw.debugContext.debugData.dtHash~ab12")
    assert where == [
        "LOWER(JSON_EXTRACT_SCALAR(raw, '$.debugContext.debugData.dtHash')) LIKE :q0 ESCAPE '!'"
    ]


def test_an_integer_column_is_compared_as_a_number():
    where, params = terms("api.response.code>=400")
    assert where == ["api_response_code >= :q0"]
    assert params == {"q0": 400}


def test_negation_and_quoting():
    where, params = terms("status!=Success message~'access denied'")
    assert where == ["LOWER(status) <> :q0", "LOWER(message) LIKE :q1 ESCAPE '!'"]
    assert params == {"q0": "success", "q1": "%access denied%"}


def test_an_unknown_field_is_rejected_rather_than_ignored():
    with pytest.raises(ValidationError, match=r"unknown field 'actor\.nam'"):
        terms("actor.nam=alice")


@pytest.mark.parametrize(
    "text",
    [
        "actor.user.name='; DROP TABLE ocsf_events --'",
        "raw.a');DELETE FROM ocsf_events WHERE 1=1--=x",
        "message~%' OR '1'='1",
    ],
)
def test_no_term_can_close_the_statement(text):
    try:
        where, params = terms(text)
    except ValidationError:
        return
    clauses = " AND ".join(where)
    for danger in (";", "--", "DROP", "DELETE", "OR '1'"):
        assert danger not in clauses, clauses
    assert all(isinstance(value, (str, int)) for value in params.values())


def test_the_row_query_can_return_the_whole_event():
    sql, params, limit = build_query(EventQuery(q="okta", include_raw=True, limit=50), "t1")
    assert "unmapped, raw, ingested_at FROM ocsf_events" in sql
    assert sql.endswith("ORDER BY time DESC LIMIT 50")
    assert params["q0"] == "%okta%"
    assert limit == 50


def test_the_default_row_stays_the_narrow_column_set():
    sql, _, _ = build_query(EventQuery(), "t1")
    assert " raw," not in sql


def test_citations_still_bypass_the_window():
    sql, params, _ = build_query(EventQuery(event_uids=["e1", "e2"]), "t1")
    assert "event_uid IN (:u0, :u1)" in sql
    assert "window_start" not in params


@pytest.mark.parametrize(
    ("since", "bucket"),
    [("-30m", "minute"), ("-24h", "hour"), ("-30d", "day")],
)
def test_the_histogram_bucket_fits_the_window(since, bucket):
    sql, _, _, used = build_summary(SummarizeInput(since=since), "t1")
    assert used == bucket
    assert f"DATE_TRUNC('{bucket}', time) AS group_key" in sql
    assert sql.endswith("ORDER BY group_key LIMIT 50")


def test_grouping_by_a_field_ranks_the_top_values():
    sql, _, _, used = build_summary(SummarizeInput(by="metadata.product.name", limit=5), "t1")
    assert used == ""
    assert "metadata_product AS group_key" in sql
    assert sql.endswith("GROUP BY metadata_product ORDER BY n DESC LIMIT 5")


@pytest.mark.parametrize("dialect_name", ["postgres", "databricks", "snowflake"])
def test_both_queries_translate_to_every_backend(dialect_name):
    row_sql, _, _ = build_query(
        EventQuery(q="actor.user.name=alice denied", include_raw=True), "t1"
    )
    hist_sql, _, _, _ = build_summary(SummarizeInput(since="-7d", q="status=Failure"), "t1")
    for canonical in (row_sql, hist_sql):
        assert dialect.translate(canonical, dialect_name)


# -- LIKE escaping (D80) --------------------------------------------------------
def test_a_windows_path_and_wildcards_are_matched_literally():
    where, params = terms(r"message~C:\Windows\Temp svc_backup 50%")
    assert where[0] == "LOWER(message) LIKE :q0 ESCAPE '!'"
    assert params["q0"] == "%c:\\windows\\temp%", "a backslash is a character, not an escape"
    assert params["q1"] == "%svc!_backup%", "an underscore is not a wildcard"
    assert params["q2"] == "%50!%%"


def test_contains_escapes_like_a_term():
    from shoc.capabilities.events import EventFilter, build_where

    where, params = build_where(EventFilter(contains="tmp_dir!"), "t1")
    assert params["needle"] == "%tmp!_dir!!%"
    assert "LIKE :needle ESCAPE '!'" in " ".join(where)


@pytest.mark.parametrize("dialect_name", ["postgres", "databricks", "snowflake", "redshift"])
def test_every_like_keeps_its_escape_on_each_backend(dialect_name):
    sql, _, _ = build_query(EventQuery(q=r"message~C:\Temp", contains="x"), "t1")
    out = dialect.translate(sql, dialect_name)
    assert out.upper().count("ESCAPE '!'") == 3, out


def test_bigquery_rewrites_the_escape_into_backslashes():
    sql, _, _ = build_query(EventQuery(q=r"message!~C:\Temp"), "t1")
    out = dialect.translate(sql, "bigquery")
    assert "ESCAPE" not in out.upper() and "REPLACE" in out.upper()


# -- times without an offset ---------------------------------------------------
def test_a_time_without_an_offset_is_utc():
    from datetime import UTC

    from shoc.capabilities.events import parse_since

    assert parse_since("2026-10-01T00:00").isoformat() == "2026-10-01T00:00:00+00:00"
    assert parse_since("2026-10-01T02:00+02:00").tzinfo == UTC


def test_a_histogram_over_a_naive_window_buckets_instead_of_crashing():
    from shoc.capabilities.events import bucket_for

    window = SummarizeInput(since="2026-10-01T00:00", until="2026-10-01T02:00")
    assert bucket_for(window) == "minute"
    assert bucket_for(SummarizeInput(since="2026-10-01T00:00")) == "day"


def test_a_malformed_time_is_a_validation_error():
    with pytest.raises(ValidationError, match="ISO-8601"):
        build_query(EventQuery(since="yesterday"), "t1")
    for bad in ("-1y", "-abc", "-99999999999d", "0001-01-01T00:00:00+05:00"):
        with pytest.raises(ValidationError, match="ISO-8601"):
            build_query(EventQuery(since=bad), "t1")


# -- reading cited events by uid ------------------------------------------------
class _Store:
    """Holds rows; answers `event_uid IN (...)` newest first, up to the limit."""

    def __init__(self, rows, dialect_name="postgres"):
        self.rows, self.dialect, self.statements = rows, dialect_name, []

    def query(self, sql, params, limit):
        from shoc.store.base import QueryResult

        self.statements.append(sql)
        wanted = {v for k, v in params.items() if k.startswith("u")}
        hits = [r for r in self.rows if r["event_uid"] in wanted]
        hits.sort(key=lambda r: r["time"], reverse=True)
        return QueryResult(rows=hits[:limit], sql=sql, truncated=len(hits) > limit)


def test_an_updated_alert_does_not_push_another_cited_event_out():
    from datetime import UTC, datetime, timedelta

    from shoc.capabilities.events import by_uid

    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    rows = [{"event_uid": "A", "time": t0 + timedelta(minutes=m), "n": m} for m in (1, 2, 3)]
    rows.append({"event_uid": "B", "time": t0, "n": 0})
    got = by_uid(_Store(rows), "t1", ["A", "B"]).rows
    assert [r["event_uid"] for r in got] == ["A", "B"]
    assert got[0]["n"] == 3, "the alert's newest row stands for it"


def test_an_alert_updated_past_the_read_budget_still_leaves_room_for_the_rest():
    from datetime import UTC, datetime, timedelta

    from shoc.capabilities.events import by_uid

    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    rows = [{"event_uid": "A", "time": t0 + timedelta(minutes=m), "n": m} for m in range(1, 11)]
    rows.append({"event_uid": "B", "time": t0, "n": 0})
    store = _Store(rows)
    got = by_uid(store, "t1", ["A", "B"])
    assert [r["event_uid"] for r in got.rows] == ["A", "B"]
    assert got.rows[0]["n"] == 10 and not got.truncated
    assert len(store.statements) == 2, "only the uid pushed out is read again"


def test_a_long_citation_list_stays_within_the_databricks_budget():
    from datetime import UTC, datetime, timedelta

    from shoc.capabilities.events import by_uid

    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    rows = [{"event_uid": f"e{i}", "time": t0 + timedelta(seconds=i)} for i in range(1000)]
    store = _Store(rows, "databricks")
    got = by_uid(store, "t1", [r["event_uid"] for r in rows]).rows
    assert len(got) == 1000 and got[0]["event_uid"] == "e999"
    assert len(store.statements) > 1
    assert all(
        dialect.placeholders(sql) <= dialect.max_params("databricks") for sql in store.statements
    )
