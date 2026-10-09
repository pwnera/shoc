from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from shoc.detect import rules as ruleset
from shoc.detect.compiler import compile_rule, evidence_sql, page_sql
from shoc.errors import ConfigError
from shoc.store.sql import translate


def make(detection: dict, **kw) -> ruleset.Rule:
    data = {"id": "r", "title": "t", "detection": detection, **kw}
    return ruleset.from_dict(data)


def test_equality_is_case_insensitive_and_parameterised():
    c = compile_rule(
        make({"selection": {"api.operation": "ConsoleLogin"}, "condition": "selection"})
    )
    assert "LOWER(api_operation) = :p1" in c.where
    assert c.params["p1"] == "consolelogin"


def test_value_list_becomes_or():
    c = compile_rule(make({"selection": {"api.operation": ["A", "B"]}, "condition": "selection"}))
    assert c.where.count("OR") == 1


def test_modifiers_compile_to_like_and_comparisons():
    c = compile_rule(
        make(
            {
                "a": {"api.operation|startswith": "List"},
                "b": {"severity_id|gte": 3},
                "c": {"actor.session.uid|exists": False},
                "condition": "a and b and c",
            }
        )
    )
    assert "LIKE :p1" in c.where and c.params["p1"] == "list%"
    assert "severity_id >= :p2" in c.where
    assert "actor_session_uid IS NULL" in c.where


def test_condition_supports_not_and_parentheses():
    c = compile_rule(
        make(
            {
                "a": {"status": "Failure"},
                "b": {"actor.user.name": "ci"},
                "condition": "a and not b",
            }
        )
    )
    assert "NOT" in c.where


def test_aggregation_produces_group_by_and_having():
    c = compile_rule(
        make(
            {
                "selection": {"api.operation": "GetObject"},
                "condition": "selection",
                "group_by": ["actor.session.uid"],
                "count": ">= 50",
            }
        )
    )
    assert "GROUP BY actor_session_uid" in c.agg_sql
    assert "HAVING COUNT(*) >= 50" in c.agg_sql


def test_unknown_field_is_rejected():
    with pytest.raises(ConfigError, match="unknown OCSF field"):
        compile_rule(make({"selection": {"not.a.field": 1}, "condition": "selection"}))


def test_unknown_block_in_condition_is_rejected():
    with pytest.raises(ConfigError, match="unknown block"):
        compile_rule(make({"selection": {"status": "x"}, "condition": "selection and missing"}))


@pytest.mark.parametrize("dialect", ["postgres", "databricks", "snowflake"])
def test_every_shipped_rule_translates_to_every_dialect(dialect):
    for rule in ruleset.load():
        compiled = compile_rule(rule)
        groups = [["x"] * len(compiled.group_exprs), [None] * len(compiled.group_exprs)]
        scans = [compiled.select_sql, *(evidence_sql(compiled, g) for g in groups if g)]
        pages = [page_sql(scan, after, 1000) for scan in scans for after in (False, True)]
        for sql in (compiled.agg_sql, compiled.buckets_sql, *pages):
            if sql:
                assert translate(sql, dialect)


def test_a_page_resumes_after_the_last_row_even_when_times_tie():
    sql = page_sql("SELECT event_uid, time FROM ocsf_events WHERE tenant_id = :tenant_id", True, 5)
    assert sql.endswith(
        "AND (time > :after_time OR (time = :after_time AND event_uid > :after_uid)) "
        "ORDER BY time, event_uid LIMIT 5"
    )


def test_a_cycle_finds_its_buckets_by_ingestion_time():
    c = compile_rule(
        make(
            {
                "selection": {"api.operation": "DeleteTrail"},
                "condition": "selection",
                "timeframe": "15m",
            }
        )
    )
    assert c.buckets_sql.startswith("SELECT DISTINCT FLOOR(TIME_TO_UNIX(time) / 900) AS bucket")
    assert "ingested_at >= :ingested_from AND ingested_at < :ingested_to" in c.buckets_sql
    assert "LOWER(api_operation) = :p1" in c.buckets_sql and ":window_start" not in c.buckets_sql
    # Each warehouse gets its own epoch function; none is left as the canonical name.
    for dialect, epoch in (
        ("postgres", "DATE_PART('epoch', time)"),
        ("databricks", "UNIX_TIMESTAMP(time)"),
        ("snowflake", "EXTRACT(epoch_second FROM time)"),
    ):
        assert epoch in translate(c.buckets_sql, dialect)


def test_a_null_group_value_is_matched_with_is_null():
    c = compile_rule(
        make(
            {
                "s": {"status": "Failure"},
                "condition": "s",
                "group_by": ["actor.session.uid", "src_endpoint.ip"],
                "count": ">= 3",
            }
        )
    )
    sql = evidence_sql(c, [None, "203.0.113.9"])
    assert "actor_session_uid IS NULL AND src_endpoint_ip = :g_1" in sql and ":g_0" not in sql


@pytest.mark.parametrize("count", ["< 3", "<= 3", "= 3"])
def test_a_threshold_is_a_floor(count):
    with pytest.raises(ConfigError, match="count must look like"):
        compile_rule(
            make(
                {
                    "s": {"status": "Failure"},
                    "condition": "s",
                    "group_by": ["actor.user.name"],
                    "count": count,
                }
            )
        )


def test_a_rule_only_matches_the_products_its_logsource_names():
    rule = ruleset.from_dict(
        {
            "id": "r",
            "title": "t",
            "logsource": {"product": "github"},
            "detection": {
                "selection": {"api.operation|contains": "secret"},
                "condition": "selection",
            },
        }
    )
    compiled = compile_rule(rule)
    assert "LOWER(metadata_product) IN (" in compiled.where
    assert "github audit log" in compiled.params.values()


def test_a_service_narrows_the_product_further():
    guardduty = ruleset.from_dict(
        {
            "id": "g",
            "title": "t",
            "logsource": {"product": "aws", "service": "guardduty"},
            "detection": {"selection": {"status": "Success"}, "condition": "selection"},
        }
    )
    both = ruleset.from_dict(
        {
            "id": "a",
            "title": "t",
            "logsource": {"product": "aws"},
            "detection": {"selection": {"status": "Success"}, "condition": "selection"},
        }
    )
    assert "aws guardduty" in compile_rule(guardduty).params.values()
    assert "aws cloudtrail" not in compile_rule(guardduty).params.values()
    assert {"aws cloudtrail", "aws guardduty"} <= set(compile_rule(both).params.values())


def test_a_logsource_no_mapping_answers_to_matches_nothing():
    """It used to match every product's events (ING-4)."""
    rule = ruleset.from_dict(
        {
            "id": "r",
            "title": "t",
            "logsource": {"product": "carrier_pigeon"},
            "detection": {"selection": {"status": "Success"}, "condition": "selection"},
        }
    )
    assert " AND FALSE AND " in compile_rule(rule).where
    anywhere = ruleset.from_dict(
        {"id": "r", "title": "t", "detection": {"selection": {"status": "Success"}}}
    )
    assert "metadata_product" not in compile_rule(anywhere).where


def test_a_new_product_is_one_mapping_file(tmp_path, monkeypatch):
    """A mapping answers to its own name, and to the logsources it lists (ING-4)."""
    from shoc.ingest import connectors, ocsf
    from shoc.store import ocsf as layout

    for path in ocsf.mappings_dir().glob("*.yaml"):
        (tmp_path / path.name).write_text(path.read_text())
    (tmp_path / "acme_saas.yaml").write_text(
        "source: acme_saas\nlogsource: [acme]\nconstants: {metadata_product: Acme SaaS}\n"
    )
    monkeypatch.setattr(ocsf, "mappings_dir", lambda: tmp_path)
    layout.products.cache_clear()
    try:
        rule = ruleset.from_dict(
            {
                "id": "r",
                "title": "t",
                "logsource": {"product": "acme", "service": "audit"},
                "detection": {"selection": {"status": "Success"}, "condition": "selection"},
            }
        )
        assert set(compile_rule(rule).params.values()) == {"acme saas", "success"}
        assert ocsf.source_for("acme", "audit") == "acme_saas"
        # A mapping with no pull connector takes pushes.
        assert connectors.push_sources() == ["acme_saas"] and connectors.accepts_push("acme_saas")
    finally:
        layout.products.cache_clear()


def test_every_shipped_rule_names_a_product_we_can_filter_on():
    from shoc.store import ocsf as layout

    for rule in ruleset.load():
        product = rule.logsource.get("product", "")
        assert layout.products_for(product, rule.logsource.get("service", "")), (
            f"{rule.id}: logsource product '{product}' is not mapped to any metadata.product.name"
        )


def test_a_regex_rule_compiles_to_a_portable_function():
    rule = ruleset.from_dict(
        {
            "id": "r",
            "title": "t",
            "logsource": {"product": "aws"},
            "detection": {
                "selection": {"actor.user.name|re": "^svc-[0-9]+$"},
                "condition": "selection",
            },
        }
    )
    compiled = compile_rule(rule)
    assert "REGEXP_LIKE(actor_user_name" in compiled.where
    for dialect in ("postgres", "databricks", "snowflake"):
        assert translate(compiled.select_sql, dialect)


def test_a_bad_regex_is_rejected_at_compile_time():
    with pytest.raises(ConfigError, match="bad regular expression"):
        compile_rule(
            ruleset.from_dict(
                {
                    "id": "r",
                    "title": "t",
                    "detection": {
                        "selection": {"actor.user.name|re": "([unclosed"},
                        "condition": "selection",
                    },
                }
            )
        )


# -- source-specific fields (RFC 0009) --------------------------------------
def test_source_path_compiles_to_a_portable_json_extraction():
    c = compile_rule(make({"s": {"raw.debugContext.debugData.dtHash": "abc"}, "condition": "s"}))
    assert "LOWER(JSON_EXTRACT_SCALAR(raw, '$.debugContext.debugData.dtHash')) = :p1" in c.where
    assert "JSONB_EXTRACT_PATH_TEXT(raw, 'debugContext', 'debugData', 'dtHash')" in translate(
        f"SELECT 1 FROM t WHERE {c.where}", "postgres"
    )


def test_source_path_comparison_survives_a_non_numeric_neighbour():
    c = compile_rule(make({"s": {"raw.detail.severity|gte": 7}, "condition": "s"}))
    assert "REGEXP_LIKE(JSON_EXTRACT_SCALAR(raw, '$.detail.severity')" in c.where
    assert "AS DOUBLE) >= :p1" in c.where


def test_source_path_is_selected_under_a_stable_alias():
    c = compile_rule(
        make(
            {"s": {"api.operation": "x"}, "condition": "s"},
            fields=["unmapped.client.device"],
        )
    )
    assert (
        "JSON_EXTRACT_SCALAR(unmapped, '$.client.device') AS unmapped_client_device" in c.select_sql
    )


def test_source_path_groups_and_the_group_key_is_the_alias():
    c = compile_rule(
        make(
            {
                "s": {"api.operation": "x"},
                "condition": "s",
                "group_by": ["raw.client.zone"],
                "count": ">= 3",
            }
        )
    )
    assert c.group_columns == ["raw_client_zone"]
    assert "AS raw_client_zone" in c.agg_sql
    assert "GROUP BY JSON_EXTRACT_SCALAR(raw, '$.client.zone')" in c.agg_sql


def test_a_path_that_could_escape_the_literal_is_not_a_field():
    with pytest.raises(ConfigError):
        compile_rule(make({"s": {"raw.a') OR (1=1--": "x"}, "condition": "s"}))


# -- RFC 0023: the format additions -----------------------------------------
DIALECTS = ("postgres", "databricks", "snowflake")


def _everywhere(compiled) -> dict[str, str]:
    """Each scan of a compiled rule, translated to every dialect."""
    out = {}
    for d in DIALECTS:
        for sql in (compiled.select_sql, compiled.agg_sql, compiled.buckets_sql):
            if sql:
                out[d] = out.get(d, "") + translate(sql, d) + "\n"
    return out


def test_like_values_are_matched_literally_with_one_escape_on_every_dialect():
    c = compile_rule(
        make(
            {
                "s": {
                    "process.cmd_line|contains": r"C:\Users\Public\x_1%!.exe",
                    "file.path|startswith": "a_b",
                    "file.path|endswith": "%",
                },
                "condition": "s",
            }
        )
    )
    assert c.params["p1"] == "%c:\\users\\public\\x!_1!%!!.exe%"
    assert c.params["p2"] == "a!_b%" and c.params["p3"] == "%!%"
    assert c.where.count("ESCAPE '!'") == 3
    for sql in _everywhere(c).values():
        assert sql.count("ESCAPE '!'") >= 3


def test_a_boolean_on_a_source_path_is_compared_as_json_text():
    c = compile_rule(
        make(
            {
                "s": {"raw.requestParameters.enabled": True, "unmapped.a.b": [False, "x"]},
                "condition": "s",
            }
        )
    )
    assert "LOWER(JSON_EXTRACT_SCALAR(raw, '$.requestParameters.enabled')) = :p1" in c.where
    assert c.params["p1"] == "true" and c.params["p2"] == "false"


def test_distinct_count_compiles_to_a_count_distinct_having():
    c = compile_rule(
        make(
            {
                "s": {"status": "Failure"},
                "condition": "s",
                "group_by": ["src_endpoint.ip"],
                "count_distinct": "raw.userName",
                "count": ">= 5",
            }
        )
    )
    assert "HAVING COUNT(DISTINCT JSON_EXTRACT_SCALAR(raw, '$.userName')) >= 5" in c.agg_sql
    assert c.distinct_column == "raw_username"
    sql = evidence_sql(c, ["203.0.113.9"])
    assert "JSON_EXTRACT_SCALAR(raw, '$.userName') AS raw_username" in sql
    for d in DIALECTS:
        assert translate(sql, d) and translate(c.agg_sql, d)


def test_distinct_count_needs_a_threshold():
    with pytest.raises(ConfigError, match="count_distinct needs count"):
        make(
            {
                "s": {"status": "Failure"},
                "condition": "s",
                "group_by": ["src_endpoint.ip"],
                "count_distinct": "actor.user.name",
            }
        )


SEQUENCE = {
    "reset": {"api.operation": "UpdateLoginProfile"},
    "signin": {"api.operation": "ConsoleLogin"},
    "sequence": {"by": "actor.user.name", "first": "reset", "then": "signin", "within": "1h"},
}


def test_a_sequence_is_an_exists_over_an_earlier_event_with_the_same_key():
    rule = make(dict(SEQUENCE), logsource={"product": "aws", "service": "cloudtrail"})
    assert rule.detection.condition == "signin"
    assert rule.detection.sequence["by"] == ["actor.user.name"]
    c = compile_rule(rule)
    assert "EXISTS (SELECT 1 FROM ocsf_events f WHERE f.tenant_id = :tenant_id" in c.where
    assert "f.actor_user_name = e.actor_user_name" in c.where
    assert "f.time >= e.time - INTERVAL '3600' SECOND" in c.where
    assert "LOWER(f.metadata_product) IN (" in c.where
    assert "AS sequence_first" in c.select_sql
    # A `first` delivered late lists the bucket of the `then` it pairs with.
    assert "UNION SELECT DISTINCT FLOOR(TIME_TO_UNIX(e.time) / 900) AS bucket" in c.buckets_sql
    assert "f.ingested_at >= :ingested_from" in c.buckets_sql
    for d, sql in _everywhere(c).items():
        assert "EXISTS" in sql and "UNION" in sql, d


@pytest.mark.parametrize(
    "bad",
    [
        {**SEQUENCE, "condition": "signin"},
        {**SEQUENCE, "sequence": {"by": "actor.user.name", "first": "reset", "within": "1h"}},
        {**SEQUENCE, "sequence": {**SEQUENCE["sequence"], "within": "soon"}},
        {**SEQUENCE, "group_by": ["actor.user.name"], "count": ">= 2"},
    ],
)
def test_a_sequence_is_refused_when_it_is_ambiguous(bad):
    with pytest.raises(ConfigError):
        make(bad)


def test_fieldref_compares_two_fields_of_the_same_event():
    c = compile_rule(
        make(
            {
                "s": {"api.operation": "CreateAccessKey"},
                "same": {"raw.requestParameters.userName|fieldref": "actor.user.name"},
                "condition": "s and not same",
            }
        )
    )
    assert (
        "NOT COALESCE((LOWER(JSON_EXTRACT_SCALAR(raw, '$.requestParameters.userName')) = "
        "LOWER(actor_user_name)), FALSE)"
    ) in c.where
    numeric = compile_rule(
        make({"s": {"src_endpoint.port|fieldref": "dst_endpoint.port"}, "condition": "s"})
    )
    assert "LOWER(CAST(src_endpoint_port AS VARCHAR))" in numeric.where


def test_fieldref_to_an_unknown_field_is_refused():
    with pytest.raises(ConfigError, match="unknown OCSF field"):
        compile_rule(make({"s": {"actor.user.name|fieldref": "nope"}, "condition": "s"}))


@pytest.mark.parametrize(
    "network",
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "203.0.113.0/24",
        "198.51.100.7/32",
        "0.0.0.0/0",
        "fc00::/7",
        "fe80::/10",
        "2001:db8::/32",
        "2001:db8:abcd:12::/64",
        "::1/128",
        "2000::/3",
        "2001:db8:1:1:1:1:1:1000/116",
    ],
)
def test_a_cidr_pattern_matches_exactly_the_addresses_in_the_network(network):
    import ipaddress
    import random
    import re

    from shoc.detect.compiler import cidr_pattern

    net = ipaddress.ip_network(network)
    pattern = re.compile(cidr_pattern(network))
    rng = random.Random(network)
    width = net.max_prefixlen
    base = int(net.network_address)
    inside = [
        base,
        base + net.num_addresses - 1,
        *(base + rng.randrange(net.num_addresses) for _ in range(200)),
    ]
    outside = [rng.randrange(2**width) for _ in range(400)] + [base - 1, base + net.num_addresses]
    cls = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
    for n in inside + outside:
        if not 0 <= n < 2**width:
            continue
        addr = cls(n)
        assert bool(pattern.fullmatch(str(addr))) == (addr in net), (network, str(addr))
    other = "203.0.113.5" if net.version == 6 else "2001:db8::5"
    assert not pattern.fullmatch(other)


@pytest.mark.parametrize("network", ["64:ff9b::/96", "2001:0:0:1::/64", "::/8", "nonsense"])
def test_a_cidr_whose_text_has_no_fixed_start_is_refused(network):
    with pytest.raises(ConfigError):
        compile_rule(make({"s": {"src_endpoint.ip|cidr": network}, "condition": "s"}))


def test_cidr_compiles_to_an_anchored_regex_on_every_dialect():
    c = compile_rule(
        make({"s": {"src_endpoint.ip|cidr": ["10.0.0.0/8", "fc00::/7"]}, "condition": "s"})
    )
    assert c.where.count("REGEXP_LIKE(LOWER(src_endpoint_ip), :p") == 2
    assert c.params["p1"] == "^10[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$"
    assert c.params["p2"] == "^f[cd][0-9a-f][0-9a-f]:.*$"
    out = _everywhere(c)
    assert "LOWER(src_endpoint_ip) ~ %(p1)s" in out["postgres"]
    assert "REGEXP_INSTR(LOWER(src_endpoint_ip), :p1) > 0" in out["snowflake"]


def test_snowflake_searches_with_re_like_the_other_dialects():
    c = compile_rule(make({"s": {"process.cmd_line|re": "-enc "}, "condition": "s"}))
    out = translate(c.select_sql, "snowflake")
    assert "REGEXP_INSTR(process_cmd_line, :p1) > 0" in out and "REGEXP_LIKE" not in out


def test_first_seen_in_a_rule_is_an_anti_join_on_its_own_selection():
    rule = make(
        {"s": {"api.operation": "ConsoleLogin", "status": "Success"}, "condition": "s"},
        logsource={"product": "aws"},
        baseline={"first_seen": ["actor.user.name", "src_endpoint.ip"], "lookback": "14d"},
    )
    c = compile_rule(rule)
    assert "NOT EXISTS (SELECT 1 FROM ocsf_events h WHERE h.tenant_id = :tenant_id" in c.where
    assert "LOWER(h.api_operation) = :" in c.where
    assert "h.src_endpoint_ip = e.src_endpoint_ip" in c.where
    assert "h.time >= e.time - INTERVAL '1209600' SECOND" in c.where
    assert "(SELECT MIN(o.time) FROM ocsf_events o" in c.where
    assert "e.src_endpoint_ip <> ''" in c.where
    for d, sql in _everywhere(c).items():
        assert "NOT EXISTS" in sql, d


def test_a_probe_reads_no_history_and_keeps_what_a_late_first_event_pairs_with():
    """A cycle asks the probe of many rules at once; it may say yes too often, never no (D149)."""
    seen = compile_rule(
        make(
            {"s": {"api.operation": "ConsoleLogin"}, "condition": "s"},
            logsource={"product": "aws"},
            baseline={"first_seen": ["actor.user.name"], "lookback": "14d"},
        ),
        prefix="r7_",
    )
    assert "EXISTS" not in seen.probe and "LOWER(api_operation) = :r7_p" in seen.probe
    assert all(name.startswith("r7_p") for name in seen.params)
    pair = compile_rule(make(dict(SEQUENCE), logsource={"product": "aws"}))
    assert "EXISTS" not in pair.probe
    bound = [pair.params[name] for name in re.findall(r":(\w+)", pair.probe)]
    assert "updateloginprofile" in bound, "a `first` ingested now wakes the rule"
    for d in ("postgres", "databricks", "snowflake", "redshift", "bigquery"):
        translate(f"SELECT MAX(CASE WHEN {pair.probe} THEN 1 ELSE 0 END) FROM ocsf_events", d)


def test_first_seen_needs_an_indexed_column_and_no_other_correlation():
    with pytest.raises(ConfigError, match="index"):
        compile_rule(
            make(
                {"s": {"status": "Success"}, "condition": "s"},
                baseline={"first_seen": ["actor.session.uid", "http_request.user_agent"]},
            )
        )
    with pytest.raises(ConfigError, match="one of count, sequence and first_seen"):
        make(
            {
                "s": {"status": "Success"},
                "condition": "s",
                "group_by": ["actor.user.name"],
                "count": ">= 3",
            },
            baseline={"first_seen": ["actor.user.name"]},
        )
    with pytest.raises(ConfigError, match="first_seen, lookback, while_learning and learns_from"):
        make(
            {"s": {"status": "Success"}, "condition": "s"},
            baseline={"rare": {"by": ["api.operation"]}},
        )
    with pytest.raises(ConfigError, match="while_learning is quiet or fire"):
        make(
            {"s": {"status": "Success"}, "condition": "s"},
            baseline={"first_seen": ["actor.user.name"], "while_learning": "loud"},
        )
    with pytest.raises(ConfigError, match="learns_from is product or selection"):
        make(
            {"s": {"status": "Success"}, "condition": "s"},
            baseline={"first_seen": ["actor.user.name"], "learns_from": "source"},
        )


def test_a_rule_that_fires_while_learning_is_new_or_not_yet_learnt():
    rule = make(
        {"s": {"api.operation": "authorize"}, "condition": "s"},
        logsource={"product": "google"},
        baseline={"first_seen": ["actor.user.name", "resource.uid"], "while_learning": "fire"},
    )
    c = compile_rule(rule, {"C0123": datetime(2026, 11, 1, tzinfo=UTC)})
    assert " OR NOT ((SELECT MIN(o.time) FROM ocsf_events o" in c.where
    assert "AND NOT (COALESCE(cloud_account_uid" not in c.where
    assert " OR (COALESCE(cloud_account_uid, '') = :" in c.where
    for d, sql in _everywhere(c).items():
        assert "NOT EXISTS" in sql, d


def test_a_rule_that_learns_from_its_selection_reads_its_own_first_match():
    """D157: the history that must cover the lookback is the rule's own matches."""
    base = {"first_seen": ["api.operation", "raw.data.object.destination"], "lookback": "60d"}
    detection = {"s": {"api.operation": "payout.created"}, "condition": "s"}
    product = compile_rule(make(detection, logsource={"product": "stripe"}, baseline=base))
    own = compile_rule(
        make(
            detection,
            logsource={"product": "stripe"},
            baseline={**base, "learns_from": "selection"},
        )
    )
    learnt = r"\(SELECT MIN\(o\.time\) FROM ocsf_events o WHERE (.*?)\) <= e\.time"
    [products] = re.findall(learnt, product.where)
    [matches] = re.findall(learnt, own.where)
    assert "o.metadata_product" in products and "o.api_operation" not in products
    assert "o.metadata_product" in matches and "o.api_operation" in matches
    for d, sql in _everywhere(own).items():
        assert "NOT EXISTS" in sql, d


def test_entity_takes_a_list_and_every_field_is_selected():
    rule = make(
        {"s": {"status": "Success"}, "condition": "s"},
        entity=["resource.uid", "raw.detail.accountId"],
    )
    assert rule.entity == ["resource.uid", "raw.detail.accountId"]
    assert "AS raw_detail_accountid" in compile_rule(rule).select_sql
    single = make({"s": {"status": "x"}, "condition": "s"}, entity="actor.user.name")
    assert single.entity == ["actor.user.name"]


def test_entity_falls_back_to_the_next_field_with_a_value():
    from shoc.detect.engine import _entity_value

    rule = make(
        {"s": {"status": "Success"}, "condition": "s"}, entity=["resource.uid", "actor.user.name"]
    )
    assert _entity_value({"resource_uid": "i-0abc", "actor_user_name": "a"}, rule) == "i-0abc"
    assert _entity_value({"resource_uid": None, "actor_user_name": "a"}, rule) == "a"
    assert _entity_value({"resource_uid": "", "actor_user_name": None}, rule) == "-"


def test_a_list_item_path_points_at_the_mapping_keyed_lists():
    with pytest.raises(ConfigError, match="keyed"):
        compile_rule(make({"s": {"raw.events.parameters[name=X].value": "y"}, "condition": "s"}))


def test_a_json_list_or_object_is_read_as_its_json_text_on_every_dialect():
    """`contains`/`re`/`exists` on a list rely on extraction returning its JSON text."""
    c = compile_rule(
        make(
            {
                "a": {"raw.rule.groups|contains": "admins"},
                "b": {"raw.rule.groups|re": '"admins"'},
                "c": {"raw.rule|exists": True},
                "condition": "a and b and c",
            }
        )
    )
    out = _everywhere(c)
    assert "JSONB_EXTRACT_PATH_TEXT(raw, 'rule', 'groups')" in out["postgres"]
    assert "raw:rule.groups" in out["databricks"]
    assert "JSON_EXTRACT_PATH_TEXT(raw, 'rule.groups')" in out["snowflake"]


def test_a_source_path_with_a_hyphen_is_quoted_on_every_dialect():
    """SQLGlot reads a bare `-` in a JSON path as an operator: the key is bracketed."""
    c = compile_rule(
        make(
            {"s": {"raw.requestParameters.x-amz-acl|contains": "public-read"}, "condition": "s"},
            fields=["raw.requestParameters.x-amz-acl"],
        )
    )
    assert """JSON_EXTRACT_SCALAR(raw, '$.requestParameters["x-amz-acl"]')""" in c.where
    assert "AS raw_requestparameters_x_amz_acl" in c.select_sql
    out = _everywhere(c)
    assert "JSONB_EXTRACT_PATH_TEXT(raw, 'requestParameters', 'x-amz-acl')" in out["postgres"]
    assert 'raw:requestParameters["x-amz-acl"]' in out["databricks"]
    assert """JSON_EXTRACT_PATH_TEXT(raw, 'requestParameters["x-amz-acl"]')""" in out["snowflake"]


def test_a_databricks_json_path_is_not_read_as_a_parameter():
    from shoc.store.sql import prepare

    c = compile_rule(make({"s": {"raw.rule.groups|contains": "admins"}, "condition": "s"}))
    params = {**c.params, "tenant_id": "t", "window_start": 1, "window_end": 2}
    sql, args = prepare(c.select_sql, params, "databricks")
    assert "raw:rule.groups" in sql and len(args) == sql.count("?")
    pg, _ = prepare("SELECT x::text FROM ocsf_events WHERE a = :tenant_id", params, "postgres")
    assert "%(tenant_id)s" in pg


def test_hunt_rare_takes_a_floor_as_well_as_a_ceiling():
    from shoc.detect import hunts
    from shoc.detect.compiler import compile_pack

    pack = hunts.from_dict(
        {
            "id": "h",
            "title": "t",
            "hypothesis": "x",
            "triage": "y",
            "pivot": ["actor.session.uid"],
            "detection": {"s": {"status": "Success"}, "condition": "s"},
            "baseline": {
                "rare": {
                    "by": ["actor.session.uid"],
                    "among": "src_endpoint.ip",
                    "seen_by_at_least": 2,
                }
            },
        }
    )
    sql = compile_pack(pack).select_sql
    assert "HAVING COUNT(DISTINCT src_endpoint_ip) >= 2 AND MAX(ingested_at)" in sql
