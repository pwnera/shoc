---
rfc: 0002
title: The EventStore adapter and the conformance suite
status: accepted
authors: ["@Rettila"]
created: 2026-09-24
requirements: ["STO-1", "STO-2", "STO-3", "STO-4"]
---

# RFC 0002: The EventStore adapter and the conformance suite

## Summary

Events live behind one small interface (`create_tenant`, `migrate`,
`load_batch`, `query`, `apply_retention`, `health`) implemented by Postgres
today and by Databricks SQL and Snowflake later. The core only ever writes
canonical SQL over the OCSF tables; each adapter translates it with SQLGlot. A
single conformance suite runs the same fixtures against every adapter and
requires the same findings.

## Motivation

A 30-person company wants one Postgres container. A 400-person company already
pays for a warehouse and will not duplicate its logs. Supporting both without
forking the detection engine means the backend has to be a detail, and the only
way to keep it a detail is to make "same fixtures, same findings" a test that
blocks the release.

## Guide-level explanation

```python
store = open_store(config, tenant_id)      # picks the backend from config
store.migrate()                            # OCSF tables for this tenant
store.load_batch("batch.ndjson.gz")        # COPY / COPY INTO
store.query(
    "SELECT event_uid, time FROM ocsf_events "
    "WHERE tenant_id = :tenant_id AND time >= :window_start",
    {"tenant_id": tid, "window_start": start},
)
```

Rules never see a dialect. `tests/conformance/` is the contract: a new adapter
is finished when that directory passes unchanged.

## Reference-level explanation

- **Canonical SQL** is ANSI over the OCSF tables with `:name` placeholders.
  `shoc/store/sql.py` transpiles it and rewrites placeholders into the driver's
  parameter style (`%(name)s` for Postgres and Snowflake, positional `?` for
  Databricks). Values are always bound, never interpolated.
- **The OCSF layout** is a flattened set of core columns plus `observables`,
  `unmapped` and `raw` (`shoc/store/ocsf.py`). It is a public contract: adding a
  column is a minor release, removing one is a major.
- **Tenancy** is a namespace per tenant: a Postgres schema, a Databricks catalog,
  a Snowflake database. `tenant_id` is also a column, and every query carries it,
  so an adapter bug cannot silently cross tenants.
- **Loading** is always batch: NDJSON.gz on local disk, then one bulk load
  (`COPY`, or `PUT` and then an insert-only `MERGE` on a warehouse). Staging
  then inserting with `ON CONFLICT DO NOTHING`, or `WHEN NOT MATCHED`, makes a
  replayed batch a no-op, which is what makes connector cursors safe to overlap.
- **Retention** drops whole partitions rather than deleting rows.
- **Per-dialect overrides are allowed inside an adapter** for performance, never
  in the core, and never in a way that changes results.

## Drawbacks

Lowest-common-denominator SQL leaves performance on the table on every backend,
and the conformance suite makes every adapter a maintenance commitment.

## Alternatives

- **Postgres only.** Rejected: excludes the larger half of the target market.
- **Per-backend detection engines.** Rejected: three engines, three bug
  surfaces, and rules that behave differently per customer.
- **A query DSL of our own instead of SQL.** Rejected: SQL is what SQLGlot
  already translates, and what a detection engineer can read.

## Dependency and scope impact

`sqlglot` in core; `databricks-sql-connector` and `snowflake-connector-python`
as optional extras only. No warehouse-specific feature may appear outside
`shoc/store/<backend>.py`.

## Security considerations

Tenant isolation lives here, not in prompts. Agents query through a read-only
role; only the ingest path writes. Assembled SQL is limited to identifiers the
code controls (`shoc/db/pool.py:q` documents the rule), and every caller-supplied
value is a bound parameter.

## Unresolved questions

Documented volume limits per backend; whether Postgres needs BRIN indexes or
declarative sub-partitioning at higher volume.

## Adoption and migration

Postgres ships in v0.1, Databricks SQL in v0.2, Snowflake in v0.4. Moving
backends is a re-ingest, not a migration; there is no cross-backend copy tool.
