---
rfc: 0009
title: Querying source-specific fields
status: proposed
authors: ["@Rettila"]
created: 2026-09-25
requirements: ["ING-3", "DET-1", "STO-1"]
amends: ["D4 (canonical SQL): adds a JSON extraction primitive"]
---

# RFC 0009: Querying source-specific fields

## Summary

A rule can only match on the OCSF columns the layout flattens. Everything else a
source emits is stored and cannot be queried, so a detection that depends on a
field one product has (an Okta device-token hash, a GuardDuty severity score, a
CrowdStrike behaviour id) cannot be written at all. This RFC makes those fields
addressable by their source path, `raw.debugContext.debugData.dtHash`, and
compiles the path to a JSON extraction each adapter already supports.

## Motivation

Normalisation is what lets one rule run across products, and it is also what
throws away the detail that decides a verdict. The flattened layout has 38
columns; an Okta system-log record has around 80 leaves, a CrowdStrike detection
several hundred. The residue was kept from the start (`raw` holds the record
verbatim and `unmapped` was meant to hold the leftovers), but nothing could read
it:

- `column_for` resolved only names in `FIELD_MAP` and `COLUMN_NAMES`, so the
  compiler rejected any other field as `unknown OCSF field`.
- `unmapped` was computed by top-level key. Reading `client.ipAddress` marked the
  whole `client` object consumed, so `client.zone` and `client.device` vanished
  from it, and the column did not mean what its name said.

The practical result was that `raw` was evidence a human could read in a case and
nothing more. A detection engineer who needed one product-specific field had two
options: add a column to the shared layout for a field one source emits, or give
up on the rule.

## Options considered

**A column per interesting field.** Every new detection widens a table every
backend has to migrate, for a field 90% of sources never populate. The layout is
a public contract and would churn on detection content.

**A declared `keep:` list per mapping, promoted into an `extra` column.** Better
than a column each, but the mapping author has to predict which fields a future
rule will want, and a rule that needs an unanticipated field still waits for a
mapping change and a re-ingest. It also adds a third residue column beside `raw`
and `unmapped`.

**Address the source path directly (chosen).** Every field is reachable the day
it arrives, no mapping predicts anything, no column is added, and the rule reads
like the vendor's own documentation.

## Design

### Addressing

`raw.<path>` and `unmapped.<path>` resolve to a JSON extraction over that
column. `raw` is the complete record; `unmapped` is the subset no field path
read, which is the right place to look when writing a new rule because it is
what normalisation has not already covered.

Path segments match `[A-Za-z0-9_@$-]` and nothing else. A path that could close
the SQL string literal does not match the pattern, so it resolves to nothing and
the compiler reports an unknown field. That regex is the whole injection
boundary; values stay bound as parameters as before.

### Canonical SQL

`raw.a.b` compiles to `JSON_EXTRACT_SCALAR(raw, '$.a.b')`, which SQLGlot writes
as `JSONB_EXTRACT_PATH_TEXT(raw, 'a', 'b')` on Postgres, `raw:a.b` on Databricks
and `JSON_EXTRACT_PATH_TEXT(raw, 'a.b')` on Snowflake. SQLGlot emits the `json_`
family for Postgres where our columns are `jsonb`, and there is no implicit cast
between the two, so `translate` carries a per-dialect fixup table beside the
parameter styles it already carries.

An extracted value is text. `gt`, `gte`, `lt` and `lte` wrap it as

```sql
CAST(CASE WHEN REGEXP_LIKE(expr, '^-?[0-9]+([.][0-9]+)?$') THEN expr END AS DOUBLE)
```

so a row where the same key holds a word yields NULL rather than aborting the
query, which is how every other non-match behaves.

### Result rows

A path also has to survive projection and grouping, where the engine reads
values back by column name. Each field carries an expression for the SQL and an
alias for the result key: `raw.client.zone` selects as
`JSON_EXTRACT_SCALAR(raw, '$.client.zone') AS raw_client_zone`. Aliases are
lower-cased because backends fold unquoted identifiers, and two paths differing
only in case or in where the dots fall share an alias. That is a name collision, not a
wrong value.

### `unmapped` becomes what it claims

Consumed paths are recorded in full and pruned leaf by leaf, list indices
normalised away, so `client.ipAddress` retires that leaf and leaves its
siblings.

## Costs

These fields are not indexed, and a rule whose only predicate is a source path
scans the window. That is acceptable at the scale v0.1 targets and would be
fixed, if a specific path became hot, by an expression index in the Postgres
adapter rather than by changing the language. Databricks' `:` operator matches
field names case-insensitively where Postgres and Snowflake do not, so a rule
that relies on case has one backend answering differently; the conformance suite
uses exact keys.

`raw` keeps the whole record, so the storage cost of this feature is one already
paid.

## Migration

None. No column is added or removed, and existing rules compile unchanged.
