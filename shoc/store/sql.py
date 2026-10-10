"""Canonical SQL -> dialect, with SQLGlot (decision D4).

Rules and capabilities only ever write canonical SQL: ANSI over the OCSF tables,
with `:name` placeholders. `translate` produces the backend's dialect and the
parameter style it expects, so the same rule yields the same finding everywhere.
"""

from __future__ import annotations

import re
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from shoc.errors import StoreError

# A placeholder follows neither a name nor another colon: Databricks writes a
# JSON path as `raw:a.b`, and Postgres a cast as `x::text`.
PLACEHOLDER = re.compile(r"(?<![\w:]):([a-zA-Z_][a-zA-Z0-9_]*)")
# `:name` as rules write it, or `%(name)s` as SQLGlot renders it for Postgres.
ANY_PLACEHOLDER = re.compile(r"(?<![\w:]):([a-zA-Z_][a-zA-Z0-9_]*)|%\(([a-zA-Z_][a-zA-Z0-9_]*)\)s")
# `@name`, as SQLGlot renders `:name` for BigQuery.
AT_PLACEHOLDER = re.compile(r"(?<![\w@])@([a-zA-Z_][a-zA-Z0-9_]*)")

# Parameter style per dialect: how a `:name` placeholder is rendered.
PARAM_STYLE: dict[str, str] = {
    "postgres": "%({name})s",
    "databricks": "?",
    "snowflake": "%({name})s",
    "redshift": "%({name})s",
    "bigquery": "@{name}",
}

# The most placeholders one statement may carry, each repeat counted: Databricks
# refuses a 257th, BigQuery a 10,001st. A caller with more values to bind spreads
# them over several statements.
MAX_PARAMS: dict[str, int] = {"databricks": 256}


def max_params(dialect: str) -> int:
    return MAX_PARAMS.get(dialect, 10_000)


def placeholders(canonical_sql: str) -> int:
    """How many `:name` placeholders a canonical statement holds, repeats included."""
    return len(PLACEHOLDER.findall(canonical_sql))


# SQLGlot writes JSON extraction for Postgres as the `json_*` functions, and our
# JSON columns are `jsonb`, which has functions of its own and no implicit cast
# between the two. Fixing it here keeps the adapters free of SQL rewriting.
FIXUPS: dict[str, tuple[tuple[re.Pattern[str], str], ...]] = {
    "postgres": (
        (re.compile(r"\bJSON_EXTRACT_PATH_TEXT\(", re.IGNORECASE), "JSONB_EXTRACT_PATH_TEXT("),
        (re.compile(r"\bJSON_EXTRACT_PATH\(", re.IGNORECASE), "JSONB_EXTRACT_PATH("),
    ),
    # Redshift raises on text that is not JSON, and the load truncates a value
    # past 64 KB; `null_if_invalid` makes such a row a non-match instead.
    "redshift": (
        (re.compile(r"\bJSON_EXTRACT_PATH_TEXT\(([^()]*)\)"), r"JSON_EXTRACT_PATH_TEXT(\1, TRUE)"),
    ),
}


def translate(canonical_sql: str, dialect: str, limit: int | None = None) -> str:
    """Parse canonical SQL and write it in `dialect`, keeping placeholders.

    Only one query passes: `query()` is the read path on every backend, and on
    a warehouse without a reader credential it is all that stands between an
    agent and a DELETE (SEC-1). With `limit`, a SELECT returns at most that
    many rows (`capped`).
    """
    try:
        statements = [s for s in sqlglot.parse(canonical_sql) if s is not None]
    except ParseError as exc:
        raise StoreError(f"could not parse canonical SQL: {exc}") from exc
    if len(statements) != 1 or not isinstance(statements[0], exp.Query):
        raise StoreError("the event store reads one SELECT at a time; this is not one")
    tree = statements[0]
    if limit is not None:
        tree = capped(tree, limit)
    if dialect == "bigquery":
        tree = tree.transform(_bigquery)
    if dialect == "snowflake":
        # Snowflake's REGEXP_LIKE matches the whole string; Postgres and
        # Databricks search in it. REGEXP_INSTR searches on Snowflake too.
        tree = tree.transform(
            lambda node: (
                exp.Paren(
                    this=exp.GT(
                        this=exp.Anonymous(
                            this="REGEXP_INSTR", expressions=[node.this, node.expression]
                        ),
                        expression=exp.Literal.number(0),
                    )
                )
                if isinstance(node, exp.RegexpLike)
                else node
            )
        )
    out = tree.sql(dialect=dialect)
    for pattern, replacement in FIXUPS.get(dialect, ()):
        out = pattern.sub(replacement, out)
    return out


def capped(tree: exp.Query, most: int) -> exp.Query:
    """`tree` with a LIMIT of at most `most`, so the store stops there.

    `query(limit=n)` keeps n rows, and Databricks and Snowflake fetched every
    row before cutting: the daily graph and posture reads moved 74,679 rows to
    keep 20,000, and the Integrator a product's whole raw history to keep 100
    (D162). A LIMIT the caller wrote that is already lower, or bound as a
    parameter, stays. A UNION is left as it is.
    """
    if not isinstance(tree, exp.Select):
        return tree
    current = tree.args.get("limit")
    value = current.expression if isinstance(current, exp.Limit) else None
    if current is not None and not (isinstance(value, exp.Literal) and value.is_int):
        return tree
    if value is not None and int(value.name) <= most:
        return tree
    return tree.limit(most)


# Stands in for an escaped `!` while the escapes around it are rewritten.
_BANG = "\ue000"


def _bigquery(node: exp.Expression) -> exp.Expression:
    """What SQLGlot writes for BigQuery and BigQuery rejects or reads otherwise."""
    if isinstance(node, exp.Escape) and node.expression.name == "!":
        # BigQuery's LIKE has no ESCAPE clause: a backslash escapes `%`, `_`
        # and itself, and nothing else. The compiler escapes with `!`, so the
        # pattern is rewritten: `\` doubled, `!!` held aside, `!%` and `!_`
        # backslashed, then `!!` put back as a plain `!`.
        pattern: exp.Expression = node.this.expression
        for old, new in (("\\", "\\\\"), ("!!", _BANG), ("!%", "\\%"), ("!_", "\\_"), (_BANG, "!")):
            pattern = exp.Anonymous(
                this="REPLACE",
                expressions=[pattern, exp.Literal.string(old), exp.Literal.string(new)],
            )
        return type(node.this)(this=node.this.this, expression=pattern)
    if isinstance(node, exp.JSONExtractScalar) and isinstance(node.expression, exp.JSONPath):
        # Its JSONPath brackets a key with a character outside `\w` in single
        # quotes, which SQLGlot drops: `$.a['x-amz-acl']`.
        keys = [k.name for k in node.expression.expressions if isinstance(k, exp.JSONPathKey)]
        path = "$" + "".join(
            f".{k}" if re.fullmatch(r"\w+", k, re.ASCII) else f"['{k}']" for k in keys
        )
        return exp.Anonymous(
            this="JSON_EXTRACT_SCALAR", expressions=[node.this, exp.Literal.string(path)]
        )
    if isinstance(node, exp.TimeToUnix):
        return exp.Anonymous(this="UNIX_SECONDS", expressions=[node.this])
    if isinstance(node, exp.Interval) and node.this.is_string and node.this.name.isdigit():
        return exp.Interval(this=exp.Literal.number(node.this.name), unit=node.args.get("unit"))
    return node


def bind(sql: str, params: dict[str, Any] | None, dialect: str) -> tuple[str, Any]:
    """Rewrite named placeholders into the driver's style, ordering args if needed.

    SQLGlot may already have rendered `:name` in the target dialect's own style
    (Postgres writes `%(name)s`), so both forms are recognised here.
    """
    params = params or {}
    if dialect == "bigquery":
        # BigQuery binds `@name` itself. An `@` in a string literal
        # ('%@example.com') reads the same, so only names passed in count.
        names = {m.group(1) for m in AT_PLACEHOLDER.finditer(sql)}
        return sql, {n: params[n] for n in names if n in params}
    style = PARAM_STYLE.get(dialect, "%({name})s")
    names = [m.group(1) or m.group(2) for m in ANY_PLACEHOLDER.finditer(sql)]
    missing = [n for n in names if n not in params]
    if missing:
        raise StoreError(f"missing query parameter(s): {', '.join(sorted(set(missing)))}")
    if style == "?":
        ordered = [params[n] for n in names]
        return ANY_PLACEHOLDER.sub("?", sql), ordered
    bound = ANY_PLACEHOLDER.sub(lambda m: style.format(name=m.group(1) or m.group(2)), sql)
    return bound, {n: params[n] for n in names}


def prepare(
    canonical_sql: str, params: dict[str, Any] | None, dialect: str, limit: int | None = None
) -> tuple[str, Any]:
    return bind(translate(canonical_sql, dialect, limit), params, dialect)
