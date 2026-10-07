"""Sigma-subset -> canonical SQL (DET-1).

We compile the subset our own rules use, rather than depending on pySigma
(decision D11). Supported:

- field matches with `contains`, `startswith`, `endswith` (the value is matched
  literally: `%`, `_` and a backslash are not wildcards), `re`, `gt/gte/lt/lte`,
  `exists`, `cidr` (an IPv4 or IPv6 network) and `fieldref` (equal to another
  field of the same event); value lists as OR;
- `and`, `or`, `not` and parentheses over named blocks;
- an optional aggregation, `group_by` + `count: ">= N"`, counting events or, with
  `count_distinct: <field>`, distinct values of a field;
- `sequence: {by, first, then, within}`: the `then` event fires when a `first`
  event with the same `by` values came before it within `within` (RFC 0023);
- `baseline: {first_seen: [...], lookback}`: the event fires only when its tuple
  was not seen in the lookback before it (RFC 0023);
- `entity: [a, b]`: the first of those fields with a value keys the finding.

A `true`/`false` on a `raw.` or `unmapped.` path is compared as the text JSON
extraction returns on every backend. Values are always bound as parameters,
never inlined.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from shoc.detect.rules import parse_timeframe
from shoc.errors import ConfigError
from shoc.store import ocsf as layout

MODIFIERS = (
    "contains",
    "startswith",
    "endswith",
    "re",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "in",
    "cidr",
    "fieldref",
)
# The rule scans name the event they read `e`, so a sequence or a first-seen
# baseline can compare it with another event in a correlated subquery.
EVENTS = f"{layout.EVENTS_TABLE} e"
# A first-seen anti-join must start from an indexed column on Postgres
# (`shoc/store/postgres.py`), or each candidate event scans the whole lookback.
INDEXED = ("actor_user_name", "api_operation", "src_endpoint_ip")


@dataclass
class CompiledRule:
    rule_id: str
    where: str
    params: dict[str, Any] = field(default_factory=dict)
    select_sql: str = ""
    agg_sql: str = ""
    group_columns: list[str] = field(default_factory=list)
    group_exprs: list[str] = field(default_factory=list)
    count_op: str = ""
    count_value: int = 0
    # With `count_distinct`, the alias and expression of the counted field.
    distinct_column: str = ""
    distinct_expr: str = ""
    buckets_sql: str = ""


class _Params:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self._n = 0

    def add(self, value: Any) -> str:
        self._n += 1
        name = f"p{self._n}"
        self.values[name] = value
        return f":{name}"


def _column(field_name: str, rule_id: str) -> str:
    col = layout.column_for(field_name)
    if col is None:
        hint = (
            "; a list item is read through the mapping's `keyed` lists, "
            "as unmapped.<alias>.<name> (RFC 0023)"
            if "[" in field_name
            else ""
        )
        raise ConfigError(f"{rule_id}: unknown OCSF field '{field_name}'{hint}")
    return col


def _like(col: str, pattern: str, params: _Params) -> str:
    """A case-insensitive LIKE whose `%` and `_` come only from the modifier.

    `!` is the escape character on every dialect: a backslash is LIKE's default
    escape on Postgres and Databricks and nothing on Snowflake, and a Windows
    path is full of them. BigQuery has no ESCAPE clause; `store.sql` rewrites
    the pattern into its backslash escapes.
    """
    return f"LOWER({col}) LIKE {params.add(pattern)} ESCAPE '!'"


def _literal(value: Any) -> str:
    return re.sub(r"([!%_])", r"!\1", str(value).lower())


def _text(col: str) -> str:
    return f"LOWER(CAST({col} AS VARCHAR))" if col in layout.INT_COLUMNS else f"LOWER({col})"


def cidr_pattern(value: Any, rule_id: str = "") -> str:
    """A regular expression matching the text of every address in a network.

    Anchored at both ends, so it means the same on Snowflake, whose
    `REGEXP_LIKE` matches the whole string, as on Postgres and Databricks.
    Addresses are compared as the mappings store them (`ipaddress` text:
    lower case, no leading zeros, `::` for the longest run of zero groups).
    """
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise ConfigError(f"{rule_id}: bad network '{value}': {exc}") from exc
    if net.prefixlen == net.max_prefixlen:
        return "^" + str(net.network_address).replace(".", "[.]") + "$"
    if net.version == 4:
        parts = []
        for i, octet in enumerate(net.network_address.packed):
            fixed = min(max(net.prefixlen - 8 * i, 0), 8)
            if fixed == 8:
                parts.append(str(octet))
            elif fixed == 0:
                parts.append("[0-9]{1,3}")
            else:
                values = range(octet, octet + 2 ** (8 - fixed))
                parts.append("(" + "|".join(str(v) for v in values) + ")")
        return "^" + "[.]".join(parts) + "$"
    if net.prefixlen == 0:
        return "^[0-9a-f:.]*:[0-9a-f:.]*$"
    packed = net.network_address.packed
    groups = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    full, bits = divmod(net.prefixlen, 16)
    if 0 in groups[:full] or (bits and groups[full] < 0x1000):
        # `::` can swallow a zero group and leading zeros are dropped, so the
        # text of such a prefix has no fixed start to match.
        raise ConfigError(
            f"{rule_id}: cidr '{value}' has a zero group in its prefix; "
            "list the narrower networks it covers instead"
        )
    head = "".join(f"{g:x}:" for g in groups[:full])
    if not bits:
        return f"^{head}.*$"
    low, high = f"{groups[full]:04x}", f"{groups[full] + 2 ** (16 - bits) - 1:04x}"
    part = "".join(
        a
        if a == b
        else "[0-9a-f]"
        if (a, b) == ("0", "f")
        else "[" + "".join(f"{d:x}" for d in range(int(a, 16), int(b, 16) + 1)) + "]"
        for a, b in zip(low, high, strict=True)
    )
    return f"^{head}{part}" + (":.*$" if full < 7 else "$")


_NUMERIC_TEXT = "'^-?[0-9]+([.][0-9]+)?$'"


def _numeric(col: str, field_name: str) -> str:
    """Compare a JSON-path field as a number without failing on the rest.

    A source field is text once extracted, and a bare CAST raises on the row
    where the same key holds a word. The CASE returns NULL there instead, which
    is what any other non-match does.
    """
    if not layout.JSON_FIELD.match(field_name):
        return col
    return f"CAST(CASE WHEN REGEXP_LIKE({col}, {_NUMERIC_TEXT}) THEN {col} END AS DOUBLE)"


def _leaf(field_spec: str, value: Any, params: _Params, rule_id: str) -> str:
    name, _, modifier = field_spec.partition("|")
    modifier = modifier.strip().lower()
    if modifier and modifier not in MODIFIERS:
        raise ConfigError(f"{rule_id}: unsupported modifier '{modifier}'")
    name = name.strip()
    col = _column(name, rule_id)
    if modifier == "exists":
        return f"{col} IS NOT NULL" if value else f"{col} IS NULL"
    if isinstance(value, list):
        if not value:
            raise ConfigError(f"{rule_id}: empty value list for '{field_spec}'")
        parts = [_leaf(field_spec, v, params, rule_id) for v in value]
        return "(" + " OR ".join(parts) + ")"
    if value is None:
        return f"{col} IS NULL"
    if isinstance(value, bool) and layout.JSON_FIELD.match(name):
        # JSON extraction returns text on every backend: `true`, not a boolean.
        value = "true" if value else "false"
    if modifier == "fieldref":
        return f"{_text(col)} = {_text(_column(str(value), rule_id))}"
    if modifier == "cidr":
        return f"REGEXP_LIKE(LOWER({col}), {params.add(cidr_pattern(value, rule_id))})"
    if modifier in ("gt", "gte", "lt", "lte"):
        op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[modifier]
        return f"{_numeric(col, name)} {op} {params.add(value)}"
    if modifier == "contains":
        return _like(col, f"%{_literal(value)}%", params)
    if modifier == "startswith":
        return _like(col, f"{_literal(value)}%", params)
    if modifier == "endswith":
        return _like(col, f"%{_literal(value)}", params)
    if modifier == "re":
        try:
            re.compile(str(value))
        except re.error as exc:
            raise ConfigError(f"{rule_id}: bad regular expression: {exc}") from exc
        return f"REGEXP_LIKE({col}, {params.add(str(value))})"
    if isinstance(value, bool):
        return f"{col} = {params.add(value)}"
    if isinstance(value, (int, float)):
        return f"{_numeric(col, name)} = {params.add(value)}"
    return f"LOWER({col}) = {params.add(str(value).lower())}"


def _block(name: str, spec: Any, params: _Params, rule_id: str) -> str:
    if isinstance(spec, list):
        return "(" + " OR ".join(_block(name, s, params, rule_id) for s in spec) + ")"
    if not isinstance(spec, dict):
        raise ConfigError(f"{rule_id}: block '{name}' must be a map or a list of maps")
    parts = [_leaf(k, v, params, rule_id) for k, v in spec.items()]
    if not parts:
        raise ConfigError(f"{rule_id}: block '{name}' is empty")
    return "(" + " AND ".join(parts) + ")"


# -- condition parser -------------------------------------------------------
_TOKEN = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_*]*)", re.IGNORECASE)


def _tokenize(condition: str, rule_id: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            if condition[pos:].strip():
                raise ConfigError(f"{rule_id}: cannot parse condition at '{condition[pos:]}'")
            break
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


def compile_condition(condition: str, blocks: dict[str, str], rule_id: str) -> str:
    """Recursive descent over `and` / `or` / `not` / parentheses and block names."""
    tokens = _tokenize(condition or " and ".join(blocks), rule_id)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def expect_name(token: str) -> str:
        if token.endswith("*"):
            prefix = token[:-1]
            matched = [blocks[b] for b in blocks if b.startswith(prefix)]
            if not matched:
                raise ConfigError(f"{rule_id}: no detection block matches '{token}'")
            return "(" + " OR ".join(matched) + ")"
        if token not in blocks:
            raise ConfigError(f"{rule_id}: condition refers to unknown block '{token}'")
        return blocks[token]

    def parse_or() -> str:
        left = parse_and()
        while peek() == "or":
            nonlocal pos
            pos += 1
            left = f"({left} OR {parse_and()})"
        return left

    def parse_and() -> str:
        left = parse_not()
        while peek() == "and":
            nonlocal pos
            pos += 1
            left = f"({left} AND {parse_not()})"
        return left

    def parse_not() -> str:
        nonlocal pos
        if peek() == "not":
            pos += 1
            # A filter on a field the event does not have did not match it, so
            # the event stays. Plain NOT turned that NULL into "hidden": an
            # exclusion on an address hid every event that carried none (D77).
            return f"(NOT COALESCE({parse_not()}, FALSE))"
        return parse_atom()

    def parse_atom() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise ConfigError(f"{rule_id}: condition ended unexpectedly")
        token = tokens[pos]
        pos += 1
        if token == "(":
            inner = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ConfigError(f"{rule_id}: unbalanced parentheses in condition")
            pos += 1
            return f"({inner})"
        return expect_name(token)

    sql = parse_or()
    if pos != len(tokens):
        raise ConfigError(f"{rule_id}: trailing tokens in condition")
    return sql


# A threshold is a floor: "at least N events in the timeframe". Anything else
# has no sliding-window meaning, so it is refused at load time.
_COUNT = re.compile(r"^\s*(>=|>)\s*(\d+)\s*$")

# Entity columns travel with every selected row so a case can correlate on them.
EVIDENCE_COLUMNS: tuple[str, ...] = (
    "event_uid",
    "time",
    "actor_user_name",
    "actor_session_uid",
    "src_endpoint_ip",
    "resource_uid",
    "cloud_account_uid",
    "device_uid",
    "actor_user_type",
    "process_hash_sha256",
    "file_hash_sha256",
)

# The row after the last one read, in (time, event_uid) order. Both columns
# together identify a stored event, so a page never repeats or skips a row.
AFTER = "(time > :after_time OR (time = :after_time AND event_uid > :after_uid))"


def page_sql(scan: str, after: bool, limit: int) -> str:
    """One page of a `SELECT ... WHERE ...` scan, ordered by (time, event_uid)."""
    keyset = f" AND {AFTER}" if after else ""
    return f"{scan}{keyset} ORDER BY time, event_uid LIMIT {int(limit)}"


def _select(selected: dict[str, str], table: str = "") -> str:
    """A projection from {result key: expression}, optionally table-qualified."""
    out = []
    for key, expr in selected.items():
        sql = _qualify(expr, table) if table else expr
        out.append(sql if sql == key else f"{sql} AS {key}")
    return ", ".join(out)


def _selected(*fields: Any) -> dict[str, str]:
    """Evidence columns plus whatever the rule asked for, deduplicated by alias."""
    out: dict[str, str] = {c: c for c in EVIDENCE_COLUMNS}
    for name in fields:
        if not name:
            continue
        expr, alias = layout.column_for(name), layout.alias_for(name)
        if expr and alias:
            out.setdefault(alias, expr)
    return out


def _interval(seconds: int) -> str:
    return f"INTERVAL '{int(seconds)}' SECOND"


def _sequence(rule: Any, first: str, then: str) -> tuple[str, str, str]:
    """An earlier `first` event with the same `by` values, within the window.

    Returns the `EXISTS` that keeps the later event, the scalar subquery that
    names one such earlier event, so the finding cites both, and a scan for the
    buckets of the `then` events that a `first` ingested in the cycle pairs
    with: a `first` delivered after its `then` is paired by the cycle that
    reads it, not only by a backfill.
    """
    seq = rule.detection.sequence
    pair = " AND ".join(
        f"{_qualify(c, 'f')} = {_qualify(c, 'e')}" for c in (_column(b, rule.id) for b in seq["by"])
    ) + (
        f" AND f.time <= e.time AND f.time >= e.time - {_interval(parse_timeframe(seq['within']))}"
        " AND f.event_uid <> e.event_uid"
    )
    first_f = _qualify(first, "f")
    body = f"FROM {layout.EVENTS_TABLE} f WHERE f.tenant_id = :tenant_id AND {first_f} AND {pair}"
    late = (
        f"SELECT DISTINCT FLOOR(TIME_TO_UNIX(e.time) / {int(rule.timeframe_seconds)}) AS bucket "
        f"FROM {layout.EVENTS_TABLE} f JOIN {EVENTS} ON e.tenant_id = f.tenant_id AND {pair} "
        "WHERE f.tenant_id = :tenant_id AND f.ingested_at >= :ingested_from "
        f"AND f.ingested_at < :ingested_to AND {first_f} AND {_qualify(then, 'e')}"
    )
    return f"EXISTS (SELECT 1 {body})", f"(SELECT MAX(f.event_uid) {body})", late


def _population(logsource: dict[str, Any], params: _Params) -> str:
    """The events a logsource covers: its products, nothing for a product no
    mapping answers to, and every product only when it names none (ING-4)."""
    product = str(logsource.get("product", "") or "")
    if not product:
        return ""
    products = layout.products_for(product, str(logsource.get("service", "") or ""))
    if not products:
        return "FALSE"
    names = [params.add(p.lower()) for p in products]
    return f"LOWER(metadata_product) IN ({', '.join(names)})"


def _not_seen(cols: list[str], history: str) -> str:
    """`e` has every column of the tuple, and no event `h` in `history` has the
    same tuple in the same account: a user familiar in one AWS account is new
    in the next. An event that names no account cannot tell tenants apart, so
    it is compared with every account: a Gateway lookup with none makes the
    name familiar to the EDR that reports it with a CID, and events loaded
    before a source named its account stay its history (RFC 0025)."""
    joins = " AND ".join(f"{_qualify(c, 'h')} = {_qualify(c, 'e')}" for c in cols)
    joins += (
        " AND (h.cloud_account_uid IS NULL OR e.cloud_account_uid IS NULL"
        " OR h.cloud_account_uid = e.cloud_account_uid)"
    )
    seen = " AND ".join(
        f"{_qualify(c, 'e')} IS NOT NULL"
        + ("" if c in layout.INT_COLUMNS else f" AND {_qualify(c, 'e')} <> ''")
        for c in cols
    )
    return (
        f"{seen} AND NOT EXISTS (SELECT 1 FROM {layout.EVENTS_TABLE} h "
        f"WHERE h.tenant_id = :tenant_id AND {history} AND {joins})"
    )


def _first_seen(rule: Any, where: str, population: str) -> str:
    """The rule's events whose tuple did not occur in the lookback before them.

    The history is the rule's own selection, so a failed attempt from an
    address does not make the successful one look familiar. Until the product
    has events older than the lookback, nothing is new: every tuple would be.
    """
    cols = [_column(f, rule.id) for f in rule.first_seen]
    if not set(cols) & set(INDEXED):
        raise ConfigError(
            f"{rule.id}: first_seen needs one of actor.user.name, api.operation or "
            "src_endpoint.ip, so the history lookup can use an index"
        )
    lookback = _interval(parse_timeframe(rule.lookback))
    history = (
        f"{_qualify(where, 'h')} AND h.time >= e.time - {lookback} "
        f"AND (h.time < e.time OR (h.time = e.time AND h.event_uid < e.event_uid))"
    )
    learned = (
        f"(SELECT MIN(o.time) FROM {layout.EVENTS_TABLE} o WHERE o.tenant_id = :tenant_id "
        f"AND {_qualify(population, 'o')}) <= e.time - {lookback}"
    )
    return f"{_not_seen(cols, history)} AND {learned}"


def compile_rule(rule: Any, learning: dict[str, Any] | None = None) -> CompiledRule:
    """Compile a `Rule` into canonical SQL over `ocsf_events`, read as `e`.

    `select_sql` and `evidence_sql` are scans without an order or a limit: the
    engine reads them page by page with `page_sql`. `buckets_sql` lists, newest
    first, the event-time buckets that the matches ingested in a window fall in,
    as bucket numbers since the epoch (DET-3).

    `learning` maps an account to the time its own history first covers a
    first-seen rule's lookback; before then nothing in it is new (D79).
    """
    params = _Params()
    det = rule.detection
    blocks = {name: _block(name, spec, params, rule.id) for name, spec in det.blocks.items()}
    where = compile_condition(det.condition, blocks, rule.id)
    scope = "tenant_id = :tenant_id AND time >= :window_start AND time < :window_end"
    # A rule only ever looks at the products its logsource names.
    narrowed = _population(rule.logsource, params)
    population = narrowed or "TRUE"
    if narrowed:
        where = f"{population} AND {where}"
    extra: dict[str, str] = {}
    late = ""
    if det.sequence:
        first = compile_condition(det.sequence["first"], blocks, rule.id)
        if narrowed:
            first = f"{population} AND {first}"
        exists, extra["sequence_first"], late = _sequence(rule, first, where)
        where = f"{where} AND {exists}"
    if rule.first_seen:
        where = f"{where} AND {_first_seen(rule, where, population)}"
        for account, ready_at in sorted((learning or {}).items()):
            where += (
                f" AND NOT (COALESCE(cloud_account_uid, '') = {params.add(account)}"
                f" AND time < {params.add(ready_at)})"
            )
    full_where = f"{scope} AND {where}"

    selected = {**_selected(*rule.fields, *det.group_by, *rule.entity), **extra}
    compiled = CompiledRule(
        rule_id=rule.id,
        where=full_where,
        params=params.values,
        select_sql=f"SELECT {_select(selected)} FROM {EVENTS} WHERE {full_where}",
        buckets_sql=(
            f"SELECT DISTINCT FLOOR(TIME_TO_UNIX(time) / {int(rule.timeframe_seconds)}) AS bucket "
            f"FROM {EVENTS} WHERE tenant_id = :tenant_id "
            f"AND ingested_at >= :ingested_from AND ingested_at < :ingested_to AND {where} "
            + (f"UNION {late} " if late else "")
            + "ORDER BY bucket DESC"
        ),
    )

    if rule.is_aggregate:
        m = _COUNT.match(det.count)
        if not m:
            raise ConfigError(f"{rule.id}: count must look like '>= 50'")
        op, number = m.group(1), int(m.group(2))
        groups = {layout.alias_for(f) or f: _column(f, rule.id) for f in det.group_by}
        compiled.group_columns = list(groups)
        compiled.group_exprs = list(groups.values())
        compiled.count_op, compiled.count_value = op, number
        measure = "COUNT(*)"
        if det.count_distinct:
            compiled.distinct_expr = _column(det.count_distinct, rule.id)
            compiled.distinct_column = layout.alias_for(det.count_distinct) or det.count_distinct
            measure = f"COUNT(DISTINCT {compiled.distinct_expr})"
        cols = ", ".join(compiled.group_exprs)
        # Only a candidate list: a group below the threshold over the whole
        # window cannot reach it inside any one timeframe of that window. The
        # heaviest come first, for when there are more than the engine reads.
        compiled.agg_sql = (
            f"SELECT {_select(groups)}, COUNT(*) AS event_count, MIN(time) AS first_seen, "
            f"MAX(time) AS last_seen FROM {EVENTS} WHERE {full_where} "
            f"GROUP BY {cols} HAVING {measure} {op} {number} ORDER BY {measure} DESC"
        )
    return compiled


def evidence_sql(compiled: CompiledRule, values: list[Any]) -> str:
    """Canonical scan of the events behind one aggregated group.

    A value is bound as `:g_<i>`; a NULL one becomes `IS NULL`, since `= NULL`
    matches nothing and the group would have no events to cite.
    """
    clauses = [
        f"{expr} IS NULL" if value is None else f"{expr} = :g_{i}"
        for i, (expr, value) in enumerate(zip(compiled.group_exprs, values, strict=True))
    ]
    extra = (" AND " + " AND ".join(clauses)) if clauses else ""
    selected = {c: c for c in EVIDENCE_COLUMNS}
    if compiled.distinct_column:
        selected.setdefault(compiled.distinct_column, compiled.distinct_expr)
    return f"SELECT {_select(selected)} FROM {EVENTS} WHERE {compiled.where}{extra}"


# -- hunt packs (DET-8, RFC 0005) -------------------------------------------
# A pack's window is the day being hunted; its baseline looks further back to
# decide what is new. Both are bound, never inlined, like everything else here.
@dataclass
class CompiledPack:
    pack_id: str
    where: str
    params: dict[str, Any] = field(default_factory=dict)
    select_sql: str = ""
    baseline: str = "none"
    group_columns: list[str] = field(default_factory=list)


def compile_pack(pack: Any, limit: int = 500, accounts: list[str] | None = None) -> CompiledPack:
    """Compile a hunt pack into canonical SQL, baseline included (RFC 0022).

    The window is what was *ingested* since the last run, so a late delivery is
    hunted rather than skipped (D64). The baseline is what was ingested before
    the window, from the same products and accounts, so an event backdated into
    the past cannot make itself look familiar, and a replay of another
    company's logs cannot make anything look normal. `accounts` restricts both
    to the accounts a connected source speaks for; an event with no account is
    kept.

    The two behavioural primitives become a correlated `NOT EXISTS` and a
    `HAVING`: no window function, the same SQL on every adapter.
    """
    params = _Params()
    blocks = {
        name: _block(name, spec, params, pack.id) for name, spec in pack.detection.blocks.items()
    }
    where = compile_condition(pack.detection.condition, blocks, pack.id)
    population = _population(pack.logsource, params) or "TRUE"
    if accounts:
        marks = [params.add(a) for a in accounts]
        population += (
            f" AND (cloud_account_uid IS NULL OR cloud_account_uid IN ({', '.join(marks)}))"
        )
    scope = (
        "tenant_id = :tenant_id AND ingested_at >= :ingested_from "
        "AND ingested_at < :ingested_to AND time >= :baseline_start"
    )
    full_where = f"{scope} AND {population} AND {where}"

    out = CompiledPack(
        pack_id=pack.id, where=full_where, params=params.values, baseline=pack.baseline.kind
    )
    selected = _selected(
        *pack.pivot,
        *pack.baseline.first_seen,
        *pack.baseline.rare_by,
        "api.operation",
        "class_name",
        "time",
    )

    if pack.baseline.kind == "first_seen":
        out.select_sql = _first_seen_sql(pack, full_where, population, selected, limit)
    elif pack.baseline.kind == "rare":
        groups = {layout.alias_for(f) or f: _column(f, pack.id) for f in pack.baseline.rare_by}
        out.group_columns = list(groups)
        out.select_sql = _rare_sql(pack, population, where, groups, limit)
    else:
        out.select_sql = (
            f"SELECT {_select(selected)} FROM {layout.EVENTS_TABLE} "
            f"WHERE {full_where} ORDER BY time LIMIT {int(limit)}"
        )
    return out


def _first_seen_sql(
    pack: Any, where: str, population: str, selected: dict[str, str], limit: int
) -> str:
    """Rows whose tuple was not seen in the lookback, among what came in before.

    "This identity has never called this API before" is the question, and the
    answer is a plain anti-join against the same table. The history is all of
    the products' activity, not the pack's selection: "an address the user has
    never used" means for anything. A failed attempt is not use, so it never
    makes a tuple familiar: a denied call or a sprayed password from the
    attacker's address would otherwise silence what came after it.
    """
    cols = [_column(f, pack.id) for f in pack.baseline.first_seen]
    history = (
        "h.time >= :baseline_start AND h.ingested_at < :ingested_from "
        f"AND {_qualify(population, 'h')} AND LOWER(COALESCE(h.status, '')) <> 'failure'"
    )
    return (
        f"SELECT {_select(selected, 'e')} FROM {EVENTS} "
        f"WHERE {_qualify(where, 'e')} AND {_not_seen(cols, history)} "
        f"ORDER BY e.time LIMIT {int(limit)}"
    )


def _rare_sql(pack: Any, population: str, where: str, groups: dict[str, str], limit: int) -> str:
    """Groupings that few principals share over the whole lookback, and that
    occurred in the window. Counting principals inside one day's window made
    every operation one person did today look rare. `seen_by_at_least` asks the
    opposite: one session seen from several addresses."""
    among = _column(pack.baseline.rare_among, pack.id)
    cols = ", ".join(groups.values())
    having = []
    if pack.baseline.seen_by_fewer_than:
        having.append(f"COUNT(DISTINCT {among}) < {int(pack.baseline.seen_by_fewer_than)}")
    if pack.baseline.seen_by_at_least:
        having.append(f"COUNT(DISTINCT {among}) >= {int(pack.baseline.seen_by_at_least)}")
    return (
        f"SELECT {_select(groups)}, COUNT(*) AS event_count, "
        f"COUNT(DISTINCT {among}) AS principals, "
        f"MIN(time) AS first_seen, MAX(time) AS last_seen, MAX(event_uid) AS event_uid "
        f"FROM {layout.EVENTS_TABLE} "
        f"WHERE tenant_id = :tenant_id AND time >= :baseline_start "
        f"AND ingested_at < :ingested_to AND {population} AND {where} GROUP BY {cols} "
        f"HAVING {' AND '.join(having)} AND MAX(ingested_at) >= :ingested_from "
        f"ORDER BY COUNT(*) DESC LIMIT {int(limit)}"
    )


def _qualify(where: str, alias: str) -> str:
    """Prefix bare column references so a correlated subquery can be read.

    Only the columns we know about are touched: parameters keep their `:name`
    form, and anything that is not an OCSF column is left exactly as written.
    """
    pattern = re.compile(
        r"(?<![:.\w])(" + "|".join(sorted(layout.COLUMN_NAMES, key=len, reverse=True)) + r")\b"
    )
    return pattern.sub(lambda m: f"{alias}.{m.group(1)}", where)
