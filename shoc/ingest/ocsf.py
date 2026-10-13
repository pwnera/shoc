"""OCSF mapping engine (ING-3).

A mapping is versioned YAML, one file per source. It declares constants, a field
map from source paths to OCSF columns, and a few `derive` rules for values that
depend on the record (a failed API call, an MFA challenge). Anything the mapping
does not read is kept in `unmapped`, leaf by leaf, and the whole source record
is kept in `raw` so a finding can always cite the original. Both are addressable
from a rule as `raw.<path>` / `unmapped.<path>`, so a field only one product
emits is queryable without a column for it.

A list of named items (Workspace `parameters`, M365 `ModifiedProperties`) has
no portable JSON path to one item, so a mapping's `keyed` section also writes
it as an object under `unmapped.<alias>`, keyed by the items' names (RFC 0023).

Mappings are data, never code: no expressions are evaluated, only the transforms
listed in `TRANSFORMS`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from shoc.errors import ConfigError
from shoc.store import ocsf as layout

TRANSFORMS: dict[str, Any] = {
    "lower": lambda v: str(v).lower(),
    "upper": lambda v: str(v).upper(),
    "str": str,
    "int": lambda v: int(v),
    "basename": lambda v: re.split(r"[\\/]", str(v))[-1],
    "arn_name": lambda v: str(v).rsplit("/", 1)[-1].rsplit(":", 1)[-1],
    "iso8601": lambda v: _to_iso(v),
    "ip": lambda v: _ip(v),
}


_OVERLONG_FRACTION = re.compile(r"\.(\d{7,})")
# Positions are dropped from a consumed path; a `[name=x]` selector is kept, so
# reading one named parameter does not retire the value of every other one.
_POSITION = re.compile(r"\[(?![^\]]*=)[^\]]*\]")
_EPOCH = re.compile(r"^\d{9,19}(\.\d+)?$")
# What a rule path can hold (`ocsf.JSON_FIELD`); anything else in a key becomes `_`.
_KEY_TEXT = re.compile(r"[^A-Za-z0-9_-]")
# Postgres refuses NUL in text and jsonb, and a lone UTF-16 surrogate (an NTFS
# file name in EDR telemetry) in either. One such record failed its whole batch,
# so the source's cursor never moved again (ING-1, STO-2).
_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")
# An event time outside these bounds is a sentinel or a wrong clock: 9999-12-31
# overflowed the partition arithmetic, a laptop clock years ahead hid its
# product's outage note, 1970 made a partition retention never dropped (ING-3).
EARLIEST = datetime(2000, 1, 1, tzinfo=UTC)
AHEAD = timedelta(days=1)


def _ip(value: Any) -> str | None:
    """An address without the port or v4-mapped prefix a vendor wraps it in.

    Exchange writes `198.51.100.7:63070`, Teams and Cloudflare `::ffff:198.51.100.7`,
    directory records the literal `<null>`, which is no address at all.
    """
    text = str(value).strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    text = text.removeprefix("::ffff:").removeprefix("ffff:")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _to_iso(value: Any) -> str:
    if isinstance(value, str) and _EPOCH.match(value.strip()):
        # Falcon Data Replicator, Cloud Funnel and Logpush write epoch times as strings.
        value = float(value)
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        seconds = float(value)
        while seconds > 1e11:
            # Milli-, micro- or nanoseconds; Cloudflare Logpush writes nanoseconds.
            seconds /= 1000
        dt = datetime.fromtimestamp(seconds, tz=UTC)
    else:
        text = str(value).strip().replace("Z", "+00:00")
        # Azure and Graph timestamps carry 7-digit ticks; fromisoformat takes six.
        text = _OVERLONG_FRACTION.sub(lambda m: "." + m.group(1)[:6], text)
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def _event_time(value: Any, ingested: datetime) -> tuple[str, Any]:
    """The event's time, or the ingest time and the vendor's value when that
    value does not parse or falls outside [EARLIEST, ingested + AHEAD]."""
    if value is None or value == "":
        return ingested.isoformat(), None
    try:
        dt = datetime.fromisoformat(_to_iso(value))
    except (TypeError, ValueError, OverflowError, OSError):
        return ingested.isoformat(), value
    if not EARLIEST <= dt <= ingested + AHEAD:
        return ingested.isoformat(), value
    return dt.isoformat(), None


def _storable(value: Any) -> Any:
    """`value` with NUL dropped and lone surrogates replaced, keys included."""
    if isinstance(value, str):
        return _UNSTORABLE.sub(lambda m: "" if m.group() == "\x00" else "\ufffd", value)
    if isinstance(value, dict):
        return {_storable(k): _storable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_storable(v) for v in value]
    return value


def _paths(spec: dict[str, Any]) -> list[str]:
    return spec.get("paths") or ([spec["path"]] if "path" in spec else [])


def dig(record: Any, path: str) -> Any:
    """Look up a dotted path.

    `a.b`, `a.b[0].c`, `a.b[*].c` and `a.b[name=x].c` all work; `[*]` takes the
    first item of the list that resolves to something, which is how a provider's
    evidence or target array is read without knowing which slot holds the user,
    and `[name=x]` the first item whose `name` is `x`.
    """
    return _dig(record, path.split("."))


def _dig(cur: Any, parts: list[str]) -> Any:
    for position, part in enumerate(parts):
        if cur is None:
            return None
        while part.endswith("]") and "[" in part:
            part, index = part[:-1].split("[", 1)
            if part:
                cur = cur.get(part) if isinstance(cur, dict) else None
                part = ""
            if not isinstance(cur, list):
                return None
            if "=" in index:
                # `[name=doc_id]` picks the first item whose `name` is `doc_id`,
                # how Workspace and others key a list of parameters.
                key, want = index.split("=", 1)
                cur = next(
                    (i for i in cur if isinstance(i, dict) and str(i.get(key)) == want), None
                )
                continue
            if index == "*":
                rest = parts[position + 1 :]
                for item in cur:
                    value = _dig(item, rest) if rest else item
                    if value is not None and value != "":
                        return value
                return None
            i = int(index)
            cur = cur[i] if -len(cur) <= i < len(cur) else None
        if part:
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
    return cur


@dataclass
class Mapping:
    source: str
    ocsf_version: str = "1.3.0"
    constants: dict[str, Any] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)
    derive: list[dict[str, Any]] = field(default_factory=list)
    observables: list[dict[str, str]] = field(default_factory=list)
    # alias -> {path, key, value?}: a list of named items, written as an object
    # under `unmapped.<alias>` so a rule reads one item by name. `path` may be a
    # list of paths, the first that holds a list wins.
    keyed: dict[str, dict[str, Any]] = field(default_factory=dict)
    # The rule logsources (`product` or `product/service`) this source's events
    # answer to; none means its own name (ING-4).
    logsource: list[str] = field(default_factory=list)
    # The ATT&CK platforms (`SaaS`, `Windows`, ...) whose techniques these events
    # can show: a report's technique on no platform we see is no backlog item (DET-2).
    attack_platforms: list[str] = field(default_factory=list)
    # `unmapped.<path>` or `raw.<path>`: where this source's events name the
    # identity-provider login their actor signed in with (RFC 0027).
    login: str = ""
    # A top-level list whose items are each an event (a Workspace activity's
    # `events`): `map_records` maps one row per item.
    explode: str = ""

    @classmethod
    def from_file(cls, path: Path) -> Mapping:
        data = yaml.safe_load(path.read_text()) or {}
        for alias, spec in (data.get("keyed") or {}).items():
            if _KEY_TEXT.search(str(alias)) or not (spec or {}).get("path") or not spec.get("key"):
                raise ConfigError(
                    f"{path}: keyed list '{alias}' needs a plain alias, a path and a key"
                )
        try:
            return cls(
                source=data["source"],
                ocsf_version=str(data.get("ocsf_version", "1.3.0")),
                constants=data.get("constants", {}) or {},
                fields=data.get("fields", {}) or {},
                derive=data.get("derive", []) or [],
                observables=data.get("observables", []) or [],
                keyed=data.get("keyed", {}) or {},
                logsource=[str(k) for k in data.get("logsource") or []],
                attack_platforms=[str(p) for p in data.get("attack_platforms") or []],
                login=str(data.get("login") or ""),
                explode=str(data.get("explode") or ""),
            )
        except KeyError as exc:
            raise ConfigError(f"{path}: mapping is missing {exc}") from exc

    def validate(self) -> list[str]:
        """Complain about columns that are not part of the OCSF layout."""
        bad = []
        for column in list(self.constants) + list(self.fields):
            if column not in layout.COLUMN_NAMES:
                bad.append(column)
        for rule in self.derive:
            bad += [c for c in (rule.get("set") or {}) if c not in layout.COLUMN_NAMES]
        if self.login and not layout.JSON_FIELD.match(self.login):
            bad.append(f"login: {self.login}")
        return sorted(set(bad))

    def paths(self, column: str) -> list[str]:
        """The record paths a column is read from: its field's in the order they
        are tried, then any a `derive` rule reads it from instead."""
        spec = self.fields.get(column)
        found = list(_paths({"path": spec} if isinstance(spec, str) else spec or {}))
        for rule in self.derive:
            value = (rule.get("set") or {}).get(column)
            if isinstance(value, dict):
                found += [p for p in _paths(value) if p not in found]
        return found

    # -- mapping ---------------------------------------------------------
    def _value(self, record: dict[str, Any], spec: Any, used: set[str]) -> Any:
        if isinstance(spec, str):
            spec = {"path": spec}
        if not isinstance(spec, dict):
            raise ConfigError(f"{self.source}: field spec must be a path or an object")
        if "const" in spec:
            return spec["const"]
        value = None
        for p in _paths(spec):
            value = dig(record, p)
            if value is not None and value != "":
                used.add(_POSITION.sub("", p))
                break
        if value is None or value == "":
            return spec.get("default")
        name = spec.get("transform")
        if name:
            if name not in TRANSFORMS:
                raise ConfigError(f"{self.source}: unknown transform '{name}'")
            try:
                value = TRANSFORMS[name](value)
            except (TypeError, ValueError, OverflowError):
                # 9999-12-31T23:00:00-05:00 is a datetime, but not one in UTC.
                return spec.get("default")
        return value

    def _matches(self, record: dict[str, Any], row: dict[str, Any], when: dict[str, Any]) -> bool:
        for path, cond in when.items():
            value = row.get(path) if path in layout.COLUMN_NAMES else dig(record, path)
            if isinstance(cond, dict):
                if "exists" in cond and bool(cond["exists"]) != (value not in (None, "")):
                    return False
                if "equals" in cond and value != cond["equals"]:
                    return False
                if "in" in cond and value not in cond["in"]:
                    return False
                if "contains" in cond and (
                    value is None or str(cond["contains"]).lower() not in str(value).lower()
                ):
                    return False
                for op, compare in (
                    ("gte", lambda a, b: a >= b),
                    ("gt", lambda a, b: a > b),
                    ("lte", lambda a, b: a <= b),
                    ("lt", lambda a, b: a < b),
                ):
                    if op in cond:
                        try:
                            if not compare(float(value), float(cond[op])):  # type: ignore[arg-type]
                                return False
                        except (TypeError, ValueError):
                            return False
            elif value != cond:
                return False
        return True

    def map_record(self, record: dict[str, Any], tenant_id: str) -> dict[str, Any]:
        row = layout.blank_row(tenant_id)
        used: set[str] = set()
        row.update({k: v for k, v in self.constants.items()})
        for column, spec in self.fields.items():
            value = self._value(record, spec, used)
            if value is not None:
                row[column] = value
        for rule in self.derive:
            if self._matches(record, row, rule.get("when") or {}):
                # A {path: ...} value reads the record, so one class can take a
                # column from another field than the rest of the source.
                for column, value in (rule.get("set") or {}).items():
                    row[column] = (
                        self._value(record, value, used) if isinstance(value, dict) else value
                    )
        for column in layout.INT_COLUMNS:
            if row.get(column) is not None:
                try:
                    row[column] = int(row[column])
                except (TypeError, ValueError):
                    row[column] = None
        # OCSF fixes both from the class and the activity, so a `derive` that
        # moves either cannot leave them stale. An extension class carries its
        # extension above the core uid: Windows' Registry Key Activity, 201001,
        # is System Activity (1).
        if row.get("class_uid") is not None:
            row["category_uid"] = row["class_uid"] % 100000 // 1000
            if row.get("activity_id") is not None:
                row["type_uid"] = row["class_uid"] * 100 + row["activity_id"]
        for column, value in row.items():
            if column in layout.JSON_COLUMNS or not isinstance(value, (dict, list)):
                continue
            # A provider field can be an object where OCSF wants text — GitLab's
            # `details.with`, for one. Keep it as JSON so the evidence survives,
            # and never hand a dict to a TEXT column.
            row[column] = json.dumps(value, sort_keys=True, default=str)
        ingested = datetime.now(UTC)
        if not row.get("time") and isinstance(timed := self.fields.get("time"), dict):
            # A time its transform could not read fell back to the default; read
            # it bare so the check below keeps it.
            row["time"] = self._value(record, {**timed, "transform": None, "default": None}, set())
        row["time"], vendor_time = _event_time(row.get("time"), ingested)
        row["ingested_at"] = ingested.isoformat()
        if not row.get("event_uid"):
            row["event_uid"] = stable_uid(self.source, record)
        row["observables"] = self._build_observables(row)
        row["unmapped"] = _residue(record, used)
        if vendor_time is not None and isinstance(row["unmapped"], dict):
            # The event is placed at ingest time; what the vendor said stays here
            # and in `raw`, and these rows can be counted per source.
            row["unmapped"]["_time_original"] = str(vendor_time)
        for alias, spec in self.keyed.items():
            # A list of paths reads the first that holds the list, as Entra's
            # Event Hub envelope wraps the Graph record in `properties`.
            paths = spec["path"] if isinstance(spec["path"], list) else [spec["path"]]
            items = next((found for p in paths if (found := dig(record, p))), None)
            keyed = _keyed(items, spec["key"], spec.get("value"))
            if keyed and isinstance(row["unmapped"], dict):
                row["unmapped"][alias] = keyed
        row["raw"] = record
        # The OCSF schema version, never the vendor's own record version.
        row["metadata_version"] = self.ocsf_version
        return _storable(row)

    def map_records(self, record: dict[str, Any], tenant_id: str) -> list[dict[str, Any]]:
        """The rows one record holds: one per item of its `explode` list, else one.

        A Workspace activity lists every setting one save changed, and only its
        first event was mapped, so turning 2SV enforcement off next to another
        change went unseen (ING-3). Each row keeps the activity's envelope with
        the list narrowed to its own item. The first keeps the record's
        event_uid, so rows stored before still deduplicate; the others add
        `-<position>`.
        """
        items = record.get(self.explode) if self.explode else None
        if not isinstance(items, list) or len(items) < 2:
            return [self.map_record(record, tenant_id)]
        rows = []
        for position, item in enumerate(items):
            row = self.map_record({**record, self.explode: [item]}, tenant_id)
            if position:
                row["event_uid"] = f"{row['event_uid']}-{position}"
            rows.append(row)
        return rows

    def _build_observables(self, row: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for spec in self.observables:
            value = row.get(spec.get("column", ""))
            if value:
                out.append(
                    {
                        "name": spec.get("name", spec.get("column")),
                        "type": spec.get("type", "Other"),
                        "value": value,
                    }
                )
        return out


def _residue(node: Any, used: set[str], prefix: str | tuple[str, ...] = "") -> Any:
    """What the mapping did not read, pruned path by path.

    Consuming `client.ipAddress` retires that leaf, not the whole `client`
    object, so the rest of the device and geolocation block stays visible here
    instead of being reachable only through `raw`. An item of a list is reached
    by position (`events.name`) or, when it has a `name`, by that name
    (`events.parameters[name=client_id].value`); either retires the leaf.
    """
    prefixes = (prefix,) if isinstance(prefix, str) else prefix
    if isinstance(node, list):
        kept = []
        for item in node:
            name = item.get("name") if isinstance(item, dict) else None
            named = (
                tuple(f"{p[:-1]}[name={name}]." for p in prefixes if p)
                if isinstance(name, str)
                else ()
            )
            child = _residue(item, used, prefixes + named)
            # A named item whose value was read leaves only its name behind.
            if child not in (None, "", {}, []) and not (named and child == {"name": name}):
                kept.append(child)
        return kept
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        paths = tuple(f"{p}{key}" for p in prefixes)
        if any(path in used for path in paths):
            continue
        child = _residue(value, used, tuple(f"{path}." for path in paths))
        if child not in (None, "", {}, []):
            out[key] = child
    return out


def _keyed(items: Any, key: str | list[str], value: str | list[str] | None) -> dict[str, Any]:
    """`[{name: a, value: 1}, …]` as `{a: {value: 1}}`, or `{a: 1}` when `value` names the field.

    A list of keys nests (`[action, role]` gives `{ADD: {roles_owner: …}}`), and
    `value` may list fields to take the first one present, as Workspace puts a
    parameter in `value`, `intValue`, `boolValue` or `multiValue`. The first
    item with a name wins, as `[name=x]` reads it. Characters a rule path cannot
    hold become `_`: `Role.DisplayName` is `Role_DisplayName`.
    """
    keys = [key] if isinstance(key, str) else list(key)
    fields = [value] if isinstance(value, str) else list(value or [])
    out: dict[str, Any] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or any(item.get(k) in (None, "") for k in keys):
            continue
        if fields:
            picked = next((item[f] for f in fields if item.get(f) not in (None, "")), None)
            if picked is None:
                continue
        else:
            picked = {k: v for k, v in item.items() if k not in keys}
        node = out
        for k in keys[:-1]:
            node = node.setdefault(_KEY_TEXT.sub("_", str(item[k])), {})
        node.setdefault(_KEY_TEXT.sub("_", str(item[keys[-1]])), picked)
    return out


def stable_uid(source: str, record: dict[str, Any]) -> str:
    """Deterministic ID so replays and overlapping cursor windows deduplicate."""
    blob = json.dumps(record, sort_keys=True, default=str)
    return f"{source}-{hashlib.sha256(blob.encode()).hexdigest()[:32]}"


_CACHE: dict[str, Mapping] = {}


def mappings_dir() -> Path:
    return Path(__file__).parent / "mappings"


def load_mapping(source: str) -> Mapping:
    if source not in _CACHE:
        path = mappings_dir() / f"{source}.yaml"
        if not path.exists():
            raise ConfigError(f"no OCSF mapping for source '{source}'")
        _CACHE[source] = Mapping.from_file(path)
    return _CACHE[source]


def for_tenant(conn: Any, tenant_id: str, source: str) -> Mapping:
    """The shipped mapping, with the field paths this tenant's override moved (D74)."""
    base = load_mapping(source)
    if conn is None:
        return base
    from shoc.db.pool import fetch_one

    row = fetch_one(
        conn,
        "SELECT fields FROM shoc.mapping_overrides WHERE tenant_id = %s AND source = %s",
        (tenant_id, source),
    )
    return replace(base, fields={**base.fields, **row["fields"]}) if row else base


def available_sources() -> list[str]:
    return sorted(p.stem for p in mappings_dir().glob("*.yaml"))


def classes() -> dict[str, tuple[str, set[int]]]:
    """Source -> its product's name and the OCSF classes its events take, read
    from the mappings.

    A findings feed (its constant class is 2004) is left out: the context
    records it maps besides its findings are not telemetry a rule or a hunt reads.
    """
    out: dict[str, tuple[str, set[int]]] = {}
    for source in available_sources():
        mapping = load_mapping(source)
        if mapping.constants.get("class_uid") == 2004:
            continue
        taken = [mapping.constants.get("class_uid")]
        taken += [(rule.get("set") or {}).get("class_uid") for rule in mapping.derive]
        name = str(mapping.constants.get("metadata_product") or source)
        out[source] = (name, {int(c) for c in taken if c})
    return out


def source_for(product: str, service: str = "") -> str:
    """The mapping a rule's logsource reads raw records through: the one named
    `<product>_<service>` (aws, guardduty), the one named after the product,
    else the first that answers to it; "" when none does."""
    names = available_sources()
    product, service = product.lower(), service.lower()
    for name in (f"{product}_{service}", product):
        if name in names:
            return name
    return next((s for s in names if product in load_mapping(s).logsource), "")
