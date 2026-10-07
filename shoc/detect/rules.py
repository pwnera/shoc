"""Rule loading and validation (DET-2).

Rules are YAML in `content/rules/`, in the Sigma subset the compiler supports.
Every rule needs a positive and a negative fixture; `tests/unit/test_rules.py`
fails the build if one is missing.

Given a connection and a tenant, the rules the Detection Engineer merged
(`shoc.merged_rules`, D48) are laid over them by id: a new id adds a rule, a
shipped id is that rule narrowed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shoc.errors import ConfigError

SEVERITIES = ("informational", "low", "medium", "high", "critical")
# Keys of `detection` that are not selection blocks.
DETECTION_KEYS = ("condition", "timeframe", "group_by", "count", "count_distinct", "sequence")


@dataclass
class Detection:
    blocks: dict[str, Any] = field(default_factory=dict)
    condition: str = ""
    timeframe: str = "15m"
    group_by: list[str] = field(default_factory=list)
    count: str = ""
    # Count distinct values of this field instead of events (RFC 0023).
    count_distinct: str = ""
    # {by, first, within}: `condition` (written `then`) fires only after `first`.
    sequence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    title: str
    severity: str = "medium"
    description: str = ""
    status: str = "experimental"
    confidence: float = 0.6
    attack: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # Where the rule was taken from: Elastic, Sigma, a vendor's own rule. Sigma's
    # licence (DRL 1.1) requires the author and a link.
    sources: list[dict[str, str]] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: Detection = field(default_factory=Detection)
    fields: list[str] = field(default_factory=list)
    # The first of these with a value keys the finding.
    entity: list[str] = field(default_factory=list)
    # A tuple that must not have occurred in the lookback before the event.
    first_seen: list[str] = field(default_factory=list)
    lookback: str = "30d"
    created: str = ""  # Sigma `date`
    updated: str = ""  # Sigma `modified`
    path: Path | None = None

    @property
    def timeframe_seconds(self) -> int:
        return parse_timeframe(self.detection.timeframe)

    @property
    def is_aggregate(self) -> bool:
        return bool(self.detection.count)

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "status": self.status,
            "confidence": self.confidence,
            "attack": list(self.attack),
            "references": list(self.references),
            "sources": [dict(s) for s in self.sources],
            "logsource": dict(self.logsource),
            "timeframe": self.detection.timeframe,
            "group_by": list(self.detection.group_by),
            "count": self.detection.count,
            "count_distinct": self.detection.count_distinct,
            "entity": ", ".join(self.entity),
            "detection": {
                **self.detection.blocks,
                "condition": self.detection.condition,
                **({"sequence": dict(self.detection.sequence)} if self.detection.sequence else {}),
            },
            "first_seen": list(self.first_seen),
            "lookback": self.lookback if self.first_seen else None,
            "fields": list(self.fields),
            "created": self.created or None,
            "updated": self.updated or self.created or None,
        }


def parse_timeframe(value: str) -> int:
    """`30s`, `15m`, `6h`, `2d` -> seconds."""
    text = str(value).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if not text or text[-1] not in units or not text[:-1].isdigit():
        raise ConfigError(f"bad timeframe '{value}' (use 30s, 15m, 6h or 2d)")
    return int(text[:-1]) * units[text[-1]]


def parse_sources(data: dict[str, Any], path: Path | None = None) -> list[dict[str, str]]:
    """`sources: [{name, title, url, author?, license?}]`, each with a link to cite."""
    out = []
    for item in data.get("sources", []) or []:
        source = {k: str(v).strip() for k, v in (item or {}).items() if v}
        if not all(source.get(k) for k in ("name", "title", "url")):
            raise ConfigError(f"{path or data.get('id')}: a source needs a name, a title and a url")
        if not source["url"].startswith("https://"):
            raise ConfigError(
                f"{path or data.get('id')}: source url must be https: {source['url']}"
            )
        out.append(source)
    return out


def from_dict(data: dict[str, Any], path: Path | None = None) -> Rule:
    try:
        det = data["detection"]
    except KeyError as exc:
        raise ConfigError(f"{path or data.get('id')}: rule has no detection block") from exc
    blocks = {k: v for k, v in det.items() if k not in DETECTION_KEYS}
    sequence = dict(det.get("sequence") or {})
    condition = str(det.get("condition", " and ".join(blocks)))
    if sequence:
        if "condition" in det:
            raise ConfigError(
                f"{path or data.get('id')}: a sequence names its events in `first` and "
                "`then`, not in `condition`"
            )
        # The later event is the one that fires: it is the rule's condition, so
        # a narrowing composed onto the condition applies to it (D77).
        condition = str(sequence.pop("then", "") or "")
        by = sequence.get("by") or []
        sequence["by"] = [by] if isinstance(by, str) else list(by)
    baseline = data.get("baseline") or {}
    if set(baseline) - {"first_seen", "lookback"}:
        raise ConfigError(
            f"{path or data.get('id')}: a rule's baseline takes first_seen and lookback"
        )
    entity = data.get("entity") or []
    rule = Rule(
        id=data["id"],
        title=data["title"],
        severity=str(data.get("severity", "medium")).lower(),
        description=data.get("description", ""),
        status=data.get("status", "experimental"),
        confidence=float(data.get("confidence", 0.6)),
        attack=list(data.get("attack", []) or []),
        references=list(data.get("references", []) or []),
        sources=parse_sources(data, path),
        logsource=dict(data.get("logsource", {}) or {}),
        detection=Detection(
            blocks=blocks,
            condition=condition,
            timeframe=str(det.get("timeframe", "15m")),
            group_by=list(det.get("group_by", []) or []),
            count=str(det.get("count", "") or ""),
            count_distinct=str(det.get("count_distinct", "") or ""),
            sequence=sequence,
        ),
        fields=list(data.get("fields", []) or []),
        entity=[entity] if isinstance(entity, str) else [str(e) for e in entity],
        first_seen=list(baseline.get("first_seen", []) or []),
        lookback=str(baseline.get("lookback", "30d")),
        created=str(data.get("date") or ""),
        updated=str(data.get("modified") or ""),
        path=path,
    )
    validate(rule)
    return rule


def validate(rule: Rule) -> None:
    if rule.severity not in SEVERITIES:
        raise ConfigError(f"{rule.id}: severity must be one of {', '.join(SEVERITIES)}")
    if not rule.detection.blocks:
        raise ConfigError(f"{rule.id}: detection has no selection block")
    if not 0.0 <= rule.confidence <= 1.0:
        raise ConfigError(f"{rule.id}: confidence must be between 0 and 1")
    parse_timeframe(rule.detection.timeframe)
    det = rule.detection
    if det.count and not det.group_by:
        raise ConfigError(f"{rule.id}: an aggregating rule needs group_by")
    if det.count_distinct and not det.count:
        raise ConfigError(f'{rule.id}: count_distinct needs count: ">= N"')
    if det.sequence:
        if not (det.sequence.get("first") and det.condition and det.sequence.get("by")):
            raise ConfigError(f"{rule.id}: a sequence needs by, first and then")
        parse_timeframe(str(det.sequence.get("within", "")))
    if rule.first_seen:
        parse_timeframe(rule.lookback)
    # One correlation per rule, so a finding has one meaning.
    if sum(map(bool, (det.count, det.sequence, rule.first_seen))) > 1:
        raise ConfigError(f"{rule.id}: use one of count, sequence and first_seen per rule")


def load_file(path: Path) -> Rule:
    # libyaml parses the shipped rules six times faster, and `health.status`
    # loads them on every poll.
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return from_dict(yaml.load(path.read_text(), Loader=loader) or {}, path)


def load_dir(directory: Path) -> list[Rule]:
    rules = [load_file(p) for p in sorted(directory.glob("*.yaml"))]
    seen: set[str] = set()
    for r in rules:
        if r.id in seen:
            raise ConfigError(f"duplicate rule id '{r.id}'")
        seen.add(r.id)
    return rules


def load(config: Any = None, conn: Any = None, tenant_id: str = "") -> list[Rule]:
    from shoc.config import Config

    cfg = config or Config.load()
    shipped = load_dir(Path(cfg.content_dir) / "rules")
    if conn is None or not tenant_id:
        return shipped
    return list(
        {
            **{r.id: r for r in shipped},
            **{r.id: r for r in merged(conn, tenant_id, shipped)},
        }.values()
    )


def fixture(rule_id: str, kind: str = "positive") -> list[dict[str, Any]]:
    """A shipped rule's fixture records, or [] when it has none."""
    import json

    from shoc.config import rule_fixtures_dir

    path = rule_fixtures_dir() / rule_id / f"{kind}.json"
    return json.loads(path.read_text()) if path.is_file() else []


# The block a narrowing adds to the shipped rule it narrows.
EXCLUSION = "filter_de"


def narrow(rule: Rule, exclude: list[dict[str, Any]]) -> Rule:
    """The shipped rule with the Detection Engineer's exclusion composed onto it.

    The shipped condition stays whole, so a later fix to the shipped rule
    reaches this tenant too; a merged copy of the rule used to mask every fix.
    """
    import copy

    out = copy.deepcopy(rule)
    out.detection.blocks = {**out.detection.blocks, EXCLUSION: list(exclude)}
    out.detection.condition = f"({rule.detection.condition}) and not {EXCLUSION}"
    return out


def merged(conn: Any, tenant_id: str, shipped: list[Rule] | None = None) -> list[Rule]:
    """The rules the Detection Engineer merged here and has not reverted.

    A row is either a new rule, as content/rules would parse it, or a narrowing
    `{narrows, exclude}` of a shipped rule. A narrowing whose rule is no longer
    shipped is dropped rather than resurrected.
    """
    from shoc.db.pool import fetch_all

    rows = fetch_all(
        conn,
        """SELECT body, merged_at FROM shoc.merged_rules
           WHERE tenant_id = %s AND state = 'merged'
             AND (lapses_at IS NULL OR lapses_at > now())""",
        (tenant_id,),
    )
    by_id = {r.id: r for r in shipped} if shipped is not None else None
    rules: list[Rule] = []
    for row in rows:
        body = row["body"]
        if "narrows" in body:
            if by_id is None:
                by_id = {r.id: r for r in load()}
            base = by_id.get(str(body["narrows"]))
            if base is None:
                continue
            rule = narrow(base, list(body.get("exclude") or []))
        else:
            rule = from_dict(body)
            rule.created = rule.created or row["merged_at"].isoformat()
        rule.updated = row["merged_at"].isoformat()
        rules.append(rule)
    return rules
