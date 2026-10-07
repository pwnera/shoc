"""Hunt packs (DET-8, RFC 0005): behaviour, not indicators.

A hunt asks *is this happening?* about a behaviour nobody has written a rule
for, and it is a success when the answer is no. An indicator lookup asks *have
we seen this value?* — a different, much smaller question, already answered in
bulk by the feeds and on demand by `intel.lookup`.

**A pack is content, not a prompt.** It lives in `content/hunts/*.yaml`, it is
compiled by the same Sigma-subset compiler as a rule, it ships with a fixture it
must surface and one it must leave alone, and it is reviewed as a diff. The
Hunter may write one for an item on its backlog (RFC 0032): the same shape,
behind a gate that runs its fixtures and its query, kept per tenant in
`shoc.merged_hunts` and laid over the shipped packs. Triage still never
writes a query and never chooses what to hunt.

A pack differs from a rule in three ways, and the differences are the point:

- **No severity and no alert.** A pack returns an *observation set*. Three
  hundred rows is a working pack; a rule that did that would be a bug.
- **A baseline.** Two behavioural primitives rules do not need:
  `first_seen: [a, b]` keeps rows whose `(a, b)` tuple does not appear in the
  lookback window, and `rare: {by: [...], seen_by_fewer_than: N}` keeps
  groupings that few principals share. Both compile to plain `NOT EXISTS` and
  `HAVING` over the same canonical schema — no window function a dialect might
  not have, and nothing SQLGlot cannot translate.
- **A hypothesis and a triage question, in prose.** They are what makes an
  observation set readable by somebody who is not a hunter, and they are what
  the Hunter is given when it triages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shoc.detect.rules import Detection, parse_sources, parse_timeframe
from shoc.errors import ConfigError


@dataclass
class Baseline:
    """What counts as normal, so the deviation is what comes back."""

    first_seen: list[str] = field(default_factory=list)
    rare_by: list[str] = field(default_factory=list)
    rare_among: str = "actor.user.name"
    seen_by_fewer_than: int = 0
    # The opposite band: a grouping shared by at least this many (RFC 0023).
    seen_by_at_least: int = 0
    lookback: str = "30d"

    @property
    def lookback_seconds(self) -> int:
        return parse_timeframe(self.lookback)

    @property
    def kind(self) -> str:
        if self.first_seen:
            return "first_seen"
        if self.rare_by:
            return "rare"
        return "none"


@dataclass
class Pack:
    id: str
    title: str
    hypothesis: str = ""
    triage: str = ""
    attack: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: Detection = field(default_factory=Detection)
    baseline: Baseline = field(default_factory=Baseline)
    pivot: list[str] = field(default_factory=list)
    window: str = "1d"
    # How often this pack must run whatever the news says, so coverage debt is
    # bounded rather than dependent on somebody remembering.
    cadence_days: int = 7
    references: list[str] = field(default_factory=list)
    sources: list[dict[str, str]] = field(default_factory=list)
    # What to check before an explanation counts, asked of the Hunter with every
    # observation set: an admin, a deploy, the defenders' own tools (RFC 0022).
    follow_up: list[str] = field(default_factory=list)
    # A pack on credentials, role grants, ACLs, DNS NS/MX or repository
    # visibility: a second inconclusive on the same tuple becomes a finding.
    sensitive: bool = False
    path: Path | None = None
    # Who merged it, for a pack the Hunter wrote here (RFC 0032); '' when shipped.
    merged_by: str = ""

    @property
    def window_seconds(self) -> int:
        return parse_timeframe(self.window)

    def logic(self) -> dict[str, Any]:
        """What the pack matches, what counts as new, and what a reader checks next."""
        b = self.baseline
        return {
            "detection": {**self.detection.blocks, "condition": self.detection.condition},
            "first_seen": list(b.first_seen),
            "rare": {
                "by": list(b.rare_by),
                "among": b.rare_among,
                "seen_by_fewer_than": b.seen_by_fewer_than,
                "seen_by_at_least": b.seen_by_at_least,
            }
            if b.rare_by
            else None,
            "lookback": b.lookback if b.kind != "none" else "",
            "window": self.window,
            "cadence_days": self.cadence_days,
            "pivot": list(self.pivot),
            "triage": self.triage,
            "follow_up": list(self.follow_up),
            "sensitive": self.sensitive,
        }

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "triage": self.triage,
            "attack": list(self.attack),
            "logsource": dict(self.logsource),
            "baseline": self.baseline.kind,
            "pivot": list(self.pivot),
            "window": self.window,
            "lookback": self.baseline.lookback,
            "cadence_days": self.cadence_days,
            "follow_up": list(self.follow_up),
            "sensitive": self.sensitive,
            "references": list(self.references),
            "sources": [dict(s) for s in self.sources],
            "merged_by": self.merged_by,
        }


def from_dict(data: dict[str, Any], path: Path | None = None) -> Pack:
    try:
        det = data["detection"]
    except KeyError as exc:
        raise ConfigError(f"{path or data.get('id')}: hunt pack has no detection block") from exc
    blocks = {k: v for k, v in det.items() if k not in ("condition",)}
    raw = data.get("baseline") or {}
    rare = raw.get("rare") or {}
    pack = Pack(
        id=data["id"],
        title=data["title"],
        hypothesis=str(data.get("hypothesis", "") or "").strip(),
        triage=str(data.get("triage", "") or "").strip(),
        attack=list(data.get("attack", []) or []),
        logsource=dict(data.get("logsource", {}) or {}),
        detection=Detection(
            blocks=blocks,
            condition=str(det.get("condition", " and ".join(blocks))),
        ),
        baseline=Baseline(
            first_seen=list(raw.get("first_seen", []) or []),
            rare_by=list(rare.get("by", []) or []),
            rare_among=str(rare.get("among", "actor.user.name")),
            seen_by_fewer_than=int(rare.get("seen_by_fewer_than", 0) or 0),
            seen_by_at_least=int(rare.get("seen_by_at_least", 0) or 0),
            lookback=str(raw.get("lookback", "30d")),
        ),
        pivot=list(data.get("pivot", []) or []),
        window=str(data.get("window", "1d")),
        cadence_days=int(data.get("cadence_days", 7)),
        references=list(data.get("references", []) or []),
        sources=parse_sources(data, path),
        follow_up=[str(q).strip() for q in data.get("follow_up", []) or [] if str(q).strip()],
        sensitive=bool(data.get("sensitive", False)),
        path=path,
    )
    validate(pack)
    return pack


def validate(pack: Pack) -> None:
    if not pack.detection.blocks:
        raise ConfigError(f"{pack.id}: detection has no selection block")
    if not pack.hypothesis:
        raise ConfigError(
            f"{pack.id}: a pack needs a hypothesis. A query without one is a search, "
            "and nobody can tell later what it was supposed to answer"
        )
    if not pack.triage:
        raise ConfigError(
            f"{pack.id}: a pack needs a triage question, so the rows it returns are "
            "readable by somebody who is not a hunter"
        )
    if not pack.pivot:
        raise ConfigError(f"{pack.id}: a pack needs at least one pivot field")
    parse_timeframe(pack.window)
    parse_timeframe(pack.baseline.lookback)
    if (
        pack.baseline.rare_by
        and max(pack.baseline.seen_by_fewer_than, pack.baseline.seen_by_at_least) <= 0
    ):
        raise ConfigError(
            f"{pack.id}: a rare baseline needs seen_by_fewer_than or seen_by_at_least"
        )
    if pack.baseline.first_seen and pack.baseline.rare_by:
        raise ConfigError(
            f"{pack.id}: use one baseline primitive per pack, so the observation set "
            "has one meaning"
        )


def load_file(path: Path) -> Pack:
    return from_dict(yaml.safe_load(path.read_text()) or {}, path)


def load_dir(directory: Path) -> list[Pack]:
    if not directory.exists():
        return []
    packs = [load_file(p) for p in sorted(directory.glob("*.yaml"))]
    seen: set[str] = set()
    for pack in packs:
        if pack.id in seen:
            raise ConfigError(f"duplicate hunt pack id '{pack.id}'")
        seen.add(pack.id)
    return packs


def load(config: Any = None, conn: Any = None, tenant_id: str = "") -> list[Pack]:
    """The shipped packs and, given a tenant, the ones the Hunter merged there."""
    from shoc.config import Config

    cfg = config or Config.load()
    shipped = load_dir(Path(cfg.content_dir) / "hunts")
    if conn is None or not tenant_id:
        return shipped
    ids = {p.id for p in shipped}
    return shipped + [p for p in merged(conn, tenant_id) if p.id not in ids]


def merged(conn: Any, tenant_id: str) -> list[Pack]:
    """The packs the Hunter merged here and nobody reverted. One that no longer
    parses is skipped rather than failing every other pack."""
    from shoc.db.pool import fetch_all

    out: list[Pack] = []
    for row in fetch_all(
        conn,
        """SELECT body, merged_by FROM shoc.merged_hunts
           WHERE tenant_id = %s AND state = 'merged' ORDER BY pack_id""",
        (tenant_id,),
    ):
        try:
            pack = from_dict(dict(row["body"]))
        except (ConfigError, KeyError, TypeError, ValueError):
            continue
        pack.merged_by = str(row["merged_by"])
        out.append(pack)
    return out
