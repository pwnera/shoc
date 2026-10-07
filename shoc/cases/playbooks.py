"""The playbook runner (RSP-2).

A playbook is YAML: a trigger and an ordered list of steps. A run is a row and a
step is a row, so the state machine survives a restart, a crash or a deploy —
there is no workflow engine to lose it (decision D6).

    running ──step needs approval──▶ waiting_approval ──approved──▶ running
        │                                                              │
        └──────────────── all steps done ─────────────────────────────▶ done

Every step is idempotent: re-running a run re-reads the rows, and an action that
is already `done` returns its recorded result instead of acting twice. A step
that fails is tried again `retries` times, minutes apart, and a timer step
(`wait_minutes`) parks the run in `waiting_timer` until a queued resume.

A person may merge a playbook of their own at runtime (RFC 0033). It has the
same shape, its steps use the actions shoc already has, and it is kept per
tenant in `shoc.merged_playbooks` and laid over content/ when playbooks load.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from shoc.actions import get as get_action
from shoc.cases import actions as action_store
from shoc.cases import credentials, engine
from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.errors import ConfigError, GateRefused, NotFound, ValidationError

PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")

log = logging.getLogger("shoc.playbooks")

# A failed step is tried again this many times, RETRY_AFTER_MINUTES times its
# attempt apart, unless the playbook says otherwise (RSP-2).
RETRIES = 2
RETRY_AFTER_MINUTES = 5


@dataclass
class Step:
    name: str
    action: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    optional: bool = False
    # A timer step acts on nothing: the run waits this long, then goes on.
    wait_minutes: int = 0
    retries: int = RETRIES


@dataclass
class Trigger:
    verdicts: list[str] = field(default_factory=lambda: ["malicious"])
    entity_kinds: list[str] = field(default_factory=list)
    attack_any: list[str] = field(default_factory=list)
    min_confidence: float = 0.0
    severity_at_least: str = "high"

    def misses(self, case: dict[str, Any], entities: dict[str, str]) -> list[str]:
        """Why this trigger did not fire, in the words a person would use.

        "No playbook matches this case" is true and unhelpful: it leaves someone
        guessing which of five conditions was the one, on the screen where they
        are deciding whether to contain something by hand.
        """
        from shoc.cases.policy import SEVERITY_ORDER

        why: list[str] = []
        if self.verdicts and case["verdict"] not in self.verdicts:
            why.append(f"verdict is '{case['verdict']}', it wants {' or '.join(self.verdicts)}")
        if float(case["confidence"]) < self.min_confidence:
            why.append(
                f"confidence is {float(case['confidence']):.2f}, it wants {self.min_confidence:.2f}"
            )
        if SEVERITY_ORDER.index(case["severity"]) < SEVERITY_ORDER.index(self.severity_at_least):
            why.append(
                f"severity is {case['severity']}, it wants {self.severity_at_least} or worse"
            )
        if self.entity_kinds and not any(k in entities for k in self.entity_kinds):
            have = ", ".join(sorted(entities)) or "none"
            why.append(f"it needs {' or '.join(self.entity_kinds)}; this case has {have}")
        if self.attack_any and not set(self.attack_any) & set(case["attack"] or []):
            why.append(f"it needs one of {', '.join(self.attack_any)}")
        return why


@dataclass
class Question:
    id: str
    ask: str


@dataclass
class Playbook:
    """How to investigate and answer the rules it names (RFC 0013).

    `questions` and `benign_when` go to the crew before a verdict; `steps` run
    after one. A rule belongs to exactly one playbook.
    """

    id: str
    title: str
    description: str = ""
    rules: list[str] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    benign_when: list[str] = field(default_factory=list)
    # One worked answer to these questions from an invented case: the shape of a
    # cited claim and of a checked absence, which a list of rules does not show.
    example: str = ""
    trigger: Trigger = field(default_factory=Trigger)
    steps: list[Step] = field(default_factory=list)
    path: Path | None = None
    # Who merged it here, for a playbook that is not in content/ (RFC 0033).
    merged_by: str = ""

    def cannot_act_on(self, product: str) -> str:
        """Why no step of this playbook acts on this product, or ''.

        Optional steps count: a rule is answered when something in its playbook
        can act on the platform it fires on, or on the login its user signs in
        as (RFC 0027). Required steps that cannot run there are a separate check
        (D53).
        """
        from shoc.actions import get as get_action
        from shoc.actions.base import out_of_scope

        product = product.lower()
        required = [
            why
            for step in self.steps
            if step.action and not step.optional
            if (why := out_of_scope(get_action(step.action), {product}))
        ]
        if required:
            return "; ".join(required)
        if any(
            product in (*get_action(s.action).platforms, *get_action(s.action).linked_from)
            for s in self.steps
            if s.action
        ):
            return ""
        return f"no step of playbook {self.id} acts on {product}"

    @classmethod
    def from_dict(cls, data: dict[str, Any], path: Path | None = None) -> Playbook:
        try:
            trigger = data.get("trigger", {}) or {}
            steps = [
                Step(
                    name=s["name"],
                    action=str(s.get("action") or ""),
                    params=s.get("params", {}) or {},
                    optional=bool(s.get("optional", False)),
                    wait_minutes=int(s.get("wait_minutes") or 0),
                    retries=int(s.get("retries", RETRIES)),
                )
                for s in data["steps"]
            ]
            questions = [Question(id=q["id"], ask=q["ask"]) for q in data.get("questions") or []]
        except KeyError as exc:
            raise ConfigError(f"{path or data.get('id')}: playbook is missing {exc}") from exc
        book = cls(
            id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            rules=list(data.get("rules") or []),
            questions=questions,
            benign_when=list(data.get("benign_when") or []),
            example=str(data.get("example") or "").strip(),
            trigger=Trigger(
                verdicts=list(trigger.get("verdict", ["malicious"])),
                entity_kinds=list(trigger.get("entity_kinds", []) or []),
                attack_any=list(trigger.get("attack_any", []) or []),
                min_confidence=float(trigger.get("min_confidence", 0.0)),
                severity_at_least=str(trigger.get("severity_at_least", "high")),
            ),
            steps=steps,
            path=path,
        )
        book.validate()
        return book

    def validate(self) -> None:
        from shoc.actions import available

        known = available()
        for step in self.steps:
            if bool(step.action) == bool(step.wait_minutes):
                raise ConfigError(
                    f"{self.id}: step '{step.name}' needs an action or wait_minutes, not both"
                )
            if step.action and step.action not in known:
                raise ConfigError(
                    f"{self.id}: step '{step.name}' uses unknown action '{step.action}'"
                )
            # A misspelt rule renders empty for ever, and an optional step is
            # then skipped on every case without a word (RFC 0026).
            for name in PLACEHOLDER.findall(json.dumps(step.params)):
                scope, _, rest = name.partition(".")
                if scope == "rule" and rest.partition(".")[0] not in self.rules:
                    raise ConfigError(
                        f"{self.id}: step '{step.name}' reads {name}, a rule it does not answer"
                    )
        if not self.steps:
            raise ConfigError(f"{self.id}: a playbook needs at least one step")
        if not self.rules:
            raise ConfigError(f"{self.id}: a playbook names the rules it answers")

    def misses(
        self,
        case: dict[str, Any],
        entities: dict[str, str],
        platforms: set[str],
        rule_ids: set[str],
    ) -> list[str]:
        """The trigger's misses, plus every required step aimed at another platform."""
        from shoc.actions import get as get_action
        from shoc.actions.base import out_of_scope

        why = [] if set(self.rules) & rule_ids else ["none of its rules fired on this case"]
        return (
            why
            + self.trigger.misses(case, entities)
            + [
                why
                for s in self.steps
                if s.action
                and not s.optional
                and (why := out_of_scope(get_action(s.action), platforms))
            ]
        )

    def to_json(self) -> dict[str, Any]:
        """The playbook as `from_dict` reads it, so a copy can be edited and merged."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "rules": self.rules,
            "questions": [{"id": q.id, "ask": q.ask} for q in self.questions],
            "benign_when": self.benign_when,
            "example": self.example,
            "merged_by": self.merged_by,
            "steps": [
                {
                    "name": s.name,
                    "action": s.action,
                    "params": s.params,
                    "optional": s.optional,
                    "wait_minutes": s.wait_minutes,
                    "retries": s.retries,
                }
                for s in self.steps
            ],
            "trigger": {
                "verdict": self.trigger.verdicts,
                "entity_kinds": self.trigger.entity_kinds,
                "attack_any": self.trigger.attack_any,
                "min_confidence": self.trigger.min_confidence,
                "severity_at_least": self.trigger.severity_at_least,
            },
        }


def load(config: Any = None, conn: Any = None, tenant_id: str = "") -> list[Playbook]:
    """Every playbook in content/ and, with a tenant, the ones merged there (RFC 0033)."""
    from shoc.config import Config

    cfg = config or Config.load()
    directory = Path(cfg.content_dir) / "playbooks"
    books = [
        Playbook.from_dict(yaml.safe_load(p.read_text()) or {}, p)
        for p in (sorted(directory.glob("*.yaml")) if directory.is_dir() else [])
    ]
    seen: set[str] = set()
    for book in books:
        if book.id in seen:
            raise ConfigError(f"duplicate playbook id '{book.id}'")
        seen.add(book.id)
    if conn is None or not tenant_id:
        return books
    return _bind(books, merged(conn, tenant_id), conn, tenant_id)


def merged(conn: Conn, tenant_id: str) -> list[Playbook]:
    """The playbooks merged here and not reverted. One that no longer loads, an
    action renamed since, is skipped and its rules go back where they were."""
    out: list[Playbook] = []
    for row in fetch_all(
        conn,
        """SELECT playbook_id, body, merged_by FROM shoc.merged_playbooks
           WHERE tenant_id = %s AND state = 'merged' ORDER BY playbook_id""",
        (tenant_id,),
    ):
        try:
            book = Playbook.from_dict(dict(row["body"]))
        except (ConfigError, AttributeError, KeyError, TypeError, ValueError) as exc:
            log.warning("merged playbook %s no longer loads: %s", row["playbook_id"], exc)
            continue
        book.merged_by = str(row["merged_by"])
        out.append(book)
    return out


def _bind(
    books: list[Playbook], mine: list[Playbook], conn: Conn, tenant_id: str
) -> list[Playbook]:
    """Lay this tenant's merges over content/. A rule still belongs to one
    playbook: a new rule merged here to the one it was merged with, and a rule a
    merged playbook names to that playbook, whichever answered it before.

    A narrowed shipped rule has no playbook of its own and keeps its shipped one.
    """
    rows = fetch_all(
        conn,
        """SELECT rule_id, playbook_id FROM shoc.merged_rules
           WHERE tenant_id = %s AND state = 'merged' AND playbook_id <> ''""",
        (tenant_id,),
    )
    by_id = {b.id: b for b in books}
    mine = [b for b in mine if b.id not in by_id]
    by_id |= {b.id: b for b in mine}
    owner = {str(r["rule_id"]): str(r["playbook_id"]) for r in rows if r["playbook_id"] in by_id}
    owner |= {rule: b.id for b in mine for rule in b.rules}
    for book in by_id.values():
        book.rules = [r for r in book.rules if owner.get(r, book.id) == book.id]
    for rule, book_id in owner.items():
        if rule not in by_id[book_id].rules:
            by_id[book_id].rules.append(rule)
    return list(by_id.values())


def get(playbook_id: str, config: Any = None, conn: Any = None, tenant_id: str = "") -> Playbook:
    for book in load(config, conn, tenant_id):
        if book.id == playbook_id:
            return book
    raise NotFound(f"no playbook '{playbook_id}'")


# -- merged here (RFC 0033) ---------------------------------------------------
# A playbook's id, as a merged rule's or pack's is (D48, RFC 0032).
PLAYBOOK_ID = re.compile(r"^[a-z0-9][a-z0-9_]{2,79}$")
# A run on a case ruled benign is cancelled before its first step.
TRIGGER_VERDICTS = ("malicious", "suspicious")


def merge(
    conn: Conn,
    tenant_id: str,
    config: Any,
    body: dict[str, Any],
    reason: str,
    who: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Keep a playbook written here, made of the actions shoc has, or say every
    reason it is refused (RFC 0033). Merging an id merged before replaces it;
    `dry_run` runs the gate and writes nothing.

    The gate refuses what would leave a rule answered worse than before with
    nobody noticing: a required step that can never run on the rule's platform
    (D53), a parameter nothing fills, a rule taken from the one playbook that
    could act on its platform, a trigger that would fail every case it reads.
    """
    from shoc.actions import get as get_action
    from shoc.actions.base import out_of_scope
    from shoc.cases.policy import SEVERITY_ORDER
    from shoc.detect import hunts
    from shoc.detect import rules as ruleset

    try:
        book = Playbook.from_dict(dict(body))
    except (ConfigError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise GateRefused.unparsed("the playbook", exc) from exc
    trigger = book.trigger
    words = [book.id, book.title, *book.rules, *book.benign_when, *trigger.verdicts]
    words += [*trigger.entity_kinds, *trigger.attack_any]
    words += [w for q in book.questions for w in (q.id, q.ask)]
    if not all(isinstance(w, str) for w in words) or not all(
        isinstance(s.params, dict) for s in book.steps
    ):
        raise GateRefused(
            [
                "the id, title, rules, questions, benign_when and the trigger's lists hold "
                "text, and a step's params are a map"
            ],
            "parse",
        )
    refused: list[str] = []
    if not PLAYBOOK_ID.match(book.id):
        refused.append("the id must be lower_snake_case, 3 to 80 characters")
    if any(b.id == book.id for b in load(config)):
        refused.append(f"'{book.id}' ships in content/; merge yours under another id")
    if not trigger.verdicts or set(trigger.verdicts) - set(TRIGGER_VERDICTS):
        refused.append(f"trigger.verdict takes {' and '.join(TRIGGER_VERDICTS)}")
    if trigger.severity_at_least not in SEVERITY_ORDER:
        refused.append(f"trigger.severity_at_least is one of {', '.join(SEVERITY_ORDER)}")
    if not 0 <= trigger.min_confidence <= 1:
        refused.append("trigger.min_confidence is between 0 and 1")
    if len({q.id for q in book.questions}) < max(2, len(book.questions)):
        refused.append("it asks the crew at least two questions, each with its own id")
    if "<" in book.example:
        refused.append("the example must not contain '<'")
    for step in book.steps:
        action = get_action(step.action) if step.action else None
        found = getattr(action, "resolve", {})
        needs = getattr(action, "required_params", ())
        if missing := [p for p in needs if p not in step.params and p not in found]:
            refused.append(f"step '{step.name}' gives {step.action} no {', '.join(missing)}")

    logsource = {r.id: r.logsource for r in ruleset.load(config, conn, tenant_id)}
    logsource |= {f"hunt:{p.id}": p.logsource for p in hunts.load(config, conn, tenant_id)}
    owner = {rule: b for b in load(config, conn, tenant_id) for rule in b.rules}
    claimed = {rule: b.id for b in merged(conn, tenant_id) if b.id != book.id for rule in b.rules}
    took: dict[str, str] = {}
    for rule in book.rules:
        if rule not in logsource:
            refused.append(f"there is no rule or hunt pack '{rule}' here")
            continue
        if rule in claimed:
            refused.append(
                f"{rule} is answered by {claimed[rule]}, merged here; merge that one again "
                "without it, or revert it, first"
            )
        product = str(logsource[rule].get("product", "")).lower()
        blocked = [
            f"step '{s.name}' is required and can never run on a case from {rule}: {why}"
            for s in book.steps
            if s.action and not s.optional
            if (why := out_of_scope(get_action(s.action), {product}))
        ]
        refused += blocked
        was = owner.get(rule)
        if was is None or was.id == book.id:
            continue
        took[rule] = was.id
        if not blocked and (why := book.cannot_act_on(product)) and not was.cannot_act_on(product):
            refused.append(f"{rule}: {why}, and {was.id}, which answers it now, does")
    if refused:
        raise GateRefused(refused, "lint")
    if dry_run:
        # The open runs a replacement would cancel, counted and left alone.
        row = fetch_one(
            conn,
            """SELECT count(*) AS n FROM shoc.playbook_runs
                WHERE tenant_id = %s AND playbook_id = %s
                  AND state NOT IN ('done', 'failed', 'cancelled')""",
            (tenant_id, book.id),
        )
        return {
            "playbook_id": book.id,
            "rules": book.rules,
            "took_from": took,
            "cancelled_runs": int(row["n"]) if row else 0,
        }

    execute(
        conn,
        """INSERT INTO shoc.merged_playbooks (tenant_id, playbook_id, body, reason, merged_by)
           VALUES (%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, playbook_id) DO UPDATE SET
               body = EXCLUDED.body, reason = EXCLUDED.reason, merged_by = EXCLUDED.merged_by,
               state = 'merged', merged_at = now(), reverted_at = NULL""",
        (tenant_id, book.id, json.dumps(body, default=str), reason[:500], who),
    )
    return {
        "playbook_id": book.id,
        "rules": book.rules,
        "took_from": took,
        "cancelled_runs": _cancel_runs(conn, tenant_id, book.id, "the playbook was merged again"),
    }


def revert(
    conn: Conn, tenant_id: str, config: Any, playbook_id: str, reason: str, who: str
) -> dict[str, Any]:
    """Take back a merged playbook: its rules go back to the playbooks that
    answered them before, and its open runs are cancelled. One in content/
    changes with a deploy, never here."""
    before = [b for b in load(config, conn, tenant_id) if b.id == playbook_id]
    rest = [b for b in merged(conn, tenant_id) if b.id != playbook_id]
    answered = {rule: b.id for b in _bind(load(config), rest, conn, tenant_id) for rule in b.rules}
    rules = [rule for b in before for rule in b.rules]
    if lost := [r for r in rules if r not in answered and not r.startswith("hunt:")]:
        raise ValidationError(
            f"not reverted: {', '.join(lost)} would be answered by no playbook; merge "
            "another playbook that names it, or revert the rule with detection.revert, first"
        )
    row = fetch_one(
        conn,
        """UPDATE shoc.merged_playbooks SET state = 'reverted', reverted_at = now(), reason = %s
           WHERE tenant_id = %s AND playbook_id = %s AND state = 'merged'
           RETURNING playbook_id""",
        (f"reverted by {who}: {reason}"[:1000], tenant_id, playbook_id),
    )
    if not row:
        raise NotFound(
            f"'{playbook_id}' is not a playbook merged here; one in content/ changes with a deploy"
        )
    return {
        "playbook_id": playbook_id,
        "state": "reverted",
        "answered_by": {r: answered[r] for r in rules if r in answered},
        "cancelled_runs": _cancel_runs(
            conn, tenant_id, playbook_id, f"the playbook was reverted: {reason}"
        ),
    }


def _cancel_runs(conn: Conn, tenant_id: str, playbook_id: str, why: str) -> int:
    """Cancel the open runs of a playbook that was replaced or reverted. A run's
    steps are rows numbered by the playbook it started on, which is gone. The
    actions it proposed stay, for a person to approve or reject."""
    return len(
        fetch_all(
            conn,
            """UPDATE shoc.playbook_runs
                  SET state = 'cancelled', error = %s, updated_at = now(), finished_at = now()
                WHERE tenant_id = %s AND playbook_id = %s
                  AND state NOT IN ('done', 'failed', 'cancelled')
               RETURNING run_uid""",
            (why[:500], tenant_id, playbook_id),
        )
    )


# -- context ----------------------------------------------------------------
def entities_of_case(conn: Conn, tenant_id: str, case_uid: str) -> dict[str, str]:
    """The typed entities on a case, as `{kind: value}` for template use."""
    rows = fetch_all(
        conn,
        "SELECT entity FROM shoc.case_entities WHERE tenant_id=%s AND case_uid=%s ORDER BY entity",
        (tenant_id, case_uid),
    )
    out: dict[str, str] = {}
    for row in rows:
        kind, _, value = str(row["entity"]).partition(":")
        out.setdefault(kind, value)
    return out


def rules_of_case(conn: Conn, tenant_id: str, case_uid: str) -> set[str]:
    rows = fetch_all(
        conn,
        "SELECT DISTINCT rule_id FROM shoc.findings WHERE tenant_id = %s AND case_uid = %s",
        (tenant_id, case_uid),
    )
    return {str(r["rule_id"]) for r in rows}


def for_rules(
    rule_ids: set[str], config: Any = None, conn: Any = None, tenant_id: str = ""
) -> list[Playbook]:
    """The playbooks that answer any of these rules: what a case's analysis follows."""
    return [b for b in load(config, conn, tenant_id) if set(b.rules) & rule_ids]


def scoped_entities(
    conn: Conn, tenant_id: str, case_uid: str, config: Any = None
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """The case's entities per rule and per platform, `{scope: {kind: value}}` (RFC 0026).

    A case holds every finding linked to it: the twenty users a spray tried and
    the one who signed in, a Gateway lookup's WARP device and the EDR's device
    id. A step names the findings its target comes from.
    """
    rows = fetch_all(
        conn,
        """SELECT rule_id, entities FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s ORDER BY rule_id""",
        (tenant_id, case_uid),
    )
    product = engine.products(conn, tenant_id, config)
    rules: dict[str, dict[str, str]] = {}
    platforms: dict[str, dict[str, str]] = {}
    for row in rows:
        for entity in sorted(row["entities"] or []):
            kind, _, value = str(entity).partition(":")
            rules.setdefault(str(row["rule_id"]), {}).setdefault(kind, value)
            if where := product.get(str(row["rule_id"]), ""):
                platforms.setdefault(where, {}).setdefault(kind, value)
    return rules, platforms


def context_for(
    conn: Conn, tenant_id: str, case: dict[str, Any], config: Any = None
) -> dict[str, Any]:
    rules, platforms = scoped_entities(conn, tenant_id, case["case_uid"], config)
    return {
        "case": {
            "case_uid": case["case_uid"],
            "title": case["title"],
            "severity": case["severity"],
            "verdict": case["verdict"],
            "confidence": float(case["confidence"]),
            "entity": case["entity_key"],
            "summary": case["summary"],
        },
        "entity": entities_of_case(conn, tenant_id, case["case_uid"]),
        "rule": rules,
        "platform": platforms,
    }


def render(value: Any, context: dict[str, Any]) -> Any:
    """Substitute `{{ case.title }}`, `{{ entity.key }}`, `{{ rule.<id>.user }}` and
    `{{ platform.<product>.device }}`. Missing values stay empty."""
    if isinstance(value, dict):
        return {k: render(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, context) for v in value]
    if not isinstance(value, str):
        return value

    def lookup(match: re.Match[str]) -> str:
        cursor: Any = context
        for part in match.group(1).split("."):
            cursor = cursor.get(part) if isinstance(cursor, dict) else None
            if cursor is None:
                return ""
        return str(cursor)

    return PLACEHOLDER.sub(lookup, value)


# -- runs -------------------------------------------------------------------
def run_uid(tenant_id: str, playbook_id: str, case_uid: str) -> str:
    blob = f"{tenant_id}|{playbook_id}|{case_uid}"
    return "RUN-" + hashlib.sha256(blob.encode()).hexdigest()[:20]


def match(conn: Conn, tenant_id: str, case: dict[str, Any], config: Any = None) -> list[Playbook]:
    entities = entities_of_case(conn, tenant_id, case["case_uid"])
    seen = engine.platforms(conn, tenant_id, case["case_uid"], config)
    fired = rules_of_case(conn, tenant_id, case["case_uid"])
    return [b for b in load(config, conn, tenant_id) if not b.misses(case, entities, seen, fired)]


def start(
    conn: Conn,
    tenant_id: str,
    playbook_id: str,
    case_uid: str,
    config: Any = None,
    dry_run: bool | None = None,
) -> dict[str, Any]:
    """Create a run and its steps. Starting the same playbook twice is a no-op."""
    from shoc.config import Config

    cfg = config or Config.load()
    book = get(playbook_id, cfg, conn, tenant_id)
    case = engine.require(conn, tenant_id, case_uid)
    uid = run_uid(tenant_id, playbook_id, case_uid)
    existing = fetch_one(conn, "SELECT * FROM shoc.playbook_runs WHERE run_uid=%s", (uid,))
    if existing:
        return existing
    context = context_for(conn, tenant_id, case, cfg)
    row = fetch_one(
        conn,
        """INSERT INTO shoc.playbook_runs (run_uid, tenant_id, case_uid, playbook_id, context, dry_run)
           VALUES (%s,%s,%s,%s,%s,%s) RETURNING *""",
        (
            uid,
            tenant_id,
            case_uid,
            playbook_id,
            json.dumps(context, default=str),
            cfg.dry_run if dry_run is None else dry_run,
        ),
    )
    for index, step in enumerate(book.steps):
        execute(
            conn,
            """INSERT INTO shoc.playbook_steps (run_uid, tenant_id, step_index, name, action_type)
               VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (uid, tenant_id, index, step.name, step.action),
        )
    engine.publish(
        conn,
        tenant_id,
        "playbook.started",
        uid,
        {"playbook_id": playbook_id, "case_uid": case_uid, "steps": len(book.steps)},
    )
    return row or {}


@dataclass
class RunReport:
    run_uid: str
    state: str = "running"
    steps_done: int = 0
    steps_total: int = 0
    waiting_on: str = ""
    detail: list[str] = field(default_factory=list)
    # Optional steps that need a human. They are left for one to approve while
    # the rest of the playbook carries on (RSP-6): containment must not wait
    # behind a step the playbook itself marked as nice-to-have.
    pending_approval: list[str] = field(default_factory=list)


def advance(
    conn: Conn,
    tenant_id: str,
    run: str,
    master_key: str,
    config: Any = None,
    principal: str = "playbook-runner",
) -> RunReport:
    """Run steps until one needs a human, one fails, or the playbook is finished."""
    row = fetch_one(
        conn, "SELECT * FROM shoc.playbook_runs WHERE tenant_id=%s AND run_uid=%s", (tenant_id, run)
    )
    if not row:
        raise NotFound(f"no playbook run '{run}'")
    if row["state"] in ("done", "failed", "cancelled"):
        # Before the playbook is read: a run of one reverted since still answers.
        return RunReport(
            run_uid=run,
            state=row["state"],
            steps_done=int(row["step_index"]),
            steps_total=len(steps_of(conn, run)),
        )
    book = get(row["playbook_id"], config, conn, tenant_id)
    context = dict(row["context"] or {})
    report = RunReport(run_uid=run, state=row["state"], steps_total=len(book.steps))

    index = int(row["step_index"])
    # The trigger is read when a run is queued; the case can be ruled benign
    # before the run starts, or while it waits for an approval.
    verdict = row["case_uid"] and engine.require(conn, tenant_id, row["case_uid"])["verdict"]
    if verdict in ("benign_expected", "false_positive"):
        _set_run(conn, tenant_id, run, "cancelled", index, f"the case is {verdict}")
        report.state, report.steps_done = "cancelled", index
        report.detail.append(f"cancelled: the case is {verdict}")
        return report
    scope: credentials.Scope | None = None
    while index < len(book.steps):
        step = book.steps[index]
        if step.wait_minutes:
            timer = fetch_one(
                conn,
                """UPDATE shoc.playbook_steps
                   SET started_at = coalesce(started_at, now()), state = 'waiting'
                   WHERE run_uid = %s AND step_index = %s
                   RETURNING started_at + %s * interval '1 minute' AS due, now() AS now""",
                (run, index, step.wait_minutes),
            )
            if timer and timer["now"] < timer["due"]:
                _wait(conn, tenant_id, run, index, timer["due"], f"timer:{run}:{index}")
                report.state, report.steps_done = "waiting_timer", index
                report.waiting_on = f"{step.name} until {timer['due']:%H:%M} UTC"
                report.detail.append(f"{step.name}: waiting {step.wait_minutes} minute(s)")
                return report
            _finish_step(conn, run, index, "done", {"waited_minutes": step.wait_minutes})
            report.detail.append(f"{step.name}: waited {step.wait_minutes} minute(s)")
            index += 1
            continue
        # A playbook names each vendor's step; the ones for a vendor this case
        # did not come from are not proposed (RFC 0031).
        if step.optional and row["case_uid"]:
            scope = scope or credentials.Scope.of(conn, tenant_id, row["case_uid"], config)
            if why := scope.excludes(get_action(step.action)):
                _finish_step(conn, run, index, "skipped", {"reason": why})
                report.detail.append(f"{step.name}: skipped, {why}")
                index += 1
                continue
        params = render(step.params, context)
        missing = [k for k, v in params.items() if v in ("", None)]
        if missing and step.optional:
            _finish_step(conn, run, index, "skipped", {"missing": missing})
            report.detail.append(f"{step.name}: skipped ({', '.join(missing)} unknown)")
            index += 1
            continue
        if missing:
            _finish_step(conn, run, index, "failed", {"missing": missing})
            _set_run(
                conn,
                tenant_id,
                run,
                "failed",
                index,
                f"step '{step.name}' needs {', '.join(missing)}",
            )
            report.state, report.steps_done = "failed", index
            report.detail.append(f"{step.name}: cannot run, {', '.join(missing)} unknown")
            return report

        # A step that already has an action keeps it: resuming a run must never
        # re-propose, or a human's approval would be overwritten by a new
        # proposal and the run would wait forever.
        step_row = (
            fetch_one(
                conn,
                "SELECT action_uid, attempts FROM shoc.playbook_steps WHERE run_uid=%s AND step_index=%s",
                (run, index),
            )
            or {}
        )
        existing_uid = step_row.get("action_uid")
        if existing_uid:
            action = action_store.require(conn, tenant_id, existing_uid)
        else:
            # The crew may have proposed the same action on this case first. A
            # failed one is proposed again with this step's parameters, never
            # reused as it stands (RSP-4).
            try:
                action = action_store.propose(
                    conn,
                    tenant_id,
                    action_store.Proposal(
                        action_type=step.action,
                        params=params,
                        rationale=f"playbook {book.id}, step '{step.name}'",
                        case_uid=row["case_uid"],
                        run_uid=run,
                    ),
                    principal=principal,
                    principal_kind="service",
                    config=config,
                )
            except ValidationError as exc:
                # A parameter the action finds for itself was not found (a key
                # whose user the events disagree on): as if it were unknown.
                _finish_step(
                    conn, run, index, "skipped" if step.optional else "failed", {"reason": str(exc)}
                )
                report.detail.append(f"{step.name}: cannot run, {exc}")
                if step.optional:
                    index += 1
                    continue
                _set_run(conn, tenant_id, run, "failed", index, f"step '{step.name}': {exc}")
                report.state, report.steps_done = "failed", index
                return report
            execute(
                conn,
                "UPDATE shoc.playbook_steps SET action_uid=%s, started_at=now(), state='running' "
                "WHERE run_uid=%s AND step_index=%s",
                (action["action_uid"], run, index),
            )
        uid = str(action["action_uid"])
        attempts = int(step_row.get("attempts") or 0)

        if action["state"] == "running":
            # Either another worker is in the call right now, or one died in it.
            stuck = action_store.fail_if_stuck(conn, tenant_id, uid, principal)
            if not stuck:
                _set_run(conn, tenant_id, run, "running", index, None)
                report.state, report.steps_done, report.waiting_on = "running", index, uid
                report.detail.append(f"{step.name}: still running")
                return report
            action = stuck
        if action["state"] == "failed":
            if attempts > step.retries:
                if _gave_up(conn, tenant_id, run, index, step, report, str(action["error"] or "")):
                    return report
                index += 1
                continue
            action = action_store.retry(conn, tenant_id, uid, principal, run)
        if action["state"] == "done":
            _finish_step(conn, run, index, "done", dict(action["result"] or {}))
            report.detail.append(f"{step.name}: already done")
            index += 1
            continue
        if action["state"] == "rolled_back":
            # Somebody undid it. Doing it again is theirs to decide, not the runner's.
            _finish_step(conn, run, index, "rolled_back", {})
            if step.optional:
                report.detail.append(f"{step.name}: undone by a person, skipped")
                index += 1
                continue
            _set_run(conn, tenant_id, run, "cancelled", index, f"'{step.name}' was undone")
            report.state, report.steps_done = "cancelled", index
            report.detail.append(f"{step.name}: undone by a person")
            return report
        if action["state"] == "rejected":
            if action.get("approved_by") == "unattended":
                # Nobody answered in time (RSP-7). That is not a decision against
                # the response, so the rest of the playbook still runs.
                _finish_step(conn, run, index, "expired", {"reason": action["error"]})
                report.detail.append(f"{step.name}: nobody approved it in time, skipped")
                index += 1
                continue
            _finish_step(conn, run, index, "rejected", {})
            if step.optional:
                report.detail.append(f"{step.name}: rejected by a human, skipped")
                index += 1
                continue
            _set_run(conn, tenant_id, run, "cancelled", index, f"'{step.name}' was rejected")
            report.state, report.steps_done = "cancelled", index
            report.detail.append(f"{step.name}: rejected by a human")
            return report
        if action["state"] == "blocked":
            _finish_step(conn, run, index, "blocked", {"reason": action["rationale"]})
            if step.optional:
                report.detail.append(f"{step.name}: blocked by policy, skipped")
                index += 1
                continue
            _set_run(conn, tenant_id, run, "failed", index, f"policy blocked '{step.name}'")
            report.state, report.steps_done = "failed", index
            report.detail.append(f"{step.name}: blocked by policy")
            return report
        if action["state"] == "proposed":
            if step.optional:
                # The action stays proposed, so a human can still approve it and
                # `action.run` will execute it; the playbook does not hold the
                # rest of the response hostage to it. The step is parked in its
                # own state so it is not mistaken for the step a *waiting* run
                # is blocked on.
                _finish_step(
                    conn,
                    run,
                    index,
                    "awaiting_approval",
                    {"action_uid": uid, "reason": action["rationale"]},
                )
                report.pending_approval.append(uid)
                report.detail.append(
                    f"{step.name}: left for a human to approve — {action['rationale']}"
                )
                engine.publish(
                    conn,
                    tenant_id,
                    "playbook.needs_approval",
                    run,
                    {
                        "step": step.name,
                        "action_uid": uid,
                        "case_uid": row["case_uid"],
                        "optional": True,
                        "reason": action["rationale"],
                    },
                )
                index += 1
                continue
            _set_run(conn, tenant_id, run, "waiting_approval", index, None)
            report.state = "waiting_approval"
            report.steps_done = index
            report.waiting_on = uid
            report.detail.append(f"{step.name}: waiting for a human to approve")
            engine.publish(
                conn,
                tenant_id,
                "playbook.waiting",
                run,
                {"step": step.name, "action_uid": uid, "case_uid": row["case_uid"]},
            )
            return report

        attempt = int(
            (
                fetch_one(
                    conn,
                    """UPDATE shoc.playbook_steps SET attempts = attempts + 1, state = 'running'
               WHERE run_uid = %s AND step_index = %s RETURNING attempts""",
                    (run, index),
                )
                or {}
            ).get("attempts")
            or 1
        )
        _row, result = action_store.execute(
            conn,
            tenant_id,
            uid,
            master_key,
            force_dry_run=row["dry_run"] or None,
            by=principal,
        )
        report.detail.append(f"{step.name}: {result.detail}")
        if result.ok:
            _finish_step(conn, run, index, "done", result.to_json())
            index += 1
            continue
        if attempt <= step.retries:
            minutes = RETRY_AFTER_MINUTES * attempt
            execute(
                conn,
                "UPDATE shoc.playbook_steps SET state='retrying', result=%s "
                "WHERE run_uid=%s AND step_index=%s",
                (json.dumps(result.to_json(), default=str), run, index),
            )
            _wait(
                conn,
                tenant_id,
                run,
                index,
                datetime.now(UTC) + timedelta(minutes=minutes),
                f"retry:{run}:{index}:{attempt}",
                result.detail[:500],
            )
            report.state, report.steps_done, report.waiting_on = "waiting_timer", index, uid
            report.detail.append(f"{step.name}: trying again in {minutes} minute(s)")
            return report
        if _gave_up(conn, tenant_id, run, index, step, report, result.detail):
            return report
        index += 1

    _set_run(conn, tenant_id, run, "done", index, None)
    report.state, report.steps_done = "done", index
    engine.publish(
        conn,
        tenant_id,
        "playbook.finished",
        run,
        {"playbook_id": row["playbook_id"], "case_uid": row["case_uid"], "steps": index},
    )
    return report


def _wait(
    conn: Conn,
    tenant_id: str,
    run: str,
    index: int,
    until: datetime,
    key: str,
    error: str | None = None,
) -> None:
    """Park the run until `until`, with the resume that wakes it already queued."""
    from shoc.db import jobs

    jobs.enqueue(
        conn, tenant_id, "playbook.resume", {"run_uid": run}, run_at=until, idempotency_key=key
    )
    _set_run(conn, tenant_id, run, "waiting_timer", index, error)


def _gave_up(
    conn: Conn,
    tenant_id: str,
    run: str,
    index: int,
    step: Step,
    report: RunReport,
    detail: str,
) -> bool:
    """A step out of retries: skipped if optional, else the run fails. True when it stops."""
    _finish_step(conn, run, index, "failed", {"error": detail[:500]})
    if step.optional:
        report.detail.append(f"{step.name}: failed {step.retries + 1} time(s), skipped")
        return False
    _set_run(conn, tenant_id, run, "failed", index, detail[:500])
    report.state, report.steps_done = "failed", index
    return True


def _finish_step(conn: Conn, run: str, index: int, state: str, result: dict[str, Any]) -> None:
    execute(
        conn,
        """UPDATE shoc.playbook_steps SET state=%s, result=%s, finished_at=now()
           WHERE run_uid=%s AND step_index=%s""",
        (state, json.dumps(result, default=str), run, index),
    )


def _set_run(
    conn: Conn, tenant_id: str, run: str, state: str, index: int, error: str | None
) -> None:
    row = fetch_one(
        conn,
        """UPDATE shoc.playbook_runs SET state=%s, step_index=%s, error=%s, updated_at=now(),
               finished_at = CASE WHEN %s IN ('done','failed','cancelled') THEN now() END
           WHERE tenant_id=%s AND run_uid=%s RETURNING case_uid""",
        (state, index, error, state, tenant_id, run),
    )
    if state in ("done", "failed", "cancelled") and row and row["case_uid"]:
        # The run has done what it could: a malicious case it left uncontained pages (RFC 0015).
        from shoc.agents import manager

        manager.uncontained(conn, tenant_id, str(row["case_uid"]))


def steps_of(conn: Conn, run: str) -> list[dict[str, Any]]:
    return fetch_all(
        conn, "SELECT * FROM shoc.playbook_steps WHERE run_uid=%s ORDER BY step_index", (run,)
    )


def runs_for(
    conn: Conn, tenant_id: str, case_uid: str = "", limit: int = 50
) -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if case_uid:
        where.append("case_uid = %(case_uid)s")
        params["case_uid"] = case_uid
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.playbook_runs WHERE {' AND '.join(where)} "
        "ORDER BY started_at DESC LIMIT %(limit)s",
        params,
    )


def give_up(conn: Conn, tenant_id: str, run: str, why: str) -> None:
    """Fail a run that nothing can wake any more, where it stopped (RSP-2)."""
    execute(
        conn,
        """UPDATE shoc.playbook_runs SET state='failed', error=%s, updated_at=now(),
               finished_at=now()
           WHERE tenant_id=%s AND run_uid=%s AND state NOT IN ('done','failed','cancelled')""",
        (why[:500], tenant_id, run),
    )
