"""The Detection Engineer (AGT-3, D48, D77): owns the detection lifecycle, and finishes it.

Noise is the primary failure mode of a SOC, and the quiet rule is the more
dangerous one, because nobody notices a detection that stopped working.

1. **Intake (code).** A case a person or the crew closed `false_positive` opens
   one item per (rule, case) at once; a `benign_expected` closure opens one only
   when the same rule and entity come back (`shoc/cases/routing.py`). The
   nightly sweep adds aggregate noise from rule health, technique gaps from
   intel, and reopens a source gap whose product now delivers.
2. **Work.** Code ends what needs no judgement first: it reverts a new rule of
   its own that turned noisy, closes items that are only shoc's own credentials
   at work, and closes items worked three times on unchanged evidence. Then one
   model turn per item, highest priority first, under a daily token ceiling.
3. **The gate (D48, D77).** A shipped rule is only ever narrowed, by an
   exclusion composed onto it at load time, so later fixes to the shipped rule
   still reach this tenant. The exclusion must name an exact global address and
   one exact id the attacker cannot set, seen for a week before the case. The
   case's events must stop matching, replayed through today's mapping, and the
   rule's positive fixture and every past true positive must still match. A
   narrowing lapses after 90 days. A new rule keeps the full gate: fixtures,
   backtest volume, the ADS form and a playbook that can act on its platform.
4. **The safety net.** A case that is reopened, or turns malicious, reverts the
   merges it produced (`routing.undo_closure`). A crew closure drives a merge
   only after the weekly recheck agreed with it.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from shoc.agents import ops
from shoc.db.pool import Conn, execute, fetch_all, fetch_one
from shoc.errors import ConfigError, GateRefused, NotFound, ValidationError

NOISY_FINDINGS_7D = 25
SILENT_DAYS = 30

# What a backlog item is worth doing first. A rule that is wrong outranks a rule
# that is loud, because a wrong rule is teaching the company to ignore it.
PRIORITY = {"defect": 2, "noise": 3, "promote": 2, "coverage": 4}


# -- intake and the backlog -------------------------------------------------
@dataclass
class BacklogItem:
    """One idea for a detection change, and where it came from."""

    item_uid: str
    kind: str
    intake: str
    rule_id: str = ""
    title: str = ""
    reason: str = ""
    priority: int = 3
    observability: str = "unknown"
    evidence: dict[str, Any] = field(default_factory=dict)
    case_uid: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "item_uid": self.item_uid,
            "kind": self.kind,
            "intake": self.intake,
            "rule_id": self.rule_id,
            "title": self.title,
            "reason": self.reason,
            "priority": self.priority,
            "observability": self.observability,
            "evidence": self.evidence,
            "case_uid": self.case_uid,
        }


def item_uid(tenant_id: str, *parts: str) -> str:
    return "DBL-" + hashlib.sha256("|".join((tenant_id, *parts)).encode()).hexdigest()[:20]


def add(conn: Conn, tenant_id: str, item: BacklogItem) -> str:
    """Put one item on the backlog, leaving an already-decided one decided."""
    execute(
        conn,
        """INSERT INTO shoc.detection_backlog
               (item_uid, tenant_id, rule_id, kind, intake, title, reason,
                priority, observability, evidence, case_uid)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (item_uid) DO UPDATE SET
               reason = EXCLUDED.reason, priority = EXCLUDED.priority,
               observability = EXCLUDED.observability,
               evidence = shoc.detection_backlog.evidence || EXCLUDED.evidence
           WHERE shoc.detection_backlog.state = 'open'""",
        (
            item.item_uid,
            tenant_id,
            item.rule_id,
            item.kind,
            item.intake,
            item.title,
            item.reason,
            item.priority,
            item.observability,
            json.dumps(item.evidence, default=str),
            item.case_uid,
        ),
    )
    return item.item_uid


def intake(conn: Conn, tenant_id: str, config: Any = None) -> list[BacklogItem]:
    """The nightly sweep. Cases route themselves when they close; this is the rest."""
    from shoc.cases import routing

    out = _from_intel(conn, tenant_id, config) + _from_health(conn, tenant_id, config)
    delivering = _delivering(conn, tenant_id)
    score_observability(conn, tenant_id, out, config, delivering)
    for item in out:
        add(conn, tenant_id, item)
    routing.recurring_suppressed(conn, tenant_id)
    _reopen_gaps(conn, tenant_id, delivering)
    _lapse(conn, tenant_id)
    return out


def _from_intel(
    conn: Conn, tenant_id: str, config: Any = None, limit: int = 20
) -> list[BacklogItem]:
    """A technique we have read about and cannot look for."""
    from shoc.detect import rules as ruleset

    covered: set[str] = set()
    with contextlib.suppress(Exception):
        for rule in ruleset.load(config, conn, tenant_id):
            covered |= {str(t).upper() for t in (rule.attack or [])}
    rows = fetch_all(
        conn,
        """SELECT report_uid, title, techniques, procedures FROM shoc.intel_reports
           WHERE tenant_id = %s AND digested_at > now() - interval '90 days'
           ORDER BY digested_at DESC LIMIT 20""",
        (tenant_id,),
    )
    out: dict[str, BacklogItem] = {}
    for row in rows:
        # What the report saw the attacker do with it, so the item is the
        # behaviour to detect and not the id alone (D132).
        said = {str(p.get("id", "")).upper(): p for p in row["procedures"] or []}
        for technique in (row["techniques"] or [])[:limit]:
            code = str(technique).upper()
            if code in covered or code.split(".", 1)[0] in covered:
                continue
            uid = item_uid(tenant_id, "cti", code)
            procedure = said.get(code, {})
            evidence = {
                "report_uid": row["report_uid"],
                "technique": code,
                "name": procedure.get("name"),
                "procedure": procedure.get("evidence"),
            }
            out.setdefault(
                uid,
                BacklogItem(
                    item_uid=uid,
                    kind="coverage",
                    intake="cti",
                    title=f"no rule maps to {code}",
                    reason=f"'{row['title']}' describes {code} and no rule we ship maps to it",
                    priority=PRIORITY["coverage"],
                    evidence={k: v for k, v in evidence.items() if v},
                ),
            )
    return list(out.values())


def _from_health(conn: Conn, tenant_id: str, config: Any = None) -> list[BacklogItem]:
    """An aggregate rule over its shipped volume. The dominant entity is evidence only."""
    from shoc.detect import rules as ruleset

    aggregate = {r.id for r in ruleset.load(config, conn, tenant_id) if r.is_aggregate}
    out: list[BacklogItem] = []
    for health in ops.rule_health(conn, tenant_id, NOISY_FINDINGS_7D, SILENT_DAYS, config):
        if not (health.noisy and health.rule_id in aggregate):
            continue
        entity, top, total = _dominant_entity(conn, tenant_id, health.rule_id)
        week = datetime.now(UTC).strftime("%G-W%V")
        out.append(
            BacklogItem(
                item_uid=item_uid(tenant_id, health.rule_id, "noise", week),
                kind="defect",
                intake="health",
                rule_id=health.rule_id,
                title=f"{health.rule_id}: over its volume",
                reason=(
                    f"{health.findings_7d} findings in 7 days across {health.cases_7d} case(s); "
                    f"the threshold may be low for this tenant"
                ),
                priority=PRIORITY["noise"],
                observability="have",
                evidence={
                    "findings_7d": health.findings_7d,
                    "dominant_entity": entity,
                    "share": round(top / max(1, total), 2),
                },
            )
        )
    return out


def _dominant_entity(conn: Conn, tenant_id: str, rule_id: str) -> tuple[str, int, int]:
    rows = fetch_all(
        conn,
        """SELECT entity_key, count(*) AS n FROM shoc.findings
           WHERE tenant_id = %s AND rule_id = %s AND last_seen > now() - interval '7 days'
             AND status NOT IN ('suppressed', 'self')
           GROUP BY entity_key ORDER BY n DESC LIMIT 5""",
        (tenant_id, rule_id),
    )
    total = sum(int(r["n"]) for r in rows)
    if not rows or not total:
        return "", 0, 0
    return str(rows[0]["entity_key"]), int(rows[0]["n"]), total


def _delivering(conn: Conn, tenant_id: str) -> set[str]:
    """Products a connected source delivered in the last 30 days."""
    return {
        str(p)
        for r in fetch_all(
            conn,
            """SELECT products FROM shoc.source_history
               WHERE tenant_id = %s AND last_loaded_at > now() - interval '30 days'""",
            (tenant_id,),
        )
        for p in (r["products"] or [])
    }


def _products_of(config: Any, conn: Conn, tenant_id: str, rule_id: str) -> list[str]:
    from shoc.detect import rules as ruleset
    from shoc.store import ocsf as layout

    rule = next((r for r in ruleset.load(config, conn, tenant_id) if r.id == rule_id), None)
    if rule is None:
        return []
    return list(
        layout.products_for(
            str(rule.logsource.get("product", "")), str(rule.logsource.get("service", ""))
        )
    )


def score_observability(
    conn: Conn,
    tenant_id: str,
    items: list[BacklogItem],
    config: Any = None,
    delivering: set[str] | None = None,
) -> None:
    """Whether we ingest what an item's rule reads, from the products that delivered."""
    delivering = _delivering(conn, tenant_id) if delivering is None else delivering
    for item in items:
        if item.intake in ("case", "health"):
            item.observability = "have"  # it fired, so we plainly ingest it
            continue
        products = _products_of(config, conn, tenant_id, item.rule_id) if item.rule_id else []
        if not products:
            item.observability = "partial" if delivering else "none"
        else:
            item.observability = "have" if set(products) & delivering else "none"


def _reopen_gaps(conn: Conn, tenant_id: str, delivering: set[str]) -> int:
    """A source gap whose product now delivers is work again."""
    reopened = 0
    for row in fetch_all(
        conn,
        """SELECT item_uid, evidence FROM shoc.detection_backlog
           WHERE tenant_id = %s AND state = 'rejected' AND intake <> 'rehearsal'
             AND evidence->>'decision' = 'source_gap'""",
        (tenant_id,),
    ):
        waiting = set((row["evidence"] or {}).get("waiting_for") or [])
        if waiting & delivering:
            execute(
                conn,
                """UPDATE shoc.detection_backlog
                      SET state = 'open', decided_at = NULL, decided_by = NULL,
                          observability = 'have', evidence = (evidence - 'later') || %s
                    WHERE tenant_id = %s AND item_uid = %s""",
                (
                    json.dumps(
                        {"reopened": f"{', '.join(sorted(waiting & delivering))} now delivers"}
                    ),
                    tenant_id,
                    row["item_uid"],
                ),
            )
            reopened += 1
    # A person's proposal waits open, as a gap, for the product it named.
    for row in fetch_all(
        conn,
        """SELECT item_uid, evidence FROM shoc.detection_backlog
           WHERE tenant_id = %s AND state = 'open' AND observability = 'none'
             AND evidence ? 'product'""",
        (tenant_id,),
    ):
        if str((row["evidence"] or {}).get("product")) in delivering:
            execute(
                conn,
                """UPDATE shoc.detection_backlog SET observability = 'have'
                    WHERE tenant_id = %s AND item_uid = %s""",
                (tenant_id, row["item_uid"]),
            )
            reopened += 1
    return reopened


def _lapse(conn: Conn, tenant_id: str) -> int:
    """A narrowing past its 90 days lapses; its item reopens with what it hid."""
    rows = fetch_all(
        conn,
        """UPDATE shoc.merged_rules SET state = 'lapsed', reverted_at = now()
           WHERE tenant_id = %s AND state = 'merged' AND lapses_at <= now()
           RETURNING rule_id, item_uid, body""",
        (tenant_id,),
    )
    for row in rows:
        if row["item_uid"]:
            execute(
                conn,
                """UPDATE shoc.detection_backlog
                      SET state = 'open', decided_at = NULL, decided_by = NULL,
                          evidence = evidence || %s
                    WHERE tenant_id = %s AND item_uid = %s""",
                (
                    json.dumps(
                        {
                            "lapsed": {
                                "rule_id": row["rule_id"],
                                "hid": (row["body"] or {}).get("hidden", [])[:50],
                            }
                        }
                    ),
                    tenant_id,
                    row["item_uid"],
                ),
            )
        _digest(
            conn,
            tenant_id,
            f"The narrowing of {row['rule_id']} lapsed after 90 days; "
            "its item is back for another look.",
        )
    return len(rows)


def backlog(
    conn: Conn, tenant_id: str, state: str = "open", limit: int = 100
) -> list[dict[str, Any]]:
    where = ["tenant_id = %(tenant_id)s"]
    params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
    if state:
        where.append("state = %(state)s")
        params["state"] = state
    return fetch_all(
        conn,
        f"SELECT * FROM shoc.detection_backlog WHERE {' AND '.join(where)} "
        "ORDER BY priority, created_at DESC LIMIT %(limit)s",
        params,
    )


def decide_item(
    conn: Conn, tenant_id: str, item_uid: str, state: str, who: str, reason: str = ""
) -> dict[str, Any]:
    """A person reopens, rejects or marks an item done, and says why."""
    if state not in ("rejected", "done", "open"):
        raise ValidationError(f"unknown backlog state '{state}'")
    reason = reason.strip()[:500]
    if state != "open" and not reason:
        raise ValidationError(f"say why it is {state}: the item shows the reason once it is closed")
    note = (
        {"reopened": reason or f"reopened by {who}"}
        if state == "open"
        else {"decision": state, "because": reason}
    )
    # What the crew put off is stale once a person decided.
    row = fetch_one(
        conn,
        """UPDATE shoc.detection_backlog SET state=%s, decided_at=now(), decided_by=%s,
                  evidence = (evidence - 'later') || %s
           WHERE tenant_id=%s AND item_uid=%s RETURNING *""",
        (state, who, json.dumps(note), tenant_id, item_uid),
    )
    if not row:
        raise NotFound(f"no backlog item '{item_uid}'")
    return row


# -- the gate (D48, D77) -------------------------------------------------------
ADS_FIELDS = (
    "goal",
    "categorization",
    "strategy",
    "technical_context",
    "blind_spots",
    "false_positives",
    "validation",
    "priority",
    "response",
)
BACKTEST_DAYS = 7
NARROWING_DAYS = 90
# An excluded value must have been seen on this many distinct days before the
# case, so the exclusion names something routine and not something new.
SEEN_ON_DAYS = 7
RULE_ID = re.compile(r"^[a-z0-9][a-z0-9_]{2,79}$")
WHO = "agent:Detection Engineer"

# What an exclusion may key on: one exact global address, one exact id the
# attacker cannot set, and optionally the operation, service or account.
EXCLUDE_ADDRESS = "src_endpoint.ip"
EXCLUDE_IDS = ("actor.user.uid", "resource.uid", "actor.session.uid")
EXCLUDE_ALSO = ("api.operation", "api.service.name", "cloud.account.uid")
# Actor types that are a person: Google's and Tailscale's USER, CloudTrail's
# IAMUser and Root. An exclusion that hides a person's events needs the
# registry to say that account is automation.
PERSON_TYPES = frozenset({"USER", "IAMUSER", "ROOT", "MEMBER"})

# The shape `merge` takes for a new rule, shown to the model.
EXAMPLE_RULE = {
    "id": "aws_access_key_created",
    "title": "New IAM access key created",
    "description": "A long-lived access key was created.",
    "severity": "high",
    "confidence": 0.6,
    "attack": ["T1098.001"],
    "logsource": {"product": "aws", "service": "cloudtrail"},
    "detection": {
        "selection": {"api.operation": "CreateAccessKey", "status": "Success"},
        "condition": "selection",
        "timeframe": "15m",
    },
    "entity": "actor.user.name",
    "fields": ["actor.user.name", "src_endpoint.ip", "cloud.account.uid"],
}
EXAMPLE_EXCLUDE = [
    {"src_endpoint.ip": "203.0.113.10", "actor.user.uid": "100000000000000000001"},
]


def backtest(store: Any, tenant_id: str, rule: Any, days: int = BACKTEST_DAYS) -> list[Any]:
    """What a rule would have raised over our own history. Writes nothing."""
    from shoc.detect.engine import run_rule

    now = datetime.now(UTC)
    return run_rule(store, tenant_id, rule, now - timedelta(days=days), now)


def volume_ceiling(days: int) -> int:
    """Findings a backtest may produce: under the noisy threshold, pro rata."""
    return max(1, NOISY_FINDINGS_7D * days // 7)


def _scratch(config: Any, tenant_id: str, name: str = "gate") -> Any:
    from shoc.store import open_store

    scratch = open_store(config, f"{tenant_id}_{name}")
    scratch.create_tenant()
    scratch.reset()
    return scratch


def fixtures_fail(
    config: Any,
    tenant_id: str,
    rule: Any,
    fixtures: dict[str, Any],
    kinds: tuple[str, ...] = ("positive", "negative"),
) -> str:
    """Why the rule does not fire on its positive fixture and stay quiet on its
    negative one, or ''. The records load into a scratch tenant of their own and
    are stamped inside the test window, whatever time they carried."""
    from shoc.detect.engine import run_rule
    from shoc.ingest import batch, ocsf
    from shoc.ingest.replay import expand

    source = str(fixtures.get("source") or "")
    if source not in ocsf.available_sources():
        return f"fixtures name source '{source}'; use one of {', '.join(ocsf.available_sources())}"
    mapping = ocsf.load_mapping(source)
    scratch = _scratch(config, tenant_id)
    try:
        for kind, should_fire in (("positive", True), ("negative", False)):
            if kind not in kinds:
                continue
            records = [r for r in fixtures.get(kind) or [] if isinstance(r, dict)]
            if not records:
                return f"there is no {kind} fixture"
            scratch.reset()
            now = datetime.now(UTC)
            rows = [mapping.map_record(r, scratch.tenant_id) for r in expand(records, source, now)]
            for i, row in enumerate(rows):
                row["time"] = (now - timedelta(seconds=5 + i % 120)).isoformat()
            batch.load(scratch, rows)
            fired = bool(
                run_rule(
                    scratch,
                    scratch.tenant_id,
                    rule,
                    now - timedelta(hours=1),
                    now + timedelta(minutes=1),
                )
            )
            if fired != should_fire:
                return f"it {'did not fire on' if should_fire else 'fired on'} its {kind} fixture"
        return ""
    finally:
        with contextlib.suppress(Exception):
            scratch.reset()
        scratch.close()


def merge(
    conn: Conn, store: Any, tenant_id: str, config: Any, spec: dict[str, Any], who: str = WHO
) -> dict[str, Any]:
    """Merge behind the gate, and say exactly why not when it refuses.

    `narrows` + `exclude` narrows a shipped rule; `rule` adds a new one. With
    `dry_run` it runs the whole gate and writes nothing. A new rule needs no
    backlog item on a dry run, nor from a person (`by_hand`): their merge
    records its own item, done (D130).
    """
    uid = str(spec.get("item_uid") or "")
    unasked = not uid and not spec.get("narrows")
    loose = unasked and (bool(spec.get("dry_run")) or bool(spec.get("by_hand")))
    item = {"item_uid": ""} if loose else _item(conn, tenant_id, uid)
    if spec.get("narrows"):
        return _narrow(conn, store, tenant_id, config, spec, item, who)
    return _new_rule(conn, store, tenant_id, config, spec, item, who)


def _item(conn: Conn, tenant_id: str, uid: str) -> dict[str, Any]:
    if not uid:
        raise GateRefused(["name the backlog item this answers (item_uid)"], "item")
    row = fetch_one(
        conn,
        "SELECT * FROM shoc.detection_backlog WHERE tenant_id = %s AND item_uid = %s",
        (tenant_id, uid),
    )
    if not row or row["state"] != "open":
        raise GateRefused([f"'{uid}' is not an open backlog item here"], "item")
    return row


def _narrow(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any,
    spec: dict[str, Any],
    item: dict[str, Any],
    who: str,
) -> dict[str, Any]:
    from shoc.detect import rules as ruleset
    from shoc.detect.compiler import compile_rule

    target = str(spec["narrows"])
    shipped = next((r for r in ruleset.load(config) if r.id == target), None)
    if shipped is None:
        raise GateRefused([f"'{target}' is not a shipped rule; a new id adds a rule"], "item")
    if item["rule_id"] != target:
        raise GateRefused(
            [f"{item['item_uid']} is about '{item['rule_id']}', not '{target}'"], "item"
        )
    exclude = spec.get("exclude")
    alternatives = (
        exclude if isinstance(exclude, list) else [exclude] if isinstance(exclude, dict) else []
    )
    refused = _lint(alternatives)
    case = _closed_case(conn, tenant_id, item)
    refused += case.pop("refused", [])
    if refused:
        raise GateRefused(refused, "lint")
    rule = ruleset.narrow(shipped, alternatives)
    try:
        compile_rule(rule)
    except ConfigError as exc:
        raise GateRefused([f"the exclusion does not compile: {exc}"], "parse") from exc

    hidden = _hidden(store, tenant_id, shipped, alternatives)
    refused += _hidden_lint(conn, store, tenant_id, config, hidden, alternatives, case)
    must_stop = _must_stop(conn, store, tenant_id, item, case, spec)
    must_match = _true_positives(conn, tenant_id, target)
    if not must_stop:
        refused.append(
            "the case's events are no longer in the store, so nothing shows it stops firing"
        )
    if refused:
        raise GateRefused(refused, "backtest")
    still, gone = _replay(conn, store, tenant_id, config, rule, must_stop + must_match)
    if leaked := [u for u in must_stop if u in still]:
        refused.append(f"{len(leaked)} of the case's events still match: {', '.join(leaked[:3])}")
    if lost := [u for u in must_match if u in gone]:
        refused.append(
            f"{len(lost)} event(s) of past true positives would be hidden: {', '.join(lost[:3])}"
        )
    if why := _positive_fixture_fails(config, tenant_id, rule):
        refused.append(why)
    if refused:
        raise GateRefused(refused, "replay")

    checked = {
        "rule_id": target,
        "narrows": True,
        "playbook_id": "",
        "backtest": {"days": 30, "findings": len(hidden)},
        "item_uid": item["item_uid"],
    }
    if spec.get("dry_run"):
        return checked
    body = {
        "narrows": target,
        "exclude": alternatives,
        "hidden": [str(e["event_uid"]) for e in hidden][:200],
    }
    execute(
        conn,
        """INSERT INTO shoc.merged_rules
               (tenant_id, rule_id, body, playbook_id, ads, fixtures, backtest,
                item_uid, reason, merged_by, lapses_at, case_uid)
           VALUES (%s,%s,%s,'',%s,'{}'::jsonb,%s,%s,%s,%s,now() + %s * interval '1 day',%s)
           ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
               body = EXCLUDED.body, playbook_id = '', ads = EXCLUDED.ads,
               fixtures = '{}'::jsonb, backtest = EXCLUDED.backtest,
               item_uid = EXCLUDED.item_uid, reason = EXCLUDED.reason,
               merged_by = EXCLUDED.merged_by, lapses_at = EXCLUDED.lapses_at,
               case_uid = EXCLUDED.case_uid,
               state = 'merged', merged_at = now(), reverted_at = NULL""",
        (
            tenant_id,
            target,
            json.dumps(body, default=str),
            json.dumps({k: str(v) for k, v in (spec.get("ads") or {}).items()}),
            json.dumps(
                {
                    "hidden": len(hidden),
                    "must_stop": len(must_stop),
                    "true_positive_events": len(must_match),
                }
            ),
            item["item_uid"],
            str(spec.get("reason") or "")[:500],
            who,
            NARROWING_DAYS,
            str(item.get("case_uid") or ""),
        ),
    )
    _close(conn, tenant_id, item["item_uid"], "done", {"decision": "merged", "rule_id": target})
    _digest(
        conn,
        tenant_id,
        f"{target} narrowed for {item.get('case_uid') or 'its case'}: "
        f"{len(hidden)} event(s) in 30 days no longer match. It lapses in "
        f"{NARROWING_DAYS} days.",
    )
    return checked


def _lint(alternatives: list[Any]) -> list[str]:
    """What an exclusion may say (D77, Summiting the Pyramid): exact values the
    attacker cannot set, never a pattern, a list, a null or a raw path."""
    from shoc.cases.own import routable

    if not alternatives:
        return ["an exclusion needs at least one alternative"]
    refused: list[str] = []
    for n, alt in enumerate(alternatives, 1):
        if not isinstance(alt, dict) or not alt:
            refused.append(f"alternative {n} is not a map of field to value")
            continue
        for key, value in alt.items():
            name = str(key)
            if "|" in name:
                refused.append(f"alternative {n}: '{name}' uses a modifier; only exact values")
            elif name.startswith(("raw.", "unmapped.")) or re.search(r"\.\d+(\.|$)|\[", name):
                refused.append(f"alternative {n}: '{name}' is a raw or positional path")
            elif name not in (EXCLUDE_ADDRESS, *EXCLUDE_IDS, *EXCLUDE_ALSO):
                refused.append(f"alternative {n}: '{name}' is not a field an exclusion may use")
            if value is None or isinstance(value, (list, dict)) or str(value).strip() == "":
                refused.append(f"alternative {n}: '{name}' must be one exact value")
        address = alt.get(EXCLUDE_ADDRESS)
        if not address or not routable(str(address)):
            refused.append(
                f"alternative {n} must hold one exact internet address ({EXCLUDE_ADDRESS}); "
                "an exclusion without one would hide a stolen copy of the same credential"
            )
        ids = [k for k in EXCLUDE_IDS if k in alt]
        if len(ids) != 1:
            refused.append(f"alternative {n} must hold exactly one of {', '.join(EXCLUDE_IDS)}")
    return refused


def _closed_case(conn: Conn, tenant_id: str, item: dict[str, Any]) -> dict[str, Any]:
    """The case behind an item, which must be closed as the rule's mistake."""
    from shoc.agents import recheck

    case_uid = str(item.get("case_uid") or "")
    if not case_uid:
        return {"refused": ["only an item from a closed case can narrow a rule"]}
    case = fetch_one(
        conn,
        "SELECT * FROM shoc.cases WHERE tenant_id = %s AND case_uid = %s",
        (tenant_id, case_uid),
    )
    if not case:
        return {"refused": [f"{case_uid} no longer exists"]}
    refused = []
    if case["state"] != "closed" or case["verdict"] not in ("false_positive", "benign_expected"):
        refused.append(f"{case_uid} is not closed false_positive or benign_expected")
    if case.get("closed_by") != "human" and not recheck.agreed(conn, tenant_id, case_uid):
        refused.append(
            f"{case_uid} was closed by the crew and the weekly recheck has not agreed with it yet"
        )
    return {**case, "refused": refused}


def _hidden(
    store: Any, tenant_id: str, rule: Any, alternatives: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The last 30 days of events the shipped rule matches and the exclusion would hide."""
    from shoc.detect import rules as ruleset
    from shoc.detect.compiler import EVENTS, compile_rule

    probe = ruleset.narrow(rule, alternatives)
    probe.detection.condition = f"({rule.detection.condition}) and {ruleset.EXCLUSION}"
    compiled = compile_rule(probe)
    now = datetime.now(UTC)
    params = {
        **compiled.params,
        "tenant_id": tenant_id,
        "window_start": now - timedelta(days=30),
        "window_end": now,
    }
    return store.query(
        f"SELECT event_uid, time, actor_user_type, actor_user_name, actor_user_uid, "
        f"src_endpoint_ip, metadata_product FROM {EVENTS} WHERE {compiled.where}",
        params,
        2000,
    ).rows


def _hidden_lint(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any,
    hidden: list[dict[str, Any]],
    alternatives: list[dict[str, Any]],
    case: dict[str, Any],
) -> list[str]:
    """What the hidden events and the excluded values must look like."""
    from shoc.cases import own
    from shoc.cases.policy import Policy
    from shoc.store import ocsf as layout

    refused: list[str] = []
    automation = own.values(conn, tenant_id, "automation")
    for event in hidden:
        if str(event.get("actor_user_type") or "").upper() in PERSON_TYPES and not (
            {
                str(event.get("actor_user_name") or "").lower(),
                str(event.get("actor_user_uid") or "").lower(),
            }
            & automation
        ):
            refused.append(
                f"it would hide {event['event_uid']}, made by a person "
                f"({event.get('actor_user_name')}) the registry does not list as automation"
            )
            break
    trusted = own.values(conn, tenant_id, *own.KINDS)
    with contextlib.suppress(Exception):
        trusted |= {
            str(e).lower() for e in Policy.load(config).guards.get("known_egress", []) or []
        }
    before = case.get("opened_at") or datetime.now(UTC)
    for alt in alternatives:
        for name, value in alt.items():
            if str(value).lower() in trusted:
                continue
            column = layout.column_for(name)
            row = store.query(
                f"SELECT count(DISTINCT CAST(time AS DATE)) AS days FROM {layout.EVENTS_TABLE} "
                f"WHERE tenant_id = :tenant_id AND {column} = :value "
                "AND time < :before AND time > :since",
                {
                    "tenant_id": tenant_id,
                    "value": str(value),
                    "before": before,
                    "since": before - timedelta(days=60),
                },
                1,
            ).rows
            days = int((row[0] if row else {}).get("days") or 0)
            if days < SEEN_ON_DAYS:
                refused.append(
                    f"{name}={value} was seen on {days} day(s) before the case, not "
                    f"{SEEN_ON_DAYS}: only a routine value can be excluded"
                )
    return refused


def _must_stop(
    conn: Conn,
    store: Any,
    tenant_id: str,
    item: dict[str, Any],
    case: dict[str, Any],
    spec: dict[str, Any],
) -> list[str]:
    """The events the narrowing has to stop matching.

    For a false positive, every event of the case's findings first seen before
    it closed. For a benign closure, the events the Detection Engineer names,
    which must recur: three of them, on two days.
    """
    rows = fetch_all(
        conn,
        """SELECT event_uids FROM shoc.findings
           WHERE tenant_id = %s AND case_uid = %s AND rule_id = %s
             AND first_seen <= coalesce(%s, now())""",
        (tenant_id, case.get("case_uid"), item["rule_id"], case.get("closed_at")),
    )
    events = list(dict.fromkeys(u for r in rows for u in (r["event_uids"] or [])))
    if case.get("verdict") != "benign_expected":
        return events
    named = [str(u) for u in (spec.get("hide_events") or []) if str(u) in set(events)]
    if len(named) < 3:
        return []
    from shoc.agents.dossier import _events

    days = {str(e["time"])[:10] for e in _events(store, tenant_id, named)}
    return named if len(days) >= 2 else []


def _true_positives(conn: Conn, tenant_id: str, rule_id: str) -> list[str]:
    """Every event of this rule's findings in cases that were an attack."""
    rows = fetch_all(
        conn,
        """SELECT f.event_uids FROM shoc.findings f JOIN shoc.cases c
             ON c.tenant_id = f.tenant_id AND c.case_uid = f.case_uid
           WHERE f.tenant_id = %s AND f.rule_id = %s AND c.state = 'closed'
             AND (c.verdict = 'malicious'
                  OR (c.verdict = 'suspicious' AND c.closed_by = 'human'))""",
        (tenant_id, rule_id),
    )
    return list(dict.fromkeys(u for r in rows for u in (r["event_uids"] or [])))


def _sources_by_product() -> dict[str, str]:
    from shoc.ingest import ocsf

    out: dict[str, str] = {}
    for source in ocsf.available_sources():
        with contextlib.suppress(Exception):
            product = str(ocsf.load_mapping(source).constants.get("metadata_product") or "")
            out.setdefault(product.lower(), source)
    return out


def _replay(
    conn: Conn, store: Any, tenant_id: str, config: Any, rule: Any, uids: list[str]
) -> tuple[set[str], set[str]]:
    """Which of these stored events the rule matches, remapped through today's mapping.

    The stored raw record is mapped again, so a mapping fixed since the event
    arrived is the one judged, and nothing the author typed is in the test.
    Returns (matched, not matched); events no longer in the store are in neither.
    """
    from shoc.detect.compiler import EVENTS, compile_rule
    from shoc.ingest import batch, ocsf
    from shoc.store import ocsf as layout

    if not uids:
        return set(), set()
    marks = ", ".join(f":u{i}" for i in range(len(uids[:500])))
    params: dict[str, Any] = {f"u{i}": u for i, u in enumerate(uids[:500])}
    params["tenant_id"] = tenant_id
    stored = store.query(
        f"SELECT event_uid, metadata_product, raw FROM {layout.EVENTS_TABLE} "
        f"WHERE tenant_id = :tenant_id AND event_uid IN ({marks})",
        params,
        len(uids) * 2,
    ).rows
    sources = _sources_by_product()
    scratch = _scratch(config, tenant_id)
    try:
        rows: dict[str, dict[str, Any]] = {}
        for event in stored:
            source = sources.get(str(event.get("metadata_product") or "").lower())
            raw = event.get("raw")
            if isinstance(raw, str):
                raw = json.loads(raw)
            if not source or not isinstance(raw, dict):
                continue
            row = ocsf.for_tenant(conn, tenant_id, source).map_record(raw, scratch.tenant_id)
            row["event_uid"] = str(event["event_uid"])
            rows[row["event_uid"]] = row
        if not rows:
            return set(), set()
        batch.load(scratch, list(rows.values()))
        compiled = compile_rule(rule)
        times = [str(r["time"]) for r in rows.values() if r.get("time")]
        start = datetime.fromisoformat(min(times)) - timedelta(seconds=1)
        end = datetime.fromisoformat(max(times)) + timedelta(seconds=1)
        found = {
            str(r["event_uid"])
            for r in scratch.query(
                f"SELECT event_uid FROM {EVENTS} WHERE {compiled.where}",
                {
                    **compiled.params,
                    "tenant_id": scratch.tenant_id,
                    "window_start": start,
                    "window_end": end,
                },
                len(rows) * 2,
            ).rows
        }
        return found, set(rows) - found
    finally:
        with contextlib.suppress(Exception):
            scratch.reset()
        scratch.close()


def _positive_fixture_fails(config: Any, tenant_id: str, rule: Any) -> str:
    """The shipped positive fixture must still fire through the narrowing."""
    from shoc.detect import rules as ruleset

    records = ruleset.fixture(rule.id, "positive")
    source = _fixture_source(rule)
    if not records or not source:
        return ""  # nothing shipped to check against; the replay still ran
    why = fixtures_fail(
        config, tenant_id, rule, {"source": source, "positive": records}, kinds=("positive",)
    )
    return f"the shipped positive fixture of {rule.id}: {why}" if why else ""


# Rules name a vendor; fixtures are raw records for that vendor's mapping.
def _fixture_source(rule: Any) -> str:
    from shoc.ingest import ocsf

    return ocsf.source_for(
        str(rule.logsource.get("product", "")), str(rule.logsource.get("service", ""))
    )


def _new_rule(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any,
    spec: dict[str, Any],
    item: dict[str, Any],
    who: str,
) -> dict[str, Any]:
    from shoc.cases import playbooks
    from shoc.detect import rules as ruleset
    from shoc.detect.compiler import compile_rule

    body = dict(spec.get("rule") or {})
    try:
        rule = ruleset.from_dict(body)
        compile_rule(rule)
    except (ConfigError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise GateRefused.unparsed("the rule", exc) from exc
    if any(r.id == rule.id for r in ruleset.load(config)):
        raise GateRefused(
            [f"'{rule.id}' is shipped; narrow it with `narrows` and `exclude`"], "lint"
        )

    refused: list[str] = []
    product = str(rule.logsource.get("product", "")).lower()
    if not RULE_ID.match(rule.id):
        refused.append("the id must be lower_snake_case, 3 to 80 characters")
    if not (rule.attack and rule.entity and product and rule.description):
        refused.append("a rule needs attack, entity, logsource.product and a description")
    ads = {k: str(v).strip() for k, v in (spec.get("ads") or {}).items() if v is not None}
    playbook_id = str(spec.get("playbook_id") or "")
    book = next((b for b in playbooks.load(config, conn, tenant_id) if b.id == playbook_id), None)
    if book is None:
        refused.append(f"no playbook '{playbook_id}' answers it")
    elif why := book.cannot_act_on(product):
        refused.append(why)
    elif not ads.get("response"):
        # The playbook is the response; the form only says so unless told more (D130).
        ads["response"] = f"{book.title} ({book.id})"
    if missing := [k for k in ADS_FIELDS if not ads.get(k)]:
        refused.append(f"the ADS form is missing {', '.join(missing)}")
    if refused:
        raise GateRefused(refused, "lint")

    fixtures = dict(spec.get("fixtures") or {})
    if why := fixtures_fail(config, tenant_id, rule, fixtures):
        raise GateRefused([why], "fixtures")
    days = min(30, max(1, int(spec.get("backtest_days") or BACKTEST_DAYS)))
    found = backtest(store, tenant_id, rule, days)
    if len(found) >= volume_ceiling(days):
        raise GateRefused(
            [
                f"it would have raised {len(found)} findings in {days} days; "
                f"the ceiling is {volume_ceiling(days) - 1}"
            ],
            "volume",
        )
    checked = {
        "rule_id": rule.id,
        "narrows": False,
        "playbook_id": playbook_id,
        "backtest": {"days": days, "findings": len(found)},
        "item_uid": item["item_uid"],
    }
    if spec.get("dry_run"):
        return checked
    if not item["item_uid"]:
        item = {
            "item_uid": add(
                conn,
                tenant_id,
                BacklogItem(
                    item_uid=item_uid(tenant_id, "human", rule.id),
                    kind="coverage",
                    intake="human",
                    title=rule.title,
                    reason=str(spec.get("reason") or "")[:1000],
                    observability="have",
                    evidence={"by": who, "attack": list(rule.attack)},
                ),
            )
        }
        checked["item_uid"] = item["item_uid"]
    execute(
        conn,
        """INSERT INTO shoc.merged_rules
               (tenant_id, rule_id, body, playbook_id, ads, fixtures, backtest,
                item_uid, reason, merged_by, case_uid)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
               body = EXCLUDED.body, playbook_id = EXCLUDED.playbook_id,
               ads = EXCLUDED.ads, fixtures = EXCLUDED.fixtures,
               backtest = EXCLUDED.backtest, item_uid = EXCLUDED.item_uid,
               reason = EXCLUDED.reason, merged_by = EXCLUDED.merged_by,
               case_uid = EXCLUDED.case_uid, lapses_at = NULL,
               state = 'merged', merged_at = now(), reverted_at = NULL""",
        (
            tenant_id,
            rule.id,
            json.dumps(body, default=str),
            playbook_id,
            json.dumps(ads),
            json.dumps(fixtures, default=str),
            json.dumps({"days": days, "findings": len(found)}),
            item["item_uid"],
            str(spec.get("reason") or "")[:500],
            who,
            str(item.get("case_uid") or ""),
        ),
    )
    _close(conn, tenant_id, item["item_uid"], "done", {"decision": "merged", "rule_id": rule.id})
    _digest(
        conn,
        tenant_id,
        f"New rule {rule.id} merged, answered by {playbook_id}; "
        f"{len(found)} finding(s) in its {days}-day backtest.",
    )
    return checked


def revert(conn: Conn, tenant_id: str, rule_id: str, reason: str, who: str = WHO) -> dict[str, Any]:
    """Take back a merge. Only a merge: a rule a human wrote is not in reach."""
    row = fetch_one(
        conn,
        """UPDATE shoc.merged_rules SET state = 'reverted', reverted_at = now(), reason = %s
           WHERE tenant_id = %s AND rule_id = %s AND state = 'merged'
           RETURNING rule_id, merged_by, item_uid""",
        (f"reverted by {who}: {reason}"[:1000], tenant_id, rule_id),
    )
    if not row:
        raise NotFound(
            f"'{rule_id}' is not a merged rule; a rule shipped in content/ stays a human's to change"
        )
    # The item that merged it says so, and why, rather than offering it again.
    execute(
        conn,
        """UPDATE shoc.detection_backlog SET evidence = evidence || %s
           WHERE tenant_id = %s AND item_uid = %s""",
        (
            json.dumps(
                {
                    "reverted": {
                        "by": who,
                        "because": reason[:500],
                        "at": datetime.now(UTC).isoformat(),
                    }
                }
            ),
            tenant_id,
            row["item_uid"] or "",
        ),
    )
    _digest(conn, tenant_id, f"{rule_id} reverted: {reason}")
    return {"rule_id": rule_id, "state": "reverted"}


def _close(conn: Conn, tenant_id: str, item: str, state: str, note: dict[str, Any]) -> None:
    execute(
        conn,
        """UPDATE shoc.detection_backlog
              SET state = %s, decided_at = now(), decided_by = %s, evidence = evidence || %s
            WHERE tenant_id = %s AND item_uid = %s AND state = 'open'""",
        (state, WHO, json.dumps(note, default=str), tenant_id, item),
    )


def _digest(conn: Conn, tenant_id: str, body: str) -> None:
    """The Manager hears of every merge, revert, lapse and gap, for the weekly."""
    from shoc.agents import manager

    with contextlib.suppress(Exception):
        manager.tell(conn, tenant_id, "Detection Engineer", "digest", body, deliver=False)


# -- the daily turn ----------------------------------------------------------
ITEMS_PER_TURN = 6
STEPS_PER_ITEM = 8
# Its lookups and its merge share one allowance: at the default twelve, an item
# researched with twelve reads never reached detection.merge.
CALLS_PER_ITEM = 24
DAILY_TOKENS = 400_000
STUCK_AFTER = 3


def work(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any = None,
    client: Any = None,
    limit: int = ITEMS_PER_TURN,
) -> dict[str, Any]:
    """End what code can end, then one model turn per item, priority first."""
    from shoc.agents.llm import NoLLM, from_config
    from shoc.config import Config

    cfg = config or Config.load()
    counted: dict[str, int] = {}
    for kind, n in _code_first(conn, tenant_id, cfg).items():
        counted[kind] = counted.get(kind, 0) + n
    client = client if client is not None else from_config(cfg, conn, tenant_id)
    if isinstance(client, NoLLM) or not getattr(client, "available", True):
        return {"worked": 0, "outcomes": counted, "why": "no model is configured"}
    items = fetch_all(
        conn,
        """SELECT item_uid, kind, intake, rule_id, title, reason, priority, evidence, case_uid
           FROM shoc.detection_backlog WHERE tenant_id = %s AND state = 'open'
           ORDER BY priority, evidence->>'worked_at' NULLS FIRST, created_at
           LIMIT %s""",
        (tenant_id, limit),
    )
    if not items:
        return {"worked": 0, "outcomes": counted, "why": "the backlog is empty"}
    spent = _spent_today(conn, tenant_id)
    tokens, reasoning, worked = 0, [], 0
    context = _context(conn, tenant_id, cfg)
    for item in items:
        if spent + tokens >= DAILY_TOKENS:
            reasoning.append(f"stopped at the daily ceiling of {DAILY_TOKENS} tokens")
            break
        outcome, because, used = _work_one(conn, store, tenant_id, cfg, client, item, context)
        tokens += used
        worked += 1
        counted[outcome] = counted.get(outcome, 0) + 1
        reasoning.append(f"{item['item_uid']}: {outcome} — {because}")
    return {
        "worked": worked,
        "outcomes": counted,
        "reasoning": " ".join(reasoning)[:2000],
        "tokens": tokens,
    }


def _spent_today(conn: Conn, tenant_id: str) -> int:
    row = (
        fetch_one(
            conn,
            """SELECT coalesce(sum((evidence->>'tokens_today')::int), 0) AS n
           FROM shoc.detection_backlog
           WHERE tenant_id = %s AND (evidence->>'worked_at')::date = current_date""",
            (tenant_id,),
        )
        or {}
    )
    return int(row.get("n") or 0)


def _code_first(conn: Conn, tenant_id: str, config: Any) -> dict[str, int]:
    """What needs no judgement: noisy new rules, shoc's own activity, stuck items."""
    done: dict[str, int] = {}
    health = {
        h.rule_id: h
        for h in ops.rule_health(conn, tenant_id, NOISY_FINDINGS_7D, SILENT_DAYS, config)
    }
    for row in fetch_all(
        conn,
        "SELECT rule_id, item_uid, body FROM shoc.merged_rules WHERE tenant_id = %s AND state = 'merged'",
        (tenant_id,),
    ):
        h = health.get(str(row["rule_id"]))
        if not (h and h.noisy):
            continue
        if "narrows" in (row["body"] or {}):
            # Reverting a narrowing restores the wider shipped rule, which is
            # louder still: its item reopens instead.
            if row["item_uid"]:
                execute(
                    conn,
                    """UPDATE shoc.detection_backlog SET state = 'open', decided_at = NULL,
                              evidence = evidence || %s
                       WHERE tenant_id = %s AND item_uid = %s""",
                    (
                        json.dumps(
                            {"reopened": f"still noisy after narrowing: {h.findings_7d} in 7 days"}
                        ),
                        tenant_id,
                        row["item_uid"],
                    ),
                )
            continue
        revert(conn, tenant_id, str(row["rule_id"]), f"{h.findings_7d} findings in 7 days")
        done["reverted"] = done.get("reverted", 0) + 1

    for item in fetch_all(
        conn,
        "SELECT item_uid, evidence FROM shoc.detection_backlog WHERE tenant_id = %s AND state = 'open'",
        (tenant_id,),
    ):
        evidence = item["evidence"] or {}
        uids = list(evidence.get("finding_uids") or [])
        if uids:
            statuses = {
                str(r["status"])
                for r in fetch_all(
                    conn,
                    "SELECT status FROM shoc.findings WHERE tenant_id = %s AND finding_uid = ANY(%s)",
                    (tenant_id, uids),
                )
            }
            if statuses == {"self"}:
                _close(
                    conn,
                    tenant_id,
                    item["item_uid"],
                    "rejected",
                    {
                        "decision": "no_rule",
                        "because": "stage 0 owns it: only shoc's own credentials",
                    },
                )
                done["no_rule"] = done.get("no_rule", 0) + 1
                continue
        digest = _evidence_hash(evidence)
        tries = evidence.get("tries") or {}
        if int(tries.get(digest, 0)) >= STUCK_AFTER:
            _close(
                conn,
                tenant_id,
                item["item_uid"],
                "rejected",
                {
                    "decision": "stuck",
                    "because": f"worked {STUCK_AFTER} times on the same evidence",
                },
            )
            _digest(
                conn,
                tenant_id,
                f"Detection item {item['item_uid']} was set aside after "
                f"{STUCK_AFTER} attempts on the same evidence.",
            )
            done["stuck"] = done.get("stuck", 0) + 1
    return done


def _evidence_hash(evidence: dict[str, Any]) -> str:
    kept = {
        k: v
        for k, v in evidence.items()
        if k not in ("worked_at", "tries", "tokens_today", "later")
    }
    return hashlib.sha256(json.dumps(kept, sort_keys=True, default=str).encode()).hexdigest()[:12]


def _context(conn: Conn, tenant_id: str, config: Any) -> str:
    """What every item's turn is told: sources, fixtures, playbooks and its own merges."""
    from shoc.cases import playbooks
    from shoc.ingest import ocsf

    books = [
        {
            "id": b.id,
            "title": b.title,
            "rules": b.rules[:8],
            "benign_when": b.benign_when[:6],
            "actions": [s.action for s in b.steps],
        }
        for b in playbooks.load(config, conn, tenant_id)
    ]
    mine = fetch_all(
        conn,
        "SELECT rule_id, body, merged_at, lapses_at FROM shoc.merged_rules WHERE tenant_id = %s AND state = 'merged'",
        (tenant_id,),
    )
    return "\n".join(
        [
            f"Products delivering here: {', '.join(sorted(_delivering(conn, tenant_id))) or 'none'}.",
            f"Fixture sources (raw records): {', '.join(ocsf.available_sources())}.",
            f"ADS fields a new rule needs: {', '.join(ADS_FIELDS)}.",
            f"A new rule's backtest stays under {NOISY_FINDINGS_7D} findings per 7 days.",
            "",
            "Your merges here:",
            json.dumps(
                [
                    {
                        "rule_id": m["rule_id"],
                        "narrows": "narrows" in (m["body"] or {}),
                        "merged_at": m["merged_at"],
                        "lapses_at": m["lapses_at"],
                    }
                    for m in mine
                ]
                or "none",
                default=str,
            ),
            "",
            "Playbooks, with what each says is benign and the actions it can take:",
            json.dumps(books, default=str),
            "",
            "To narrow a shipped rule, call detection.merge with `narrows` (the rule id), "
            "`exclude` (a list of alternatives) and `item_uid`. An alternative is exactly this "
            "shape, with real values:",
            json.dumps(EXAMPLE_EXCLUDE),
            "To add a new rule, pass `rule` in this shape, with fixtures, ads and playbook_id:",
            json.dumps(EXAMPLE_RULE),
        ]
    )


def _work_one(
    conn: Conn,
    store: Any,
    tenant_id: str,
    config: Any,
    client: Any,
    item: dict[str, Any],
    context: str,
) -> tuple[str, str, int]:
    """One model turn for one item, and what code records about it."""
    from shoc.agents import roles, safety, tools
    from shoc.agents.llm import complete_typed

    uid = str(item["item_uid"])
    prompt = "\n".join(
        [
            "Work this one backlog item to an end: `merged` once detection.merge accepted "
            "the change, `no_rule` when no detection change is worth making, `source_gap` "
            "when we do not ingest the data, `later` only when something you need is "
            "missing today, and say what.",
            "",
            safety.quote("detection_backlog_item", item),
            "",
            context,
        ]
    )
    now = datetime.now(UTC).isoformat()
    evidence = item["evidence"] or {}
    tries = dict(evidence.get("tries") or {})
    digest = _evidence_hash(evidence)
    tries[digest] = int(tries.get(digest, 0)) + 1
    try:
        answer, usage = complete_typed(
            client,
            safety.system_prompt(roles.DETECTION_ENGINEER.prompt),
            prompt,
            roles.DetectionEngineerOutput,
            config.llm_max_tokens,
            tools=tools.specs(roles.DETECTION_ENGINEER.tools, "Detection Engineer"),
            invoke=tools.invoker(
                tenant_id,
                config,
                roles.DETECTION_ENGINEER.tools,
                who="Detection Engineer",
                db=conn,
                store=store,
            ),
            max_steps=STEPS_PER_ITEM,
            max_calls=CALLS_PER_ITEM,
        )
    except Exception as exc:
        with contextlib.suppress(Exception):
            ops.record_failure(
                conn, tenant_id, getattr(client, "model", "none"), f"{type(exc).__name__}: {exc}"
            )
        execute(
            conn,
            "UPDATE shoc.detection_backlog SET evidence = evidence || %s WHERE tenant_id = %s AND item_uid = %s",
            (json.dumps({"worked_at": now, "tries": tries}), tenant_id, uid),
        )
        return "failed", f"{type(exc).__name__}", 0
    ops.charge(conn, tenant_id, usage)
    outcome = next((o for o in answer.outcomes if str(o.item_uid) == uid), None)
    kind = outcome.outcome if outcome else "later"
    because = str(outcome.because if outcome else answer.reasoning)[:500]
    merged = fetch_one(
        conn,
        "SELECT 1 FROM shoc.merged_rules WHERE tenant_id = %s AND item_uid = %s AND state = 'merged'",
        (tenant_id, uid),
    )
    note: dict[str, Any] = {"worked_at": now, "tries": tries, "tokens_today": usage.tokens}
    if kind == "merged" and not merged:
        kind = "later"  # a merge the gate never accepted is not a merge
        because = f"the gate did not accept a merge: {because}"
        # What the gate said, or that it was never asked: the model's own account
        # of a refused merge reads the same either way.
        said = [
            a for n, a in zip(usage.lookups, usage.seen, strict=False) if n == "detection_merge"
        ]
        note["gate"] = said[-1][:800] if said else "detection.merge was never called"
    if kind in ("no_rule", "source_gap"):
        decided: dict[str, Any] = {"decision": kind, "because": because}
        if kind == "source_gap":
            decided["waiting_for"] = _products_of(
                config, conn, tenant_id, str(item["rule_id"])
            ) or [p for p in [str((item["evidence"] or {}).get("product") or "")] if p]
        _close(conn, tenant_id, uid, "rejected", decided)
        if kind == "source_gap":
            execute(
                conn,
                "UPDATE shoc.detection_backlog SET observability = 'none' WHERE tenant_id = %s AND item_uid = %s",
                (tenant_id, uid),
            )
            _digest(
                conn,
                tenant_id,
                f"No detection for {item['title']} until we ingest "
                f"{', '.join(decided['waiting_for']) or 'the data it needs'}.",
            )
    elif kind == "later":
        note["later"] = because
    execute(
        conn,
        "UPDATE shoc.detection_backlog SET evidence = evidence || %s WHERE tenant_id = %s AND item_uid = %s",
        (json.dumps(note, default=str), tenant_id, uid),
    )
    return kind, because, usage.tokens
