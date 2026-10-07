"""What a backlog item means here (DET-7, DET-8, D133).

A coverage gap or a hunt hypothesis names ATT&CK techniques, and an id says
nothing to the person deciding it. This joins each item to what this
deployment holds about its techniques, read once per backlog page and never
stored:

- what each report read in the last 90 days said the attacker did with them;
- the kinds of logs that would show them (CTI names them from `LOG_KINDS`),
  the sources whose events take those OCSF classes, and which we receive;
- the rules and hunt packs on the same techniques, or on a sibling when they
  read a product we receive;
- the cases of the last 90 days that named them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shoc.db.pool import Conn, fetch_all

# A kind of log CTI may name, its words on screen, and the OCSF classes that carry it.
LOG_KINDS: dict[str, tuple[str, tuple[int, ...]]] = {
    "process": ("process starts", (1007,)),
    "file": ("file changes", (1001,)),
    "registry": ("registry changes", (201001, 201002)),
    "scheduled_task": ("scheduled tasks", (1006,)),
    "network": ("network connections", (4001,)),
    "dns": ("DNS lookups", (4003,)),
    "web": ("web requests", (4002,)),
    "email": ("email", (4009, 4011, 4012)),
    "sign_in": ("sign-ins", (3002,)),
    "account_change": ("account and group changes", (3001, 3004, 3005, 3006)),
    "admin_api": ("admin and API actions", (6003,)),
    "documents": ("document access", (6001,)),
}
DAYS = 90
SHOWN = 8


def kinds(values: Any) -> list[str]:
    """The log kinds named in `values` that this module knows, once each, in order."""
    out: list[str] = []
    for value in values or []:
        kind = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        if kind in LOG_KINDS and kind not in out:
            out.append(kind)
    return out


def family(technique: str) -> str:
    """T1003.001 and T1003 are one family: a rule on a sibling is near the gap."""
    return str(technique).upper().split(".", 1)[0]


@dataclass
class Near:
    """A rule or a pack: its techniques, and the products whose events it reads."""

    id: str
    title: str
    techniques: set[str]
    products: set[str]


@dataclass
class Here:
    """What every item on a page is compared with."""

    receiving: set[str]
    # kind -> the (source, product) pairs whose events can carry it
    carriers: dict[str, list[tuple[str, str]]]
    rules: list[Near]
    packs: list[Near]
    reports: list[dict[str, Any]]
    cases: list[dict[str, Any]]


def _near(item: Any) -> Near:
    from shoc.store import ocsf as layout

    source = item.logsource
    return Near(
        item.id,
        item.title,
        {str(t).upper() for t in item.attack or []},
        set(layout.products_for(source.get("product", ""), source.get("service", ""))),
    )


def here(conn: Conn, tenant_id: str, config: Any = None) -> Here:
    from shoc.agents.detection_engineer import _delivering
    from shoc.detect import hunts, rules
    from shoc.ingest import ocsf

    taken = ocsf.classes()
    return Here(
        receiving=_delivering(conn, tenant_id),
        carriers={
            kind: sorted(
                (source, product)
                for source, (product, classes) in taken.items()
                if classes & set(carry)
            )
            for kind, (_, carry) in LOG_KINDS.items()
        },
        rules=[_near(r) for r in rules.load(config, conn, tenant_id)],
        packs=[_near(p) for p in hunts.load(config, conn, tenant_id)],
        reports=fetch_all(
            conn,
            """SELECT report_uid, title, relevance, techniques, procedures FROM shoc.intel_reports
               WHERE tenant_id = %s AND digested_at > now() - %s * interval '1 day'
               ORDER BY digested_at DESC""",
            (tenant_id, DAYS),
        ),
        cases=fetch_all(
            conn,
            """SELECT case_uid, title, attack FROM shoc.cases
               WHERE tenant_id = %s AND opened_at > now() - %s * interval '1 day'
                 AND attack <> '{}'
               ORDER BY opened_at DESC""",
            (tenant_id, DAYS),
        ),
    )


def about(
    h: Here,
    techniques: list[str],
    seen_in: list[str] | None = None,
    report_uid: str = "",
    every_report: bool = True,
) -> dict[str, Any]:
    """One item's context. `seen_in` is what the item itself says would show it;
    without it, what the reports said about its techniques. The report that
    raised it comes first, and alone unless `every_report`."""
    codes = list(dict.fromkeys(str(t).upper() for t in techniques if t))
    families = {family(c) for c in codes}
    names: dict[str, str] = {}
    said_in: list[str] = kinds(seen_in)
    reports: list[dict[str, Any]] = []
    for row in sorted(h.reports, key=lambda r: r["report_uid"] != report_uid):
        named = {str(t).upper() for t in row["techniques"] or []} & set(codes)
        if not named or not (every_report or row["report_uid"] == report_uid):
            continue
        said = []
        for entry in row["procedures"] or []:
            code = str(entry.get("id", "")).upper()
            if code not in named:
                continue
            names.setdefault(code, str(entry.get("name") or ""))
            if seen_in is None:
                said_in += [k for k in kinds(entry.get("seen_in")) if k not in said_in]
            if entry.get("evidence"):
                said.append({"technique": code, "procedure": str(entry["evidence"])})
        reports.append(
            {
                "report_uid": row["report_uid"],
                "title": row["title"],
                "relevance": row["relevance"],
                "said": said,
            }
        )

    def near(rows: list[Near]) -> list[dict[str, Any]]:
        """On the same technique, then on a sibling when it reads a product we
        receive; what reads one comes first."""
        hits = [
            n
            for n in rows
            if n.techniques & set(codes)
            or ({family(t) for t in n.techniques} & families and n.products & h.receiving)
        ]
        hits.sort(key=lambda n: (not n.techniques & set(codes), not n.products & h.receiving, n.id))
        return [
            {"id": n.id, "title": n.title, "live": bool(n.products & h.receiving)}
            for n in hits[:SHOWN]
        ]

    return {
        "techniques": [{"id": c, "name": names.get(c, "")} for c in codes],
        "reports": reports[:SHOWN],
        "seen_in": [
            {
                "kind": kind,
                "label": LOG_KINDS[kind][0],
                "products": [{"source": s, "product": p} for s, p in h.carriers[kind]],
                "received": [p for _, p in h.carriers[kind] if p in h.receiving],
            }
            for kind in said_in
        ],
        "rules": near(h.rules),
        "packs": near(h.packs),
        "cases": [
            {"case_uid": c["case_uid"], "title": c["title"]}
            for c in h.cases
            if {family(t) for t in c["attack"] or []} & families
        ][:SHOWN],
    }
