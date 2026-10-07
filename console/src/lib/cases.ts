/**
 * The case queue: tabs that do not overlap, the order a list sorts in (or
 * holds), and the since windows other screens link with. Pure, so the tests
 * can feed it.
 */
import { sinceTime } from "./since";
import { severityRank } from "./sort";
import type { Case, CaseState } from "@/types";

export type CaseTab = "investigating" | "contained" | "closed";

/** The Cases screen's tabs, All first: it sorts open work to the top, so nobody lands on closed cases. */
export const TABS = ["all", "investigating", "contained", "closed"] as const;
export type TabId = (typeof TABS)[number];

export function caseTab(state: CaseState): CaseTab {
  if (state === "closed") return "closed";
  if (state === "triage" || state === "analysis") return "investigating";
  return "contained";
}

/** Every case lands in exactly one bucket, so the tab counts add up to the queue. */
export function bucket(rows: Case[]): Record<CaseTab, Case[]> {
  const out: Record<CaseTab, Case[]> = { investigating: [], contained: [], closed: [] };
  for (const row of rows) out[caseTab(row.state)].push(row);
  return out;
}

export const isOpen = (row: Pick<Case, "state">) => row.state !== "closed";

const at = (value: string | null | undefined) => (value ? Date.parse(value) : 0);

/**
 * Open before closed; open cases by severity, then the newest change (or the
 * longest open first with `oldest`); closed cases by when they closed.
 */
export function order(rows: Case[], by: "" | "oldest" = ""): Case[] {
  return [...rows].sort((a, b) => {
    const open = Number(isOpen(b)) - Number(isOpen(a));
    if (open) return open;
    if (!isOpen(a)) return at(b.closed_at ?? b.updated_at) - at(a.closed_at ?? a.updated_at);
    if (by === "oldest") return at(a.opened_at) - at(b.opened_at);
    return severityRank(b.severity) - severityRank(a.severity) || at(b.updated_at) - at(a.updated_at);
  });
}

/**
 * The rows in an order the reader already saw (`held`, by uid): each keeps its
 * place, and a row the order does not name waits outside the list. Null keeps
 * `rows` as they are.
 */
export function hold(rows: Case[], held: string[] | null): Case[] {
  if (!held) return rows;
  const byUid = new Map(rows.map((row) => [row.case_uid, row]));
  return held.flatMap((uid) => byUid.get(uid) ?? []);
}

/** When a case counts for `since`: when it closed on the Closed tab, when it opened anywhere else. */
export function inWindow(row: Case, since: string, tab: TabId, now = Date.now()): boolean {
  const from = sinceTime(since, now);
  const when = tab === "closed" ? row.closed_at : row.opened_at;
  return !Number.isNaN(from) && Boolean(when) && at(when) >= from;
}

/**
 * Who closed it. "crew" also takes shoc's own closes, so Overview's "closed by
 * crew" counter and the list it links to agree.
 */
export function closedBy(row: Case, by: string): boolean {
  if (isOpen(row)) return false;
  return by === "crew" ? row.closed_by === "crew" || row.closed_by === "system" : row.closed_by === by;
}

/** The text filter: title, entity, uid and technique. `needle` is lower case. */
export function matches(row: Case, needle: string): boolean {
  return [row.title, row.entity_key, row.case_uid, ...row.attack].some((v) => v.toLowerCase().includes(needle));
}

/** A hunt-born case's title without its "Hunt:" prefix, which a glyph replaces; null for any other case. */
export function huntTitle(title: string): string | null {
  const m = /^hunt:\s*/i.exec(title);
  return m ? title.slice(m[0].length) : null;
}
