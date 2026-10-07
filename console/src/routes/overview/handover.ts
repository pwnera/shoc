/**
 * What happened since the viewer left, counted from the lists the console
 * already holds: the case log, the action log and the window's findings. Each
 * counter carries the link that reproduces it; each counted thing gets one
 * time-bar mark that opens it. Pure, so the tests can feed it.
 */
import type { TimeMark } from "@/components/ui/timebar";
import { actionLabel, isPage } from "@/lib/labels";
import type { Action, Case, Finding, Severity } from "@/types";

export type Source = "cases" | "actions" | "findings";

export type Counter = {
  id: "opened" | "closed" | "ran" | "undone" | "expired" | "paged" | "findings";
  source: Source;
  n: number;
  /** The list came back at its cap and may not reach back to `since`: "200+". */
  more: boolean;
  to: string;
  /** Every action it counts was a dry run. */
  dry?: boolean;
  /** Findings by severity, for the stacked meter. */
  mix?: Record<Severity, number>;
};

/** What each counter says after its number. */
export const LABEL: Record<Counter["id"], string> = {
  opened: "opened",
  closed: "closed by crew",
  ran: "done",
  undone: "undone",
  expired: "expired",
  paged: "paged",
  findings: "findings",
};

/** The counters of each source, in the order they show; drawn as "—" when the source failed. */
export const COUNTERS: Record<Source, Counter["id"][]> = {
  cases: ["opened", "closed"],
  actions: ["ran", "undone", "expired", "paged"],
  findings: ["findings"],
};

export type Mark = TimeMark & { to: string };

const t = (value: string | null | undefined) => (value ? Date.parse(value) : NaN);
const after = (value: string | null | undefined, since: number) => t(value) >= since;
const crewClosed = (c: Case) => c.closed_by === "crew" || c.closed_by === "system";
const ranAt = (a: Action) => a.executed_at ?? a.updated_at ?? a.created_at;
const unattended = (a: Action) => a.state === "rejected" && a.approved_by === "unattended";

/** A capped list reaches back to `since` only when its oldest row is older. */
function short(times: (string | null | undefined)[], cap: number, since: number): boolean {
  return times.length >= cap && Math.min(...times.map(t).filter((n) => !Number.isNaN(n))) > since;
}

export function caseCounters(rows: Case[], since: string, cap: number): Counter[] {
  const from = Date.parse(since);
  const more = short(rows.map((c) => c.updated_at), cap, from);
  const q = encodeURIComponent(since);
  return [
    {
      id: "opened",
      source: "cases",
      n: rows.filter((c) => after(c.opened_at, from)).length,
      more,
      to: `/cases?since=${q}`,
    },
    {
      id: "closed",
      source: "cases",
      n: rows.filter((c) => c.state === "closed" && crewClosed(c) && after(c.closed_at, from)).length,
      more,
      to: `/cases?tab=closed&since=${q}&by=crew`,
    },
  ];
}

/** Done without a person's approval, not a page: what the crew ran on its own. */
const ran = (a: Action, from: number) => a.state === "done" && !a.approved_by && !isPage(a) && after(ranAt(a), from);

export function actionCounters(rows: Action[], since: string, cap: number): Counter[] {
  const from = Date.parse(since);
  const more = short(rows.map((a) => a.created_at), cap, from);
  const q = encodeURIComponent(since);
  const done = rows.filter((a) => ran(a, from));
  const count = (test: (a: Action) => boolean) => rows.filter(test).length;
  const undone = rows.filter((a) => a.state === "rolled_back" && !isPage(a) && after(a.updated_at, from));
  return [
    {
      id: "ran",
      source: "actions",
      n: done.length,
      more,
      to: `/response?since=${q}&state=done&by=crew`,
      dry: done.length > 0 && done.every((a) => a.dry_run),
    },
    {
      id: "undone",
      source: "actions",
      n: undone.length,
      more,
      to: `/response?since=${q}&state=rolled_back`,
      dry: undone.length > 0 && undone.every((a) => a.dry_run),
    },
    {
      id: "expired",
      source: "actions",
      n: count((a) => unattended(a) && after(a.updated_at, from)),
      more,
      to: `/response?since=${q}&state=expired`,
    },
    {
      id: "paged",
      source: "actions",
      n: count((a) => isPage(a) && after(a.created_at, from)),
      more,
      to: `/response?tab=pages&since=${q}`,
    },
  ];
}

/** shoc's own credentials at work and findings set aside are not news. */
export const counted = (f: Finding) => f.status !== "self" && f.status !== "suppressed";

export function findingCounter(rows: Finding[], since: string, cap: number): Counter {
  const kept = rows.filter(counted);
  const mix: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of kept) mix[f.severity] = (mix[f.severity] ?? 0) + 1;
  return {
    id: "findings",
    source: "findings",
    n: kept.length,
    more: rows.length >= cap,
    to: `/findings?since=${encodeURIComponent(since)}`,
    mix,
  };
}

/**
 * One mark per counted thing, plus the crew's runs that failed: ▲ opened, ▽
 * closed by the crew, ■ ran (good) or failed (bad), ↺ undone, ■ expired
 * (warn), ⌁ paged, ● a finding. A mark opens its case, the action's dialog when
 * it has no case, or the finding.
 */
export function handoverMarks(input: {
  since: string;
  cases?: Case[];
  actions?: Action[];
  findings?: Finding[];
}): Mark[] {
  const from = Date.parse(input.since);
  const out: Mark[] = [];
  for (const c of input.cases ?? []) {
    const to = `/cases/${c.case_uid}`;
    if (after(c.opened_at, from))
      out.push({ key: `o:${c.case_uid}`, at: c.opened_at, kind: "case", tone: c.severity, label: `Opened: ${c.title}`, to });
    if (c.state === "closed" && crewClosed(c) && after(c.closed_at, from))
      out.push({ key: `c:${c.case_uid}`, at: c.closed_at!, kind: "closed", tone: "neutral", label: `Closed by the crew: ${c.title}`, to });
  }
  for (const a of input.actions ?? []) {
    const to = a.case_uid ? `/cases/${a.case_uid}` : `?action=${a.action_uid}`;
    const what = `${actionLabel(a.type)} · ${a.target}`;
    const mark = (at: string, kind: Mark["kind"], tone: string, verb: string) =>
      out.push({ key: `a:${a.action_uid}`, at, kind, tone, label: `${what} ${verb}`, to });
    if (ran(a, from)) mark(ranAt(a), "action", "good", a.dry_run ? "planned" : "done");
    else if (a.state === "failed" && !isPage(a) && after(ranAt(a), from)) mark(ranAt(a), "action", "bad", "failed");
    else if (a.state === "rolled_back" && !isPage(a) && after(a.updated_at, from)) mark(a.updated_at!, "undone", "idle", a.dry_run ? "plan undone" : "undone");
    else if (unattended(a) && after(a.updated_at, from)) mark(a.updated_at!, "action", "warn", "expired");
    else if (isPage(a) && after(a.created_at, from)) mark(a.created_at, "page", "neutral", "paged");
  }
  for (const f of input.findings ?? [])
    if (counted(f) && after(f.last_seen, from))
      out.push({ key: `f:${f.finding_uid}`, at: f.last_seen, kind: "finding", tone: f.severity, label: f.title, to: `/findings/${f.finding_uid}` });
  return out;
}
