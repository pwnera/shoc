/**
 * A case in order, from what the page already holds: `timeline.build` events
 * (a run of uncited events with one operation and actor inside 60 seconds
 * collapses to one row with ×N), extended events, findings at first seen, crew
 * decisions, actions by when they ran, and the case opening and closing. Pages
 * are not moments; they have their own tab. Pure, so the tests feed it.
 */
import { citeIndex, type Cites } from "@/lib/cite";
import { IN_CASE, who } from "@/lib/crew";
import { count, num } from "@/lib/format";
import type { Action, Case, CaseFinding, CaseRecord, Disposition, OpenspaceMessage, TimelineEvent, TimelineResult } from "@/types";

/** What the page's parts open: its dialogs, held once by the page. */
export type Open = {
  /** An event, stepping over `list` (uids) when given. */
  event: (uid: string, list?: string[]) => void;
  /** An action, stepping over `list` (the rows of the list it came from) when given. */
  action: (action: Action, list?: Action[]) => void;
  /** A crew message, stepping over `list` (msg_ids) when given. */
  message: (msgId: number, list?: number[]) => void;
  run: (runUid: string) => void;
  /** The close dialog, with a disposition chosen. */
  close: (disposition?: Disposition) => void;
  /** The propose dialog, prefilled from an expired approval. */
  propose: (again?: Pick<Action, "type" | "params">) => void;
  playbook: () => void;
};

type Base = { key: string; at: string };

export type CaseMoment =
  | (Base & {
      type: "event";
      event: TimelineEvent;
      /** Every uid the row stands for (a collapsed burst holds several). */
      uids: string[];
      count: number;
      /** Seconds from the burst's first event to its last. */
      lasted: number;
    })
  | (Base & { type: "finding"; finding: CaseFinding })
  | (Base & { type: "decision"; message: OpenspaceMessage })
  | (Base & { type: "action"; action: Action })
  | (Base & { type: "case"; what: "opened" | "closed" });

export type MomentFilter = "all" | "events" | "findings" | "crew" | "actions";

const FILTER: Record<MomentFilter, CaseMoment["type"][]> = {
  all: ["event", "finding", "decision", "action", "case"],
  events: ["event"],
  findings: ["finding"],
  crew: ["decision"],
  actions: ["action"],
};

export const showsIn = (m: CaseMoment, filter: MomentFilter) => FILTER[filter].includes(m.type);

const BURST = 60_000;
const op = (e: TimelineEvent) => e.api_operation ?? e.activity_name ?? e.class_name ?? "event";

/** When an action happened: when it ran, else when it was asked for. */
export const actedAt = (a: Action) => a.executed_at ?? a.created_at;

/** Executed containment: done or since undone, never a page. */
const contained = (a: Action) =>
  a.type !== "notify.page" && Boolean(a.executed_at) && (a.state === "done" || a.state === "rolled_back");

/** The first containment that ran, for "to contain" and the response gap. */
export function firstContainment(actions: readonly Action[]): Action | undefined {
  return actions
    .filter(contained)
    .sort((a, b) => Date.parse(a.executed_at!) - Date.parse(b.executed_at!))[0];
}

export function caseMoments(input: {
  record: Case;
  events: readonly TimelineEvent[];
  findings: readonly CaseFinding[];
  openspace: readonly OpenspaceMessage[];
  actions: readonly Action[];
}): CaseMoment[] {
  const { record } = input;
  const out: CaseMoment[] = [{ key: "case:opened", at: record.opened_at, type: "case", what: "opened" }];

  let burst: Extract<CaseMoment, { type: "event" }> | null = null;
  for (const event of input.events) {
    const joins =
      burst &&
      !event.cited &&
      !burst.event.cited &&
      Boolean(event.extended) === Boolean(burst.event.extended) &&
      op(event) === op(burst.event) &&
      event.actor_user_name === burst.event.actor_user_name &&
      Date.parse(event.time) - Date.parse(burst.at) <= BURST;
    if (burst && joins) {
      burst.uids.push(event.event_uid);
      burst.count += 1;
      burst.lasted = (Date.parse(event.time) - Date.parse(burst.at)) / 1000;
      continue;
    }
    burst = { key: `event:${event.event_uid}`, at: event.time, type: "event", event, uids: [event.event_uid], count: 1, lasted: 0 };
    out.push(burst);
  }

  for (const finding of input.findings)
    out.push({ key: `finding:${finding.finding_uid}`, at: finding.first_seen, type: "finding", finding });
  for (const message of input.openspace)
    if (message.kind === "decision")
      out.push({ key: `decision:${message.msg_id}`, at: message.created_at, type: "decision", message });
  for (const action of input.actions)
    if (action.type !== "notify.page")
      out.push({ key: `action:${action.action_uid}`, at: actedAt(action), type: "action", action });
  if (record.closed_at) out.push({ key: "case:closed", at: record.closed_at, type: "case", what: "closed" });

  return out.filter((m) => m.at).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

/** The uids a moment lights when pointed at. */
export function momentUids(m: CaseMoment): string[] {
  if (m.type === "event") return m.uids;
  if (m.type === "finding") return m.finding.event_uids;
  if (m.type === "decision") return m.message.cited_event_uids;
  return [];
}

/**
 * The case's E-numbers: every event `timeline.build` marks cited and every uid
 * the crew cited, E1 the earliest in time.
 */
export function caseCites(events: readonly TimelineEvent[], openspace: readonly OpenspaceMessage[]): Cites {
  const cited = new Set<string>();
  for (const e of events) if (e.cited) cited.add(e.event_uid);
  for (const m of openspace) for (const uid of m.cited_event_uids) cited.add(uid);
  return citeIndex(events, cited);
}

/** The crew message the verdict stands on: the newest decision, else the newest hypothesis. */
export function verdictMessage(openspace: readonly OpenspaceMessage[]): OpenspaceMessage | undefined {
  const newest = (kind: OpenspaceMessage["kind"]) => [...openspace].reverse().find((m) => m.kind === kind);
  return newest("decision") ?? newest("hypothesis");
}

/** What the crew could not see, as typed rows for the gaps chip. */
export function gapsOf(data: CaseRecord, timeline?: TimelineResult): string[] {
  const rows: string[] = [];
  if (timeline) {
    const stored = new Set(timeline.events.map((e) => e.event_uid));
    const cited = new Set(data.openspace.flatMap((m) => m.cited_event_uids));
    const gone = [...cited].filter((uid) => !stored.has(uid)).length;
    if (!timeline.truncated && gone) rows.push(`${count(gone, "cited event")} no longer stored`);
    if (timeline.truncated) rows.push(`first ${num(timeline.limit)} events in the window`);
  }
  if (data.openspace_total > data.openspace.length) rows.push("older messages not shown");
  const spoke = new Set(data.openspace.map((m) => who(m.agent).name));
  const silent = IN_CASE.filter((role) => !spoke.has(role));
  if (silent.length) rows.push(`${silent.join(", ")} never spoke`);
  return rows;
}

