/**
 * The decisions only a person can make, merged from the lists that hold them,
 * and the two shell signals that mirror a home: the crew is down, a critical
 * case is open. The rail count, the title, the favicon, the mobile tab and the
 * Overview heading all read these selectors, so they always agree.
 *
 * Capabilities used (through `lib/queries.ts`): action.list, case.list,
 * source.list, ops.alerts, health.status; presence (`lib/presence.ts`) adds a
 * model failure the live stream saw before the alerts did.
 */
import { usePresence } from "./presence";
import { useAlerts, useActionLog, useCaseLog, useHealth, useProposals, useSourceList } from "./reads";
import type { Action, Case, ConfiguredSource, NeedsItem, Onboarding, OpsAlert, Severity } from "@/types";

/** A source credential the provider refused, by the kernel's own test of the error text. */
const REJECTED = /rejected the credential/i;

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 3, low: 4, informational: 5 };
/** Source rows rank after high; a row whose case is unknown ranks with medium. */
const rank = (item: NeedsItem) =>
  item.severity ? RANK[item.severity] : item.kind === "credential" || item.kind === "rejected_credential" ? 2 : 3;

const open = (c: Case | undefined) => Boolean(c && c.state !== "closed");

/** The inbox, from whatever lists answered. Pure, so the tests can feed it. */
export function inbox(input: {
  proposals?: Action[];
  actions?: Action[];
  cases?: Case[];
  configured?: ConfiguredSource[];
  onboarding?: Onboarding[];
}): NeedsItem[] {
  const cases = new Map((input.cases ?? []).map((c) => [c.case_uid, c]));
  const items: NeedsItem[] = [];

  for (const action of input.proposals ?? []) {
    if (action.state !== "proposed") continue;
    const owner = action.case_uid ? cases.get(action.case_uid) : undefined;
    items.push({
      kind: "approval",
      key: action.action_uid,
      severity: owner?.severity ?? null,
      action,
      ...(owner ? { case: owner } : {}),
      at: action.decide_by ?? null,
      to: `?decide=${action.action_uid}`,
    });
  }

  for (const c of cases.values())
    if (open(c) && c.verdict === "needs_human")
      items.push({
        kind: "verdict",
        key: c.case_uid,
        severity: c.severity,
        case: c,
        at: c.worked_at ?? c.opened_at,
        to: `/cases/${c.case_uid}`,
      });

  // An approval nobody decided in time, on a case still open, with nothing newer of its kind.
  const all = [...(input.actions ?? []), ...(input.proposals ?? [])];
  const expired = new Map<string, Action>();
  for (const action of input.actions ?? []) {
    if (action.state !== "rejected" || action.approved_by !== "unattended") continue;
    if (action.type === "notify.page" || !action.case_uid) continue;
    const owner = cases.get(action.case_uid);
    if (!open(owner)) continue;
    const when = action.updated_at ?? action.created_at;
    const newer = all.some(
      (other) =>
        other.action_uid !== action.action_uid &&
        other.case_uid === action.case_uid &&
        other.type === action.type &&
        other.created_at > action.created_at &&
        !(other.state === "rejected" && other.approved_by === "unattended"),
    );
    if (newer) continue;
    const key = `${action.case_uid}|${action.type}`;
    const seen = expired.get(key);
    if (!seen || (seen.updated_at ?? seen.created_at) < when) expired.set(key, action);
  }
  for (const action of expired.values()) {
    const owner = cases.get(action.case_uid!)!;
    items.push({
      kind: "expired",
      key: action.action_uid,
      severity: owner.severity,
      action,
      case: owner,
      at: action.updated_at ?? action.created_at,
      to: `/cases/${owner.case_uid}`,
    });
  }

  for (const row of input.onboarding ?? [])
    if (row.step === "credentials")
      items.push({
        kind: "credential",
        key: `credential:${row.source}`,
        severity: null,
        source: row.source,
        at: row.updated_at ?? null,
        to: `/connections?source=${encodeURIComponent(row.source)}&view=settings`,
      });

  for (const row of input.configured ?? [])
    if (row.last_error && REJECTED.test(row.last_error))
      items.push({
        kind: "rejected_credential",
        key: `rejected:${row.source}`,
        severity: null,
        source: row.source,
        at: row.last_run_at,
        to: `/connections?source=${encodeURIComponent(row.source)}&view=settings`,
      });

  const deadline = (i: NeedsItem) => (i.kind === "approval" && i.at ? Date.parse(i.at) : Infinity);
  const age = (i: NeedsItem) => (i.kind !== "approval" && i.at ? Date.parse(i.at) : Infinity);
  return items.sort((a, b) => rank(a) - rank(b) || deadline(a) - deadline(b) || age(a) - age(b));
}

export type Needs = {
  items: NeedsItem[];
  count: number;
  /** A list the inbox reads has not answered yet. */
  pending: boolean;
  /** The lists that failed: approvals, actions, cases, sources. Never read an empty inbox into these. */
  failed: string[];
  /** The newest approval by a person, for "last decision 3h ago". */
  lastDecision: string | null;
  retry: () => void;
};

export function useNeedsYou(): Needs {
  const proposals = useProposals();
  const actions = useActionLog();
  const cases = useCaseLog();
  const sources = useSourceList();
  const named = [
    ["approvals", proposals],
    ["actions", actions],
    ["cases", cases],
    ["sources", sources],
  ] as const;
  const items = inbox({
    proposals: proposals.data?.rows,
    actions: actions.data?.rows,
    cases: cases.data?.rows,
    configured: sources.data?.configured,
    onboarding: sources.data?.onboarding,
  });
  let lastDecision: string | null = null;
  for (const a of actions.data?.rows ?? [])
    if (a.approved_by?.startsWith("human:") && a.approved_at && (!lastDecision || a.approved_at > lastDecision))
      lastDecision = a.approved_at;
  // A list fails only when it has nothing to show; a refresh that failed keeps its rows.
  const failed = named.filter(([, q]) => q.isError && !q.data).map(([name]) => name);
  const pending = named.some(([, q]) => q.isPending);
  return {
    items,
    // Counted once every list is in, so the rail, the tab title and the icon never show part of the inbox.
    count: pending || failed.length ? 0 : items.length,
    pending,
    failed,
    lastDecision,
    retry: () => {
      for (const [, q] of named) if (q.isError) void q.refetch();
    },
  };
}

export type CrewDown = {
  down: boolean;
  /** "model" when the crew cannot reach its model, "worker" when schedules run late. */
  cause: "model" | "worker" | null;
  /** The schedules more than an hour late. */
  overdue: string[];
  /** Not down, but the alerts or health have not answered yet, or failed: never "idle". */
  pending?: boolean;
  failed?: boolean;
};

/**
 * Pure, for the tests. The model failing wins: it is the cause a person can fix
 * first. `modelFailing` is a `health.llm.failing` the live stream saw.
 */
export function crewDown(alerts: OpsAlert[] | undefined, overdue: string[] | undefined, modelFailing = false): CrewDown {
  const late = overdue ?? [];
  if (modelFailing || alerts?.some((a) => a.kind === "llm.failing")) return { down: true, cause: "model", overdue: late };
  if (late.length) return { down: true, cause: "worker", overdue: late };
  return { down: false, cause: null, overdue: [] };
}

/** The one selector the crew pulse, the rail's Health dot and the banner read. */
export function useCrewDown(): CrewDown {
  const alerts = useAlerts();
  const health = useHealth();
  const presence = usePresence();
  const crew = crewDown(alerts.data?.alerts, health.data?.jobs.overdue_schedules, presence.down);
  if (crew.down) return crew;
  return { ...crew, pending: alerts.isPending || health.isPending, failed: alerts.isError || health.isError };
}

/** An open case is critical: the rail's Cases dot and the favicon's red corner. */
export function useCriticalOpen(): boolean {
  const cases = useCaseLog();
  return (cases.data?.rows ?? []).some((c) => c.state !== "closed" && c.severity === "critical");
}
