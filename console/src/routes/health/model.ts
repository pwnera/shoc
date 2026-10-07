/**
 * Health's rows as pure functions of what the kernel returns, so the tests
 * can hold them: the platform problems, failed jobs grouped by class, spend
 * per day, and each crew role's state.
 */
import { ownedByHealth } from "@/lib/alerts";
import { ROLES, who } from "@/lib/crew";
import { jobWord } from "@/lib/labels";
import type { TimeBucket } from "@/components/ui/timebar";
import type { AuditRow, FailedJob, OpsAlert, Role, SpendRow, StreamTail, SystemHealth } from "@/types";

/* -- Problems --------------------------------------------------------------- */

export type Problem = {
  key: string;
  tone: "bad" | "warn";
  component: "worker" | "model" | "spend" | "store";
  subject: string;
  /** The kind behind a worker row's words, for its tip ("hunt.daily"). */
  id?: string;
  word: string;
  /** The tab that owns it; the store's row opens its facts instead. */
  to?: string;
};

const COMPONENT: Record<string, Problem["component"]> = { jobs: "worker", llm: "model", cost: "spend" };
const OWNER: Record<string, string> = { jobs: "/health/jobs", llm: "/health/crew", cost: "/health/spend" };
const WORD: Record<string, string> = {
  "jobs.failed": "failed",
  "llm.failing": "failing",
  "cost.over_budget": "over budget",
  "cost.unpriced": "no price",
};

/** Pure, for the tests: the rows Health owns, worst first. */
export function problemsOf(alerts: OpsAlert[], health: SystemHealth | undefined): Problem[] {
  const rows: Problem[] = [];
  if (health && !health.store.ok)
    rows.push({ key: "store", tone: "bad", component: "store", subject: health.store.dialect, word: "unreachable" });
  for (const name of health?.jobs.overdue_schedules ?? [])
    rows.push({
      key: `overdue:${name}`,
      tone: "bad",
      component: "worker",
      subject: jobWord(name),
      id: name,
      word: "overdue",
      to: "/health/jobs",
    });
  for (const alert of alerts.filter(ownedByHealth)) {
    const prefix = alert.kind.split(".")[0]!;
    rows.push({
      key: `${alert.kind}:${alert.subject}`,
      tone: alert.severity === "high" ? "bad" : "warn",
      component: COMPONENT[prefix] ?? "worker",
      subject: alert.subject,
      word: WORD[alert.kind] ?? alert.kind.split(".").slice(1).join(" ").replace(/_/g, " "),
      to: OWNER[prefix],
    });
  }
  // Keys stay unique when Ops raises the same kind twice on one subject.
  const seen = new Map<string, number>();
  return rows
    .map((row) => {
      const n = seen.get(row.key) ?? 0;
      seen.set(row.key, n + 1);
      return n ? { ...row, key: `${row.key}#${n}` } : row;
    })
    .sort((a, b) => (a.tone === b.tone ? 0 : a.tone === "bad" ? -1 : 1));
}

/* -- Jobs ------------------------------------------------------------------- */

export const WINDOWS = [
  { value: "1", label: "24h" },
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
] as const;
export type Days = (typeof WINDOWS)[number]["value"];

export type JobGroup = {
  key: string;
  kind: string;
  /** The text before the error's first colon ("ConfigError"). */
  cls: string;
  jobs: number;
  last_at: string | null;
  errors: string[];
  /** An overdue schedule rather than failed jobs. */
  overdue?: boolean;
};

const classOf = (error: string | null) => (error ? (error.split(":")[0] ?? error).trim() : "unknown");

/** Pure, for the tests: overdue schedules, then failures grouped by kind and error class, newest first. */
export function groupJobs(failed: FailedJob[], overdue: string[] = []): JobGroup[] {
  const groups = new Map<string, JobGroup>();
  for (const job of failed) {
    const cls = classOf(job.error);
    const key = `${job.kind}|${cls}`;
    const group = groups.get(key) ?? { key, kind: job.kind, cls, jobs: 0, last_at: null, errors: [] };
    group.jobs += job.jobs;
    if (!group.last_at || job.last_at > group.last_at) group.last_at = job.last_at;
    if (job.error && !group.errors.includes(job.error)) group.errors.push(job.error);
    groups.set(key, group);
  }
  const late: JobGroup[] = overdue.map((name) => ({
    key: `overdue|${name}`,
    kind: name,
    cls: "overdue",
    jobs: 0,
    last_at: null,
    errors: [],
    overdue: true,
  }));
  return [...late, ...[...groups.values()].sort((a, b) => (b.last_at ?? "").localeCompare(a.last_at ?? ""))];
}

/* -- Spend ------------------------------------------------------------------ */

const DAY = 86_400_000;
const TONES = ["neutral", "muted", "low"];

/** Pure, for the tests: one bucket per UTC day of the window, parts per model. */
export function spendBuckets(rows: SpendRow[], days: number, now = Date.now(), by: "usd" | "tokens" = "usd"): TimeBucket[] {
  const today = Math.floor(now / DAY) * DAY;
  const models = [...new Set(rows.map((r) => r.model))];
  return Array.from({ length: days }, (_, i) => {
    const from = today - (days - 1 - i) * DAY;
    const day = new Date(from).toISOString().slice(0, 10);
    const of = rows.filter((r) => r.day === day);
    return {
      key: day,
      from: new Date(from).toISOString(),
      to: new Date(from + DAY).toISOString(),
      parts: models.map((model, m) => ({
        label: model,
        tone: TONES[m % TONES.length]!,
        value: of
          .filter((r) => r.model === model)
          .reduce((sum, r) => sum + (by === "usd" ? r.usd : r.tokens_in + r.tokens_out), 0),
      })),
    };
  });
}

/* -- Crew ------------------------------------------------------------------- */

export type CrewEvent = StreamTail["events"][number];
export type RoleState = "working" | "idle" | "down" | "silent" | "errors";

export type RoleRow = {
  role: Role;
  state: RoleState;
  /** The newest message or call in the window; null when neither is there. */
  last: string | null;
  messages: CrewEvent[];
  calls: AuditRow[];
  errors: number;
};


/** Pure, for the tests: each role's state and last act from the window, the calls and presence. */
export function roleRows(
  events: CrewEvent[],
  calls: AuditRow[],
  working: Set<string>,
  modelDown: boolean,
): RoleRow[] {
  const caseTalk = events.length > 0;
  return ROLES.map((role) => {
    const messages = events
      .filter((e) => who(String(e.payload.agent ?? "")).key === role.name)
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    const mine = calls.filter((c) => c.principal_kind === "agent" && who(c.principal_id).key === role.name);
    const errors = mine.filter((c) => c.error).length;
    const last = [messages[0]?.created_at, mine[0]?.ts].filter(Boolean).sort().at(-1) ?? null;
    const state: RoleState =
      modelDown && role.tier !== "code"
        ? "down"
        : working.has(role.name)
          ? "working"
          : errors
            ? "errors"
            : role.inCase && caseTalk && !messages.length
              ? "silent"
              : "idle";
    return { role, state, last, messages, calls: mine, errors };
  });
}
