/**
 * The arithmetic behind the Hunts screen, kept out of the components so it is
 * tested without a DOM: runs by local day or week and outcome for the strip's
 * bars, and the order the Packs tab lists readiness in.
 */
import type { TimeBucket } from "@/components/ui/timebar";
import { OUTCOMES } from "@/lib/labels";
import type { HuntOutcome, HuntReadiness, HuntRun } from "@/types";
import type { TraceRun } from "./HuntRunDialog";

/** A stored run as the trace draws it. */
export const fromRun = (run: HuntRun): TraceRun => ({ ...run, rows: run.rows_returned });

const pad = (n: number) => String(n).padStart(2, "0");

/** A time's local day, "2026-10-01": the bars and the day filter bucket by the reader's calendar. */
export function dayOf(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** Back to the local Monday on or before a date, in place. */
const toMonday = (d: Date) => d.setDate(d.getDate() - ((d.getDay() + 6) % 7));

/** The local Monday a time's week starts on, "2026-09-28": the 90-day bars and the week filter. */
export function weekOf(iso: string): string {
  const d = new Date(iso);
  toMonday(d);
  return dayOf(d.toISOString());
}

/** A bar is a day up to 30 days and a week past it, so 90 days draws 13 bars wide enough to read and press. */
export const byWeek = (days: number) => days > 30;

/*
 * Bottom to top; status hues only. Clear is the usual outcome, so it fades to the chart's muted ink and
 * only suspicious (warn) and couldn't look (hatched) stand out; explained is hollow, inconclusive dashed.
 */
const ORDER: HuntOutcome[] = ["clear", "explained", "inconclusive", "gap", "suspicious"];
const TONE: Record<HuntOutcome, string> = {
  clear: "muted",
  explained: "good-hollow",
  inconclusive: "idle-dashed",
  gap: "idle-hatched",
  suspicious: "warn",
};

/**
 * One bucket per local day (or Monday-to-Monday week) the window touches,
 * oldest first, its parts the outcomes of that bucket's runs. `hunt.results
 * {days}` reads a rolling days × 24h, so the first bucket holds the window's
 * start and every run in the answer has its bar. A bucket's key is the day it
 * starts, as `dayOf` or `weekOf` names a run's.
 */
export function outcomeBuckets(runs: HuntRun[], days: number, now: number, active = ""): TimeBucket[] {
  const weeks = byWeek(days);
  const keyOf = weeks ? weekOf : dayOf;
  const counts = new Map<string, Partial<Record<HuntOutcome, number>>>();
  for (const run of runs) {
    const key = keyOf(run.ran_at);
    const bucket = counts.get(key) ?? {};
    bucket[run.outcome] = (bucket[run.outcome] ?? 0) + 1;
    counts.set(key, bucket);
  }
  const buckets: TimeBucket[] = [];
  const from = new Date(now - days * 86_400_000);
  from.setHours(0, 0, 0, 0);
  if (weeks) toMonday(from);
  while (from.getTime() <= now) {
    const to = new Date(from);
    to.setDate(from.getDate() + (weeks ? 7 : 1));
    const key = dayOf(from.toISOString());
    const bucket = counts.get(key) ?? {};
    buckets.push({
      key,
      from: from.toISOString(),
      to: to.toISOString(),
      active: key === active,
      parts: ORDER.map((outcome) => ({ value: bucket[outcome] ?? 0, tone: TONE[outcome], label: OUTCOMES[outcome].word })),
    });
    from.setTime(to.getTime());
  }
  return buckets;
}

const RANK: Record<HuntReadiness["state"], number> = { ready: 0, learning: 1, stale: 2, not_applicable: 3 };

/** Ready first, then learning by the day it will be ready, stale, and the packs that cannot run; then by title. */
export function byReadiness(a: HuntReadiness, b: HuntReadiness): number {
  return (
    RANK[a.state] - RANK[b.state] ||
    (a.ready_at ?? "").localeCompare(b.ready_at ?? "") ||
    (a.title ?? a.pack_id).localeCompare(b.title ?? b.pack_id)
  );
}

/** A pack that can run here now or soon: the Packs tab's default view. */
export const applicable = (row: HuntReadiness) => row.state !== "not_applicable";

/** Days until a learning pack's baseline is ready, "27d"; "" when it has no date or the date passed. */
export function readyIn(row: HuntReadiness, now: number): string {
  if (row.state !== "learning" || !row.ready_at) return "";
  const days = Math.ceil((Date.parse(row.ready_at) - now) / 86_400_000);
  return days > 0 ? `${days}d` : "";
}
