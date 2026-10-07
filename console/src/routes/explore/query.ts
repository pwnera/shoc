/**
 * Explore's state is its URL: `q`, `since`, `until`, `page` and `event`. A run
 * pushes a history entry, so Back steps through queries; paging and the open
 * event replace it. The screen re-reads the URL on every change, so a link to
 * Explore while already on it runs the new query. Time windows are shared with
 * Findings: a relative `since` ("7d", "-7d") or an ISO instant.
 */
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import type { EventGroup } from "@/types";
import type { TimeBucket } from "@/components/ui/timebar";
import { day, time } from "@/lib/format";
import { closeParams, routerHere } from "@/lib/popup";

const UNIT: Record<string, number> = { m: 60_000, h: 3_600_000, d: 86_400_000 };
const RELATIVE = /^-?(\d+)([mhd])$/;

/** A relative window's length in ms, or null for an instant. */
export function relativeMs(since: string): number | null {
  const m = RELATIVE.exec(since.trim());
  return m ? Number(m[1]) * UNIT[m[2]!]! : null;
}

/** The window as the URL keeps it: "7d" for a relative one, the instant otherwise. */
export const tidy = (since: string) => (relativeMs(since) === null ? since : since.replace(/^-/, ""));

/** What the kernel takes: "-7d" or an ISO instant. */
export const kernelSince = (since: string) => (relativeMs(since) === null ? since : `-${tidy(since)}`);

/** The window as instants (ms). */
export function windowOf(since: string, until: string, now = Date.now()): { from: number; to: number } {
  const rel = relativeMs(since);
  const to = until ? Date.parse(until) : now;
  return { from: rel === null ? Date.parse(since) : to - rel, to };
}

/** The seg value a window shows, or "" when it is none of them. */
export const windowValue = (since: string, until: string, windows: readonly string[]) =>
  !until && windows.includes(tidy(since)) ? tidy(since) : "";

/** "13:07", on the 24-hour clock every table and axis uses. */
export const hm = (value: string) => time(value).slice(0, 5);

/** "Fri 2 Oct 10:00 → 14:00", with the end's day when it differs; the start alone without an end. */
export function rangeLabel(from: string, to = ""): string {
  const start = `${day(from)} ${hm(from)}`;
  if (!to) return start;
  return `${start} → ${day(to) === day(from) ? "" : `${day(to)} `}${hm(to)}`;
}

/* -- the URL ---------------------------------------------------------------- */

export const DEFAULT_SINCE = "24h";

export type Query = { q: string; since: string; until: string };

export function useExploreQuery() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const q = params.get("q") ?? "";
  // A window that is neither relative nor an instant (a mangled link) reads as the default.
  const asked = tidy(params.get("since") || DEFAULT_SINCE);
  const since = relativeMs(asked) === null && Number.isNaN(Date.parse(asked)) ? DEFAULT_SINCE : asked;
  const until = Number.isNaN(Date.parse(params.get("until") ?? "")) ? "" : params.get("until")!;
  const page = Math.max(1, Number(params.get("page")) || 1);
  const event = params.get("event") ?? "";

  const edit = (change: (out: URLSearchParams) => void, replace: boolean) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        change(out);
        return out;
      },
      { replace },
    );

  return {
    q,
    since,
    until,
    page,
    event,
    /**
     * A new query: a history step; the page and the open event start over. The
     * same query again replaces the entry, so Back never lands on a twin.
     */
    run: (next: Partial<Query>) => {
      const merged = { q, since, until, ...next };
      const want = {
        q: merged.q.trim(),
        since: merged.since === DEFAULT_SINCE && !merged.until ? "" : tidy(merged.since),
        // A relative window ends now.
        until: relativeMs(merged.since) !== null ? "" : merged.until,
      };
      const same = Object.entries(want).every(([k, v]) => (params.get(k) ?? "") === v);
      edit((out) => {
        for (const [k, v] of Object.entries(want))
          if (v) out.set(k, v);
          else out.delete(k);
        out.delete("page");
        out.delete("event");
      }, same);
    },
    setPage: (n: number) => edit((out) => (n > 1 ? out.set("page", String(n)) : out.delete("page")), true),
    /** Opening adds a history entry, so Back closes the event; stepping replaces it; closing goes back over it. */
    openEvent: (uid: string, page?: number) => {
      if (!uid) return closeParams(["event"], navigate, routerHere(location));
      edit((out) => {
        out.set("event", uid);
        if (page !== undefined) {
          if (page > 1) out.set("page", String(page));
          else out.delete("page");
        }
      }, Boolean(event));
    },
  };
}

/* -- per viewer --------------------------------------------------------------- */

function read<T>(key: string, fallback: T): T {
  try {
    const value = JSON.parse(localStorage.getItem(key) ?? "null") as T | null;
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function write(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* kept for this page */
  }
}

const RECENT = "shoc.explore.recent";
const PINS = "shoc.explore.fields";

/** The last ten queries run, newest first. */
export const recentQueries = (): string[] => read<string[]>(RECENT, []).filter((x) => typeof x === "string");
export const remember = (q: string) => {
  if (q.trim()) write(RECENT, [q.trim(), ...recentQueries().filter((x) => x !== q.trim())].slice(0, 10));
};

export const savedPins = (fallback: string[]): string[] => {
  const saved = read<string[]>(PINS, fallback);
  return Array.isArray(saved) && saved.every((x) => typeof x === "string") ? saved : fallback;
};
export const savePins = (pins: string[]) => write(PINS, pins);

/* -- the histogram ------------------------------------------------------------- */

const STEP: Record<string, number> = { minute: 60_000, hour: 3_600_000, day: 86_400_000 };
const MAX_BUCKETS = 300;

/**
 * One bucket per interval across the window, the empty ones included, each
 * split into failures (bad) and the rest. The store returns only buckets that
 * hold events, so a quiet hour would otherwise be no bar at all.
 */
export function buckets(
  all: EventGroup[],
  failed: EventGroup[],
  interval: string,
  window: { from: number; to: number },
): TimeBucket[] {
  const step = STEP[interval] ?? STEP.hour!;
  const counts = new Map(all.map((g) => [Date.parse(g.key), g.count]));
  const fails = new Map(failed.map((g) => [Date.parse(g.key), g.count]));
  const keys = [...counts.keys()].filter((t) => !Number.isNaN(t));
  // Buckets start on the interval's UTC boundary, as the store truncates them.
  const first = Math.min(Math.floor(window.from / step) * step, ...keys);
  const out: TimeBucket[] = [];
  for (let at = first; at < window.to && out.length < MAX_BUCKETS; at += step) {
    const total = counts.get(at) ?? 0;
    const bad = Math.min(total, fails.get(at) ?? 0);
    out.push({
      key: String(at),
      from: new Date(at).toISOString(),
      to: new Date(at + step).toISOString(),
      parts: [
        { value: bad, tone: "bad", label: "failed" },
        { value: total - bad, tone: "neutral", label: "events" },
      ],
    });
  }
  return out;
}
