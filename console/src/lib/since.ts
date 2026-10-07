/**
 * "Since you left": when this viewer's current visit began. The shell writes
 * `last` every minute while the tab is visible; a load more than 30 minutes
 * after `last` starts a new visit whose window opens at `last`, and a reload
 * inside a visit keeps its window. No record means the last 24 hours. Kept in
 * this browser only (`shoc.visit`), and nothing breaks without storage.
 *
 * Also the `?since=` a link carries to Cases, Findings or Response, relative
 * ("7d", "-24h", "90m") or an ISO time: its instant, its chip word, and the
 * filter dimension that reads it.
 */
import { useEffect, useSyncExternalStore } from "react";
import { clock, day } from "./format";
import type { Dim } from "./filters";

const KEY = "shoc.visit";
const CHOICE = "shoc.since";
const GAP = 30 * 60_000;
const DAY = 24 * 3_600_000;

export type Visit = { since: number; last: number };
export type SinceChoice = "visit" | "24h" | "7d";

/** The visit a load at `now` belongs to, given what the browser kept. */
export function begin(stored: Partial<Visit> | null, now: number): Visit {
  const last = Number(stored?.last);
  const since = Number(stored?.since);
  if (!Number.isFinite(last) || last <= 0) return { since: now - DAY, last: now };
  if (now - last > GAP) return { since: last, last: now };
  return { since: Number.isFinite(since) && since > 0 ? since : last, last: now };
}

function read<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function write(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* private window: the visit lasts as long as the tab */
  }
}

let visit = begin(read<Visit>(KEY), Date.now());
write(KEY, visit);

let choice: SinceChoice = (() => {
  const stored = read<SinceChoice>(CHOICE);
  return stored === "24h" || stored === "7d" ? stored : "visit";
})();
const listeners = new Set<() => void>();
const listen = (l: () => void) => (listeners.add(l), () => listeners.delete(l));

/** Mounted once by the shell: records that the viewer is still here. */
export function useHeartbeat(): void {
  useEffect(() => {
    const beat = () => {
      if (document.visibilityState !== "visible") return;
      visit = { ...visit, last: Date.now() };
      write(KEY, visit);
    };
    const timer = setInterval(beat, 60_000);
    document.addEventListener("visibilitychange", beat);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", beat);
    };
  }, []);
}

/** The window Overview reports on, as an ISO time, with the viewer's choice of window. */
export function useSince(): {
  since: string;
  /** When this visit began, for "Last visit · Tue 14:02". */
  visit: string;
  choice: SinceChoice;
  setChoice: (next: SinceChoice) => void;
} {
  const current = useSyncExternalStore(listen, () => choice);
  // Rounded to ten minutes, so the window is a stable query key and not a new one per render.
  const now = Math.floor(Date.now() / 600_000) * 600_000;
  const from = current === "24h" ? now - DAY : current === "7d" ? now - 7 * DAY : visit.since;
  return {
    since: new Date(from).toISOString(),
    visit: new Date(visit.since).toISOString(),
    choice: current,
    setChoice: (next) => {
      choice = next;
      write(CHOICE, next);
      for (const l of listeners) l();
    },
  };
}

/* -- a since from a link ------------------------------------------------------ */

const RELATIVE = /^-?(\d+)([mhd])$/;
const UNIT = { m: 60_000, h: 3_600_000, d: DAY } as const;

/** A `since` link value as epoch ms: "7d", "-24h", "90m" before `now`, or an ISO time; NaN when it is neither. */
export function sinceTime(value: string, now = Date.now()): number {
  const m = RELATIVE.exec(value.trim());
  if (m) return now - Number(m[1]) * UNIT[m[2] as keyof typeof UNIT];
  return Date.parse(value);
}

/** The since chip's word: "7d" as given (without a minus), an ISO time as "Tue 14:02". */
export function sinceWord(value: string): string {
  const v = value.trim();
  if (RELATIVE.test(v)) return v.replace(/^-/, "");
  return Number.isNaN(Date.parse(v)) ? v : `${day(v).split(" ")[0]} ${clock(v)}`;
}

/** The `since` filter dimension, for a list that takes it from links only: a chip word, no menu entry. */
export function sinceDim<T>(at: (row: T) => string | null | undefined): Dim<T> {
  return {
    id: "since",
    label: "since",
    word: sinceWord,
    test: (row, value) => {
      const from = sinceTime(value);
      const when = at(row);
      return Number.isNaN(from) || (when ? Date.parse(when) >= from : false);
    },
  };
}
