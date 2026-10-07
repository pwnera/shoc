/**
 * Pointing and brushing on one case page. Pointing at an E-chip, a timeline
 * row, a time-bar mark or a graph node lights the same event uids in all four;
 * a brushed range on the time bar hides timeline rows outside it and dims the
 * graph. A tiny store, so the four hosts never pass props through each other.
 */
import { useSyncExternalStore } from "react";
import type { TimeRange } from "@/components/ui/timebar";

export type Brush = {
  /** The event uids pointed at; empty when nothing is. */
  point: readonly string[];
  /** The brushed range in ms, or null; the time bar draws it from here. */
  range: { from: number; to: number } | null;
};

const NONE: readonly string[] = [];
let state: Brush = { point: NONE, range: null };
const listeners = new Set<() => void>();

function set(next: Partial<Brush>) {
  state = { ...state, ...next };
  for (const l of listeners) l();
}

/** Light these uids, or clear with null. */
export function point(uids: readonly string[] | null) {
  if (!uids?.length && !state.point.length) return;
  set({ point: uids?.length ? uids : NONE });
}

export function brush(range: TimeRange | null) {
  set({ range: range ? { from: Date.parse(range.from), to: Date.parse(range.to) } : null });
}

/** Clear the range from outside the time bar: Escape, the timeline's range chip. */
export function clearRange() {
  set({ range: null });
}

/** A new case starts unbrushed. */
export function resetBrush() {
  set({ point: NONE, range: null });
}

export function useBrush(): Brush {
  return useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => state,
  );
}

/** Whether a time falls inside the brushed range (always, when nothing is brushed). */
export function within(b: Brush, at: string): boolean {
  if (!b.range) return true;
  const t = Date.parse(at);
  return t >= b.range.from && t <= b.range.to;
}

/** Whether any of these uids is pointed at. */
export function lit(b: Brush, uids: readonly string[]): boolean {
  return b.point.length > 0 && uids.some((uid) => b.point.includes(uid));
}
