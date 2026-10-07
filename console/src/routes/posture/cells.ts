/**
 * The arithmetic behind Posture, tested without a DOM: which quadrant of
 * exposed × privileged an entity sits in, the one flag a row still needs to
 * say once a filter is on and the one tone each flag takes wherever it shows,
 * and the entities a source lists that did nothing.
 * Every number comes from the same `surface.list` rows, so the quadrant and the
 * list always agree.
 */
import type { Exposure, SnapshotRow } from "@/types";

/** e = exposed, p = privileged, n = not. */
export type Cell = "ep" | "en" | "np" | "nn";

export const CELLS: { id: Cell; label: string }[] = [
  { id: "ep", label: "exposed · privileged" },
  { id: "en", label: "exposed only" },
  { id: "np", label: "privileged only" },
  { id: "nn", label: "neither" },
];

export const cellOf = (e: Pick<Exposure, "exposed" | "privileged">): Cell =>
  `${e.exposed ? "e" : "n"}${e.privileged ? "p" : "n"}` as Cell;

export type Flag = "both" | "exposed" | "privileged" | "stale";

/**
 * Each flag's word and its one look, in the quadrant, the rows and their
 * badges alike: exposed warns, privileged takes the human outline (a person
 * decides what is privileged), the two together are bad. Stale is idle.
 * `short` is the word a phone row has room for, so the entity keeps the row.
 */
export const FLAGS: Record<Flag, { word: string; short: string; tone?: "warn" | "bad" | "idle"; className?: string }> = {
  both: { word: "exposed · privileged", short: "exp · priv", tone: "bad" },
  exposed: { word: "exposed", short: "exp", tone: "warn" },
  privileged: { word: "privileged", short: "priv", className: "border-[var(--human-line)] text-human" },
  stale: { word: "stale", short: "stale", tone: "idle" },
};

/** The flag a quadrant cell stands for; "neither" has none. */
export const CELL_FLAG: Record<Cell, Flag | null> = { ep: "both", en: "exposed", np: "privileged", nn: null };

/** The first flag the active filter does not already say ("both" when it says neither), or null. */
export function flagOf(e: Exposure, filter: { cell?: string; stale?: string }): Flag | null {
  const said = new Set<Flag>();
  if (filter.cell?.startsWith("e")) said.add("exposed");
  if (filter.cell?.endsWith("p")) said.add("privileged");
  if (filter.stale) said.add("stale");
  const left = (["exposed", "privileged", "stale"] as const).filter((f) => e[f] && !said.has(f));
  if (left[0] === "exposed" && left[1] === "privileged") return "both";
  return left[0] ?? null;
}

/** Exposed and privileged first, then by how much each did. */
export function byRisk(a: Exposure, b: Exposure): number {
  const risk = (e: Exposure) => (e.exposed && e.privileged ? 2 : e.exposed || e.privileged ? 1 : 0);
  return risk(b) - risk(a) || b.events - a.events;
}

/** A snapshot row's entity key: as the source gave it when it is already a key, else `kind:entity`. */
export const snapshotKey = (row: SnapshotRow) => (row.entity.includes(":") ? row.entity : `${row.kind}:${row.entity}`);

/**
 * What a source lists that never acted in the window. Only honest while the
 * seen list is whole: at the cap a seen entity could fall outside it and read
 * as listed only, so the caller shows nothing then.
 */
export function listedOnly(snapshots: SnapshotRow[], seen: Exposure[]): SnapshotRow[] {
  const keys = new Set(seen.map((e) => e.entity));
  return snapshots.filter((row) => !keys.has(snapshotKey(row)));
}
