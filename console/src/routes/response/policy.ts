/**
 * What Response and the playbook page share beyond `lib/policy.ts`: the
 * newest run of each playbook, and the action log split into Activity and
 * Pages.
 */
import { isPage } from "@/lib/labels";
import type { Action, PlaybookRun } from "@/types";

/** The newest run of each playbook; runs come newest first, but a refetch is not trusted to keep that. */
export function newestRuns(runs: PlaybookRun[]): Map<string, PlaybookRun> {
  const out = new Map<string, PlaybookRun>();
  for (const run of runs) {
    const seen = out.get(run.playbook_id);
    if (!seen || run.started_at > seen.started_at) out.set(run.playbook_id, run);
  }
  return out;
}

/* -- the action log, split ---------------------------------------------------- */

/** Activity: what ran or was tried. Proposals are decisions (the Overview inbox); pages have their own tab. */
export const isActivity = (a: Action) => !isPage(a) && a.state !== "proposed";

/**
 * The Activity segments, partitioning by state, and a rejection by who let it
 * lapse: Expired when nobody answered in time (the rows' own word), Rejected
 * when someone said no. The ids are the `?state=` values links send.
 */
export const SEGMENTS = [
  { id: "running", label: "Running", test: (a: Action) => a.state === "approved" || a.state === "running" },
  { id: "done", label: "Done", test: (a: Action) => a.state === "done" },
  { id: "rolled_back", label: "Undone", test: (a: Action) => a.state === "rolled_back" },
  { id: "rejected", label: "Rejected", test: (a: Action) => a.state === "rejected" && a.approved_by !== "unattended" },
  { id: "expired", label: "Expired", test: (a: Action) => a.state === "rejected" && a.approved_by === "unattended" },
  { id: "failed", label: "Failed", test: (a: Action) => a.state === "failed" || a.state === "blocked" },
] as const;

export type Segment = "all" | (typeof SEGMENTS)[number]["id"];

/** Who let an action through: the crew alone or a person; nobody in time is Expired's, so neither. */
export function deciderOf(a: Action): "crew" | "human" | null {
  if (a.approved_by === "unattended") return null;
  if (a.approved_by?.startsWith("human:")) return "human";
  return "crew";
}

/** The time a row of the feed sits at: when it last changed. */
export const changedAt = (a: Action) => a.updated_at ?? a.created_at;
