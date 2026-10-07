/**
 * The case's playbook runs, one compact card each: the playbook, the run's
 * state, dry run, and steps done against the playbook's own count, with a warn
 * glyph when a finished run stopped short. A run waiting on an approval points
 * at its card in the decision bar rather than offering a second Approve. A card
 * opens RunDialog, which fetches the run's steps. Run a playbook (Y) sits under
 * them while the case is open, or in a quiet card when there are none.
 *
 * Capabilities used: playbook.runs, playbook.list (titles and step counts).
 */
import { AlertTriangle, ListPlus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { Status } from "@/components/ui/status";
import { Steps, type Step } from "@/components/ui/steps";
import { Tip } from "@/components/ui/tip";
import { runState } from "@/lib/labels";
import type { Action, Playbook, PlaybookRun } from "@/types";
import { focusDecision } from "./links";
import type { Open } from "./moments";

function RunCard({ run, playbook, waitsOn, open }: { run: PlaybookRun; playbook?: Playbook; waitsOn?: string; open: Open }) {
  const total = playbook?.steps.length ?? 0;
  const state = runState(run.state, run.dry_run);
  const short = total > 0 && (run.state === "done" || run.state === "failed") && run.step_index < total;
  const steps: Step[] = Array.from({ length: Math.max(total, run.step_index) }, (_, i) => ({
    key: String(i),
    label: playbook?.steps[i]?.name ?? String(i + 1),
    state: i < run.step_index ? "done" : "todo",
  }));
  // The title is the card's one button and its hit area covers the card; "waits ↑" and the tip sit above it.
  return (
    <Card className="relative hover:bg-bg-2">
      <div className="flex flex-col gap-2 p-3">
        <span className="flex min-w-0 items-center gap-2">
          <button
            type="button"
            className="min-w-0 truncate text-left font-medium text-fg-1 after:absolute after:inset-0 after:rounded-[var(--radius-2)] after:content-[''] focus-visible:shadow-none focus-visible:after:shadow-[var(--focus-ring)]"
            onClick={() => open.run(run.run_uid)}
          >
            {playbook?.title ?? run.playbook_id}
          </button>
          {short ? (
            <Tip label="Finished short of its steps">
              <AlertTriangle className="relative h-3.5 w-3.5 shrink-0 text-warn" role="img" aria-label="finished short of its steps" />
            </Tip>
          ) : null}
        </span>
        <span className="flex items-center gap-2">
          {run.state === "waiting_approval" ? (
            <button type="button" className="sh-link sh-mono relative text-crew" onClick={() => focusDecision(waitsOn)}>
              waits ↑
            </button>
          ) : (
            <Status tone={state.tone} badge>
              {state.word}
            </Status>
          )}
          {run.dry_run && state.word !== "planned" ? <Badge tone="idle">dry run</Badge> : null}
          <span className="ml-auto">{steps.length ? <Steps steps={steps} variant="progress" label="Steps done" /> : null}</span>
        </span>
      </div>
    </Card>
  );
}

export function Rail({
  runs,
  actions,
  loading,
  error,
  onRetry,
  playbooks,
  closed,
  open,
}: {
  runs: PlaybookRun[];
  /** The case's actions, for the approval a waiting run is held on. */
  actions: Action[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  playbooks: Playbook[];
  closed: boolean;
  open: Open;
}) {
  const run = closed ? null : (
    <Tip label="Run a playbook" kbd="Y">
      <Button onClick={open.playbook} aria-keyshortcuts="Y">
        <ListPlus aria-hidden />
        Run a playbook
      </Button>
    </Tip>
  );
  if (error) return <ErrorNote error={error} onRetry={onRetry} />;
  if (loading)
    return (
      <>
        <Skel kind="block" />
        <Skel kind="block" />
      </>
    );
  // No runs: a quiet card holding Run a playbook; a closed case shows no rail at all (the page drops it).
  if (!runs.length)
    return run ? (
      <Card className="p-3">
        <Empty title="No playbook runs" action={run} />
      </Card>
    ) : null;
  return (
    <>
      {runs.map((r) => (
        <RunCard
          key={r.run_uid}
          run={r}
          playbook={playbooks.find((p) => p.id === r.playbook_id)}
          waitsOn={actions.find((a) => a.state === "proposed" && a.run_uid === r.run_uid)?.action_uid}
          open={open}
        />
      ))}
      {run}
    </>
  );
}
