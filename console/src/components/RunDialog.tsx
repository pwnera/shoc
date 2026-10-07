/**
 * One playbook run: its playbook, state and steps, each step with its state,
 * attempts, error and times, and a link to the action it ran. Fetched when it
 * opens, never polled (the live stream refreshes it). Resume only for a run
 * waiting on its timer.
 *
 * Capabilities used: playbook.get, playbook.list (the title), playbook.resume.
 */
import { useSearchParams } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { span, stamp } from "@/lib/format";
import { actionLabel, runState, stepState } from "@/lib/labels";
import { usePlaybookRun, usePlaybooks, useResumeRun } from "@/lib/queries";
import { toastError } from "@/lib/toast";
import type { PlaybookRunDetail } from "@/types";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Empty, ErrorNote } from "./ui/misc";
import { Skel } from "./ui/state";
import { Status } from "./ui/status";
import { Steps, type Step } from "./ui/steps";
import { Tip } from "./ui/tip";

/** The run's state says one thing, its steps another: done with a failed step, failed with none. */
function disagrees(run: PlaybookRunDetail): boolean {
  const failed = run.steps.some((s) => stepState(s.state) === "failed");
  return (run.state === "done" && failed) || (run.state === "failed" && !failed && run.steps.length > 0);
}

export function RunDialog({ runUid, onClose }: { runUid: string; onClose: () => void }) {
  const run = usePlaybookRun(runUid);
  const playbooks = usePlaybooks();
  const resume = useResumeRun();
  const [, setParams] = useSearchParams();
  const data = run.data;
  const title = data ? (playbooks.data?.playbooks.find((p) => p.id === data.playbook_id)?.title ?? data.playbook_id) : "Run";

  const steps: Step[] =
    data?.steps.map((s) => {
      const took =
        s.started_at && s.finished_at ? span((Date.parse(s.finished_at) - Date.parse(s.started_at)) / 1000) : null;
      // The action's own words, as the playbook page and the policy dialog say it; the playbook's step name is the tip.
      const label = actionLabel(s.action_type);
      return {
        key: String(s.step_index),
        label,
        state: stepState(s.state),
        value: [s.attempts && s.attempts > 1 ? `×${s.attempts}` : "", took ?? ""].filter(Boolean).join(" · ") || undefined,
        tip:
          [s.name && s.name !== label ? s.name : "", s.started_at ? stamp(s.started_at) : "", s.error ?? ""]
            .filter(Boolean)
            .join(" · ") || undefined,
      };
    }) ?? [];

  const openAction = (uid: string) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.set("action", uid);
      return out;
    });

  const state = data ? runState(data.state, data.dry_run) : null;
  return (
    <Dialog
      title={title}
      id={runUid}
      onClose={onClose}
      head={
        data && state ? (
          <>
            <Status tone={state.tone} badge>
              {state.word}
            </Status>
            {data.dry_run ? <Badge tone="idle">dry run</Badge> : null}
            {disagrees(data) ? (
              <Tip label="The run's state and its steps disagree">
                <AlertTriangle className="h-3.5 w-3.5 text-warn" role="img" aria-label="state and steps disagree" />
              </Tip>
            ) : null}
          </>
        ) : null
      }
      footer={
        data?.state === "waiting_timer" ? (
          <Button
            disabled={resume.isPending}
            onClick={() => resume.mutate(runUid, { onError: (error) => toastError(error, "Resume failed") })}
          >
            Resume
          </Button>
        ) : undefined
      }
    >
      {run.isError ? (
        <ErrorNote error={run.error} onRetry={() => void run.refetch()} />
      ) : !data ? (
        <Skel kind="block" />
      ) : (
        <>
          {data.pending_approval.length ? (
            <Status tone="idle" badge>
              waits on the decision above
            </Status>
          ) : null}
          {steps.length ? (
            <Steps
              steps={steps}
              variant="vertical"
              label="Steps"
              // A step opens the action it ran.
              onPick={(step) => {
                const uid = data.steps.find((s) => String(s.step_index) === step.key)?.action_uid;
                if (uid) openAction(uid);
              }}
            />
          ) : (
            <Empty title="No steps yet" />
          )}
          {data.steps
            .filter((s) => s.error)
            .map((s) => (
              <p key={s.step_index} className="sh-mono m-0 text-bad">
                {actionLabel(s.action_type)}: {s.error}
              </p>
            ))}
        </>
      )}
    </Dialog>
  );
}
