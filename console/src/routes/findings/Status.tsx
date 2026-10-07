/**
 * A finding's status as a segmented control. New and triage apply at once;
 * closed and "rule was wrong", and any change away from a status the console
 * cannot set back (shoc's own, suppressed), confirm first with an optional
 * note for the audit log. Those two lead the control as its checked segment,
 * which picking again leaves as it is. The toast offers Undo with the same
 * capability.
 */
import { forwardRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Confirm, Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { shortId } from "@/lib/format";
import { findingStatus } from "@/lib/labels";
import { useSetFindingStatus } from "@/lib/queries";
import { toast, toastError } from "@/lib/toast";

const SETTABLE = ["new", "triage", "closed", "false_positive"] as const;
type Settable = (typeof SETTABLE)[number];
const OPTIONS = SETTABLE.map((value) => ({ value, label: findingStatus(value) }));
const settable = (status: string): status is Settable => (SETTABLE as readonly string[]).includes(status);

const VERB: Record<Settable, { what: string; go: string }> = {
  new: { what: "Reopen as new", go: "Reopen" },
  triage: { what: "Move to triage", go: "Move" },
  closed: { what: "Close finding", go: "Close" },
  false_positive: { what: "Rule was wrong", go: "Mark" },
};

export const FindingStatus = forwardRef<HTMLSpanElement, { uid: string; status: string }>(function FindingStatus(
  { uid, status },
  ref,
) {
  const set = useSetFindingStatus();
  const [shown, setShown] = useState<string | null>(null);
  const [asking, setAsking] = useState<Settable | null>(null);
  // The server's value wins once it catches up with the one picked.
  const value = shown && shown !== status ? shown : status;
  if (shown && shown === status) setShown(null);

  const apply = (next: Settable, note = "") => {
    const before = status;
    setShown(next);
    return set.mutateAsync({ finding_uid: uid, status: next, ...(note ? { note } : {}) }).then(
      () =>
        toast({
          tone: "ok",
          subject: { label: shortId(uid), to: `/findings/${uid}`, title: uid },
          text: `Set to ${findingStatus(next)}`,
          ...(settable(before)
            ? {
                action: {
                  label: "Undo",
                  run: () =>
                    set.mutate(
                      { finding_uid: uid, status: before },
                      { onError: (error) => toastError(error, "Undo failed") },
                    ),
                },
              }
            : {}),
        }),
      (error: unknown) => {
        setShown(null);
        throw error;
      },
    );
  };

  const pick = (next: Settable) => {
    if (next === value) return;
    if (next === "closed" || next === "false_positive" || !settable(status)) setAsking(next);
    else apply(next).catch((error: unknown) => toastError(error, "Status not set"));
  };

  return (
    <span ref={ref} className="relative inline-flex items-center gap-2">
      {/* Set aside by intake: the status no segment sets leads the control, checked, so one segment always is.
          Not disabled: a disabled checked segment would leave the group no tab stop. */}
      <Seg<string>
        label="Status"
        value={value}
        options={settable(value) ? OPTIONS : [{ value, label: findingStatus(value) }, ...OPTIONS]}
        onChange={(v) => settable(v) && pick(v)}
      />
      <Popover
        align="end"
        label="Change status"
        open={asking !== null}
        onOpenChange={(open) => !open && setAsking(null)}
        trigger={(props) => <Anchor {...props} />}
      >
        {(close) =>
          asking ? (
            <Confirm
              what={`${VERB[asking].what} · ${shortId(uid)}`}
              facts={
                settable(status) ? null : (
                  <Badge tone="bad">⊘ {findingStatus(status)} can't be set back</Badge>
                )
              }
              go={VERB[asking].go}
              note={{ placeholder: "Note (optional)", label: "Note" }}
              onConfirm={(note) => apply(asking, note).then(close)}
              onCancel={close}
            />
          ) : null
        }
      </Popover>
    </span>
  );
});

/** The popover's anchor: an invisible point under the control's right edge. */
function Anchor(props: Record<string, unknown>) {
  return (
    <button
      {...props}
      type="button"
      tabIndex={-1}
      aria-hidden
      className="pointer-events-none absolute right-0 bottom-0 h-px w-px opacity-0"
    />
  );
}
