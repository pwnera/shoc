/**
 * Close the case as a person: what it was (preset from the crew's verdict,
 * never guessed when the crew had none), why, and for Expected and Rule was
 * wrong how long the crew should remember it (the kernel writes a memory for
 * those two only, and reads "none" as 90 days, so there is no "don't
 * remember"). Close confirms first, in a popover on the button; 1–4 pick the
 * disposition, and with no preset the choice holds the focus so they work at
 * once. Under 768px the four choices sit two by two.
 *
 * Capabilities used: case.close (its hook toasts what it rejected and links the memory).
 */
import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Input, Label } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { AutonomyBadge } from "@/components/ui/status";
import { shortId } from "@/lib/format";
import { DISPOSITIONS } from "@/lib/labels";
import { useCloseCase } from "@/lib/queries";
import type { Case, Disposition, Verdict } from "@/types";

const CHOICES = Object.entries(DISPOSITIONS).map(([value, label]) => ({ value: value as Disposition, label }));

/** The crew's verdict as a disposition; nothing when it handed the call to a person. */
const PRESET: Partial<Record<Verdict, Disposition>> = {
  malicious: "malicious",
  suspicious: "suspicious",
  benign: "benign_expected",
  benign_expected: "benign_expected",
  false_positive: "false_positive",
};

const REMEMBER = [
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
  { value: "365", label: "1y" },
];

const remembers = (d: Disposition | "") => d === "benign_expected" || d === "false_positive";

export function CloseDialog({
  record,
  disposition: chosen,
  onClose,
}: {
  record: Case;
  /** Chosen in the decision bar's "Close as". */
  disposition?: Disposition;
  onClose: () => void;
}) {
  const close = useCloseCase();
  const [preset] = useState<Disposition | "">(() => chosen ?? PRESET[record.verdict] ?? "");
  const [disposition, setDisposition] = useState<Disposition | "">(preset);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("90");
  const [asking, setAsking] = useState(false);
  const ready = Boolean(disposition) && Boolean(reason.trim());
  const form = useRef<HTMLFormElement>(null);

  // Runs after the dialog's own focus, so it wins.
  useEffect(() => {
    if (!preset) form.current?.querySelector<HTMLElement>('[role="radio"][tabindex="0"]')?.focus();
  }, [preset]);

  const onKeyDown = (event: KeyboardEvent) => {
    const target = event.target as HTMLElement;
    if (/^(INPUT|TEXTAREA)$/.test(target.tagName) || !/^[1-4]$/.test(event.key)) return;
    const next = CHOICES[Number(event.key) - 1]!.value;
    setDisposition(next);
    setAsking(false);
    // The focus follows the check, so only one choice looks picked.
    form.current?.querySelector<HTMLElement>(`[role="radio"][data-value="${next}"]`)?.focus();
  };

  const footer = (
    <Popover
      open={asking}
      onOpenChange={setAsking}
      label="Close the case"
      align="end"
      trigger={(props) => (
        <Button {...props} variant="primary" disabled={!ready}>
          Close
        </Button>
      )}
    >
      {disposition ? (
        <Confirm
          what={`Close ${shortId(record.case_uid)} as ${DISPOSITIONS[disposition]}`}
          facts={<AutonomyBadge level="L2" />}
          go="Close"
          onConfirm={() =>
            close
              .mutateAsync({
                case_uid: record.case_uid,
                disposition,
                reason: reason.trim(),
                ...(remembers(disposition) ? { remember_days: Number(days) } : {}),
              })
              .then(onClose)
          }
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Popover>
  );

  return (
    <Dialog title="Close the case" id={shortId(record.case_uid)} onClose={onClose} footer={footer}>
      <form
        ref={form}
        className="flex flex-col gap-4"
        onKeyDown={onKeyDown}
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) setAsking(true);
        }}
      >
        <Seg<Disposition | "">
          size="md"
          label="What it was"
          className="max-md:grid max-md:h-auto max-md:grid-cols-2 max-md:[&>*]:h-7 max-md:[&>*]:justify-center"
          value={disposition}
          options={CHOICES}
          onChange={(next) => {
            setDisposition(next);
            setAsking(false);
          }}
        />
        <Field label="Reason">
          <Input value={reason} onChange={(event) => setReason(event.target.value)} data-autofocus={preset ? "" : undefined} />
        </Field>
        {remembers(disposition) ? (
          <div className="flex items-center gap-3">
            <Label>Remember</Label>
            <Seg label="Remember" value={days} options={REMEMBER} onChange={setDays} />
          </div>
        ) : null}
      </form>
    </Dialog>
  );
}
