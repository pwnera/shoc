/**
 * Add indicators by hand (`intel.add`): values one per line, typed by the
 * kernel, with a severity, a confidence, a lifetime, why they are bad, and
 * whether to sweep our events for them now. The hook's toast counts what was
 * added and refused; values the kernel refused stay here as chips to fix.
 */
import { useId, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { Chip } from "@/components/ui/filterbar";
import { ErrorNote, Input, Spinner, Switch } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { useAddIndicators } from "@/lib/queries";

const SEVERITY = ["low", "medium", "high", "critical"] as const;

export function AddDialog({ onClose }: { onClose: () => void }) {
  const form = useId();
  const add = useAddIndicators();
  const [values, setValues] = useState("");
  const [severity, setSeverity] = useState<(typeof SEVERITY)[number]>("medium");
  const [confidence, setConfidence] = useState("0.8");
  const [days, setDays] = useState("90");
  const [description, setDescription] = useState("");
  const [retro, setRetro] = useState(true);
  const [refused, setRefused] = useState<string[]>([]);
  const list = values
    .split("\n")
    .map((v) => v.trim())
    .filter(Boolean);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!list.length || add.isPending) return;
    add.mutate(
      {
        values: list,
        severity,
        confidence: Math.max(0, Math.min(1, Number(confidence) || 0)),
        days: Math.max(0, Math.round(Number(days) || 0)),
        ...(description.trim() ? { description: description.trim() } : {}),
        retro_hunt: retro,
      },
      {
        onSuccess: ({ data }) => {
          if (!data.rejected.length) return onClose();
          // Keep only what was refused, to correct and send again.
          setRefused(data.rejected);
          setValues(data.rejected.join("\n"));
        },
      },
    );
  };

  return (
    <Dialog
      title="Add indicators"
      onClose={onClose}
      footer={
        <Button type="submit" form={form} variant="primary" disabled={!list.length || add.isPending}>
          {add.isPending ? <Spinner /> : null}
          Add {list.length > 1 ? list.length : ""}
        </Button>
      }
    >
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Values" hint="one per line">
          <textarea
            className="sh-input sh-input--mono min-h-28 py-1.5"
            value={values}
            onChange={(event) => setValues(event.target.value)}
            data-autofocus
            spellCheck={false}
          />
        </Field>
        {refused.length ? (
          <div className="flex flex-wrap items-center gap-1" role="status">
            <span className="sh-label">refused</span>
            {refused.map((value) => (
              <Chip key={value} value={value} struck />
            ))}
          </div>
        ) : null}
        <Field label="Severity" group>
          <Seg label="Severity" value={severity} onChange={setSeverity} options={SEVERITY} size="md" className="self-start" />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Confidence">
            <Input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={confidence}
              onChange={(event) => setConfidence(event.target.value)}
            />
          </Field>
          <Field label="Expires in days" hint="0 never">
            <Input
              type="number"
              min={0}
              step={1}
              value={days}
              onChange={(event) => setDays(event.target.value)}
            />
          </Field>
        </div>
        <Field label="Why they are bad">
          <Input value={description} onChange={(event) => setDescription(event.target.value)} />
        </Field>
        <Switch checked={retro} onChange={setRetro}>
          Sweep our events now
        </Switch>
        {add.error ? <ErrorNote error={add.error} inline /> : null}
      </form>
    </Dialog>
  );
}
