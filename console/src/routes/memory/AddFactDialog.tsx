/**
 * Tell the crew a fact (`memory.add_fact`, kind semantic): what is true, what
 * it is about, and how long it holds (90 days by default, so a person's word
 * does not silence the crew forever by accident). ⌘↵ saves.
 */
import { useId, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { ErrorNote, Input, Spinner } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { useAddFact } from "@/lib/queries";

const EXPIRY = { "30d": 30, "90d": 90, "1y": 365, never: 0 } as const;
type Expiry = keyof typeof EXPIRY;

export function AddFactDialog({ onClose, onAdded }: { onClose: () => void; onAdded: (memoryId: string) => void }) {
  const form = useId();
  const add = useAddFact();
  const [body, setBody] = useState("");
  const [subject, setSubject] = useState("");
  const [expiry, setExpiry] = useState<Expiry>("90d");
  const ready = body.trim().length > 0;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!ready || add.isPending) return;
    const days = EXPIRY[expiry];
    add.mutate(
      {
        body: body.trim(),
        subject: subject.trim(),
        kind: "semantic",
        ...(days ? { expires_at: new Date(Date.now() + days * 86_400_000).toISOString() } : {}),
      },
      { onSuccess: ({ data }) => onAdded(data.memory_id) },
    );
  };

  return (
    <Dialog
      title="Add a fact"
      onClose={onClose}
      footer={
        <Button type="submit" form={form} variant="primary" disabled={!ready || add.isPending}>
          {add.isPending ? <Spinner /> : null}
          Add fact
        </Button>
      }
    >
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Fact">
          <textarea
            className="sh-input min-h-24 py-1.5"
            value={body}
            onChange={(event) => setBody(event.target.value)}
            data-autofocus
          />
        </Field>
        <Field label="About">
          <Input
            mono
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            spellCheck={false}
          />
        </Field>
        <Field label="Expires" group>
          <Seg
            label="Expires"
            className="self-start"
            size="md"
            value={expiry}
            onChange={setExpiry}
            options={(Object.keys(EXPIRY) as Expiry[]).map((value) => ({ value, label: value === "never" ? "never" : value }))}
          />
        </Field>
        {add.error ? <ErrorNote error={add.error} inline /> : null}
      </form>
    </Dialog>
  );
}
