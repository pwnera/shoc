/**
 * Read a report (`intel.digest`): a link, or the text pasted in with a title,
 * and whether to sweep our events for what it publishes. The CTI role reads
 * it; the hook's crew toast says what it stored, and the report opens when it
 * is done. Closing this dialog early lets the reading finish anyway. An unread
 * report opens it with its link filled in.
 */
import { useId, useState, type FormEvent } from "react";
import { Button, CrewMark } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field } from "@/components/ui/field";
import { ErrorNote, Input, Spinner, Switch } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { useDigest } from "@/lib/queries";

export function DigestDialog({
  url: link = "",
  onClose,
  onRead,
}: {
  /** A link to start from. */
  url?: string;
  onClose: () => void;
  onRead: (reportUid: string) => void;
}) {
  const form = useId();
  const digest = useDigest();
  const [mode, setMode] = useState<"link" | "text">("link");
  const [url, setUrl] = useState(link);
  const [text, setText] = useState("");
  const [title, setTitle] = useState("");
  const [retro, setRetro] = useState(true);
  const ready = mode === "link" ? /^https?:\/\/\S+$/.test(url.trim()) : text.trim().length > 0;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!ready || digest.isPending) return;
    digest.mutate(
      mode === "link"
        ? { url: url.trim(), retro_hunt: retro }
        : { text: text.trim(), ...(title.trim() ? { title: title.trim() } : {}), retro_hunt: retro },
      { onSuccess: ({ data }) => onRead(data.report_uid) },
    );
  };

  return (
    <Dialog
      title="Read a report"
      onClose={onClose}
      footer={
        <Button type="submit" form={form} variant="crew" disabled={!ready || digest.isPending}>
          {digest.isPending ? <Spinner /> : <CrewMark />}
          {digest.isPending ? "Reading…" : "Read it"}
        </Button>
      }
    >
      <form id={form} onSubmit={submit} className="flex flex-col gap-3">
        <Seg
          label="From"
          className="self-start"
          value={mode}
          onChange={setMode}
          options={[
            { value: "link", label: "Link" },
            { value: "text", label: "Text" },
          ]}
        />
        {mode === "link" ? (
          <Field label="Link">
            <Input
              mono
              type="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://"
              data-autofocus
            />
          </Field>
        ) : (
          <>
            <Field label="Text">
              <textarea
                className="sh-input min-h-40 py-1.5"
                value={text}
                onChange={(event) => setText(event.target.value)}
                data-autofocus
              />
            </Field>
            <Field label="Title">
              <Input value={title} onChange={(event) => setTitle(event.target.value)} />
            </Field>
          </>
        )}
        <Switch checked={retro} onChange={setRetro}>
          Sweep our events for what it publishes
        </Switch>
        {digest.error ? <ErrorNote error={digest.error} inline /> : null}
      </form>
    </Dialog>
  );
}
