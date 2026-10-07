/**
 * Steer the crew: a person's message into the case, to the whole crew or one
 * role, behind a button, so no text box sits open on the page. The text stays
 * until the post succeeds; a failure shows here and on the pending row.
 *
 * Capabilities used: openspace.post (kind inject).
 */
import { useState, type KeyboardEvent } from "react";
import { Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { ErrorNote } from "@/components/ui/misc";
import { Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { Tip } from "@/components/ui/tip";
import { useInject } from "@/lib/queries";

const TARGETS = [
  { value: "crew", label: "Crew" },
  { value: "Investigator", label: "Investigator" },
  { value: "IR Commander", label: "IR" },
  { value: "CTI", label: "CTI" },
  { value: "Surveyor", label: "Surveyor" },
];

export type Post = { body: string; to: string; at: string; error?: unknown };

export function SteerPopover({
  caseUid,
  open,
  onOpenChange,
  draft,
  onDraft,
  onPost,
}: {
  caseUid: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  draft: string;
  onDraft: (text: string) => void;
  /** The optimistic row: posted, or failed with its error. */
  onPost: (post: Post) => void;
}) {
  const inject = useInject();
  const [to, setTo] = useState("crew");

  const send = () => {
    const body = draft.trim();
    if (!body || inject.isPending) return;
    const at = new Date().toISOString();
    onPost({ body, to, at });
    inject.mutate(
      { case_uid: caseUid, body, ...(to === "crew" ? {} : { to }) },
      {
        onSuccess: () => {
          onDraft("");
          onOpenChange(false);
        },
        onError: (error) => onPost({ body, to, at, error }),
      },
    );
  };
  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) return;
    event.preventDefault();
    send();
  };

  return (
    <Popover
      pad
      align="end"
      label="Steer the crew"
      open={open}
      onOpenChange={onOpenChange}
      trigger={(props) => (
        <Tip label="Steer the crew" kbd="S">
          <Button {...props} size="sm" aria-keyshortcuts="S">
            <Send aria-hidden />
            Steer
          </Button>
        </Tip>
      )}
    >
      <form
        className="flex w-[320px] max-w-full flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          send();
        }}
      >
        <Seg label="To" value={to} options={TARGETS} onChange={setTo} />
        <Field label="Message">
          <textarea
            autoFocus
            rows={3}
            className="sh-input h-auto py-1.5"
            value={draft}
            onChange={(event) => onDraft(event.target.value)}
            onKeyDown={onKeyDown}
          />
        </Field>
        {inject.error ? <ErrorNote error={inject.error} inline /> : null}
        <Button type="submit" variant="primary" size="sm" className="self-end" disabled={!draft.trim() || inject.isPending}>
          Send
        </Button>
      </form>
    </Popover>
  );
}
