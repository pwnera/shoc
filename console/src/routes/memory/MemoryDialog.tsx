/**
 * One memory: titled by what it is about, drawn as the list row draws it (an
 * entity as its chip, which opens EntityDialog), its words quoted as they were
 * written, less the subject the title names, and attributed to where they came
 * from; a correction's rule (by its title, opening the rule page), the case
 * a note was written from and how it closed, how sure, and when it was added. A correction's title is who the rule fired on: its
 * rule has a field of its own, since a rule's title would crowd the chip out
 * of a one-line heading. No retract or expiry control: the kernel has neither
 * yet.
 */
import { Link } from "react-router-dom";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Quote } from "@/components/ui/field";
import { Meter } from "@/components/ui/meter";
import { who } from "@/lib/crew";
import { percent, shortId, stamp } from "@/lib/format";
import type { Memory } from "@/types";
import { aboutKey, aboutOf, bodyOf, caseOf, ORIGINS, originOf } from "./origin";

/**
 * What a memory is about, never its raw key: an entity as its chip, a
 * correction's rule by its title beside who it fired on, else the subject's
 * own words. `button` lets the chip open EntityDialog.
 */
export function Subject({
  memory,
  ruleTitle,
  button,
  mono,
}: {
  memory: Pick<Memory, "kind" | "subject">;
  ruleTitle: (id: string) => string;
  button?: boolean;
  /** A plain subject (an identifier, "backup") in mono, as a list row sets it. */
  mono?: boolean;
}) {
  const { rule, rest } = aboutOf(memory);
  const key = aboutKey(rule, rest);
  const what = key ? (
    <Entity value={key} button={button} className="align-middle" />
  ) : rest && mono ? (
    <span className="font-mono text-xs">{rest}</span>
  ) : (
    rest || null
  );
  if (!rule) return <>{what}</>;
  return (
    <>
      {ruleTitle(rule)}
      {what ? <> · {what}</> : null}
    </>
  );
}

export function MemoryDialog({
  memory,
  ruleTitle,
  onClose,
  step,
}: {
  memory: Memory;
  ruleTitle: (id: string) => string;
  onClose: () => void;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const origin = ORIGINS[originOf(memory.source)];
  // A note signed by its role ("Surveyor") names that role.
  const signer = who(memory.source);
  const role = signer.kind === "crew" ? signer : null;
  const { rule, rest } = aboutOf(memory);
  const key = aboutKey(rule, rest);
  const from = caseOf(memory);
  const title = !memory.subject ? (
    "memory"
  ) : !rule ? (
    <Subject memory={memory} ruleTitle={ruleTitle} button />
  ) : key ? (
    <Entity value={key} button className="align-middle" />
  ) : (
    rest || ruleTitle(rule)
  );
  return (
    <Dialog
      title={title}
      onClose={onClose}
      step={step}
      head={<Avatar who={origin.who} size={16} />}
    >
      <Quote crew={originOf(memory.source) === "crew"} {...(role ? { by: role } : { label: origin.word })}>
        {bodyOf(memory)}
      </Quote>
      <Fields
        rows={[
          [
            "rule",
            rule ? (
              <Link to={`/detection/rules/${encodeURIComponent(rule)}`} className="sh-link">
                {ruleTitle(rule)}
              </Link>
            ) : null,
          ],
          [
            "case",
            from ? (
              <span className="inline-flex items-center gap-2">
                <Link to={`/cases/${from.uid}`} className="sh-link font-mono">
                  {shortId(from.uid)}
                </Link>
                <Badge>{from.closed}</Badge>
              </span>
            ) : null,
          ],
          [
            "confidence",
            <Meter value={memory.confidence} label="Confidence" format={percent} width={96} valueText={percent(memory.confidence)} />,
          ],
          ["added", <span className="sh-mono">{stamp(memory.created_at)}</span>],
        ]}
      />
    </Dialog>
  );
}
