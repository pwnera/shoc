/**
 * One suppression: the reason in its author's words, the entity it spares (or
 * the whole rule), the case that justified it, and how much of its life has
 * run. The title is the rule (or hunt pack) it mutes, as a link. A case closed
 * as expected activity writes its own reason ("CASE-… closed as expected
 * activity"); that is the case row and its disposition, never a quote.
 * Nothing lifts a suppression early yet (no capability), so there is no
 * control here.
 */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Copy, Quote } from "@/components/ui/field";
import { shortId, stamp } from "@/lib/format";
import { closedWord } from "@/lib/labels";
import type { Suppression } from "@/types";
import { Left, RuleLink } from "./parts";
import { useKeepFocus } from "./stepper";

/** The reason `case.close` writes when it mutes a rule: `<case_uid> closed as <disposition>`. */
const CLOSED = /^CASE-\S+ closed as (.+)$/;

export function SuppressionDialog({
  row,
  title,
  step,
  onClose,
}: {
  row: Suppression;
  /** The rule's title, or the hunt pack's. */
  title: ReactNode;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  onClose: () => void;
}) {
  const keep = useKeepFocus(row.suppression_uid);
  const said = CLOSED.exec(row.reason)?.[1];
  const closed = said ? closedWord(said) : undefined;
  return (
    <Dialog title={<RuleLink id={row.rule_id}>{title}</RuleLink>} step={step} onClose={onClose}>
      <div ref={keep} className="flex flex-col gap-4">
        {closed ? null : (
          <Quote by={row.created_by} label="reason">
            {row.reason}
          </Quote>
        )}
        <Fields
          rows={[
            ["Entity", row.entity ? <Entity value={row.entity} button /> : <span className="sh-mono">whole rule</span>],
            [
              "Case",
              row.case_uid ? (
                <span className="inline-flex items-center gap-2">
                  <Link to={`/cases/${row.case_uid}`} className="sh-link font-mono">
                    {shortId(row.case_uid)}
                  </Link>
                  {closed ? <Badge>{closed}</Badge> : null}
                </span>
              ) : null,
            ],
            [
              "Created",
              // With no quote, the author goes here.
              closed ? (
                <span className="inline-flex items-center gap-2">
                  <Avatar who={row.created_by} size={16} />
                  {stamp(row.created_at)}
                </span>
              ) : (
                stamp(row.created_at)
              ),
            ],
            [
              "Expires",
              <span className="inline-flex items-center gap-3">
                {stamp(row.expires_at)}
                <Left row={row} />
              </span>,
            ],
            ["Id", <Copy value={row.suppression_uid} label="Copy id" />],
          ]}
        />
      </div>
    </Dialog>
  );
}
