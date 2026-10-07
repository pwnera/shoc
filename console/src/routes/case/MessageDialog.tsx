/**
 * One crew message, its one home: who said it to whom, the tools it looked
 * things up with and the stance it argued, the words themselves as a quote,
 * the events it cites, then one block of fields: a proposal's own (with a link
 * to the action it became) and the model, tokens and round. J and K step
 * through the rows the Discussion shows.
 *
 * Capabilities used: none (the message comes from `case.get`).
 */
import type { ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { Cites } from "@/components/Citations";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Quote } from "@/components/ui/field";
import { AutonomyBadge } from "@/components/ui/status";
import type { Cites as CiteIndex } from "@/lib/cite";
import { who } from "@/lib/crew";
import { parseEntity } from "@/lib/entity";
import { num, percent, stamp } from "@/lib/format";
import { actionLabel, kindWord, reachLabel } from "@/lib/labels";
import type { OpenspaceMessage } from "@/types";
import { point, useBrush } from "./brush";
import { proposalOf, strip, type Proposal } from "./messages";

const mono = (value: ReactNode) => <span className="sh-mono sh-mono--strong">{value}</span>;

/** A proposal's JSON as rows (`shoc/agents/ir.py`). */
function proposalRows(proposal: Proposal): [string, ReactNode][] {
  const reach = proposal.blast_radius?.principals;
  return [
    ["action", mono(actionLabel(proposal.action))],
    ["target", proposal.target ? parseEntity(proposal.target) ? <Entity value={proposal.target} button /> : mono(proposal.target) : null],
    ["stage", proposal.stage ? mono(proposal.stage) : null],
    ["autonomy", proposal.autonomy ? <AutonomyBadge level={proposal.autonomy} /> : null],
    [
      "reversible",
      proposal.reversible === undefined ? null : proposal.reversible ? <Badge tone="idle">↺ reversible</Badge> : <Badge tone="bad">⊘ one-way</Badge>,
    ],
    ["reach", reach ? mono(reachLabel(reach)) : null],
    ["fallback", proposal.fallback ? mono(actionLabel(proposal.fallback)) : null],
    ["fallback after", proposal.fallback_after_minutes ? mono(`${proposal.fallback_after_minutes}m`) : null],
    ["destroys evidence", proposal.destroys_evidence ? <span className="text-fg-2">{proposal.destroys_evidence}</span> : null],
  ];
}

export function MessageDialog({
  message,
  cites,
  step,
  onClose,
}: {
  message: OpenspaceMessage;
  cites: CiteIndex;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  onClose: () => void;
}) {
  const [, setParams] = useSearchParams();
  const brushed = useBrush();
  const proposal = proposalOf(message);
  const said = strip(proposal?.rationale ?? message.body);
  const author = who(message.agent);
  // One Fields block, so a proposal's labels and the model's line up.
  const meta: [string, ReactNode][] = [
    ["model", message.model ? mono(message.model) : null],
    ["tokens", message.tokens ? mono(num(message.tokens)) : null],
    ["round", mono(message.round)],
    ["at", mono(stamp(message.created_at))],
    ["repeats", message.repeats ? mono(`×${message.repeats + 1}`) : null],
  ];

  const openAction = (uid: string) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.delete("msg");
      out.set("action", uid);
      return out;
    });

  return (
    <Dialog
      title={`${author.name} · ${kindWord(message.kind)}`}
      id={`#${message.msg_id}`}
      onClose={onClose}
      step={step}
      head={
        <>
          <Avatar who={message.agent} size={20} />
          {message.to_agent ? (
            <>
              <ArrowRight className="h-3 w-3 text-fg-4" aria-label="to" />
              <Avatar who={message.to_agent} size={20} />
            </>
          ) : null}
          {message.confidence !== null ? <Badge tone="faint">{percent(message.confidence)}</Badge> : null}
        </>
      }
      footer={
        proposal?.action_uid ? (
          <Button onClick={() => openAction(proposal.action_uid!)}>Open action</Button>
        ) : undefined
      }
    >
      {said.tools.length || said.arguing ? (
        <div className="flex flex-wrap gap-1.5">
          {said.tools.map((tool) => (
            <span key={tool.name} className="sh-chip">
              <span className="sh-chip__value">{tool.name}</span>
              {tool.count > 1 ? <span className="sh-chip__count">×{tool.count}</span> : null}
            </span>
          ))}
          {said.arguing ? <Badge>arguing {said.arguing}</Badge> : null}
          {said.grounded ? <Badge>grounded: {said.grounded}</Badge> : null}
        </div>
      ) : null}
      {said.text ? (
        <Quote by={message.agent} at={message.created_at} crew={author.kind === "crew" || author.kind === "code"}>
          {said.text}
        </Quote>
      ) : null}
      {message.cited_event_uids.length ? (
        <Cites
          uids={message.cited_event_uids}
          number={cites.of}
          onPoint={(uid) => point(uid ? [uid] : null)}
          highlight={brushed.point}
        />
      ) : null}
      <Fields ruled={Boolean(proposal)} rows={proposal ? [...proposalRows(proposal), ...meta] : meta} />
    </Dialog>
  );
}
