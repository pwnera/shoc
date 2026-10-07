/**
 * A backlog item's story as trace steps: raised (where from, the technique,
 * the case, report, pack or rehearsal behind it), worked by the Detection
 * Engineer (tries, tokens), decided (the decision, by whom, when) and, when the
 * rule it merged was taken back, reverted. The backlog dialog draws it; so does
 * the front page's sample item.
 */
import type { ReactNode } from "react";
import { GitMerge, Gavel, Inbox, Undo2, Wrench, type LucideIcon } from "lucide-react";
import { productName } from "@/components/brands";
import { Badge } from "@/components/ui/badge";
import { Chip } from "@/components/ui/filterbar";
import { Tip } from "@/components/ui/tip";
import type { Who } from "@/lib/crew";
import { num, shortId } from "@/lib/format";
import { INTAKES } from "@/lib/labels";
import type { BacklogItem } from "@/types";
import { techniqueChips } from "./context";
import { LinkChip } from "./parts";
import { decisionOf, ENGINEER, revertOf } from "./state";

export type Step = {
  key: string;
  glyph: LucideIcon;
  who?: string | Who | null;
  badge: ReactNode;
  text?: ReactNode;
  chips?: ReactNode;
  meta?: string;
  time?: string | null;
};

const str = (value: unknown) => (typeof value === "string" && value ? value : "");

/** The tries the Engineer spent, summed over every version of the evidence. */
function triesOf(value: unknown): number {
  if (typeof value === "number") return value;
  if (value && typeof value === "object")
    return Object.values(value).reduce((n: number, v) => n + Number(v || 0), 0);
  return 0;
}

const tokens = (n: number) => (n >= 1000 ? `${num(Math.round(n / 1000))}k tok` : `${n} tok`);

/** `reportTitle` and `title` name a report, a rule or a pack once their lists have them; the id stays in the tip. */
export function story(
  item: BacklogItem,
  reportTitle: (uid: string) => string | undefined,
  title: (id: string) => string | undefined,
): Step[] {
  const e = item.evidence ?? {};
  const technique = str(e.technique);
  const report = str(e.report_uid);
  const pack = str(e.pack_id);
  const persona = str(e.persona);
  // With a context, its "connect" row names what to connect.
  const waiting = item.context ? [] : (e.waiting_for ?? []).filter(Boolean);
  // A person's proposal names its techniques as a list, and who raised it.
  const attack = (Array.isArray(e.attack) ? e.attack : []).map(str).filter((t) => t && t !== technique);
  const steps: Step[] = [
    {
      key: "raised",
      glyph: Inbox,
      who: str(e.by) || null,
      badge: <Badge tone="faint">{INTAKES[item.intake] ?? item.intake}</Badge>,
      text: "raised",
      chips: (
        <>
          {techniqueChips([technique, ...attack].filter(Boolean), item.context)}
          {item.rule_id ? (
            <Tip label={item.rule_id} mono>
              <span className="inline-flex min-w-0">
                <LinkChip
                  to={`/detection/rules/${encodeURIComponent(item.rule_id)}`}
                  label="Rule"
                  value={title(item.rule_id) ?? item.rule_id}
                />
              </span>
            </Tip>
          ) : null}
          {item.case_uid ? (
            <LinkChip to={`/cases/${item.case_uid}`} label="Case" value={shortId(item.case_uid)} />
          ) : null}
          {report ? (
            <Tip label={report} mono>
              <span className="inline-flex min-w-0">
                <LinkChip
                  to={`/intel?tab=reports&report=${encodeURIComponent(report)}`}
                  label="Report"
                  value={reportTitle(report) ?? shortId(report)}
                />
              </span>
            </Tip>
          ) : null}
          {pack ? (
            <Tip label={pack} mono>
              <span className="inline-flex min-w-0">
                <LinkChip
                  to={`/hunts?pack=${encodeURIComponent(pack)}`}
                  label="Hunt"
                  value={title(`hunt:${pack}`) ?? pack}
                />
              </span>
            </Tip>
          ) : null}
          {persona ? <Chip label="Rehearsal" value={persona.replace(/_/g, " ")} /> : null}
          {item.observability === "none" ? (
            <Chip dashed label="Source" value="not ingested" />
          ) : null}
          {waiting.map((product) => (
            <LinkChip
              key={product}
              to={`/connections?add=${encodeURIComponent(product)}`}
              label="Connect"
              value={productName(product)}
            />
          ))}
        </>
      ),
      time: item.created_at,
    },
  ];
  if (e.worked_at) {
    const tries = triesOf(e.tries);
    const spent = Number(e.tokens_today ?? 0);
    steps.push({
      key: "worked",
      glyph: Wrench,
      who: ENGINEER,
      badge: <Badge tone="faint">worked</Badge>,
      meta: [tries > 1 ? `${tries} tries` : "", spent ? tokens(spent) : ""]
        .filter(Boolean)
        .join(" · "),
      time: str(e.worked_at),
    });
  }
  const decision = decisionOf(item);
  const ruleId = str(e.rule_id);
  const merged = decision?.word === "merged" && ruleId;
  const reverted = revertOf(item);
  if (decision || item.decided_at)
    steps.push({
      key: "decided",
      glyph: merged ? GitMerge : Gavel,
      who: decision ? decision.by : (item.decided_by ?? null),
      badge: <Badge>{decision?.word ?? item.state}</Badge>,
      chips:
        merged && !reverted ? (
          <LinkChip to={`/detection/rules/${encodeURIComponent(ruleId)}`} label="Rule" value={title(ruleId) ?? ruleId} />
        ) : merged ? (
          <Chip label="Rule" value={ruleId} />
        ) : null,
      time: item.decided_at ?? null,
    });
  if (reverted)
    steps.push({
      key: "reverted",
      glyph: Undo2,
      who: reverted.by || null,
      badge: <Badge>reverted</Badge>,
      time: reverted.at || null,
    });
  return steps;
}
