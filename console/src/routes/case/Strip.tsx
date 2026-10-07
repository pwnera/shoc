/**
 * The facts this case owns, in its header: the verdict with its confidence and
 * who decided (a closed case: its verdict, who closed it and why, with no
 * badge when the crew left the call to a person, as the stepper says closed),
 * the evidence it stands on as E-chips in E order, dashed for events the store
 * no longer holds, how long the intruder had before the case opened,
 * how long the case waited for its first containment, and the crew's tokens
 * against the case's cap. A gaps chip says what the crew could not see.
 * Values read "—" while their query is pending; time to contain reads "?"
 * in warn when `action.list` failed, so a failure never reads as "never
 * contained".
 */
import { Link } from "react-router-dom";
import { Info } from "lucide-react";
import { Cites } from "@/components/Citations";
import { Avatar } from "@/components/ui/avatar";
import { Badge, VerdictBadge } from "@/components/ui/badge";
import { Quote } from "@/components/ui/field";
import { Meter } from "@/components/ui/meter";
import { Popover } from "@/components/ui/pop";
import { Strip, type StripFact } from "@/components/ui/strip";
import { Tip } from "@/components/ui/tip";
import type { Cites as CiteIndex } from "@/lib/cite";
import { cn } from "@/lib/cn";
import type { Who } from "@/lib/crew";
import { compact, count, shortId, span } from "@/lib/format";
import type { Action, CaseRecord, TimelineResult } from "@/types";
import { point, useBrush } from "./brush";
import { Gaps } from "./Gaps";
import { firstContainment, verdictMessage } from "./moments";

/** Dash the E-chips from the nth on: the evidence the store lost sorts last. Literal, so Tailwind sees each. */
const DASH_FROM = [
  "",
  "[&_.sh-cite:nth-child(n+1)]:border-dashed",
  "[&_.sh-cite:nth-child(n+2)]:border-dashed",
  "[&_.sh-cite:nth-child(n+3)]:border-dashed",
  "[&_.sh-cite:nth-child(n+4)]:border-dashed",
  "[&_.sh-cite:nth-child(n+5)]:border-dashed",
];

/** A person who closed a case, drawn as the Cases list draws one: the person glyph, not a monogram. */
const PERSON: Who = { key: "human", kind: "human", name: "a person", mono: "P", glyph: "person" };

/** Who closed it, as an avatar: a person, the crew (its last decider) or shoc; older rows name nobody, so the decider. */
function closer(closedBy: string | null | undefined, decider: string | undefined): string | Who | null {
  if (closedBy === "human") return PERSON;
  if (closedBy === "crew") return decider ?? "Investigator";
  if (closedBy === "system") return "shoc";
  return decider ?? null;
}

export function CaseStrip({
  data,
  timeline,
  actions,
  actionsFailed,
  cites,
  asOf,
}: {
  data: CaseRecord;
  timeline?: TimelineResult;
  actions?: Action[];
  /** `action.list` failed with nothing cached. */
  actionsFailed?: boolean;
  cites: CiteIndex;
  asOf?: string | null;
}) {
  const brushed = useBrush();
  const record = data.case;
  const closed = record.state === "closed";
  const decision = [...data.openspace].reverse().find((m) => m.kind === "decision");
  const order = (uid: string) => cites.of(uid) ?? Infinity;
  const evidence = [...(verdictMessage(data.openspace)?.cited_event_uids ?? [])].sort((a, b) => order(a) - order(b));
  // Counted only when the timeline is whole: a cut one may simply not reach them.
  const stored = new Set(timeline && !timeline.truncated ? timeline.events.map((e) => e.event_uid) : evidence);
  const firstGone = evidence.findIndex((uid) => !stored.has(uid)) + 1;

  const cited = timeline?.events.filter((e) => e.cited) ?? [];
  const earliest = cited.length ? Math.min(...cited.map((e) => Date.parse(e.time))) : NaN;
  const dwell = timeline && cited.length ? span((Date.parse(record.opened_at) - earliest) / 1000) : null;
  const first = actions ? firstContainment(actions) : undefined;
  const contain = first ? span((Date.parse(first.executed_at!) - Date.parse(record.opened_at)) / 1000) : null;

  const by = closed ? closer(record.closed_by, decision?.agent) : (decision?.agent ?? null);
  // Closed with no verdict of the crew's, the stepper already says closed: only who closed it and why.
  const blank = closed && (record.verdict === "needs_human" || record.verdict === "unknown");
  const verdict: StripFact = {
    key: "verdict",
    label: "",
    value: blank && !by && !record.disposition_reason && !record.related_case_uid ? null : (
      <span className="inline-flex items-center gap-2">
        {blank ? null : <VerdictBadge verdict={record.verdict} confidence={closed ? undefined : record.confidence} />}
        {by ? <Avatar who={by} size={16} /> : null}
        {!closed && decision ? <span className="sh-mono text-fg-4">round {decision.round}</span> : null}
        {closed && record.disposition_reason ? (
          <Popover
            pad
            label="Why it was closed"
            trigger={(props) => (
              <Tip label="Why">
                <button {...props} type="button" className="sh-btn sh-btn--ghost sh-btn--icon" aria-label="Why it was closed">
                  <Info aria-hidden />
                </button>
              </Tip>
            )}
          >
            <Quote label="reason" by={by}>
              {record.disposition_reason}
            </Quote>
          </Popover>
        ) : null}
        {closed && record.related_case_uid ? (
          <Link className="sh-link sh-mono" to={`/cases/${record.related_case_uid}`}>
            followed by {shortId(record.related_case_uid)}
          </Link>
        ) : null}
      </span>
    ),
  };
  const facts: StripFact[] = [
    verdict,
    {
      key: "evidence",
      label: "",
      value: (
        <span className={cn("inline-flex items-center gap-2", DASH_FROM[firstGone])} data-evidence>
          <Cites uids={evidence} number={cites.of} onPoint={(uid) => point(uid ? [uid] : null)} highlight={brushed.point} />
          {/* Evidence or nothing; the verdict badge already asks when the crew handed it over. */}
          {evidence.length || closed || record.verdict === "needs_human" ? null : <Badge tone="crew">needs you</Badge>}
        </span>
      ),
    },
    { key: "dwell", label: "before opening", value: dwell, tip: "From the earliest cited event to the case opening" },
    {
      key: "contain",
      label: first?.dry_run ? "to contain · planned" : "to contain",
      value: actionsFailed ? "?" : contain,
      tone: actionsFailed ? "warn" : undefined,
      tip: actionsFailed ? "Actions not loaded" : `From the case opening to its first containment${first?.dry_run ? ", a dry run" : ""}`,
    },
    {
      key: "crew",
      label: record.token_cap ? "" : "tokens",
      value: record.token_cap ? (
        <Meter
          value={record.tokens_used}
          max={record.token_cap}
          tone={(v) => (v >= (record.token_cap ?? Infinity) ? "warn" : "crew")}
          label="Tokens against the cap"
          format={(v) => `${compact(v)}/${compact(record.token_cap ?? 0)}`}
          width={72}
        />
      ) : (
        compact(record.tokens_used)
      ),
      tip: count(record.rounds, "round"),
    },
  ];

  return <Strip facts={facts} asOf={asOf} aside={<Gaps data={data} timeline={timeline} />} />;
}
