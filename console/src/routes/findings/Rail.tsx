/**
 * The finding page's rail: the rule, hunt or indicator (its id and the
 * finding's ATT&CK), the siblings (this rule on this entity over 14 days,
 * linking the filtered list) and the Sentinel's decision. The rule's own
 * severity and provenance stay on the rule page; the case's state stays on
 * the case.
 */
import { Link } from "react-router-dom";
import { Avatar } from "@/components/ui/avatar";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Copy, Quote } from "@/components/ui/field";
import { Chip } from "@/components/ui/filterbar";
import { ErrorNote } from "@/components/ui/misc";
import { Popover } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { Tactics } from "@/components/ui/tactics";
import { TimeBar, type TimeBucket } from "@/components/ui/timebar";
import { attackUrl } from "@/lib/attack";
import { num, shortId } from "@/lib/format";
import { huntTitle } from "@/lib/cases";
import { findingTab } from "@/lib/labels";
import { useFindings } from "@/lib/queries";
import type { Finding } from "@/types";
import { useTitles } from "../detection/state";
import { sourceOf } from "./group";

const DAY = 86_400_000;

export function Rail({ finding }: { finding: Finding }) {
  return (
    <>
      <RuleCard finding={finding} />
      <Siblings finding={finding} />
      <Sentinel finding={finding} />
    </>
  );
}

function RuleCard({ finding }: { finding: Finding }) {
  const source = sourceOf(finding);
  // Headed by its kind, so it never repeats the page title; the rule's (or pack's) own title shows only when it differs.
  const named = useTitles()(finding.rule_id).title;
  return (
    <Card>
      <CardHeader
        title={
          <Link className="sh-link" to={source.href}>
            {source.label}
          </Link>
        }
      />
      <CardBody className="flex flex-col gap-3">
        {named && source.label !== "Indicator" && named !== (huntTitle(finding.title) ?? finding.title) ? <span className="text-fg-1">{named}</span> : null}
        <Copy value={finding.rule_id} label="Copy rule id" className="self-start" />
        {finding.attack.length ? (
          <>
            {/* Seven by two: fourteen cells in one row are wider than the rail. */}
            <div className="[&_.sh-tactics]:grid-cols-[repeat(7,24px)]">
              <Tactics techniques={finding.attack} named compact />
            </div>
            <span className="flex flex-wrap gap-1">
              {finding.attack.map((t) => (
                <a key={t} className="sh-chip sh-link" href={attackUrl(t)} target="_blank" rel="noreferrer">
                  <span className="sh-chip__value">{t}</span>
                </a>
              ))}
            </span>
          </>
        ) : null}
      </CardBody>
    </Card>
  );
}

function Siblings({ finding }: { finding: Finding }) {
  const list = useFindings({ rule_id: finding.rule_id, entity: finding.entity_key, since: "-14d", limit: 500 });
  // The count and the spark both leave this finding out.
  const others = (list.data?.rows ?? []).filter((r) => r.finding_uid !== finding.finding_uid);
  const end = new Date();
  end.setHours(24, 0, 0, 0);
  const days: TimeBucket[] = Array.from({ length: 14 }, (_, i) => {
    const to = end.getTime() - (13 - i) * DAY;
    const n = others.filter((r) => {
      const t = Date.parse(r.last_seen);
      return t >= to - DAY && t < to;
    }).length;
    return {
      key: String(to),
      from: new Date(to - DAY).toISOString(),
      to: new Date(to).toISOString(),
      parts: [{ value: n, tone: "neutral", label: "findings" }],
    };
  });
  const tab = findingTab(finding.status);
  const href = `/findings?${new URLSearchParams({
    rule: finding.rule_id,
    entity: finding.entity_key,
    since: "14d",
    ...(tab === "open" ? {} : { tab }),
  })}`;
  return (
    <Card>
      <CardHeader
        title={
          <Link className="sh-link" to={href}>
            Siblings
          </Link>
        }
        subtitle={list.isPending ? undefined : list.isError && !list.data ? "—" : others.length ? `×${num(others.length)} more` : "none"}
      />
      <CardBody>
        {list.isPending ? (
          <Skel kind="block" />
        ) : list.isError && !list.data ? (
          <ErrorNote error={list.error} onRetry={() => void list.refetch()} inline />
        ) : (
          <TimeBar
            variant="spark"
            from={days[0]!.from}
            to={days[13]!.to}
            bars={days}
            label="This rule on this entity, findings per day over 14 days"
          />
        )}
      </CardBody>
    </Card>
  );
}

type Decision = { decision?: string; case_uid?: string; basis?: string; because?: string };

function Sentinel({ finding }: { finding: Finding }) {
  const s = finding.evidence?.sentinel as Decision | undefined;
  if (!s?.decision) return null;
  return (
    <Card>
      <CardHeader title="Sentinel" />
      <CardBody className="flex flex-wrap items-center gap-2">
        <Avatar who="Sentinel" />
        <Chip value={s.decision} />
        {s.case_uid ? (
          <Link className="sh-chip sh-link" to={`/cases/${encodeURIComponent(s.case_uid)}`}>
            <span className="sh-chip__value">{shortId(s.case_uid)}</span>
          </Link>
        ) : null}
        {s.basis && s.basis !== "none" ? <Chip label="by" value={s.basis} /> : null}
        {s.because ? (
          <Popover
            pad
            label="Because"
            trigger={(props) => (
              <button {...props} type="button" className="sh-filterbar__clear">
                because
              </button>
            )}
          >
            <Quote by="Sentinel">{s.because}</Quote>
          </Popover>
        ) : null}
      </CardBody>
    </Card>
  );
}
