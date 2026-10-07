/**
 * Since you left: counters that each link to the list reproducing them, then
 * one time bar from the window's start to now with a mark per counted thing.
 * A zero counter is not drawn; a source still loading shows a skeleton and a
 * failed one reads "—" with Retry, never a zero; nothing at all reads "Quiet"
 * (the since chip above holds the time).
 *
 * Capabilities used: case.list and action.list (the shared logs), finding.list.
 */
import { Link, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Meter } from "@/components/ui/meter";
import { Empty } from "@/components/ui/misc";
import { Skel, type QueryLike } from "@/components/ui/state";
import { TimeBar } from "@/components/ui/timebar";
import { bannered, useUnreachable } from "@/lib/api";
import { num } from "@/lib/format";
import { useNow } from "@/lib/now";
import { ACTION_CAP, CASE_CAP, useActionLog, useCaseLog, useFindings } from "@/lib/queries";
import type { Severity } from "@/types";
import {
  actionCounters,
  caseCounters,
  COUNTERS,
  findingCounter,
  handoverMarks,
  LABEL,
  type Counter,
  type Source,
} from "./handover";

const FINDING_CAP = 500;
const MIX: Severity[] = ["critical", "high", "medium", "low", "informational"];
const SOURCES = Object.keys(COUNTERS) as Source[];

export function Handover({ since, label }: { since: string; label: string }) {
  const navigate = useNavigate();
  const now = useNow();
  const cases = useCaseLog();
  const actions = useActionLog();
  const findings = useFindings({ since, limit: FINDING_CAP }, { live: true });

  const queries: Record<Source, QueryLike & { data?: unknown }> = { cases, actions, findings };
  const counters: Counter[] = [
    ...(cases.data ? caseCounters(cases.data.rows, since, CASE_CAP) : []),
    ...(actions.data ? actionCounters(actions.data.rows, since, ACTION_CAP) : []),
    ...(findings.data && !findings.isPlaceholderData ? [findingCounter(findings.data.rows, since, FINDING_CAP)] : []),
  ];
  const marks = handoverMarks({
    since,
    cases: cases.data?.rows,
    actions: actions.data?.rows,
    findings: findings.isPlaceholderData ? undefined : findings.data?.rows,
  });
  const loading = (s: Source) => queries[s].isPending || (s === "findings" && findings.isPlaceholderData);
  const failed = (s: Source) => queries[s].isError && !queries[s].data;
  const down = useUnreachable();
  const refused = (s: Source) => bannered((queries[s] as { error?: unknown }).error, down);
  const settled = SOURCES.every((s) => !loading(s) && !failed(s));
  const quiet = settled && marks.length === 0 && counters.every((c) => c.n === 0);

  return (
    <Card aria-label="Since you left">
      <CardHeader title="Since you left" />
      {quiet ? (
        <Empty title="Quiet" />
      ) : (
        <div className="flex flex-col gap-3 p-3">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            {SOURCES.flatMap((source) => {
              if (loading(source))
                return COUNTERS[source].map((id) => <Skel key={id} kind="fact" />);
              if (failed(source))
                return [
                  ...COUNTERS[source].map((id) => <Fact key={id} value="—" label={LABEL[id]} />),
                  // A refused token, or shoc unreachable, gains nothing from Retry: the shell's banner has it.
                  ...(refused(source)
                    ? []
                    : [
                        <Button key={`${source}-retry`} variant="ghost" size="sm" onClick={() => void queries[source].refetch()}>
                          Retry
                        </Button>,
                      ]),
                ];
              return counters
                .filter((c) => c.source === source && c.n > 0)
                .map((c) => <CounterLink key={c.id} counter={c} />);
            })}
          </div>
          {/* Never a scroll box, which hid the newest marks on a phone; pt-2 clears the counts above merged marks. */}
          <div className="pt-2">
            <TimeBar
              from={since}
              to={new Date(now).toISOString()}
              marks={marks}
              label={`What happened since ${label}`}
              // A "?action=" mark opens its dialog over Overview, whose URL holds nothing else.
              onPick={(mark) => navigate(marks.find((m) => m.key === mark.key)?.to ?? "/")}
            />
          </div>
        </div>
      )}
    </Card>
  );
}

function Fact({ value, label }: { value: string; label: string }) {
  return (
    <span className="inline-flex items-baseline gap-1.5 whitespace-nowrap">
      <span className="[font:var(--text-fact)] text-fg-4 tabular">{value}</span>
      <span className="text-fg-3">{label}</span>
    </span>
  );
}

function CounterLink({ counter }: { counter: Counter }) {
  const value = `${num(counter.n)}${counter.more ? "+" : ""}`;
  // Every action it counts was a dry run: the dry-run word Response and the case strip use.
  const label = counter.dry ? (counter.id === "undone" ? "plan undone" : "planned") : LABEL[counter.id];
  const mix = counter.mix;
  return (
    <Link
      to={counter.to}
      className="group inline-flex items-center gap-1.5 whitespace-nowrap rounded-control no-underline"
      aria-label={`${value} ${label}`}
    >
      <span className="[font:var(--text-fact)] text-fg-1 tabular">{value}</span>
      <span className="text-fg-3 group-hover:text-fg-1">{label}</span>
      {mix ? (
        <Meter
          value={counter.n}
          max={counter.n}
          width={48}
          showValue={false}
          label="Findings by severity"
          parts={MIX.map((s) => ({ value: mix[s], tone: s === "informational" ? "low" : s, label: s }))}
        />
      ) : null}
    </Link>
  );
}
