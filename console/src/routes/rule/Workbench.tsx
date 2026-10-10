/**
 * The rule's logic and what it does on our data, side by side. Left: the
 * detection as YAML with token inks, the matching facts and the rule's
 * confidence. Right: Replay (`rule.backtest`: findings against the merge
 * ceiling, the top entities, sample findings), Test (`rule.test`: the
 * would-be findings) and SQL (canonical and backend, from the test). Side by
 * side once the main column has room for both (a container query, so a
 * collapsed rail counts), stacked below that. R replays; the view and window
 * live in the URL.
 *
 * Capabilities used: rule.backtest, rule.test (both write nothing).
 */
import { useEffect, useRef, type ReactNode } from "react";
import { Play } from "lucide-react";
import { Cites } from "@/components/Citations";
import { ConfidenceBar, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { BarList } from "@/components/ui/charts";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Copy } from "@/components/ui/field";
import { ErrorNote } from "@/components/ui/misc";
import { Tip } from "@/components/ui/tip";
import { Meter } from "@/components/ui/meter";
import { Seg } from "@/components/ui/seg";
import { Skel } from "@/components/ui/state";
import { Table, type Column } from "@/components/ui/table";
import { keyLabel, useCommand, useListNav, useSingleKeys } from "@/lib/commands";
import { age, num, stamp } from "@/lib/format";
import { SEVERITIES } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { useParam } from "@/lib/param";
import { useBacktest, useTestRule } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import type { Finding, Rule } from "@/types";
import { useKeepFocus, useLocalPick, useStepper } from "../detection/stepper";
import { INK, scalar, yaml } from "./yaml";

/** A detection as inked YAML; the hunt pack dialog shows a pack's the same way. */
export function Yaml({ value }: { value: Record<string, unknown> }) {
  return (
    // It scrolls sideways on long values, so it takes focus to scroll from the keyboard.
    <pre className="sh-code" tabIndex={0} aria-label="Detection logic">
      {yaml(value).map((line, i) => (
        <span key={i} className="block">
          {line.map((t, j) => (
            <span key={j} className={t.ink ? INK[t.ink] : undefined}>
              {t.text}
            </span>
          ))}
        </span>
      ))}
    </pre>
  );
}

// The kernel folds `then` into the condition, so it is usually absent.
type Sequence = { by?: string[]; first: string; then?: string; within: string };

const mono = (value: string | null | undefined): ReactNode => (value ? <span className="sh-mono text-fg-1">{value}</span> : null);

function Logic({ rule }: { rule: Rule }) {
  const sequence = rule.detection.sequence as Sequence | undefined;
  const grouped = Boolean(rule.count) || Boolean(sequence);
  const { sequence: _drop, ...blocks } = rule.detection;
  return (
    <Card aria-label="Logic" className="h-full">
      <CardHeader title="Logic" />
      <div className="flex flex-col gap-3 p-3">
        <Yaml value={blocks} />
        <Fields
          ruled
          rows={[
            ["Entity", mono(rule.entity)],
            ["Group by", mono(rule.group_by.join(", "))],
            ["Fires at", mono(rule.count ? `${rule.count}${rule.count_distinct ? ` distinct ${rule.count_distinct}` : ""}` : "")],
            ["Sequence", sequence ? mono(`${sequence.first} → ${sequence.then ?? String(rule.detection.condition)}`) : null],
            ["Joined on", mono(sequence?.by?.join(", "))],
            ["First seen", mono(rule.first_seen?.join(", "))],
            ["Lookback", rule.first_seen?.length ? mono(rule.lookback) : null],
            ["Window", grouped ? mono(sequence?.within ?? rule.timeframe) : null],
            ["Confidence", <ConfidenceBar value={rule.confidence} plain />],
          ]}
        />
      </div>
    </Card>
  );
}

/* -- replay, test, SQL --------------------------------------------------------- */

type View = "replay" | "test" | "sql";
type Days = "7" | "30";

/** A would-be finding's own facts; nothing here was stored, but its events were. Titled by its entity. */
function WouldBe({
  finding,
  step,
  onClose,
}: {
  finding: Finding;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  onClose: () => void;
}) {
  const sample = (finding.evidence?.sample ?? {}) as Record<string, unknown>;
  const keep = useKeepFocus(finding.finding_uid);
  return (
    <Dialog
      title={finding.entity_key || finding.title}
      head={<SeverityBadge severity={finding.severity} />}
      step={step}
      onClose={onClose}
    >
      <div ref={keep}>
        <Fields
          rows={[
            ["First seen", stamp(finding.first_seen)],
            ["Last seen", finding.last_seen !== finding.first_seen ? stamp(finding.last_seen) : null],
            [
              "Events",
              <span className="flex flex-wrap items-center gap-2">
                <Cites uids={finding.event_uids} />
                {finding.event_count > finding.event_uids.length ? (
                  <span className="sh-mono">{num(finding.event_count)} in all</span>
                ) : null}
              </span>,
            ],
            ...Object.entries(sample)
              .filter(([k, v]) => k !== "time" && v !== null && v !== "")
              .map(([k, v]): [string, ReactNode] => [k.replace(/_/g, " "), mono(scalar(v))]),
          ]}
        />
      </div>
    </Dialog>
  );
}

const NO_PAGES = { start: 0, size: Infinity, prev: () => {}, next: () => {} };

/** Would-be findings as rows: severity, entity, events, first seen; one popup steps through them. */
function Findings({ rows: given, label }: { rows: Finding[]; label: string }) {
  const now = useNow();
  const pick = useLocalPick();
  const columns: Column<Finding>[] = [
    {
      label: "Severity",
      fit: true,
      sort: (f) => SEVERITIES.indexOf(f.severity),
      cell: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      label: "Entity",
      truncate: false,
      sort: (f) => f.entity_key,
      cell: (f) => (f.entity_key ? <Entity value={f.entity_key} /> : <span className="sh-mono">—</span>),
    },
    { label: "Events", width: 56, align: "right", mono: true, sort: (f) => f.event_count, cell: (f) => num(f.event_count) },
    {
      label: "Seen",
      width: 56,
      align: "right",
      mono: true,
      hide: "md",
      sort: (f) => f.first_seen,
      cell: (f) => age(f.first_seen, now),
    },
  ];
  const sorted = useSort(given, columns);
  const rows = sorted.rows;
  const nav = useListNav(rows, (f) => f.finding_uid, { onOpen: (f) => pick[1](f.finding_uid, true) });
  const open = useStepper(rows, (f) => f.finding_uid, pick, { ...NO_PAGES, setActive: nav.setActive });
  return (
    <>
      <Table
        label={label}
        columns={columns}
        rows={rows}
        sort={sorted.sort}
        rowKey={(f) => f.finding_uid}
        rowProps={nav.rowProps}
        bounded={240}
        className="[scrollbar-gutter:stable]"
      />
      {open.row ? <WouldBe finding={open.row} onClose={open.close} step={open.step} /> : null}
    </>
  );
}

function Waiting() {
  return (
    <div className="flex flex-col gap-3 p-3" aria-busy="true">
      <span role="status" className="sr-only">
        loading
      </span>
      <Skel kind="row" width="40%" />
      <Skel kind="block" />
      <Skel kind="row" width="60%" />
    </div>
  );
}

const VIEWS: View[] = ["replay", "test", "sql"];

function Bench({ ruleId }: { ruleId: string }) {
  // The view and window live in the URL (`?bench=test&days=30`); a run is on demand, bar the test SQL reads.
  const [asked, setView] = useParam<View>("bench", "replay");
  const view = VIEWS.includes(asked) ? asked : "replay";
  const [daysParam, setDays] = useParam<Days>("days", "7");
  const days: Days = daysParam === "30" ? "30" : "7";
  const [dialect, setDialect] = useParam<"canonical" | "backend">("sql", "canonical");
  const backtest = useBacktest();
  const test = useTestRule();

  const replay = (d = days) => backtest.mutate({ rule_id: ruleId, days: Number(d) });
  const tryIt = (d = days) => test.mutate({ rule_id: ruleId, since: `-${d}d` });
  useCommand("rule.replay", () => {
    setView("replay");
    if (!backtest.isPending) replay();
  });

  // The SQL comes from a test; ask for one the first time SQL shows, a reload of `?bench=sql` too
  // (once: strict mode runs a mount's effect twice before the mutation's state reaches this render).
  const sqlAsked = useRef(false);
  useEffect(() => {
    if (view !== "sql" || !test.isIdle || sqlAsked.current) return;
    sqlAsked.current = true;
    tryIt();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view]);
  // The window is the card's: a run behind another view follows it as well, so no view shows an old window.
  const pickDays = (d: Days) => {
    setDays(d);
    if (backtest.data) replay(d);
    if (test.data) tryIt(d);
  };

  let body: ReactNode;
  if (view === "replay") {
    const b = backtest.data;
    body = backtest.isPending ? (
      <Waiting />
    ) : backtest.error ? (
      <ErrorNote error={backtest.error} onRetry={() => replay()} />
    ) : b ? (
      <div className="flex flex-col gap-4 p-3">
        <div className="flex items-baseline gap-3">
          <span className="[font:var(--text-fact)] text-fg-1">{num(b.findings)}</span>
          <span className="sh-label">findings {b.days}d</span>
          <span className="sh-mono ml-auto">ceiling {num(b.ceiling)}</span>
        </div>
        <Meter
          label="Findings against the merge ceiling"
          value={b.findings}
          max={Math.max(b.ceiling * 1.5, b.findings, 1)}
          tone={b.findings > b.ceiling ? "bad" : "neutral"}
          marks={[{ at: b.ceiling, label: "ceiling" }]}
          size="md"
          showValue={false}
          valueText={`${b.findings} findings, ceiling ${b.ceiling}`}
        />
        {Object.keys(b.top_entities).length ? (
          <div className="flex flex-col gap-1">
            <span className="sh-label">Top entities</span>
            <BarList
              label="Top entities"
              rows={Object.entries(b.top_entities)
                .sort((x, y) => y[1] - x[1])
                .slice(0, 8)
                .map(([label, value]) => ({ label, value }))}
            />
          </div>
        ) : null}
        {b.sample.length ? <Findings rows={b.sample} label="Sample findings" /> : null}
      </div>
    ) : (
      <Idle onRun={() => replay()} label={`Replay ${days} days`} kbd="r" />
    );
  } else {
    const t = test.data?.data;
    body = test.isPending ? (
      <Waiting />
    ) : test.error ? (
      <ErrorNote error={test.error} onRetry={() => tryIt()} />
    ) : !t ? (
      <Idle onRun={() => tryIt()} label={`Test ${days} days`} />
    ) : view === "test" ? (
      <div className="flex flex-col gap-3 p-3">
        <div className="flex items-baseline gap-3">
          <span className="[font:var(--text-fact)] text-fg-1">{num(t.findings.length)}</span>
          <span className="sh-label">would-be findings {test.variables?.since.slice(1)}</span>
        </div>
        {t.findings.length ? <Findings rows={t.findings} label="Would-be findings" /> : null}
      </div>
    ) : (
      <div className="flex flex-col gap-2 p-3">
        <Seg
          label="SQL"
          className="self-start"
          value={dialect}
          onChange={setDialect}
          options={[
            { value: "canonical", label: "canonical" },
            { value: "backend", label: "backend" },
          ]}
        />
        <Copy block value={dialect === "canonical" ? t.canonical_sql : t.dialect_sql} label="Copy SQL" />
      </div>
    );
  }

  return (
    <Card aria-label="On our data" className="h-full">
      <div className="sh-card__toolbar">
        <Seg
          label="View"
          value={view}
          onChange={setView}
          options={[
            { value: "replay", label: "Replay" },
            { value: "test", label: "Test" },
            { value: "sql", label: "SQL" },
          ]}
        />
        {view !== "sql" ? (
          <Seg
            label="Window"
            className="ml-auto"
            value={days}
            onChange={pickDays}
            options={[
              { value: "7", label: "7d" },
              { value: "30", label: "30d" },
            ]}
          />
        ) : null}
      </div>
      {body}
    </Card>
  );
}

/** Before a run: the button that runs it, its key in the tip when it has one (no key cap renders on a page). */
function Idle({ onRun, label, kbd }: { onRun: () => void; label: string; kbd?: string }) {
  const [single] = useSingleKeys();
  const button = (
    <Button size="sm" onClick={onRun} aria-keyshortcuts={single ? kbd?.toUpperCase() : undefined}>
      <Play aria-hidden />
      {label}
    </Button>
  );
  return (
    <div className="flex h-24 items-center justify-center gap-2">
      {kbd && single ? (
        <Tip label={label} kbd={keyLabel(kbd)}>
          {button}
        </Tip>
      ) : (
        button
      )}
    </div>
  );
}

export function Workbench({ rule }: { rule: Rule }) {
  return (
    <div className="@container">
      <div className="grid items-stretch gap-4 @min-[760px]:grid-cols-2">
        <Logic rule={rule} />
        <Bench ruleId={rule.id} />
      </div>
    </div>
  );
}
