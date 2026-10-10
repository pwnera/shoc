/**
 * Findings: what detection fired, and which of it is not handled yet. A row
 * groups one rule's findings on one entity (×N); tabs partition by status; the
 * tabs, the strip's severity facts and the filter options count findings, as
 * every other screen does, and the pager says how many groups hold them. The
 * strip draws the findings over the window, and a brush on the bars narrows
 * the window. Every filter lives in the URL, so the rule page, Overview and the
 * palette link to any slice. A hunt-born title trades its "Hunt:" prefix for a
 * telescope, as on Cases. New findings wait behind a pill. If a refresh fails,
 * the rows on screen stay and the strip says how old they are.
 *
 * Capabilities used: finding.list (`since`, `rule_id`, `entity` sent to the
 * kernel; severity, tactic, title text and a brushed `until` filter the rows).
 */
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { ChevronLeft, ChevronRight, Telescope } from "lucide-react";
import { Card } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Entity } from "@/components/ui/entity";
import { Chip, FilterBar } from "@/components/ui/filterbar";
import { Empty, NewPill, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Seg } from "@/components/ui/seg";
import { Skel } from "@/components/ui/state";
import { Strip, type StripTone } from "@/components/ui/strip";
import { Table, type Column } from "@/components/ui/table";
import { TimeBar, type TimeBucket } from "@/components/ui/timebar";
import { Tip } from "@/components/ui/tip";
import { tacticLabel, tacticsOf, TACTICS } from "@/lib/attack";
import { cn } from "@/lib/cn";
import { huntTitle } from "@/lib/cases";
import { useCommand, useListNav, useTabKeys } from "@/lib/commands";
import { copyAndSay } from "@/lib/copy";
import { age, num, shortId } from "@/lib/format";
import type { Dim, Option } from "@/lib/filters";
import { useFilters } from "@/lib/filters";
import { findingTab, FINDING_TABS, SEVERITIES as RANK } from "@/lib/labels";
import { useNewFindings } from "@/lib/live";
import { useNow } from "@/lib/now";
import { useTab } from "@/lib/param";
import { useFindings } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import type { Finding, Severity } from "@/types";
import { kernelSince, rangeLabel, tidy, windowOf, windowValue } from "./explore/query";
import { groupFindings, stepOrder, type Signal } from "./findings/group";

const CAP = 500;
const PAGE = 25;
const WINDOWS = ["24h", "7d", "30d"] as const;
const DEFAULT_SINCE = "7d";
const TAB_IDS = Object.keys(FINDING_TABS) as (keyof typeof FINDING_TABS)[];
const TAB_LABEL = { open: "Open", handled: "Handled", aside: "Set aside" } as const;
const EMPTY_TAB = { open: "Nothing open", handled: "Nothing handled", aside: "Nothing set aside" } as const;
const SEVERITIES = ["critical", "high", "medium", "low"] as const;

/** "low" holds informational too, so four facts cover every group. */
const ofSeverity = (row: { severity: string }, value: string) =>
  row.severity === value || (value === "low" && row.severity === "informational");
const ofTactic = (finding: Finding, value: string) => (tacticsOf(finding.attack) as string[]).includes(value);

// Severity has no row test: it goes by a group's worst finding, as the row's badge does.
const DIMS: Dim<Finding>[] = [
  { id: "rule", label: "Rule" },
  // `on`, not `entity`: `?entity=` is the shell's EntityDialog, so a filter by it would open the dialog too.
  { id: "on", label: "Entity" },
  { id: "severity", label: "Severity" },
  { id: "tactic", label: "Tactic", test: ofTactic },
];

/** How many findings the groups hold. */
const findingsIn = (list: Signal[]) => list.reduce((n, s) => n + s.findings.length, 0);

/** Distinct values and how many findings hold each, busiest first; a group's findings share its rule, so its tactics. */
function options(rows: Signal[], pick: (s: Signal) => string[], label?: (v: string) => string): Option[] {
  const counts = new Map<string, number>();
  for (const row of rows) for (const v of pick(row)) counts.set(v, (counts.get(v) ?? 0) + row.findings.length);
  return [...counts]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([value, count]) => ({ value, count, ...(label ? { label: label(value) } : {}) }));
}

const HOUR = 3_600_000;

/** Bars by hour for a day (25 hours, so a picked day bar across a clock change stays hourly) or by local day, stacked by severity. */
function bars(rows: Finding[], from: number, to: number): TimeBucket[] {
  const hourly = to - from <= 25 * HOUR;
  const start = new Date(from);
  if (hourly) start.setMinutes(0, 0, 0);
  else start.setHours(0, 0, 0, 0);
  const out: TimeBucket[] = [];
  for (let at = start; at.getTime() < to && out.length < 200; ) {
    const next = new Date(at);
    if (hourly) next.setHours(at.getHours() + 1);
    else next.setDate(at.getDate() + 1);
    const inside = rows.filter((r) => {
      const t = Date.parse(r.last_seen);
      return t >= at.getTime() && t < next.getTime();
    });
    out.push({
      key: String(at.getTime()),
      from: at.toISOString(),
      to: next.toISOString(),
      parts: SEVERITIES.map((s) => ({ value: inside.filter((r) => ofSeverity(r, s)).length, tone: s, label: s })),
    });
    at = next;
  }
  return out;
}

/** The state word over every open finding in the window, the tab's own word: warn when a high or critical is open. */
function state(rows: Finding[]): { tone: StripTone; word: string } {
  const open = rows.filter((r) => findingTab(r.status) === "open");
  if (!open.length) return { tone: "good", word: "Nothing open" };
  return { tone: open.some((r) => r.severity === "critical" || r.severity === "high") ? "warn" : "idle", word: "Open" };
}

export function Findings() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const now = useNow();
  const asked = tidy(params.get("since") || DEFAULT_SINCE);
  // A since that is neither a window nor an instant reads as the default.
  const since = Number.isNaN(windowOf(asked, "").from) ? DEFAULT_SINCE : asked;
  const until = Number.isNaN(Date.parse(params.get("until") ?? "")) ? "" : params.get("until")!;
  const [tab, setTab] = useTab(TAB_IDS);
  useTabKeys(TAB_IDS.length, (i) => setTab(TAB_IDS[i]!));
  const filters = useFilters(DIMS, { match: (row, text) => row.title.toLowerCase().includes(text) });
  const findings = useFindings({
    since: kernelSince(since),
    limit: CAP,
    rule_id: filters.values.rule,
    entity: filters.values.on,
  });
  const [fresh, resetFresh] = useNewFindings();
  const reset = useRef(resetFresh);
  useLayoutEffect(() => {
    reset.current = resetFresh;
  });
  // The list on screen is fresh; only findings from now on count into the pill.
  useEffect(() => reset.current(), []);

  const loaded = findings.data?.rows ?? [];
  const all = until ? loaded.filter((r) => Date.parse(r.last_seen) < Date.parse(until)) : loaded;
  const kept = all.filter(filters.keep);
  const inTab = (r: Finding) => findingTab(r.status) === tab;
  const severity = filters.values.severity;
  const keepSeverity = (list: Signal[]) => (severity ? list.filter((s) => ofSeverity(s, severity)) : list);
  // Severity facts count the tab with every filter but severity, so pressing one never zeroes the rest.
  const bySeverity = groupFindings(kept.filter(inTab));
  const signals = keepSeverity(bySeverity);
  const rows = signals.flatMap((s) => s.findings);

  // No time column: the name's cell ends with the time, as on Cases.
  const columns: Column<Signal>[] = [
    {
      label: "Severity",
      fit: true,
      sort: (s) => RANK.indexOf(s.severity as Severity),
      cell: (s) => <SeverityBadge severity={s.severity as Severity} />,
    },
    {
      label: "Finding",
      truncate: false,
      sort: (s) => huntTitle(s.title) ?? s.title,
      cell: (s) => {
        const hunt = huntTitle(s.title);
        return (
          <span className="flex min-w-0 items-center gap-3">
            <span className="flex min-w-0 flex-1 items-center gap-2 max-sm:flex-col max-sm:items-start max-sm:gap-0.5 max-sm:py-1">
              <span className="flex min-w-0 max-w-full items-center gap-2">
                <Tip label={s.rule_id} mono>
                  <span className="min-w-0 truncate font-medium text-fg-1 max-sm:line-clamp-2 max-sm:whitespace-normal">{hunt ?? s.title}</span>
                </Tip>
                {hunt !== null ? (
                  <Tip label="From a hunt">
                    <Telescope className="h-3.5 w-3.5 shrink-0 text-fg-3" role="img" aria-label="hunt" />
                  </Tip>
                ) : null}
              </span>
              {/* An aggregate's key names each entity ("AKIA…|203.0.113.55"); on a phone they sit under a two-line title. */}
              {s.entity_key || s.findings.length > 1 ? (
                <span className="inline-flex min-w-0 max-w-[40%] shrink-0 items-center gap-1 max-sm:max-w-full">
                  {s.entity_key ? s.entity_key.split("|").map((part) => <Entity key={part} value={part} />) : null}
                  {s.findings.length > 1 ? <span className="sh-mono shrink-0">×{num(s.findings.length)}</span> : null}
                </span>
              ) : null}
            </span>
            <span className="shrink-0 text-right font-mono text-xs text-fg-3 tabular md:min-w-12">
              {age(s.last_seen, Math.max(now, Date.now()))}
            </span>
          </span>
        );
      },
    },
  ];
  const sorted = useSort(signals, columns);
  const order = stepOrder(sorted.rows);

  // Paging clamps on refresh and starts over when the slice changes.
  const slice = `${tab}|${since}|${until}|${JSON.stringify(filters.values)}|${filters.text}`;
  const [paging, setPaging] = useState({ slice, at: 0 });
  const pages = Math.max(1, Math.ceil(signals.length / PAGE));
  const at = paging.slice === slice ? Math.min(paging.at, pages - 1) : 0;
  const go = (n: number) => setPaging({ slice, at: Math.max(0, Math.min(pages - 1, n)) });
  const page = sorted.rows.slice(at * PAGE, at * PAGE + PAGE);

  const open = (s: Signal) => {
    const uid = s.findings[0]!.finding_uid;
    navigate(`/findings/${encodeURIComponent(uid)}`, {
      // `keys` is each uid's row, so a step on the finding page moves the row Back lands on.
      state: {
        uids: order,
        keys: sorted.rows.flatMap((g) => g.findings.map(() => g.key)),
        index: order.indexOf(uid),
        back: `${location.pathname}${location.search}`,
      },
    });
  };
  const nav = useListNav(page, (s) => s.key, { onOpen: open, onPrevPage: () => go(at - 1), onNextPage: () => go(at + 1) });
  useCommand("findings.copy-id", () => {
    const s = page.find((x) => x.key === nav.activeKey) ?? page[0];
    const uid = s?.findings[0]?.finding_uid;
    if (uid) void copyAndSay(uid, shortId(uid));
  });

  const edit = (change: (out: URLSearchParams) => void) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        change(out);
        return out;
      },
      { replace: true },
    );
  const setWindow = (from: string, to = "") =>
    edit((out) => {
      if (from === DEFAULT_SINCE && !to) out.delete("since");
      else out.set("since", from);
      if (to) out.set("until", to);
      else out.delete("until");
    });

  const failed = findings.isError && !findings.data;
  const pending = findings.isPending;
  // The last window's or filter's answer still draws the rows, dimmed; its counts and state word are not this one's.
  const unknown = pending || findings.isPlaceholderData;
  const win = windowOf(since, until, Math.max(now, Date.now()));
  const custom = !windowValue(since, until, WINDOWS);
  // Tabs, facts and options count findings; a severity fact counts the findings of the groups it shows.
  const tabCount = (id: keyof typeof FINDING_TABS) =>
    findingsIn(keepSeverity(groupFindings(kept.filter((r) => findingTab(r.status) === id))));
  // Options count the tab; severities and tactics keep their own order.
  const tabAll = groupFindings(all.filter(inTab));
  const ordered = (list: Option[], sequence: readonly string[]) => sequence.flatMap((v) => list.filter((o) => o.value === v));
  const dims: Dim<Finding>[] = [
    { ...DIMS[0]!, options: options(tabAll, (s) => [s.rule_id]) },
    { ...DIMS[1]!, options: options(tabAll, (s) => [s.entity_key]) },
    { ...DIMS[2]!, options: ordered(options(tabAll, (s) => [s.severity === "informational" ? "low" : s.severity]), SEVERITIES) },
    {
      ...DIMS[3]!,
      options: ordered(
        options(tabAll, (s) => [...new Set(s.findings.flatMap((f) => tacticsOf(f.attack)))], tacticLabel),
        TACTICS.map(([id]) => id),
      ),
    },
  ];
  const fromIso = new Date(win.from).toISOString();
  // No rows draw no bars: an axis over zero would still print its "1".
  const drawn = unknown || !rows.length ? [] : bars(rows, win.from, win.to);


  const aside = (
    <span className="flex items-center gap-2">
      {custom ? (
        <Chip
          label="since"
          value={rangeLabel(fromIso, until)}
          active
          onRemove={() => setWindow(DEFAULT_SINCE)}
        />
      ) : null}
      <Seg label="Window" value={windowValue(since, until, WINDOWS)} options={WINDOWS} onChange={(v) => setWindow(v)} />
    </span>
  );

  const empty = filters.active ? (
    <Empty
      kind="filtered"
      title="No findings match"
      chips={filters.chips.map((c) => (
        <Chip key={c.id} label={c.label} value={c.word} active />
      ))}
      onClear={filters.clear}
    />
  ) : (
    <Empty kind={tab === "open" ? "clear" : "row"} title={EMPTY_TAB[tab]} />
  );

  return (
    <div className={cn("flex flex-col gap-4", !drawn.length && String.raw`[&_.sh-timebar\_\_ymax]:invisible`)}>
      <PageHeader
        title="Findings"
        strip={
          <>
            <Strip
              // The state word is about open findings; beside another tab's counts it would read as theirs.
              // Not `loading`: the strip would add a "…" word on the other tabs and push the facts aside.
              state={tab !== "open" ? undefined : unknown ? { tone: "idle", word: "…" } : state(all)}
              // The table's error carries the one Retry; a failed refresh keeps the rows and says how old they are.
              error={failed ? findings.error : undefined}
              asOf={findings.isRefetchError ? new Date(findings.dataUpdatedAt).toISOString() : null}
              facts={SEVERITIES.map((s) => ({
                key: s,
                label: s,
                value: unknown ? <Skel kind="fact" /> : findingsIn(bySeverity.filter((x) => ofSeverity(x, s))),
                pressed: filters.values.severity === s,
                onClick: () => filters.set("severity", filters.values.severity === s ? "" : s),
              }))}
              aside={aside}
            />
            {failed ? null : (
              <TimeBar
                // A new window draws afresh: a brush belongs to the window it was drawn on.
                key={`${since}|${until}`}
                variant="bars"
                from={fromIso}
                to={new Date(win.to).toISOString()}
                bars={drawn}
                onBrush={(range) => range && setWindow(range.from, range.to)}
                onBucket={(bucket) => setWindow(bucket.from, bucket.to)}
                label="Findings over the window, by severity"
              />
            )}
          </>
        }
      />

      <Tabs
        id="findings"
        label="Status"
        value={tab}
        onChange={setTab}
        tabs={TAB_IDS.map((id) => ({ value: id, label: TAB_LABEL[id], count: unknown || failed ? null : tabCount(id) }))}
      />
      <TabPanel id="findings" value={tab}>
        <Card
          // The pill floats over the rows rather than push them down: live data never moves the reader.
          className={cn("[&>.sh-newpill]:-mb-6", findings.isPlaceholderData && "opacity-60")}
          aria-busy={findings.isFetching || undefined}
        >
          <FilterBar
            dims={dims}
            value={filters.values}
            onChange={filters.set}
            text={filters.text}
            onText={filters.setText}
            onClear={filters.clear}
            placeholder="Filter titles"
          />
          <NewPill
            count={fresh}
            onClick={() => {
              resetFresh();
              go(0);
              nav.setActive("");
              void findings.refetch();
              document.getElementById(`findings-panel-${tab}`)?.scrollIntoView?.({ block: "nearest" });
            }}
          />
          <Table
            columns={columns}
            rows={page}
            sort={sorted.sort}
            onSort={() => go(0)}
            rowKey={(s) => s.key}
            rowProps={nav.rowProps}
            loading={pending}
            error={failed ? findings.error : undefined}
            onRetry={() => void findings.refetch()}
            empty={empty}
            label="Findings"
          />
          {signals.length ? (
            <div className="sh-pager">
              <span className="sh-pager__range">
                <b>
                  {at * PAGE + 1}–{at * PAGE + page.length}
                </b>{" "}
                of {num(signals.length)}
                {rows.length === signals.length
                  ? ` ${rows.length === 1 ? "finding" : "findings"}`
                  : ` ${signals.length === 1 ? "group" : "groups"} · ${num(rows.length)} findings`}
                {loaded.length >= CAP ? ` · newest ${CAP}` : ""}
              </span>
              {pages > 1 ? (
                <>
                  <Button variant="ghost" size="sm" disabled={at === 0} onClick={() => go(at - 1)} aria-label="Previous page">
                    <ChevronLeft aria-hidden />
                  </Button>
                  <Button variant="ghost" size="sm" disabled={at === pages - 1} onClick={() => go(at + 1)} aria-label="Next page">
                    <ChevronRight aria-hidden />
                  </Button>
                </>
              ) : null}
            </div>
          ) : null}
        </Card>
      </TabPanel>
    </div>
  );
}
