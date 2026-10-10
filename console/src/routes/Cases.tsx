/**
 * Cases — which cases are open, how far along each is, and is the crew on it?
 * A strip of open-case facts that filter the list, four tabs that do not
 * overlap (All first, open work sorted to the top), a filter bar, and one row
 * per case: the crew's state or who closed it, one badge, the title and one
 * time. A row opens the case, and Escape there comes back to this list as it
 * was; C copies its id.
 *
 * Capabilities used: case.list, action.list (proposals, for "waits on you"),
 * ops.alerts (stalled cases); crew presence comes from the live store.
 */
import { useState, type ReactNode } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { Cog, Telescope, User } from "lucide-react";
import { SeverityBadge, VerdictBadge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { CrewState } from "@/components/ui/avatar";
import { Entity } from "@/components/ui/entity";
import { Chip, FilterBar } from "@/components/ui/filterbar";
import { Empty, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Strip, type StripFact } from "@/components/ui/strip";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import {
  bucket,
  closedBy,
  hold,
  huntTitle,
  inWindow,
  isOpen,
  matches,
  order,
  TABS,
  type TabId,
} from "@/lib/cases";
import { useCommand, useListNav, useTabKeys } from "@/lib/commands";
import { copyAndSay } from "@/lib/copy";
import { bare } from "@/lib/entity";
import { type Dim, useFilters } from "@/lib/filters";
import { age, capped } from "@/lib/format";
import { principalWord, severityLabel, SEVERITIES, verdictOf, VERDICTS } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { useFlash } from "@/lib/flash";
import { usePaged } from "@/lib/paged";
import { useTab } from "@/lib/param";
import { usePresence } from "@/lib/presence";
import { CASE_CAP, useAlerts, useCaseLog, useProposals } from "@/lib/queries";
import { sinceWord } from "@/lib/since";
import { useSort } from "@/lib/sort";
import type { Case, Verdict } from "@/types";

const TAB_LABEL: Record<TabId, string> = {
  all: "All",
  investigating: "Investigating",
  contained: "Contained",
  closed: "Closed",
};

/** Under 768px a verdict badge is its glyph: the word is sized to nothing, so it is still heard. */
const PHONE_GLYPH = String.raw`max-md:[&_.sh-badge]:gap-0 max-md:[&_.sh-badge]:border-0 max-md:[&_.sh-badge]:bg-transparent max-md:[&_.sh-badge]:px-0 max-md:[&_.sh-badge]:text-[0px] max-md:[&_.sh-badge>span]:text-xs`;

const CREW_OPTIONS = [
  { value: "working", label: "working" },
  { value: "waiting", label: "waits on you" },
  { value: "stalled", label: "stalled" },
];

/** The strip's facts that filter, as (parameter, value): each lands on All with state=open beside it. */
const FACTS = [
  ["severity", "critical"],
  ["severity", "high"],
  ["crew", "working"],
  ["crew", "stalled"],
  ["sort", "oldest"],
] as const;

const BY_OPTIONS = ["crew", "human", "system"].map((value) => ({ value, label: principalWord(value) }));

export function Cases() {
  const now = useNow();
  const cases = useCaseLog();
  const proposals = useProposals();
  const alerts = useAlerts();
  const presence = usePresence();
  const [tab] = useTab(TABS);
  const [params, setParams] = useSearchParams();
  const sortBy = params.get("sort") === "oldest" ? "oldest" : "";
  // The tabs pick the state, so a tab change drops state=open, and with it the fact that set it:
  // "critical, state open" on Closed would be a list that can never fill.
  const setTab = (next: TabId) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      if (out.get("state") === "open") for (const [id, value] of FACTS) if (out.get(id) === value) out.delete(id);
      for (const name of ["state", "tab", "pane", "page"]) out.delete(name);
      if (next !== TABS[0]) out.set("tab", next);
      return out;
    });
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));

  const rows = cases.data?.rows;
  const all = rows ?? [];
  const buckets = bucket(all);
  const open = all.filter(isOpen);
  const waiting = new Set((proposals.data?.rows ?? []).map((a) => a.case_uid));
  const stalled = new Set((alerts.data?.alerts ?? []).filter((a) => a.kind === "case.stalled").map((a) => a.subject));
  const working = (row: Case) => isOpen(row) && presence.onCase(row.case_uid).length > 0;
  const crew: Record<string, (row: Case) => boolean> = {
    working,
    waiting: (row) => isOpen(row) && (waiting.has(row.case_uid) || row.verdict === "needs_human"),
    stalled: (row) => isOpen(row) && stalled.has(row.case_uid),
  };

  const inTab = tab === "all" ? all : buckets[tab];
  const tally = (test: (row: Case) => boolean) => inTab.filter(test).length;
  const entities = [...new Set(inTab.map((row) => row.entity_key).filter(Boolean))]
    .map((value) => ({ value, count: tally((row) => row.entity_key === value) }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
  const dims: Dim<Case>[] = [
    {
      id: "severity",
      label: "severity",
      options: SEVERITIES.map((s) => ({ value: s, label: severityLabel(s), count: tally((row) => row.severity === s) })),
      test: (row, v) => row.severity === v,
    },
    {
      id: "verdict",
      label: "verdict",
      options: (Object.keys(VERDICTS) as Verdict[])
        .filter((v) => v !== "benign")
        .map((v) => ({ value: v, label: VERDICTS[v].word, count: tally((row) => verdictOf(row) === v) })),
      test: (row, v) => verdictOf(row) === v || (v === "benign_expected" && row.verdict === "benign"),
    },
    // `on`: `?entity=` belongs to the shell's EntityDialog.
    { id: "on", label: "entity", options: entities, test: (row, v) => row.entity_key === v },
    {
      id: "crew",
      label: "crew",
      // The crew works open cases only; a value from a link still shows as a chip.
      options: tab === "closed" ? [] : CREW_OPTIONS.map((o) => ({ ...o, count: tally(crew[o.value]!) })),
      test: (row, v) => crew[v]?.(row) ?? false,
    },
    {
      id: "since",
      label: tab === "closed" ? "closed" : "opened",
      options: ["24h", "7d", "30d"].map((v) => ({ value: v, label: `last ${v}` })),
      // An ISO since from another screen's link reads as a time, not as the raw value.
      word: sinceWord,
      test: (row, v) => inWindow(row, v, tab, now),
    },
    {
      id: "by",
      label: "closed by",
      options:
        tab === "all" || tab === "closed"
          ? BY_OPTIONS.map((o) => ({ ...o, count: tally((row) => closedBy(row, o.value)) }))
          : [],
      test: closedBy,
    },
    // Set only by a strip fact (the tabs pick a state), so it has no menu; "open" takes every open state.
    { id: "state", label: "state", test: (row, v) => (v === "open" ? isOpen(row) : row.state === v) },
  ];
  const filters = useFilters(dims, { match: matches });
  // The list remounts on a new tab, sort or filter, so each lands on its first page.
  const listKey = JSON.stringify([tab, sortBy, filters.text, filters.values]);
  const fresh = useFlash(rows?.map((row) => [row.case_uid, row.updated_at]));

  const failed = cases.isError && !rows;
  // A fact counts open cases, so it lands on All with its parameter and state=open alone:
  // the list reproduces the number from any tab. Pressed again, it lifts both. A fact that
  // counts nothing (0, or "—" while unknown) would only filter to an empty list, so it
  // presses only while on, to lift.
  const press = (id: (typeof FACTS)[number][0], value: string, count: number | null = 1) => {
    const on = tab === "all" && params.get(id) === value && params.get("state") === "open";
    if (!count && !on) return {};
    return {
      pressed: on,
      onClick: () =>
        setParams((current) => {
          if (!on) return { [id]: value, state: "open" };
          const out = new URLSearchParams(current);
          for (const name of [id, "state", "page"]) out.delete(name);
          return out;
        }),
    };
  };
  const oldest = order(open, "oldest")[0];
  // The state already says no case is open; four zeros would only repeat it.
  const quiet = !cases.isPending && !failed && open.length === 0;
  const critical = open.filter((r) => r.severity === "critical").length;
  const high = open.filter((r) => r.severity === "high").length;
  const busy = presence.ready ? open.filter(working).length : null;
  const stuck = alerts.data ? open.filter(crew.stalled!).length : null;
  const facts: StripFact[] = quiet
    ? []
    : [
        { label: "critical", value: critical, ...press("severity", "critical", critical) },
        { label: "high", value: high, ...press("severity", "high", high) },
        { label: "crew working", value: busy, tone: busy ? "crew" : undefined, ...press("crew", "working", busy) },
        { label: "stalled", value: stuck, tone: stuck ? "warn" : undefined, ...press("crew", "stalled", stuck) },
        ...(oldest ? [{ label: "oldest", value: age(oldest.opened_at, now), tip: "Sort by age", ...press("sort", "oldest") }] : []),
      ];
  const state = open.some((r) => r.severity === "critical")
    ? { tone: "bad" as const, word: "Critical" }
    : open.length
      ? { tone: "idle" as const, word: "Open" }
      : { tone: "good" as const, word: "No open cases" };

  const count = (n: number) => (failed ? null : cases.isPending ? null : n);
  const isCapped = all.length >= CASE_CAP;
  const columns: Column<Case>[] = [
    {
      label: "Crew",
      width: 40,
      truncate: false,
      // Working, waits on you, stalled, idle; then closed rows by who closed them.
      sort: (row) =>
        isOpen(row)
          ? [working, crew.waiting!, crew.stalled!, () => true].findIndex((test) => test(row))
          : 5 + ["crew", "human", "system"].indexOf(row.closed_by ?? ""),
      // A 16px box with or without a glyph: the badge column never moves between views.
      cell: (row) => (
        <span className="flex w-4">
          {isOpen(row) ? (
            <CrewState row={row} waiting={waiting.has(row.case_uid)} stalled={stalled.has(row.case_uid)} />
          ) : (
            <Closer by={row.closed_by} />
          )}
        </span>
      ),
    },
    {
      // Severity on open rows, the verdict on closed ones: the badge says which. Open rows sort first.
      label: "Severity",
      fit: true,
      sort: (row) =>
        isOpen(row) ? SEVERITIES.indexOf(row.severity) : SEVERITIES.length + Object.keys(VERDICTS).indexOf(verdictOf(row)),
      // A phone keeps a verdict's glyph and drops its word (still heard), as a row's status badge does.
      cell: (row) =>
        isOpen(row) ? (
          <SeverityBadge severity={row.severity} />
        ) : (
          <span className={PHONE_GLYPH}>
            <VerdictBadge verdict={verdictOf(row)} />
          </span>
        ),
    },
    // The time ends the name's cell rather than holding a 72px column: a column counts toward the
    // table's narrowest width, which a 375px phone cannot fit, and a column dropped under 1024px
    // left phone rows with no time at all.
    {
      label: "Case",
      strong: true,
      truncate: false,
      sort: (row) => huntTitle(row.title) ?? row.title,
      cell: (row) => <Name row={row} ago={timeOf(row, now)} />,
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Cases"
        strip={
          <Strip
            state={state}
            facts={facts}
            loading={cases.isPending}
            error={failed ? cases.error : undefined}
            onRetry={() => void cases.refetch()}
            asOf={cases.isError && rows ? new Date(cases.dataUpdatedAt).toISOString() : null}
          />
        }
      />
      <Tabs
        id="cases"
        label="Cases"
        value={tab}
        onChange={setTab}
        tabs={TABS.map((id) => ({
          value: id,
          // The kernel returns 200 cases at most; a full log reads "200+" (section 7 item 16).
          label: id === "all" && isCapped ? `All ${capped(all.length, CASE_CAP)}` : TAB_LABEL[id],
          count: id === "all" ? (isCapped ? undefined : count(all.length)) : count(buckets[id].length),
        }))}
      />
      <TabPanel id="cases" value={tab}>
        <Card>
          <FilterBar
            dims={dims}
            value={filters.values}
            onChange={filters.set}
            text={filters.text}
            onText={filters.setText}
            onClear={filters.clear}
            placeholder="Filter cases"
          />
          <CaseList
            key={listKey}
            rows={inTab.filter(filters.keep)}
            sortBy={sortBy}
            columns={columns}
            isNew={(row) => fresh.has(row.case_uid)}
            loading={cases.isPending}
            error={failed ? cases.error : undefined}
            onRetry={() => void cases.refetch()}
            empty={
              filters.active && inTab.length ? (
                <Empty
                  kind="filtered"
                  title="No case matches"
                  chips={[
                    ...filters.chips.map((c) => (
                      <Chip key={c.id} label={c.label} value={c.word} />
                    )),
                    filters.text ? <Chip key="q" value={`“${filters.text}”`} /> : null,
                  ]}
                  onClear={filters.clear}
                />
              ) : (
                <EmptyTab tab={tab} lastClosed={buckets.closed[0] ? lastClosed(buckets.closed) : null} />
              )
            }
          />
        </Card>
      </TabPanel>
    </div>
  );
}

/**
 * The table and its pager. Past the first page the order holds still: a
 * refresh keeps each row where it was and a case that opens waits for page one,
 * though the tab counts take it at once; back on page one the list sorts again.
 */
function CaseList({
  rows,
  sortBy,
  columns,
  isNew,
  loading,
  error,
  onRetry,
  empty,
}: {
  rows: Case[];
  sortBy: "" | "oldest";
  columns: Column<Case>[];
  isNew: (row: Case) => boolean;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  empty: ReactNode;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [held, setHeld] = useState<string[] | null>(null);
  const sorted = useSort(order(rows, sortBy), columns);
  const shown = hold(sorted.rows, held);
  const { page, pager, start, prev, next, first } = usePaged(shown, 25, { cap: CASE_CAP });
  // Set while rendering, the documented way to keep what an earlier render showed.
  if ((start > 0) !== (held !== null)) setHeld(start > 0 ? shown.map((row) => row.case_uid) : null);
  const nav = useListNav(page, (row) => row.case_uid, {
    // Escape on the case comes back to this tab, filters and page kept.
    onOpen: (row) => navigate(`/cases/${row.case_uid}`, { state: { back: `${location.pathname}${location.search}` } }),
    onPrevPage: prev,
    onNextPage: next,
  });
  useCommand("cases.copy-id", () => {
    const row = page.find((r) => r.case_uid === nav.activeKey);
    if (row) void copyAndSay(row.case_uid);
  });
  return (
    <>
      <Table
        label="Cases"
        columns={columns}
        rows={page}
        sort={sorted.sort}
        onSort={first}
        rowKey={(row) => row.case_uid}
        rowProps={nav.rowProps}
        activeKey={nav.activeKey}
        isNew={isNew}
        loading={loading}
        error={error}
        onRetry={onRetry}
        empty={empty}
      />
      {pager}
    </>
  );
}

/** One time per row: how long an open case has been open, how long ago a closed one closed. */
const timeOf = (row: Case, now: number) => age(isOpen(row) ? row.opened_at : (row.closed_at ?? row.updated_at), now);

/** A closed case shows the disposition a person or the crew closed it with, never a stale "needs you". */

const lastClosed = (closed: Case[]) =>
  closed.reduce((newest, row) => ((row.closed_at ?? "") > newest ? (row.closed_at ?? "") : newest), "");

function EmptyTab({ tab, lastClosed }: { tab: TabId; lastClosed: string | null }) {
  if (tab === "investigating")
    return <Empty kind="row" title="No open investigations" meta={lastClosed ? `last closed ${age(lastClosed)} ago` : undefined} />;
  const words: Record<TabId, string> = {
    all: "No cases yet",
    investigating: "",
    contained: "Nothing contained",
    closed: "Nothing closed",
  };
  return <Empty kind="row" title={words[tab]} />;
}

/**
 * The title; a telescope after it for a hunt-born case, so every title starts
 * on one edge; the entity when the title does not name it; the row's one time
 * at the end, at least 48px from 768px so every title clips on one edge. From
 * 768px the name is one 20px line that wraps and clips: the entity stays on it
 * only while the title leaves it 88px, so the title never ellipsizes first and
 * the entity is readable or gone, as in the inbox. Under 768px the title takes
 * up to two lines and the entity the line under it.
 */
function Name({ row, ago }: { row: Case; ago: string }) {
  const hunt = huntTitle(row.title);
  return (
    <span className="flex min-w-0 items-center gap-3">
      <span className="flex min-w-0 flex-1 items-center gap-2 md:h-5 md:flex-wrap md:overflow-hidden max-md:flex-col max-md:items-start max-md:gap-0.5 max-md:py-1.5">
        {/* A phone gives the title up to two lines and the entity the line under it, as Findings does. The
            telescope shares the title's item, so the wrapping name never strands it on the clipped line. */}
        <span className="flex min-w-0 max-w-full items-center gap-2">
          <span className="truncate max-md:line-clamp-2 max-md:whitespace-normal">{hunt ?? row.title}</span>
          {hunt !== null ? (
            <Tip label="From a hunt">
              <Telescope className="h-3.5 w-3.5 shrink-0 text-fg-3" role="img" aria-label="hunt" />
            </Tip>
          ) : null}
        </span>
        {row.entity_key && !row.title.includes(bare(row.entity_key)) ? (
          <span className="flex min-w-0 max-w-max grow basis-[88px] max-md:max-w-full max-md:basis-auto">
            <Entity value={row.entity_key} />
          </span>
        ) : null}
      </span>
      <span className="shrink-0 text-right font-mono text-xs text-fg-3 tabular md:min-w-12">{ago}</span>
    </span>
  );
}

const CLOSERS: Record<string, { kind: string; label: string; glyph: ReactNode }> = {
  crew: { kind: "crew", label: "Closed by the crew", glyph: "›" },
  human: { kind: "human", label: "Closed by a person", glyph: <User aria-hidden /> },
  system: { kind: "system", label: "Closed by shoc", glyph: <Cog aria-hidden /> },
};

/** Who closed it; the row names no closer, so the deciding role and the person live on the case page. */
function Closer({ by }: { by: Case["closed_by"] }) {
  const closer = by ? CLOSERS[by] : undefined;
  if (!closer) return null;
  return (
    <Tip label={closer.label}>
      <span className={`sh-avatar sh-avatar--16 sh-avatar--${closer.kind}`} role="img" aria-label={closer.label}>
        {closer.glyph}
      </span>
    </Tip>
  );
}
