/**
 * Response › Pages: every page to the on-call person, grouped by the case it
 * was about, the newest first. A group reads the state most of its pages are
 * in, in the words the case's Pages tab uses: delivered, planned (a dry run),
 * not sent, withdrawn; a split group says so in the badge's tip, so 36 pages
 * in one state and 1 in another never hide behind "mixed". The page message is the record's own words and lives in
 * ActionDialog, never in a column. A row opens the case on its Pages tab, or
 * ActionDialog for a page with no case. The tab counts pages, as the
 * Overview's counter does; the pager says how many groups hold them. The text
 * (`?pq=`) matches the case title and who was paged; the state chip keeps the
 * pages in one state, so a group shows only those.
 *
 * Capabilities used: action.list (the shared log), case.list (case titles).
 */
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { Telescope } from "lucide-react";
import { Card } from "@/components/ui/card";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Mark, Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { huntTitle } from "@/lib/cases";
import { age, count, shortId } from "@/lib/format";
import { isPage, pageState, type Word } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useActionLog, useCaseLog } from "@/lib/queries";
import { sinceDim } from "@/lib/since";
import type { Action, Case } from "@/types";

type Group = {
  key: string;
  caseUid: string | null;
  pages: Action[];
  last: string;
  /** The state most pages are in; `split` counts every state when they differ. */
  state: Word;
  split: { state: Word; n: number }[] | null;
};

function grouped(pages: Action[]): Group[] {
  const by = new Map<string, Action[]>();
  // A page with no case stands alone, so it can open its own dialog.
  for (const p of pages) by.set(p.case_uid ?? p.action_uid, [...(by.get(p.case_uid ?? p.action_uid) ?? []), p]);
  return [...by]
    .map(([key, list]): Group => {
      const tally = new Map<string, { state: Word; n: number }>();
      for (const p of list) {
        const state = pageState(p);
        tally.set(state.word, { state, n: (tally.get(state.word)?.n ?? 0) + 1 });
      }
      // Most first; a page that went out wins a tie, since that is the one somebody saw.
      const out = (s: { state: Word }) => Number(s.state.word === "delivered");
      const split = [...tally.values()].sort((a, b) => b.n - a.n || out(b) - out(a));
      const last = list.reduce((m, p) => (Date.parse(p.created_at) > Date.parse(m) ? p.created_at : m), list[0]!.created_at);
      return {
        key,
        caseUid: list[0]!.case_uid,
        pages: list,
        last,
        state: split[0]!.state,
        split: split.length > 1 ? split : null,
      };
    })
    .sort((a, b) => Date.parse(b.last) - Date.parse(a.last));
}

export function Pages() {
  const log = useActionLog();
  const cases = useCaseLog();
  const now = useNow();
  const navigate = useNavigate();
  const location = useLocation();
  const [, setParams] = useSearchParams();
  const byCase = new Map<string, Case>((cases.data?.rows ?? []).map((c) => [c.case_uid, c]));
  const all = (log.data?.rows ?? []).filter(isPage);
  const states = new Map<string, number>();
  for (const p of all) states.set(pageState(p).word, (states.get(pageState(p).word) ?? 0) + 1);
  const dims: Dim<Action>[] = [
    sinceDim<Action>((a) => a.created_at),
    {
      id: "pstate",
      label: "state",
      options: [...states].map(([value, n]) => ({ value, count: n })),
      test: (a, v) => pageState(a).word === v,
    },
  ];
  const filters = useFilters(dims, {
    text: "pq",
    match: (a, text) => `${(a.case_uid && byCase.get(a.case_uid)?.title) ?? ""} ${a.target}`.toLowerCase().includes(text),
  });
  const rows = grouped(all.filter(filters.keep));

  const open = (g: Group) => {
    if (g.caseUid) navigate(`/cases/${g.caseUid}?tab=pages`, { state: { back: location.pathname + location.search } });
    else
      setParams((current) => {
        const out = new URLSearchParams(current);
        out.set("action", g.pages[0]!.action_uid);
        return out;
      });
  };
  const sent = rows.reduce((n, g) => n + g.pages.length, 0);
  const { page, pager, prev, next } = usePaged(rows, 25, {
    of: rows.length === sent ? undefined : `${count(rows.length, "group")} · ${count(sent, "page")}`,
  });
  const nav = useListNav(page, (g) => g.key, { onOpen: open, onPrevPage: prev, onNextPage: next });

  const columns: Column<Group>[] = [
    {
      label: "",
      width: 28,
      cell: (g) => {
        const severity = g.caseUid ? byCase.get(g.caseUid)?.severity : undefined;
        return <Mark tone={severity ?? "idle"} label={severity ?? "severity unknown"} />;
      },
    },
    { label: "", fit: true, cell: (g) => <GroupState group={g} /> },
    {
      label: "",
      strong: true,
      truncate: false,
      // The count stays outside the part that truncates, so a narrow screen keeps it.
      cell: (g) => {
        const title = g.caseUid ? (byCase.get(g.caseUid)?.title ?? shortId(g.caseUid)) : "no case";
        const hunt = huntTitle(title);
        return (
          <span className="flex min-w-0 items-center gap-2">
            <span className="sh-cell min-w-0">{hunt ?? title}</span>
            {hunt !== null ? (
              <Tip label="From a hunt">
                <Telescope className="h-3.5 w-3.5 shrink-0 text-fg-3" role="img" aria-label="hunt" />
              </Tip>
            ) : null}
            {g.pages.length > 1 ? <span className="sh-tl__count shrink-0">×{g.pages.length}</span> : null}
          </span>
        );
      },
    },
    { label: "", width: 56, align: "right", mono: true, cell: (g) => age(g.last, now) },
  ];

  return (
    <Card>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter pages"
      />
      <Table
        columns={columns}
        rows={page}
        rowKey={(g) => g.key}
        rowProps={nav.rowProps}
        loading={log.isPending}
        error={log.data ? undefined : log.error}
        onRetry={() => void log.refetch()}
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No page matches" onClear={filters.clear} />
          ) : (
            <Empty kind="row" title="Nobody was paged" />
          )
        }
        label="Pages"
      />
      {pager}
    </Card>
  );
}

/** The group's badge; its tip names every state of a split group. */
function GroupState({ group }: { group: Group }) {
  const { word, tone } = group.state;
  const badge = (
    <Status tone={tone} badge>
      {word}
    </Status>
  );
  const tip = group.split?.map((s) => `${s.n} ${s.state.word}`).join(" · ") ?? "";
  if (!tip) return badge;
  return (
    <Tip label={tip} mono>
      <span className="inline-flex">{badge}</span>
    </Tip>
  );
}
