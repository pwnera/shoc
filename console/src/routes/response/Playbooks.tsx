/**
 * Response › Playbooks: the catalogue and the one cross-case view of runs
 * that need a look. A row carries the logo of its first rule's product, the
 * status of its newest run (failed, waiting, running; nothing when done or
 * never run), "you" when any step waits for a person (a bare glyph under
 * 1024px, so the title keeps the room), the title and when it last ran. Until
 * the policy answers no row claims "you" or its absence. Runs that need a
 * look sort first. Filters: product and tactic
 * (joined through the rules it answers) and "last run failed" (`?run=failed`,
 * which Health's Playbooks stage links to). A row opens the playbook page.
 * New playbook (N, `?new=playbook`, so Back closes it) writes one as YAML from
 * the actions shoc has.
 *
 * Capabilities used: playbook.list, playbook.runs (newest run per playbook),
 * rule.list (products and techniques), policy.show (step autonomy),
 * playbook.merge.
 */
import { useLocation, useNavigate } from "react-router-dom";
import { Plus, User } from "lucide-react";
import { productName } from "@/components/brands";
import { PlaybookEditor } from "@/components/Editors";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { AutonomyBadge, Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { tacticLabel, tacticsOf, TACTICS } from "@/lib/attack";
import { keyLabel, useCommand, useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { age } from "@/lib/format";
import { runState } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { ruleOf } from "@/lib/policy";
import { usePopValue } from "@/lib/popup";
import { usePlaybooks, usePolicy, useRules, useRuns } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import type { Playbook, PlaybookRun, Rule } from "@/types";
import { PlatformMark } from "./marks";
import { newestRuns } from "./policy";

/** Runs that need a look first: failed, then waiting on a person, then running. */
const LOOK: Record<string, number> = { failed: 0, waiting_approval: 1, running: 2, waiting_timer: 3 };

type Row = {
  book: Playbook;
  products: string[];
  product: string | null;
  tactics: string[];
  run: PlaybookRun | undefined;
  /** Null until the policy answers: a missing policy reads as nothing, never as L2 everywhere. */
  human: boolean | null;
};

export function Playbooks() {
  const playbooks = usePlaybooks();
  const runs = useRuns({ limit: 200 });
  const rules = useRules();
  const policy = usePolicy();
  const now = useNow();
  const navigate = useNavigate();
  const location = useLocation();
  const [writing, setWriting] = usePopValue("new");
  useCommand("response.new-playbook", () => setWriting("playbook"));

  const byRule = new Map<string, Rule>((rules.data?.rules ?? []).map((r) => [r.id, r]));
  const levels = policy.data?.data;
  const newest = newestRuns(runs.data?.runs ?? []);
  const all: Row[] = (playbooks.data?.playbooks ?? []).map((book) => {
    const answered = book.rules.flatMap((id) => byRule.get(id) ?? []);
    const products = [...new Set(answered.flatMap((r) => r.logsource.product ?? []))].sort();
    return {
      book,
      products,
      product: answered.find((r) => r.logsource.product)?.logsource.product ?? null,
      tactics: tacticsOf([...book.trigger.attack_any, ...answered.flatMap((r) => r.attack)]),
      run: newest.get(book.id),
      human: levels ? book.steps.some((s) => ruleOf(levels, s.action).autonomy === "L2") : null,
    };
  });

  const count = (test: (row: Row) => boolean) => all.filter(test).length;
  const dims: Dim<Row>[] = [
    {
      id: "product",
      label: "product",
      options: [...new Set(all.flatMap((r) => r.products))]
        .map((p) => ({ value: p, label: productName(p), count: count((r) => r.products.includes(p)) }))
        .sort((a, b) => a.label.localeCompare(b.label)),
      test: (row, v) => row.products.includes(v),
    },
    {
      id: "tactic",
      label: "tactic",
      options: TACTICS.map(([id]) => ({ value: id, label: tacticLabel(id), count: count((r) => r.tactics.includes(id)) })).filter(
        (o) => o.count > 0,
      ),
      test: (row, v) => row.tactics.includes(v),
    },
    {
      id: "run",
      label: "run",
      options: [{ value: "failed", label: "last run failed", count: count((r) => r.run?.state === "failed") }],
      test: (row, v) => row.run?.state === v,
    },
  ];
  // Its own text parameter: Activity, a tab away, keeps `q`.
  const filters = useFilters(dims, {
    text: "bq",
    match: (row, text) => `${row.book.title} ${row.book.id}`.toLowerCase().includes(text),
  });

  const columns: Column<Row>[] = [
    {
      label: "Product",
      width: 56,
      truncate: false,
      sort: (row) => (row.product ? productName(row.product) : null),
      cell: (row) => <Glyphs row={row} pending={runs.isPending} />,
    },
    {
      label: "Approval",
      fit: true,
      sort: (row) => (row.human === null ? null : Number(!row.human)),
      cell: (row) => <You human={row.human} pending={policy.isPending} />,
    },
    { label: "Name", strong: true, cell: (row) => row.book.title },
    {
      label: "Last run",
      width: 64,
      align: "right",
      mono: true,
      sort: (row) => row.run?.started_at,
      cell: (row) =>
        runs.isError && !runs.data ? "—" : runs.isPending ? <Skel kind="text" width={32} /> : row.run ? age(row.run.started_at, now) : "never",
    },
  ];
  const sorted = useSort(
    all.filter(filters.keep).sort(
      (a, b) =>
        (LOOK[a.run?.state ?? ""] ?? 9) - (LOOK[b.run?.state ?? ""] ?? 9) ||
        (b.run?.started_at ?? "").localeCompare(a.run?.started_at ?? "") ||
        a.book.title.localeCompare(b.book.title),
    ),
    columns,
  );
  const rows = sorted.rows;
  const open = (row: Row) =>
    navigate(`/response/playbooks/${encodeURIComponent(row.book.id)}`, { state: { back: location.pathname + location.search } });
  const { page, pager, prev, next, first } = usePaged(rows, 25);
  const nav = useListNav(page, (row) => row.book.id, { onOpen: open, onPrevPage: prev, onNextPage: next });

  return (
    <Card>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter playbooks"
      >
        <Tip label="New playbook" kbd={keyLabel("n")}>
          <Button size="sm" onClick={() => setWriting("playbook")} aria-keyshortcuts="N">
            <Plus aria-hidden />
            New playbook
          </Button>
        </Tip>
      </FilterBar>
      <Table
        columns={columns}
        rows={page}
        sort={sorted.sort}
        onSort={first}
        rowKey={(row) => row.book.id}
        rowProps={nav.rowProps}
        loading={playbooks.isPending}
        error={playbooks.data ? undefined : playbooks.error}
        onRetry={() => void playbooks.refetch()}
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No playbook matches" onClear={filters.clear} />
          ) : (
            <Empty kind="row" title="No playbook is loaded" />
          )
        }
        label="Playbooks"
      />
      {pager}
      {writing === "playbook" ? <PlaybookEditor onClose={() => setWriting(null)} /> : null}
    </Card>
  );
}

/** The first rule's product logo and the newest run's status mark. */
function Glyphs({ row, pending }: { row: Row; pending: boolean }) {
  const state = row.run ? runState(row.run.state, row.run.dry_run) : null;
  const look = row.run && row.run.state !== "done" && row.run.state !== "cancelled";
  return (
    // A block, so the cell centres it on the row instead of sitting it on the text's baseline.
    <span className="flex items-center gap-2">
      {row.product ? <PlatformMark id={row.product} named /> : <span className="w-4" aria-hidden />}
      {!pending && look && state ? <Mark tone={state.tone} label={`last run ${state.word}`} /> : null}
    </span>
  );
}

/** "you" when a step waits for a person: the badge from 1024px, its bare glyph below. */
function You({ human, pending }: { human: boolean | null; pending: boolean }) {
  if (human === null) return pending ? <Skel kind="badge" /> : null;
  if (!human) return null;
  return (
    <>
      <span className="hidden lg:inline-flex">
        <AutonomyBadge level="L2" />
      </span>
      <Tip label="A person approves">
        <User className="block h-3.5 w-3.5 text-fg-2 lg:hidden" role="img" aria-label="you" />
      </Tip>
    </>
  );
}
