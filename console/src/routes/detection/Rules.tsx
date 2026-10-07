/**
 * Every rule, the ones that need a look first: failing, noisy, field empty,
 * live, armed, never sent, no source, then by severity. A row is the severity
 * and product glyphs, the state badge, the title and when it last fired; the
 * rest is the rule page's. Filters (product, tactic, severity, state and the
 * text) live in the URL, so the strip and other screens link here filtered;
 * a new filter starts on the first page, and back from a rule turns to the
 * page that holds it. New rule (N, `?new=rule`, so Back closes it) writes one
 * as YAML behind Check and Merge.
 *
 * Capabilities used: detection.merge, playbook.list (the playbook a new rule
 * hands its cases to); the rows are Detection's `rule.list` and `health.rules`.
 */
import { useLayoutEffect, useRef, type ReactNode } from "react";
import { Plus } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import type { UseQueryResult } from "@tanstack/react-query";
import { productName } from "@/components/brands";
import { RuleEditor } from "@/components/Editors";
import { Button } from "@/components/ui/button";
import { FilterBar } from "@/components/ui/filterbar";
import { ProductLogo } from "@/components/ui/logo";
import { Empty } from "@/components/ui/misc";
import { Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { tacticLabel, tacticsOf, TACTICS } from "@/lib/attack";
import { keyLabel, useCommand, useListNav } from "@/lib/commands";
import { copyAndSay } from "@/lib/copy";
import { useFilters, type Dim, type Option } from "@/lib/filters";
import { age } from "@/lib/format";
import { RULE_STATES, SEVERITIES, severityLabel } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { usePopValue } from "@/lib/popup";
import { RuleStatus } from "./parts";
import { byAttention, type RuleRow } from "./state";

const SIZE = 25;

/** Options with their counts over the loaded rows; values that never occur are left out. */
function options(rows: RuleRow[], values: (row: RuleRow) => string[], label?: (value: string) => string): Option[] {
  const counts = new Map<string, number>();
  for (const row of rows) for (const v of new Set(values(row))) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts].map(([value, n]) => ({ value, label: label?.(value) ?? value, count: n }));
}

const productOf = (row: RuleRow) => row.logsource.product ?? "";
const productLabel = productName;

function dims(rows: RuleRow[]): Dim<RuleRow>[] {
  const rank = (list: readonly string[]) => (a: Option, b: Option) => list.indexOf(a.value) - list.indexOf(b.value);
  return [
    {
      id: "product",
      label: "product",
      options: options(rows, (r) => [productOf(r)], productLabel).sort((a, b) => a.label!.localeCompare(b.label!)),
      test: (r, v) => productOf(r) === v,
    },
    {
      id: "tactic",
      label: "tactic",
      options: options(rows, (r) => tacticsOf(r.attack), tacticLabel).sort(rank(TACTICS.map(([id]) => id))),
      test: (r, v) => tacticsOf(r.attack).includes(v as never),
    },
    {
      id: "severity",
      label: "severity",
      options: options(rows, (r) => [r.severity], severityLabel).sort(rank(SEVERITIES)),
      test: (r, v) => r.severity === v,
    },
    {
      id: "state",
      label: "state",
      options: RULE_STATES.flatMap((s) => {
        const n = rows.filter((r) => r.state === s.id).length;
        return n ? [{ value: s.id, label: s.word, count: n }] : [];
      }),
      test: (r, v) => r.state === v,
    },
  ];
}

function match(row: RuleRow, text: string): boolean {
  return (
    row.id.includes(text) ||
    row.title.toLowerCase().includes(text) ||
    productOf(row).includes(text) ||
    row.attack.some((t) => t.toLowerCase().includes(text))
  );
}

/** The severity square and the product's logo (or its initial when the console has none); a phone keeps the square. */
function Glyphs({ row }: { row: RuleRow }) {
  const product = productOf(row);
  return (
    <span className="inline-flex items-center gap-2">
      <Tip label={severityLabel(row.severity)}>
        <Mark tone={row.severity} label={`severity ${severityLabel(row.severity)}`} />
      </Tip>
      <Tip label={product || "no product"} mono>
        <span className="inline-flex max-md:hidden">
          <ProductLogo product={product} named />
        </span>
      </Tip>
    </span>
  );
}

export function Rules({
  rows,
  rules,
  health,
}: {
  rows: RuleRow[];
  rules: Pick<UseQueryResult, "isPending" | "error" | "refetch" | "data">;
  health: Pick<UseQueryResult, "isPending" | "isError" | "data">;
}) {
  const dimensions = dims(rows);
  const filters = useFilters(dimensions, { match });
  const shown = rows.filter(filters.keep).sort(byAttention);
  const [writing, setWriting] = usePopValue("new");
  useCommand("detection.new-rule", () => setWriting("rule"));
  return (
    <section className="sh-card" aria-label="Rules">
      <FilterBar
        dims={dimensions}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter rules"
      >
        <Tip label="New rule" kbd={keyLabel("n")}>
          <Button size="sm" onClick={() => setWriting("rule")} aria-keyshortcuts="N">
            <Plus aria-hidden />
            New rule
          </Button>
        </Tip>
      </FilterBar>
      {writing === "rule" ? <RuleEditor onClose={() => setWriting(null)} /> : null}
      {/* Another filter is another list, so it starts on its first page. */}
      <RuleList
        key={JSON.stringify([filters.values, filters.text])}
        rows={shown}
        rules={rules}
        health={health}
        empty={filters.active ? <Empty kind="filtered" title="No rule matches" onClear={filters.clear} /> : "No rules"}
      />
    </section>
  );
}

function RuleList({
  rows,
  rules,
  health,
  empty,
}: {
  rows: RuleRow[];
  rules: Pick<UseQueryResult, "isPending" | "error" | "refetch" | "data">;
  health: Pick<UseQueryResult, "isPending" | "isError" | "data">;
  empty: ReactNode;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const now = useNow();
  const paged = usePaged(rows, SIZE);
  // Back and the rule page's Escape both return here, filters and all, to the page that holds the rule.
  const open = (row: RuleRow) => {
    navigate({ pathname: location.pathname, search: location.search }, { replace: true, state: { row: row.id } });
    navigate(`/detection/rules/${encodeURIComponent(row.id)}`, {
      state: { back: location.pathname + location.search },
    });
  };
  const nav = useListNav(paged.page, (r) => r.id, {
    onOpen: open,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // C copies with a toast, over HTTP too; the route's key wins over the list's.
  useCommand("detection.copy-id", () => {
    if (nav.activeKey) void copyAndSay(nav.activeKey);
  });

  // Back from a rule (`state.row`): turn to its page a page per render, before paint, then make its row
  // the active one. The order needs health, so the walk waits for it.
  const restore = useRef((location.state as { row?: string } | null)?.row ?? "");
  useLayoutEffect(() => {
    const id = restore.current;
    if (!id || rules.isPending || health.isPending) return;
    const at = rows.findIndex((r) => r.id === id);
    if (at >= paged.start + SIZE) return paged.next();
    restore.current = "";
    if (at < 0) return;
    nav.setActive(id);
    document.querySelector<HTMLElement>(`main [data-row-key="${CSS.escape(id)}"]`)?.focus();
  });

  // A failed refresh keeps the states it had.
  const unknown = health.isPending || (health.isError && !health.data);
  const columns: Column<RuleRow>[] = [
    { label: "", width: 44, truncate: false, cell: (r) => <Glyphs row={r} /> },
    {
      label: "",
      fit: true,
      cell: (r) => <RuleStatus health={r.health} />,
    },
    {
      label: "",
      strong: true,
      truncate: false,
      // A phone gives the title two lines before it clips.
      cell: (r) => (
        <Tip label={r.id} mono>
          <span className="block truncate max-md:line-clamp-2 max-md:whitespace-normal">{r.title}</span>
        </Tip>
      ),
    },
    {
      label: "",
      width: 72,
      align: "right",
      mono: true,
      cell: (r) => (unknown || !r.health ? "—" : age(r.health.last_fired, now)),
    },
  ];

  // Rows wait for health too: they sort by its state, so drawing them before it lands would move them.
  return (
    <>
      <Table
        label="Rules"
        columns={columns}
        rows={paged.page}
        rowKey={(r) => r.id}
        rowProps={nav.rowProps}
        loading={rules.isPending || health.isPending}
        // A failed refresh keeps the rows; the strip says how old they are.
        error={rules.data ? undefined : rules.error}
        onRetry={() => void rules.refetch()}
        empty={empty}
      />
      {/* Drawn with the rows, so it never sits under the skeleton and then jumps down. */}
      {rules.isPending || health.isPending ? null : paged.pager}
    </>
  );
}
