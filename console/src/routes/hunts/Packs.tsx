/**
 * Hunts › Packs: whether each pack can be answered here. Applicable (ready,
 * learning, stale) by default, so the packs no connected source can feed stay
 * out of the first view; All lists every pack. A row is the product's logo,
 * the readiness, the title and the last run in the window, with a "couldn't
 * look" mark when the Ops role raised a `hunt.gap` for it. A row opens the pack
 * dialog (`?pack=`), the target of every `hunt:` link. New pack (N,
 * `?new=pack`, so Back closes it) writes one as YAML behind Check and Merge.
 *
 * Capabilities used: hunt.merge.
 */
import { useSearchParams } from "react-router-dom";
import { Plus } from "lucide-react";
import { PackEditor } from "@/components/Editors";
import { Button } from "@/components/ui/button";
import { FilterBar } from "@/components/ui/filterbar";
import { productName } from "@/components/brands";
import { ProductLogo } from "@/components/ui/logo";
import { Empty } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { Mark, Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { tacticLabel, tacticsOf, TACTICS } from "@/lib/attack";
import { keyLabel, useCommand, useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { age } from "@/lib/format";
import { READINESS } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow, usePopValue } from "@/lib/popup";
import { useParam } from "@/lib/param";
import type { HuntReadiness } from "@/types";
import { applicable, readyIn } from "./runs";

const productOf = (row: HuntReadiness) => row.product ?? "";

/** The readiness badge: "ready", "learning 27d", "stale", "not applicable"; `compact` drops the outline and word under 768px. */
export function Readiness({ row, now, compact }: { row: HuntReadiness; now: number; compact?: boolean }) {
  const word = READINESS[row.state] ?? { word: row.state, tone: "idle" as const };
  const tone = word.tone;
  const days = readyIn(row, now);
  const text = `${word.word}${days ? ` ${days}` : ""}`;
  return (
    <>
      <Status tone={tone} badge className={compact ? "max-md:hidden" : undefined}>
        {text}
      </Status>
      {compact ? <Status tone={tone} label={text} className="md:hidden" /> : null}
    </>
  );
}

export function Packs({
  readiness,
  lastRun,
  gaps,
  loading,
  error,
  onRetry,
  onOpen,
}: {
  /** Ordered `byReadiness`. */
  readiness: HuntReadiness[];
  lastRun: Map<string, string>;
  /** Packs with an open `hunt.gap` alert. */
  gaps: Set<string>;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onOpen: (row: HuntReadiness, list: HuntReadiness[]) => void;
}) {
  const now = useNow();
  const [show, setShow] = useParam<"applicable" | "all">("packs", "applicable");
  const [writing, setWriting] = usePopValue("new");
  useCommand("hunts.new-pack", () => setWriting("pack"));
  const shown = show === "all" ? readiness : readiness.filter(applicable);
  const count = (test: (row: HuntReadiness) => boolean) => shown.filter(test).length;
  const products = [...new Set(shown.map(productOf).filter(Boolean))].sort();
  const dims: Dim<HuntReadiness>[] = [
    {
      id: "product",
      label: "product",
      options: products.map((p) => ({ value: p, label: productName(p), count: count((r) => productOf(r) === p) })),
      test: (row, value) => productOf(row) === value,
    },
    {
      id: "tactic",
      label: "tactic",
      options: TACTICS.map(([id]) => ({
        value: id,
        label: tacticLabel(id),
        count: count((r) => tacticsOf(r.attack ?? []).includes(id)),
      })).filter((o) => o.count),
      test: (row, value) => (tacticsOf(row.attack ?? []) as string[]).includes(value),
    },
  ];
  // Its own text parameter: Runs, a tab away, keeps `q`.
  const filters = useFilters(dims, {
    text: "kq",
    match: (r, text) => `${r.title ?? ""} ${r.pack_id} ${r.hypothesis ?? ""}`.toLowerCase().includes(text),
  });
  const rows = shown.filter(filters.keep);
  const paged = usePaged(rows, 25);
  const nav = useListNav(paged.page, (r) => r.pack_id, {
    onOpen: (r) => onOpen(r, rows),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // The pack dialog's J and K turn the page and move the active row with them.
  const [params] = useSearchParams();
  useFollow(nav, params.get("pack") ?? "", { keys: rows.map((r) => r.pack_id), size: 25, go: paged.go });

  const columns: Column<HuntReadiness>[] = [
    {
      label: "",
      fit: true,
      cell: (r) => (
        <span className="flex items-center gap-1.5">
          <ProductLogo product={r.product} named />
          {gaps.has(r.pack_id) ? <Mark tone="warn" label="couldn't look" /> : null}
          <Readiness row={r} now={now} compact />
        </span>
      ),
    },
    { label: "", strong: true, cell: (r) => r.title ?? r.pack_id },
    { label: "", fit: true, mono: true, hide: "md", cell: (r) => (lastRun.has(r.pack_id) ? age(lastRun.get(r.pack_id), now) : "—") },
  ];

  return (
    <>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter packs"
      >
        <Seg
          label="Packs"
          value={show}
          onChange={setShow}
          options={[
            { value: "applicable", label: "Applicable" },
            { value: "all", label: "All", count: loading || error ? undefined : readiness.length },
          ]}
        />
        <Tip label="New pack" kbd={keyLabel("n")}>
          <Button size="sm" onClick={() => setWriting("pack")} aria-keyshortcuts="N">
            <Plus aria-hidden />
            New pack
          </Button>
        </Tip>
      </FilterBar>
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(r) => r.pack_id}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Packs"
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No pack matches" onClear={filters.clear} />
          ) : (
            <Empty kind="row" title={show === "all" ? "No packs" : "No pack can run here yet"} />
          )
        }
      />
      {paged.pager}
      {writing === "pack" ? <PackEditor onClose={() => setWriting(null)} /> : null}
    </>
  );
}
