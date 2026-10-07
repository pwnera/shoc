/**
 * Intel › Indicators: the newest 200 indicators, filtered by type and text
 * in the kernel and by severity and source over the loaded rows. A row is a
 * severity square, the exact type (a URL stays a URL), the value (a URL
 * defanged) and when it was last seen; source, confidence and tags are in the indicator dialog,
 * which a row opens (`?ioc=`). Add (`N`) is the tab's action.
 */
import { Plus } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { age } from "@/lib/format";
import { SEVERITIES, severityLabel } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow, usePopParam } from "@/lib/popup";
import type { Indicator } from "@/types";
import { defang, feedName } from "./feeds";
import { IndicatorDialog } from "./IndicatorDialog";

/** What `intel.list` takes as a type. */
const TYPES = ["ip", "domain", "url", "sha256", "md5", "cve"];

export function Indicators({
  rows: loaded,
  capped,
  loading,
  error,
  onRetry,
  onAdd,
}: {
  rows: Indicator[];
  /** The kernel returned its limit: these are the newest, not all. */
  capped: boolean;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onAdd: () => void;
}) {
  const now = useNow();
  const [params] = useSearchParams();
  const sources = [...new Set(loaded.map((r) => r.source))].sort();
  const dims: Dim<Indicator>[] = [
    // The kernel filters type and text; severity and source filter the loaded rows.
    { id: "type", label: "type", options: TYPES.map((t) => ({ value: t })) },
    {
      id: "severity",
      label: "severity",
      options: SEVERITIES.map((s) => ({ value: s, label: severityLabel(s), count: loaded.filter((r) => r.severity === s).length })).filter(
        (o) => o.count,
      ),
      test: (r, v) => r.severity === v,
    },
    {
      id: "source",
      label: "source",
      options: sources.map((s) => ({ value: s, label: feedName(s), count: loaded.filter((r) => r.source === s).length })),
      test: (r, v) => r.source === v,
    },
  ];
  const filters = useFilters(dims);
  const rows = loaded.filter(filters.keep);
  const paged = usePaged(rows, 25, { newest: capped });
  const pop = usePopParam("ioc");
  const open = (row: Indicator | undefined, replace = false) => pop(row && row.value, replace);
  const nav = useListNav(paged.page, (r) => `${r.type}:${r.value}`, {
    onOpen: (r) => open(r),
    copy: (r) => r.value,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const at = rows.findIndex((r) => r.value === params.get("ioc"));
  const picked = rows[at];
  // J and K in the dialog turn the pager and move the active row with them.
  useFollow(nav, picked ? `${picked.type}:${picked.value}` : "", {
    keys: rows.map((r) => `${r.type}:${r.value}`),
    size: 25,
    go: paged.go,
  });

  const columns: Column<Indicator>[] = [
    {
      label: "",
      fit: true,
      cell: (r) => (
        <span className="inline-flex items-center gap-2">
          <Mark tone={r.severity} label={severityLabel(r.severity)} />
          <Badge>{r.type}</Badge>
        </span>
      ),
    },
    { label: "", mono: true, strong: true, cell: (r) => defang(r.type, r.value) },
    { label: "", fit: true, mono: true, hide: "md", cell: (r) => age(r.last_seen, now) },
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
        placeholder="Filter indicators"
      >
        <Tip label="Add indicators" kbd="N">
          <Button size="sm" onClick={onAdd} aria-keyshortcuts="N">
            <Plus aria-hidden />
            Add indicators
          </Button>
        </Tip>
      </FilterBar>
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(r) => `${r.type}:${r.value}`}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Indicators"
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No indicator matches" onClear={filters.clear} />
          ) : (
            <Empty kind="row" title="No indicators" />
          )
        }
      />
      {paged.pager}
      {picked ? (
        <IndicatorDialog
          indicator={picked}
          onClose={() => open(undefined, true)}
          step={{
            index: at,
            total: rows.length,
            onPrev: at > 0 ? () => open(rows[at - 1], true) : undefined,
            onNext: at < rows.length - 1 ? () => open(rows[at + 1], true) : undefined,
          }}
        />
      ) : null}
    </>
  );
}
