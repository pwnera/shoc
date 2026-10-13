/**
 * Health › Problems: the platform's own problems, one row each: the worker
 * (failed jobs, overdue schedules), the model, spend, notify (nobody
 * reachable, pages not sent), the store and its disk. Source, rule, case,
 * action, hunt and audit alerts render on the screens that own them. A row
 * opens its owner: the Jobs, Crew or Spend tab, Connections › Services, Pages,
 * or the store's facts, its disk among them. The kernel's alert prose is
 * never printed.
 *
 * Capabilities used: ops.alerts, health.status.
 */
import { useLocation, useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Empty } from "@/components/ui/misc";
import { Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { age, num, percent, stamp } from "@/lib/format";
import { useSort } from "@/lib/sort";
import type { SystemHealth } from "@/types";
import type { Problem } from "./model";

export function Problems({
  rows: given,
  loading,
  error,
  onRetry,
  onStore,
}: {
  rows: Problem[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  /** Opens the store's facts, the home of the store row. */
  onStore: () => void;
}) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  // `back` lets the tab it opens return here on Escape.
  const open = (row: Problem) => (row.to ? navigate(row.to, { state: { back: pathname } }) : onStore());
  const columns: Column<Problem>[] = [
    { label: "", width: 28, truncate: false, cell: (row) => <Mark tone={row.tone} label={row.tone === "bad" ? "failing" : "warning"} /> },
    { label: "Part", fit: true, cell: (row) => <Badge tone="muted">{row.component}</Badge> },
    {
      label: "Problem",
      truncate: false,
      // A long model name gives way; the word that says what is wrong stays whole.
      cell: (row) => (
        <span className="flex min-w-0 items-baseline gap-1">
          {row.id ? (
            <Tip label={row.id}>
              <span className="truncate text-fg-1">{row.subject}</span>
            </Tip>
          ) : (
            <span className="sh-mono sh-mono--strong truncate">{row.subject}</span>
          )}
          <span className="shrink-0 text-fg-3">· {row.word}</span>
        </span>
      ),
    },
  ];
  const sorted = useSort(given, columns);
  const rows = sorted.rows;
  const nav = useListNav(rows, (row) => row.key, { onOpen: open });
  return (
    <Table
      label="Platform problems"
      columns={columns}
      rows={rows}
      sort={sorted.sort}
      rowKey={(row) => row.key}
      rowProps={nav.rowProps}
      loading={loading}
      error={error}
      onRetry={onRetry}
      empty={<Empty kind="clear" title="No platform problems" />}
      bounded
    />
  );
}

/** The event store's facts: the Store stage and the store row open it. */
export function StoreDialog({ health, onClose }: { health: SystemHealth; onClose: () => void }) {
  const store = health.store;
  const disk = health.disk;
  // Postgres' size in the kernel's decimal GB, and its share of SHOC_DISK_BUDGET_GB when set.
  const gb = (n: number) => `${n.toFixed(1)} GB`;
  const budget = disk?.budget_gb ? ` of ${gb(disk.budget_gb)} · ${percent(disk.used)}` : "";
  return (
    <Dialog title="Event store" size="sm" onClose={onClose}>
      <Fields
        ruled
        rows={[
          ["Dialect", store.dialect],
          ["Reachable", store.ok ? "yes" : "no"],
          ["Latency", store.latency_ms !== undefined ? `${num(store.latency_ms)} ms` : null],
          ["Events", num(store.event_count)],
          ["Newest", store.latest_event ? `${stamp(store.latest_event)} · ${age(store.latest_event)}` : null],
          ["Disk", disk ? `${gb(disk.bytes / 1e9)}${budget}` : null],
          ["Detail", store.detail ? <span className="sh-mono">{store.detail}</span> : null],
        ]}
      />
    </Dialog>
  );
}
