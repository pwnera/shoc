/**
 * Health › Problems: the platform's own problems, one row each: the worker
 * (failed jobs, overdue schedules), the model, spend, and the store. Source,
 * rule, case, action, hunt and audit alerts render on the screens that own
 * them. A row opens its owner: the Jobs, Crew or Spend tab, or the store's
 * facts. The kernel's alert prose is never printed.
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
import { age, num, stamp } from "@/lib/format";
import type { SystemHealth } from "@/types";
import type { Problem } from "./model";

export function Problems({
  rows,
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
  const nav = useListNav(rows, (row) => row.key, { onOpen: open });
  const columns: Column<Problem>[] = [
    { label: "", width: 28, truncate: false, cell: (row) => <Mark tone={row.tone} label={row.tone === "bad" ? "failing" : "warning"} /> },
    { label: "", fit: true, cell: (row) => <Badge tone="muted">{row.component}</Badge> },
    {
      label: "",
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
  return (
    <Table
      label="Platform problems"
      columns={columns}
      rows={rows}
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
          ["Detail", store.detail ? <span className="sh-mono">{store.detail}</span> : null],
        ]}
      />
    </Dialog>
  );
}
