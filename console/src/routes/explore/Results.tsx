/**
 * One page of the loaded events in a box that fills the viewport, under a
 * sticky row per day. The row anatomy is EventTable's (`eventColumns`).
 * Heads do not sort: sorting 100 rows of 1,707 would pass a sample off as the
 * window's oldest or newest, so rows stay newest first. The open event stays
 * marked after its dialog closes.
 */
import type { ReactNode } from "react";
import { eventColumns } from "@/components/eventColumns";
import { Table } from "@/components/ui/table";
import { day, time } from "@/lib/format";
import type { EventRow } from "@/types";

/** The viewport under the histogram, never below 320px: the results grow to it, then scroll; the field rail stops at it too. */
export const FILL = "max-h-[max(320px,calc(100dvh-28.5rem))]";

// Each day has its own heading, so a row reads HH:MM:SS.
const COLUMNS = eventColumns(time);

export function Results({
  rows,
  rowProps,
  loading,
  error,
  onRetry,
  empty,
}: {
  rows: EventRow[];
  rowProps: (row: EventRow) => Record<string, unknown>;
  loading: boolean;
  error?: unknown;
  onRetry: () => void;
  empty: ReactNode;
}) {
  const days: { day: string; rows: EventRow[] }[] = [];
  for (const row of rows) {
    const d = day(String(row.time));
    if (days.at(-1)?.day === d) days.at(-1)!.rows.push(row);
    else days.push({ day: d, rows: [row] });
  }
  const table = (list: EventRow[], label: string) => (
    <Table
      columns={COLUMNS}
      rows={list}
      rowKey={(r) => String(r.event_uid)}
      rowProps={rowProps}
      loading={loading}
      error={error}
      onRetry={onRetry}
      empty={empty}
      label={label}
    />
  );
  return (
    <div className={`${FILL} overflow-y-auto scrollbar-thin`} aria-busy={loading || undefined}>
      {loading || error || !rows.length
        ? table([], "Events")
        : days.map((group) => (
            <section key={group.day} aria-label={group.day}>
              <h3 className="sticky top-0 z-[2] m-0 flex h-6 items-center border-b border-line-1 bg-bg-1 px-3 [font:var(--text-mono)] text-fg-3">
                {group.day}
              </h3>
              {table(group.rows, `Events on ${group.day}`)}
            </section>
          ))}
    </div>
  );
}
