/**
 * Events as rows, the same everywhere: the product's logo and an outcome mark
 * as glyphs, the operation as the name with actor and source IP after it, and
 * the time. Every other field lives in EventDialog, which a row opens with
 * stepping over the whole set ("3 / 25"), or the host's own `onOpen` (Explore
 * opens `?event=` itself). Paged at 25 unless told otherwise; `page` and
 * `onPage` keep the page in the URL, `cap` and `newest` say what the pager
 * says of a list the kernel cut.
 */
import { useState, type ReactNode } from "react";
import { stamp, time } from "@/lib/format";
import { useListNav } from "@/lib/commands";
import { usePaged } from "@/lib/paged";
import { focusRow, useFollow } from "@/lib/popup";
import { useSort } from "@/lib/sort";
import type { EventRow } from "@/types";
import { EventDialog } from "./EventDialog";
import { eventColumns } from "./eventColumns";
import { Table } from "./ui/table";

export function EventTable({
  rows: given,
  loading,
  error,
  onRetry,
  empty = "No events",
  bounded,
  size = 25,
  label = "Events",
  onOpen,
  page,
  onPage,
  cap,
  newest,
  followed = "",
}: {
  rows: EventRow[];
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  empty?: ReactNode;
  bounded?: boolean | number;
  size?: number;
  label?: string;
  /** Opens a row the host's way instead of the table's own EventDialog. */
  onOpen?: (row: EventRow, index: number) => void;
  page?: number;
  onPage?: (index: number) => void;
  cap?: number;
  newest?: boolean;
  /** The event the host's dialog shows: the active row and the page follow it through J and K. */
  followed?: string;
}) {
  const [open, setOpen] = useState<number | null>(null);
  // One day of rows reads HH:MM:SS; a longer set keeps its date.
  const days = new Set(given.map((r) => String(r.time ?? "").slice(0, 10)));
  const when = (value: string) => (days.size > 1 ? stamp(value) : time(value));
  const columns = eventColumns(when);
  const sorted = useSort(given, columns);
  const rows = sorted.rows;
  const paged = usePaged(rows, size, { cap, newest, page, onPage });
  const nav = useListNav(paged.page, (r) => String(r.event_uid), {
    onOpen: (r) => (onOpen ? onOpen(r, rows.indexOf(r)) : setOpen(rows.indexOf(r))),
    copy: (r) => String(r.event_uid),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  useFollow(nav, followed, { keys: rows.map((r) => String(r.event_uid)), size, go: paged.go });
  return (
    <>
      <div>
        <Table
          columns={columns}
          rows={paged.page}
          sort={sorted.sort}
          onSort={paged.first}
          rowKey={(r) => String(r.event_uid)}
          rowProps={nav.rowProps}
          loading={loading}
          error={error}
          onRetry={onRetry}
          empty={empty}
          bounded={bounded}
          label={label}
        />
        {paged.pager}
      </div>
      {open !== null && rows[open] ? (
        <EventDialog
          event={rows[open]}
          // After J and K the row to return to is the one the dialog ended on.
          onClose={() => {
            const uid = String(rows[open]!.event_uid);
            setOpen(null);
            nav.setActive(uid);
            focusRow(uid);
          }}
          step={{
            index: open,
            total: rows.length,
            onPrev: open > 0 ? () => setOpen(open - 1) : undefined,
            onNext: open < rows.length - 1 ? () => setOpen(open + 1) : undefined,
          }}
        />
      ) : null}
    </>
  );
}
