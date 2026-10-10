/**
 * A dense list: one 32px line per row, a hairline between rows, uppercase
 * mono heads on a 28px sticky row. One row anatomy for object lists: glyphs,
 * one badge, the name, one time; every other number lives on the record's page
 * or popup. A row opens its page or popup (Enter or Space too); rows never
 * expand. Every column but one has a width or `fit`; the free one takes the
 * rest and truncates. A trailing `menu` cell sits outside the row's click
 * target. While loading it draws skeleton rows; on error it never shows the
 * empty state. A list whose rows open something is a grid to assistive tech:
 * its active row is the selected one, and the table says what Enter does.
 * A head sorts its column (`useSort` in lib/sort): ascending, descending, then back to the
 * list's own order.
 */
import { useId, type KeyboardEvent, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/cn";
import { sortable, type Sorting } from "@/lib/sort";
import { Empty, ErrorNote } from "./misc";
import { Skel } from "./state";

export type Column<R> = {
  /** Empty on every column and the head row is left out. */
  label: string;
  cell: (row: R) => ReactNode;
  width?: number;
  align?: "right";
  mono?: boolean;
  strong?: boolean;
  /** Cells truncate with an ellipsis; false for a cell that holds controls. */
  truncate?: boolean;
  /** Sized to its content (badge columns); the table lays out automatically. */
  fit?: boolean;
  /** Dropped under 1024px. */
  hide?: "md";
  /** A trailing ⋯ menu: clicks and keys inside it never open the row. */
  menu?: boolean;
  /** What the head sorts by: the cell's text by default, false for a column that does not sort. */
  sort?: ((row: R) => string | number | null | undefined) | false;
};

/** Room for a free column before a narrow panel scrolls sideways instead of crushing it. */
const FREE = 160;
const FIT = 80;
const INDEX = 32;
/** A head narrower than this sorts from its arrow alone; the word stays for screen readers and the tip. */
const GLYPH = 56;
const SKELETON_ROWS = 6;

const stop = (event: { stopPropagation: () => void }) => event.stopPropagation();

export function Table<R>({
  columns,
  rows,
  rowKey,
  onRow,
  indexed,
  start = 0,
  className,
  srHead,
  loading,
  error,
  onRetry,
  empty,
  activeKey,
  onActive,
  rowProps,
  isNew,
  bounded,
  label,
  sort,
  onSort,
}: {
  columns: Column<R>[];
  rows: R[];
  rowKey: (row: R) => string;
  onRow?: (row: R) => void;
  indexed?: boolean;
  /** The first row's position in the whole list, for the index on a later page. */
  start?: number;
  className?: string;
  /** The head row's names reach screen readers but take no room: the rows show what each column holds. */
  srHead?: boolean;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  /** Shown as one row when there are no rows and nothing failed. */
  empty?: ReactNode;
  /** The active row (`useListNav`), drawn with a bar on its first cell. */
  activeKey?: string;
  onActive?: (key: string) => void;
  /** `useListNav().rowProps`: keys, focus and click handled by the list. */
  rowProps?: (row: R) => Record<string, unknown>;
  /** Rows that just arrived flash once. */
  isNew?: (row: R) => boolean;
  /** A bounded scroll box (px, default 480) with the head sticky inside it. */
  bounded?: boolean | number;
  label?: string;
  /** `useSort().sort`: the heads sort the rows. */
  sort?: Sorting;
  /** Called after a head is clicked (the pager's `first`). */
  onSort?: () => void;
}) {
  const hint = useId();
  const headless = columns.every((column) => !column.label);
  const fit = columns.some((column) => column.fit);
  const span = columns.length + (indexed ? 1 : 0);
  // Under 1024px the hide:"md" columns are gone, so they stop counting towards the width that scrolls.
  const widthOf = (narrow: boolean) =>
    (indexed ? INDEX : 0) +
    columns.reduce(
      (sum, column) => sum + (narrow && column.hide === "md" ? 0 : (column.width ?? (column.fit ? FIT : FREE))),
      0,
    );
  const cellClass = (column: Column<R>) =>
    cn(
      column.align === "right" && "is-num",
      column.fit && "is-fit",
      fit && !column.fit && !column.width && "is-free",
      column.hide === "md" && "is-hide-md",
    );
  const failed = error !== undefined && error !== null && error !== false;
  const navigable = Boolean(onRow || rowProps);
  const last = columns.length - 1;

  let body: ReactNode;
  if (failed)
    body = (
      <tr className="is-empty">
        <td colSpan={span}>
          <ErrorNote error={error} onRetry={onRetry} inline />
        </td>
      </tr>
    );
  else if (loading)
    body = Array.from({ length: SKELETON_ROWS }, (_, i) => (
      <tr key={i} className="is-skel" aria-hidden>
        {indexed ? <td className="is-idx" /> : null}
        {columns.map((column, index) => (
          <td key={index} className={cellClass(column)}>
            <Skel kind="row" width={`${40 + ((i * 7 + index * 13) % 45)}%`} />
          </td>
        ))}
      </tr>
    ));
  else if (!rows.length && empty !== undefined && empty !== null)
    body = (
      <tr className="is-empty">
        <td colSpan={span}>{typeof empty === "string" ? <Empty kind="row" title={empty} /> : empty}</td>
      </tr>
    );
  else
    body = rows.map((row, position) => {
      const key = rowKey(row);
      const listed = rowProps?.(row);
      const open = onRow && !listed ? () => onRow(row) : undefined;
      return (
        <tr
          key={key}
          className={cn((onRow || listed) && "is-link", isNew?.(row) && "is-new")}
          data-active={!listed && activeKey === key ? "" : undefined}
          tabIndex={open ? 0 : undefined}
          onClick={
            open
              ? () => {
                  onActive?.(key);
                  open();
                }
              : undefined
          }
          onFocus={open && onActive ? () => onActive(key) : undefined}
          onKeyDown={
            open
              ? (event: KeyboardEvent<HTMLTableRowElement>) => {
                  if (event.target !== event.currentTarget) return;
                  if (event.key !== "Enter" && event.key !== " ") return;
                  event.preventDefault();
                  open();
                }
              : undefined
          }
          {...listed}
          aria-selected={navigable ? (listed ? listed["data-active"] === "" : activeKey === key) : undefined}
        >
          {indexed ? <td className="is-idx">{String(start + position + 1).padStart(2, "0")}</td> : null}
          {columns.map((column, index) => {
            const value = column.cell(row);
            return (
              <td
                key={index}
                className={cn(
                  cellClass(column),
                  column.mono && "is-mono",
                  column.strong && "is-strong",
                  column.menu && "is-menu",
                )}
                onClick={column.menu ? stop : undefined}
                onKeyDown={column.menu ? stop : undefined}
              >
                {column.truncate === false || column.menu || column.fit ? (
                  value
                ) : (
                  // The native title repeats a truncated string; a tip per cell would cost a popover each.
                  <span
                    className="sh-cell"
                    title={typeof value === "string" || typeof value === "number" ? String(value) : undefined}
                  >
                    {value}
                  </span>
                )}
              </td>
            );
          })}
        </tr>
      );
    });

  return (
    <div
      className={cn("sh-table-wrap", bounded && "sh-table-wrap--bounded", className)}
      style={typeof bounded === "number" ? ({ "--table-max": `${bounded}px` } as React.CSSProperties) : undefined}
      aria-busy={loading || undefined}
    >
      {loading ? (
        <span role="status" className="sr-only">
          loading
        </span>
      ) : null}
      {navigable ? (
        <span id={hint} hidden>
          Enter opens the row
        </span>
      ) : null}
      <table
        className={cn("sh-table", fit && "sh-table--fit")}
        style={{ "--table-min": `${widthOf(false)}px`, "--table-min-md": `${widthOf(true)}px` } as React.CSSProperties}
        aria-label={label}
        role={navigable ? "grid" : undefined}
        aria-readonly={navigable || undefined}
        aria-describedby={navigable && rows.length ? hint : undefined}
      >
        <colgroup>
          {indexed ? <col style={{ width: INDEX }} /> : null}
          {columns.map((column, index) => (
            <col
              key={index}
              className={column.hide === "md" ? "is-hide-md" : undefined}
              // The last cell is padded clear of the floating launcher; its width grows by the same.
              style={
                column.width
                  ? { width: index === last ? `calc(${column.width}px + var(--launcher-room, 0px))` : column.width }
                  : undefined
              }
            />
          ))}
        </colgroup>
        {headless ? null : (
          <thead className={srHead ? "sh-table__srhead" : undefined}>
            <tr>
              {indexed ? <th scope="col">#</th> : null}
              {columns.map((column, index) => {
                const on = sort?.by?.by === index ? sort.by : null;
                const glyph = column.width !== undefined && column.width < GLYPH;
                const Arrow = on ? (on.desc ? ArrowDown : ArrowUp) : glyph ? ArrowUpDown : ArrowUp;
                return (
                  <th
                    key={index}
                    scope="col"
                    className={cellClass(column)}
                    aria-sort={on ? (on.desc ? "descending" : "ascending") : undefined}
                  >
                    {column.menu ? (
                      <span className="sr-only">{column.label || "Actions"}</span>
                    ) : sort && sortable(column) ? (
                      <button
                        type="button"
                        className="sh-table__sort"
                        data-on={on ? "" : undefined}
                        data-glyph={glyph ? "" : undefined}
                        title={glyph ? column.label : undefined}
                        onClick={() => {
                          sort.toggle(index);
                          onSort?.();
                        }}
                      >
                        {glyph ? <span className="sr-only">{column.label}</span> : column.label}
                        <Arrow aria-hidden />
                      </button>
                    ) : (
                      column.label
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
        )}
        <tbody>{body}</tbody>
      </table>
    </div>
  );
}
