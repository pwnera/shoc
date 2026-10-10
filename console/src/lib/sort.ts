import { isValidElement, useState, type ReactNode } from "react";
import { useNavigationType } from "react-router-dom";
import type { Column } from "@/components/ui/table";

const SEVERITY = ["informational", "low", "medium", "high", "critical"];
/** Severity as a number, so a list sorts by weight rather than by name. */
export const severityRank = (severity: string) => SEVERITY.indexOf(severity);

export type Sort = { by: number; desc: boolean } | null;
export type Sorting = { by: Sort; toggle: (index: number) => void };

export const sortable = <R,>(column: Column<R>) => Boolean(column.label) && !column.menu && column.sort !== false;

/** The text a cell shows, read from the element tree (strings, numbers and children). */
const text = (node: ReactNode): string =>
  typeof node === "string" || typeof node === "number"
    ? String(node)
    : Array.isArray(node)
      ? node.map(text).join("")
      : isValidElement(node)
        ? text((node.props as { children?: ReactNode }).children)
        : "";

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** The sort each list was left in, by history entry, URL and columns, so Back from a row's page keeps it. */
const left = new Map<string, Sort>();

/**
 * The rows in the order the heads ask for, before paging so a sort spans every
 * page. Empty values go last either way. Pass `sort` to the Table, and its
 * `onSort` to turn back to the first page.
 */
export function useSort<R>(rows: R[], columns: Column<R>[]): { rows: R[]; sort: Sorting } {
  const idx = (window.history.state as { idx?: number } | null)?.idx;
  const key = `${idx}:${window.location.pathname}${window.location.search}#${columns.map((c) => c.label).join("|")}`;
  const back = useNavigationType() === "POP";
  const [by, setBy] = useState<Sort>(() => (back ? (left.get(key) ?? null) : null));
  const toggle = (index: number) => {
    const to: Sort = by?.by !== index ? { by: index, desc: false } : by.desc ? null : { by: index, desc: true };
    left.set(key, to);
    setBy(to);
  };
  const column = by ? columns[by.by] : undefined;
  if (!by || !column || !sortable(column)) return { rows, sort: { by, toggle } };
  const value = column.sort || ((row: R) => text(column.cell(row)));
  const keyed = rows.map((row) => ({ row, v: value(row) }));
  const empty = (v: unknown) => v === null || v === undefined || v === "";
  keyed.sort((a, b) => {
    if (empty(a.v) || empty(b.v)) return Number(empty(a.v)) - Number(empty(b.v));
    const order =
      typeof a.v === "number" && typeof b.v === "number" ? a.v - b.v : collator.compare(String(a.v), String(b.v));
    return by.desc ? -order : order;
  });
  return { rows: keyed.map((k) => k.row), sort: { by, toggle } };
}
