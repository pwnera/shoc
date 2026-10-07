/**
 * The filter bar's state, in the URL: one parameter per dimension and `q` for
 * the text, so any count elsewhere can link to a filtered view and Back undoes a
 * filter. Every URL value becomes a chip, even one missing from the options, so
 * a stale link never filters invisibly. Replaces `lib/facets.ts`.
 */
import type { ReactNode } from "react";
import { useSearchParams } from "react-router-dom";

export type Option = { value: string; label?: string; count?: number };

export type Dim<T> = {
  /** The URL parameter. */
  id: string;
  label: string;
  /** The "+ Filter" menu's choices; a dimension without options or `menu` is set by links only. */
  options?: Option[];
  /** The chip's word for a value no option names (a since from a link: "Tue 14:02"). */
  word?: (value: string) => string;
  /** Its own content in the "+ Filter" menu in place of the option list (the tactic cells). */
  menu?: (ctx: { value: string; set: (value: string) => void; close: () => void }) => ReactNode;
  /** Whether a loaded row matches; leave it out for a dimension the kernel filters. */
  test?: (row: T, value: string) => boolean;
};

/** A value's chip word: its option's label, the dimension's own word for it, or the value. */
export function chipWord<T>(dim: Dim<T>, value: string): string {
  return dim.options?.find((o) => o.value === value)?.label ?? dim.word?.(value) ?? value;
}

export type Chip = { id: string; label: string; value: string; word: string };

export type Filters<T> = {
  values: Record<string, string>;
  set: (id: string, value: string) => void;
  clear: () => void;
  text: string;
  setText: (text: string) => void;
  chips: Chip[];
  /** True when the row passes every client-side dimension and the text. */
  keep: (row: T) => boolean;
  active: boolean;
};

export function useFilters<T>(
  dims: Dim<T>[],
  opts: { text?: string; match?: (row: T, text: string) => boolean } = {},
): Filters<T> {
  const [params, setParams] = useSearchParams();
  const textParam = opts.text ?? "q";
  const values: Record<string, string> = {};
  for (const dim of dims) {
    const value = params.get(dim.id);
    if (value) values[dim.id] = value;
  }
  const text = params.get(textParam) ?? "";
  const write = (change: (out: URLSearchParams) => void) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        change(out);
        // A filter change lands on the first page of the list.
        out.delete("page");
        return out;
      },
      { replace: true },
    );

  const chips = dims.flatMap((dim): Chip[] => {
    const value = values[dim.id];
    if (!value) return [];
    return [{ id: dim.id, label: dim.label, value, word: chipWord(dim, value) }];
  });

  return {
    values,
    set: (id, value) => write((out) => (value ? out.set(id, value) : out.delete(id))),
    clear: () =>
      write((out) => {
        for (const dim of dims) out.delete(dim.id);
        out.delete(textParam);
      }),
    text,
    setText: (next) => write((out) => (next ? out.set(textParam, next) : out.delete(textParam))),
    chips,
    keep: (row) =>
      dims.every((dim) => !values[dim.id] || !dim.test || dim.test(row, values[dim.id]!)) &&
      (!text || !opts.match || opts.match(row, text.toLowerCase())),
    active: chips.length > 0 || text !== "",
  };
}
