/**
 * The field rail: each pinned field's five commonest values over the whole
 * match (the strip's total), not over the loaded rows. A value takes the row's width
 * with its count at the end and its share as a line under it. A value filters
 * in on click or +, out on −; both edit the running query and never add a term
 * twice. "+ field" pins any OCSF field for this viewer; × unpins it. A field
 * pinned by its stored column (an older viewer's `metadata_product`) reads,
 * and goes into the query, as its OCSF path.
 */
import { useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { Minus, Plus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { ErrorNote, Input } from "@/components/ui/misc";
import { Popover } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { cn } from "@/lib/cn";
import { FIELDS, fieldPath } from "@/lib/explore";
import { num } from "@/lib/format";
import type { Summary } from "@/types";
import { FILL } from "./Results";

export function FieldRail({
  pins,
  tops,
  total,
  onPivot,
  onPin,
  onUnpin,
  adding,
  onAdding,
}: {
  pins: string[];
  tops: UseQueryResult<Summary>[];
  total?: number;
  onPivot: (field: string, value: string, op: "=" | "!=") => void;
  onPin: (field: string) => void;
  onUnpin: (field: string) => void;
  /** The "+ field" popover, opened by F. */
  adding: boolean;
  onAdding: (open: boolean) => void;
}) {
  // One error and one Retry for the rail, however many fields failed; a failed field reads "—".
  const failed = tops.filter((q) => q?.isError && !q.data);
  return (
    <Card aria-label="Fields">
      <CardHeader title="Fields" />
      {/* As tall as the results box at most, so the page never scrolls past it. */}
      <div className={cn(FILL, "flex flex-col gap-3 overflow-y-auto p-3 scrollbar-thin")}>
        {failed.length ? (
          <ErrorNote error={failed[0]!.error} onRetry={() => void Promise.all(failed.map((q) => q.refetch()))} inline />
        ) : null}
        {/* Nothing matched: no field has a value to show. */}
        {total === 0
          ? null
          : pins.map((field, i) => (
              <FieldTops
                key={field}
                field={field}
                query={tops[i]}
                onPivot={(value, op) => onPivot(fieldPath(field), value, op)}
                onUnpin={() => onUnpin(field)}
              />
            ))}
        <Popover
          label="Pin a field"
          pad
          open={adding}
          onOpenChange={onAdding}
          trigger={(props) => (
            <Button {...props} variant="ghost" size="sm" className="self-start" aria-keyshortcuts="F">
              <Plus aria-hidden />
              field
            </Button>
          )}
        >
          {(close) => (
            <PickField
              pinned={pins}
              onPick={(field) => {
                onPin(field);
                close();
              }}
            />
          )}
        </Popover>
      </div>
    </Card>
  );
}

function FieldTops({
  field,
  query,
  onPivot,
  onUnpin,
}: {
  field: string;
  query?: UseQueryResult<Summary>;
  onPivot: (value: string, op: "=" | "!=") => void;
  onUnpin: () => void;
}) {
  const rows = (query?.data?.rows ?? []).filter((r) => r.key !== null && r.key !== "");
  const of = Math.max(1, query?.data?.total ?? 0);
  return (
    <section className="group/field flex flex-col gap-1">
      <h3 className="m-0 flex items-center gap-1 [font:var(--text-mono)] text-fg-3">
        <span className="min-w-0 truncate">{fieldPath(field)}</span>
        <button
          type="button"
          className="ml-auto inline-flex h-4 w-4 items-center justify-center rounded-control text-fg-4 opacity-0 hover:text-fg-1 focus-visible:opacity-100 group-hover/field:opacity-100"
          onClick={onUnpin}
          aria-label={`Unpin ${fieldPath(field)}`}
        >
          <X className="h-3 w-3" aria-hidden />
        </button>
      </h3>
      {!query || (query.isPending && !query.data) ? (
        <div className="flex flex-col gap-1.5" aria-hidden>
          <Skel kind="row" width="80%" />
          <Skel kind="row" width="55%" />
        </div>
      ) : rows.length === 0 ? (
        <span className="[font:var(--text-mono)] text-fg-4">—</span>
      ) : (
        <ul className="m-0 flex list-none flex-col p-0">
          {rows.map((row) => {
            const value = String(row.key);
            return (
              <li key={value} className="group/value relative flex flex-col pb-1">
                <span className="flex h-6 items-center gap-2">
                  <button
                    type="button"
                    className="min-w-0 flex-1 truncate border-0 bg-transparent p-0 text-left [font:var(--text-mono)] text-fg-2 hover:text-fg-1"
                    onClick={() => onPivot(value, "=")}
                    title={value}
                  >
                    {value}
                  </button>
                  <span className="shrink-0 [font:var(--text-mono)] text-fg-3 tabular">{num(row.count)}</span>
                </span>
                {/* The share of the whole match, a thin line under the value. */}
                <span className="sh-barlist__track h-0.5" aria-hidden>
                  <span className="sh-barlist__fill" style={{ width: `${Math.min(100, (row.count / of) * 100)}%` }} />
                </span>
                {/* + and − cover the count on hover and focus. */}
                <span className="sh-fields__pivot absolute top-0.5 right-0 m-0 bg-bg-1 group-focus-within/value:opacity-100 group-hover/value:opacity-100">
                  <button type="button" onClick={() => onPivot(value, "=")} aria-label={`Only ${value}`}>
                    <Plus aria-hidden />
                  </button>
                  <button type="button" onClick={() => onPivot(value, "!=")} aria-label={`Without ${value}`}>
                    <Minus aria-hidden />
                  </button>
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function PickField({ pinned, onPick }: { pinned: string[]; onPick: (field: string) => void }) {
  const [filter, setFilter] = useState("");
  const wanted = filter.trim().toLowerCase();
  const taken = pinned.map(fieldPath);
  const shown = FIELDS.filter((f) => !taken.includes(f) && f.includes(wanted));
  return (
    <div className="flex w-64 flex-col gap-2">
      <Input
        small
        mono
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
        placeholder="Field"
        aria-label="Field"
        data-autofocus
        autoFocus
        onKeyDown={(event) => {
          if (event.key === "Enter" && shown[0]) {
            event.preventDefault();
            onPick(shown[0]);
          }
        }}
      />
      <ul className="m-0 flex max-h-64 list-none flex-col overflow-y-auto p-0 scrollbar-thin">
        {shown.map((f) => (
          <li key={f}>
            <button
              type="button"
              className="flex h-7 w-full items-center rounded-control border-0 bg-transparent px-2 text-left [font:var(--text-mono)] text-fg-2 hover:bg-bg-3 hover:text-fg-1"
              onClick={() => onPick(f)}
            >
              {f}
            </button>
          </li>
        ))}
        {shown.length ? null : <li className="px-2 [font:var(--text-mono)] text-fg-4">No field</li>}
      </ul>
    </div>
  );
}
