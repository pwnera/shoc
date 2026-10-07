/**
 * The window: 15m · 1h · 24h · 7d · 30d, or a range picked in a popover with
 * two datetime fields and Apply, so a half-typed date never runs a query. A
 * range shows on the button; the segments then show no choice.
 */
import { forwardRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/misc";
import { Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { rangeLabel, windowOf, windowValue } from "./query";

const WINDOWS = ["15m", "1h", "24h", "7d", "30d"] as const;

/** An instant as a datetime-local input shows it, in local time. */
function local(ms: number): string {
  if (!Number.isFinite(ms)) return "";
  return new Date(ms - new Date(ms).getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export const TimeControl = forwardRef<
  HTMLSpanElement,
  { since: string; until: string; onPick: (since: string, until: string) => void }
>(function TimeControl({ since, until, onPick }, ref) {
  const value = windowValue(since, until, WINDOWS);
  const range = windowOf(since, until);
  const from = Number.isFinite(range.from) ? new Date(range.from).toISOString() : "";
  return (
    <span ref={ref} className="flex flex-wrap items-center gap-2">
      <Seg label="Window" value={value} options={WINDOWS} onChange={(v) => onPick(v, "")} />
      <Popover
        label="Time range"
        pad
        align="end"
        trigger={(props) => (
          <Button {...props} data-range="" variant="ghost" size="sm" aria-pressed={!value}>
            {value || !from ? "range" : until ? rangeLabel(from, until) : `${rangeLabel(from)} → now`}
          </Button>
        )}
      >
        {(close) => (
          <Range
            from={local(range.from)}
            to={local(range.to)}
            onApply={(a, b) => {
              onPick(new Date(a).toISOString(), new Date(b).toISOString());
              close();
            }}
          />
        )}
      </Popover>
    </span>
  );
});

function Range({ from, to, onApply }: { from: string; to: string; onApply: (from: string, to: string) => void }) {
  const [a, setA] = useState(from);
  const [b, setB] = useState(to);
  const valid = Boolean(a && b) && Date.parse(a) < Date.parse(b);
  return (
    <form
      className="flex w-64 flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) onApply(a, b);
      }}
    >
      <Field label="From">
        <Input type="datetime-local" small value={a} max={b} onChange={(event) => setA(event.target.value)} data-autofocus />
      </Field>
      <Field label="To">
        <Input type="datetime-local" small value={b} min={a} onChange={(event) => setB(event.target.value)} />
      </Field>
      <Button type="submit" variant="primary" size="sm" className="self-end" disabled={!valid}>
        Apply
      </Button>
    </form>
  );
}
