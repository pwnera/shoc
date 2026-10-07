/**
 * The state strip in a page header: one status word, at most five facts, one
 * chart, one aside. The word is never a number and never repeats a fact; a
 * fact links to the list that reproduces it, presses to filter the list
 * below, or opens a popover (the targets behind "4 protected"). Loading shows
 * "…" and skeleton values (no word on a screen without a state); an error
 * reads "Can't tell" with Retry and every value "—", never a zero; a failed
 * refetch over cached data says "as of 14:02". `vizWide` lets the chart take
 * the rest of the row (a share over the catalogue, the pipeline);
 * `reserveViz` holds its slot while loading, so the strip does not jump.
 */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { bannered, useUnreachable } from "@/lib/api";
import { cn } from "@/lib/cn";
import { clock } from "@/lib/format";
import { Button } from "./button";
import { Popover } from "./pop";
import { Skel } from "./state";
import { Mark } from "./status";
import { Tip } from "./tip";

export type StripTone = "good" | "warn" | "bad" | "crew" | "idle";

export type StripFact = {
  label: ReactNode;
  /** null or undefined reads "—" (unknown, never zero). */
  value: ReactNode;
  tone?: "good" | "warn" | "bad" | "crew";
  /** A link to the list that reproduces the fact. */
  to?: string;
  /** Filters the list below; `pressed` says it is on. */
  onClick?: () => void;
  pressed?: boolean;
  /** Opens a popover of what the fact counts; `popoverLabel` names it. */
  popover?: ReactNode | ((close: () => void) => ReactNode);
  popoverLabel?: string;
  tip?: ReactNode;
  /** Needed when `label` is not a string. */
  key?: string;
};

function Value({ fact, unknown }: { fact: StripFact; unknown: boolean }) {
  const raw = fact.value;
  const shown = unknown || raw === null || raw === undefined || raw === "" ? "—" : raw;
  return (
    <span className="sh-strip__value" data-tone={unknown ? undefined : fact.tone}>
      {typeof shown === "number" ? shown.toLocaleString() : shown}
    </span>
  );
}

export function Strip({
  state,
  facts = [],
  viz,
  vizWide,
  reserveViz,
  aside,
  alert,
  loading,
  stateless,
  error,
  onRetry,
  asOf,
}: {
  /** Left out on screens with no status of their own (Explore, a finding, a rule). */
  state?: { tone: StripTone; word: string };
  facts?: StripFact[];
  /** One chart: a share, a time bar, stage steps or a meter. */
  viz?: ReactNode;
  /** The chart takes the rest of the row instead of 240px. */
  vizWide?: boolean;
  /** While loading with no chart yet, hold its slot with a skeleton. */
  reserveViz?: boolean;
  /** A window control, a since chip or one action. */
  aside?: ReactNode;
  /** A 2px bad bar on the left; on by default when the state is bad. */
  alert?: boolean;
  loading?: boolean;
  /** The screen has no state word: loading shows no "…" (an error still reads "Can't tell"). */
  stateless?: boolean;
  error?: unknown;
  onRetry?: () => void;
  /** When cached data shows after a failed refetch: the time it is from. */
  asOf?: string | null;
}) {
  const failed = error !== undefined && error !== null && error !== false;
  // A refused token, or shoc unreachable, gains nothing from this Retry (ErrorNote hides it too): the shell's banner has it.
  const down = useUnreachable();
  const retry = failed && onRetry && !bannered(error, down) ? onRetry : undefined;
  const word = failed
    ? { tone: "bad" as const, word: "Can't tell" }
    : loading && !stateless
      ? { tone: "idle" as const, word: "…" }
      : state;
  const bad = alert ?? word?.tone === "bad";
  const shownViz = viz ?? (loading && reserveViz ? <Skel kind="row" /> : null);
  const shown = facts.slice(0, 5);
  return (
    <div className={cn("sh-strip", bad && "sh-strip--alert")}>
      {word ? (
        <span className="sh-strip__state" data-tone={word.tone} role="status">
          <Mark tone={word.tone} large />
          {word.word}
          {retry ? (
            <Button variant="ghost" size="sm" onClick={retry}>
              Retry
            </Button>
          ) : null}
        </span>
      ) : null}
      {shown.length ? (
        <span className="sh-strip__facts" role="group" aria-label="Facts">
          {shown.map((fact, index) => {
            const body = (
              <>
                {loading && !failed ? <Skel kind="fact" /> : <Value fact={fact} unknown={failed} />}
                <span className="sh-strip__label">{fact.label}</span>
              </>
            );
            const key = fact.key ?? (typeof fact.label === "string" ? fact.label : String(index));
            const el = fact.to ? (
              <Link key={key} to={fact.to} className="sh-strip__fact">
                {body}
              </Link>
            ) : fact.popover ? (
              <Popover
                key={key}
                label={fact.popoverLabel ?? (typeof fact.label === "string" ? fact.label : undefined)}
                pad
                trigger={(props) => (
                  <button {...props} type="button" className="sh-strip__fact">
                    {body}
                  </button>
                )}
              >
                {fact.popover}
              </Popover>
            ) : fact.onClick ? (
              <button
                key={key}
                type="button"
                className="sh-strip__fact"
                onClick={fact.onClick}
                aria-pressed={fact.pressed ?? false}
              >
                {body}
              </button>
            ) : (
              <span key={key} className="sh-strip__fact">
                {body}
              </span>
            );
            return fact.tip && !fact.popover ? (
              <Tip key={key} label={fact.tip}>
                {el}
              </Tip>
            ) : (
              el
            );
          })}
        </span>
      ) : null}
      {shownViz ? <span className={cn("sh-strip__viz", vizWide && "sh-strip__viz--wide")}>{shownViz}</span> : null}
      {aside || asOf ? (
        <span className="sh-strip__aside">
          {asOf ? <span className="sh-strip__stale">as of {clock(asOf)}</span> : null}
          {aside}
        </span>
      ) : null}
    </div>
  );
}
