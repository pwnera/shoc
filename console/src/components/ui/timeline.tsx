/**
 * A timeline: sticky day rows, HH:MM:SS stamps (HH:MM on a phone), a marker on the axis, the
 * actor's avatar, what happened and one end slot (a badge or an E-chip). A
 * gap of an hour or more gets its own 12px row ("25h 31m"), in warn when it is
 * the response gap; a hairline marks the first row since the reader's last
 * visit. Rows are buttons that open their record; the end slot sits beside
 * the button, not in it, so an E-chip there is a real button of its own.
 * `feed` drops the axis.
 */
import { Fragment, type ReactNode } from "react";
import { cn } from "@/lib/cn";
import { day, span, time } from "@/lib/format";
import { Avatar } from "./avatar";

export type MomentDot =
  | "event"
  | "cited"
  | "extended"
  | "finding"
  | "crew"
  | "human"
  | "system"
  | "done"
  | "failed"
  | "undone";

export type Moment = {
  key: string;
  at: string;
  dot: MomentDot;
  /** A finding's severity, for its dot. */
  tone?: string;
  /** The actor, as `who()` reads it. */
  who?: string | null;
  what: ReactNode;
  /** One badge or E-chip at the end of the row, outside its button. */
  end?: ReactNode;
  /** ×N for a collapsed burst. */
  count?: number;
  active?: boolean;
  /** Brushed from the graph, the time bar or an E-chip. */
  hl?: boolean;
  /** Outside the brushed range: hidden. */
  out?: boolean;
  isNew?: boolean;
};

const HOUR = 3_600_000;

export function Timeline({
  moments,
  onOpen,
  variant = "axis",
  newAfter,
  responseGap,
  rowProps,
  label,
}: {
  /** Oldest first. */
  moments: Moment[];
  onOpen?: (moment: Moment) => void;
  variant?: "axis" | "feed";
  /** The reader's last visit: a "new" hairline before the first later row. */
  newAfter?: string | null;
  /** From case opened to first containment: a gap inside it reads in warn. */
  responseGap?: { from: string; to: string } | null;
  /** `useListNav().rowProps`, for J/K and Enter over the rows. */
  rowProps?: (moment: Moment) => Record<string, unknown>;
  label?: string;
}) {
  const fresh = newAfter ? Date.parse(newAfter) : NaN;
  const gapFrom = responseGap ? Date.parse(responseGap.from) : NaN;
  const gapTo = responseGap ? Date.parse(responseGap.to) : NaN;
  let lastDay = "";
  let lastAt = NaN;
  let marked = false;

  return (
    <ol className={cn("sh-tl", variant === "feed" && "sh-tl--feed")} aria-label={label}>
      {moments.map((moment) => {
        const at = Date.parse(moment.at);
        const heading = day(moment.at);
        const newDay = heading !== lastDay;
        const gap = !newDay && at - lastAt >= HOUR ? at - lastAt : 0;
        const late = gap > 0 && lastAt >= gapFrom && at <= gapTo;
        const isFresh = !marked && at > fresh;
        if (isFresh) marked = true;
        lastDay = heading;
        lastAt = at;
        return (
          <Fragment key={moment.key}>
            {newDay ? <li className="sh-tl__day">{heading}</li> : null}
            {gap ? (
              <li className={cn("sh-tl__gap", late && "sh-tl__gap--warn")} aria-label={`${span(gap / 1000)} later`}>
                {span(gap / 1000)}
              </li>
            ) : null}
            {isFresh && moments[0] !== moment ? <li className="sh-tl__new">new</li> : null}
            <li
              className={cn("sh-tl__item", moment.hl && "is-hl", moment.out && "is-out")}
              data-active={moment.active ? "" : undefined}
              data-new={moment.isNew ? "" : undefined}
            >
              <button
                type="button"
                className="sh-tl__row"
                onClick={onOpen ? () => onOpen(moment) : undefined}
                {...rowProps?.(moment)}
              >
                <time className="sh-tl__time" dateTime={moment.at}>
                  {time(moment.at).slice(0, 5)}
                  {/* A phone keeps the minute: the seconds cost the row 20px. */}
                  <span className="max-md:hidden">{time(moment.at).slice(5)}</span>
                </time>
                {variant === "axis" ? (
                  <span className="sh-tl__mark" aria-hidden>
                    <i className={`sh-tl__dot sh-tl__dot--${moment.dot}`} data-tone={moment.tone} />
                  </span>
                ) : null}
                <span className="sh-tl__who">{moment.who ? <Avatar who={moment.who} size={16} /> : null}</span>
                <span className="sh-tl__what">
                  {moment.what}
                  {moment.count && moment.count > 1 ? <span className="sh-tl__count">×{moment.count}</span> : null}
                </span>
              </button>
              {moment.end !== undefined && moment.end !== null ? <span className="sh-tl__end">{moment.end}</span> : null}
            </li>
          </Fragment>
        );
      })}
    </ol>
  );
}
