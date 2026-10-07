/**
 * The one time chart. `marks` draws one shaped mark per thing (▲ case,
 * ■ action, ◆ crew decision, ● finding, | event, ⌁ page, ▽ closed, ↺ undone)
 * toned by severity or status (`plain` for an fg-2 mark); `bars` draws stacked
 * buckets with the bucket maximum in a y gutter of its own, a part toned
 * `good-hollow`, `idle-hatched` or `idle-dashed` where a hue alone would not
 * tell it apart; `spark` is a 24px bar strip with no axis. With `compress`, an
 * empty stretch of an hour or more shrinks to 16px and says how long it was.
 * Ticks fall on round local times (on the hour, at midnight) a step of 10s to
 * 7d apart, three to eight across as the width allows, and read HH:MM, HH:MM:SS under ten minutes,
 * "27 Sep" past a day and a half. Marks of different kinds at one moment
 * stack (the event's tick shortens under the other), and a merged mark's count
 * is a badge on its corner. One tab stop: ←/→ move between marks or buckets, Enter opens,
 * Shift+←/→ brushes a range, Escape clears it; dragging brushes too (from a
 * bar or a mark once the pointer moves), and a double click clears. Pass
 * `brush` to hold the range yourself. Pixels come from a ResizeObserver; marks
 * keep half a mark of room at each end so the first and last are drawn whole,
 * and a gap's length that would run into the next one moves into its tip. To
 * assistive tech the plot is a listbox of its marks or buckets.
 */
import { useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type MouseEvent, type PointerEvent } from "react";
import { cn } from "@/lib/cn";
import { dayMonth, span, time } from "@/lib/format";

export type TimeMark = {
  key: string;
  at: string;
  kind: "case" | "action" | "decision" | "finding" | "event" | "page" | "closed" | "undone";
  /** A severity for cases and findings, a status for actions. */
  tone?: string;
  label: string;
  active?: boolean;
  hl?: boolean;
};

export type TimePart = { value: number; tone: string; label: string };

export type TimeBucket = {
  key: string;
  from: string;
  to: string;
  parts: TimePart[];
  active?: boolean;
};

export type TimeRange = { from: string; to: string };

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const GAP = 16;
const MIN_SPAN = 12;
const AXIS = 14;
/** Pixels a drag must cover before it brushes; less is a click. */
const DRAG = 4;
/** Two merged counts closer than this would read as one number ("18" and "2" as "182"). */
const COUNT_ROOM = 14;
/** Half a mark: the room kept at each end of a marks plot. */
const INSET = 6;
/** About one --text-micro character, for keeping gap lengths apart. */
const CHAR = 6;

type Seg = { t0: number; t1: number; x0: number; x1: number; gap: boolean };

/** Piecewise time → x: linear, or with every empty hour-plus stretch cut to GAP pixels. */
function segments(t0: number, t1: number, times: number[], width: number, compress: boolean): Seg[] {
  const linear = [{ t0, t1, x0: 0, x1: width, gap: false }];
  if (!compress) return linear;
  // Only stretches between two things shrink; the window's own edges stay to scale.
  const points = times.filter((t) => t > t0 && t < t1).sort((a, b) => a - b);
  const cuts: [number, number][] = [];
  for (let i = 1; i < points.length; i++)
    if (points[i]! - points[i - 1]! >= HOUR) cuts.push([points[i - 1]!, points[i]!]);
  if (!cuts.length) return linear;
  const spans: [number, number][] = [];
  let start = t0;
  for (const [a, b] of cuts) {
    spans.push([start, a]);
    start = b;
  }
  spans.push([start, t1]);
  const room = width - cuts.length * GAP - spans.length * MIN_SPAN;
  if (room < 0) return linear;
  const total = spans.reduce((sum, [a, b]) => sum + (b - a), 0);
  const out: Seg[] = [];
  let x = 0;
  spans.forEach(([a, b], i) => {
    const w = MIN_SPAN + (total ? (room * (b - a)) / total : room / spans.length);
    out.push({ t0: a, t1: b, x0: x, x1: x + w, gap: false });
    x += w;
    const cut = cuts[i];
    if (cut) {
      out.push({ t0: cut[0], t1: cut[1], x0: x, x1: x + GAP, gap: true });
      x += GAP;
    }
  });
  return out;
}

const toX = (segs: Seg[], t: number) => {
  const s = segs.find((seg) => t <= seg.t1) ?? segs[segs.length - 1]!;
  return s.x0 + ((Math.max(s.t0, Math.min(s.t1, t)) - s.t0) / (s.t1 - s.t0 || 1)) * (s.x1 - s.x0);
};
const toT = (segs: Seg[], x: number) => {
  const s = segs.find((seg) => x <= seg.x1) ?? segs[segs.length - 1]!;
  return s.t0 + ((Math.max(s.x0, Math.min(s.x1, x)) - s.x0) / (s.x1 - s.x0 || 1)) * (s.t1 - s.t0);
};

const STEPS = [10_000, 30_000, MINUTE, 5 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY];
/** Room per tick label. */
const TICK_ROOM = 64;
/** Half a tick label ("01:45", "25 Sep") at the micro font. */
const TICK_HALF = 16;

/**
 * Round local times in [a, b]: the finest step that gives at most `most` of
 * them, never finer than the labels can tell apart (`least`), counted from
 * local midnight so an hour tick is on the hour and a day tick at midnight.
 */
function roundTicks(a: number, b: number, most: number, least: number): number[] {
  if (most < 1) return [];
  const step = STEPS.find((s) => s >= least && (b - a) / s <= most) ?? STEPS[STEPS.length - 1]!;
  const day = new Date(a);
  day.setHours(0, 0, 0, 0);
  const out: number[] = [];
  if (step >= DAY) {
    // By the calendar, so a daylight-saving change keeps the ticks at midnight.
    const n = step / DAY;
    for (; day.getTime() < a; ) day.setDate(day.getDate() + 1);
    for (; day.getTime() <= b; day.setDate(day.getDate() + n)) out.push(day.getTime());
    return out;
  }
  const base = day.getTime();
  for (let t = base + Math.ceil((a - base) / step) * step; t <= b; t += step) out.push(t);
  return out;
}

/** A moment as precisely as the window needs: "14:15:30" under ten minutes, "14:15" within a day and a half, else "27 Sep". */
function moment(t: number, range: number): string {
  const iso = new Date(t).toISOString();
  if (range <= 10 * MINUTE) return time(iso);
  return range <= 36 * HOUR ? time(iso).slice(0, 5) : dayMonth(iso);
}

/** A bucket by its size: a day bucket by its day, a shorter one by its start. */
function bucketName(bucket: TimeBucket, range: number): string {
  const from = Date.parse(bucket.from);
  return Date.parse(bucket.to) - from >= DAY - MINUTE ? dayMonth(bucket.from) : moment(from, Math.min(range, 36 * HOUR));
}

type Item = { key: string; x: number; t: number; label: string; open: () => void };

export function TimeBar({
  from,
  to,
  marks = [],
  bars,
  variant,
  compress,
  responseGap,
  brush,
  onPick,
  onBucket,
  onBrush,
  onPoint,
  label,
}: {
  from: string;
  to: string;
  marks?: TimeMark[];
  bars?: TimeBucket[];
  variant?: "marks" | "bars" | "spark";
  /** Shrink empty stretches of an hour or more to 16px. */
  compress?: boolean;
  /** From case opened to first containment: a gap inside it is labelled in warn. */
  responseGap?: TimeRange | null;
  /** The brushed range, held by the caller; null draws none. Left out, the bar holds its own. */
  brush?: TimeRange | null;
  onPick?: (mark: TimeMark) => void;
  /** A bucket, and the part of it that was clicked (none from the keyboard). */
  onBucket?: (bucket: TimeBucket, part?: TimePart) => void;
  /** A brushed range, or null when it is cleared. */
  onBrush?: (range: TimeRange | null) => void;
  /** Hovering or moving onto a mark, for brushing other views; null when it ends. */
  onPoint?: (key: string | null) => void;
  label: string;
}) {
  const kind = variant ?? (bars ? "bars" : "marks");
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  const [active, setActive] = useState(-1);
  const [anchor, setAnchor] = useState<number | null>(null);
  const [own, setOwn] = useState<{ t0: number; t1: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const [cursor, setCursor] = useState<number | null>(null);
  const drag = useRef<{ x: number; on: boolean } | null>(null);

  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    setWidth(el.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const watch = new ResizeObserver(([entry]) => entry && setWidth(Math.round(entry.contentRect.width)));
    watch.observe(el);
    return () => watch.disconnect();
  }, []);

  const t0 = Date.parse(from);
  const t1 = Math.max(t0 + 1, Date.parse(to));
  const range = t1 - t0;
  const max = Math.max(1, ...(bars ?? []).map((b) => b.parts.reduce((sum, p) => sum + p.value, 0)));
  // The bucket maximum gets a gutter of its own, so it never sits on the first bar; marks keep half a mark at each end.
  const gutter = kind === "bars" ? max.toLocaleString().length * 6 + 6 : kind === "marks" ? INSET : 0;
  const right = kind === "marks" ? INSET : 0;
  const times = [...marks.map((m) => Date.parse(m.at)), ...(bars ?? []).flatMap((b) => [Date.parse(b.from), Date.parse(b.to)])];
  const segs = segments(t0, t1, times, Math.max(1, width - gutter - right), Boolean(compress) && kind === "marks");
  const x = (t: number) => gutter + toX(segs, t);
  const tAt = (px: number) => toT(segs, px - gutter);
  const plotH = kind === "spark" ? 24 : kind === "bars" ? 64 - AXIS : 32 - AXIS;

  const controlled = brush !== undefined;
  const held = brush ? { t0: Date.parse(brush.from), t1: Date.parse(brush.to) } : null;
  const sel = dragging || !controlled ? own : held;

  // Marks of one kind and tone within 8px merge into one with a count.
  const merged: (TimeMark & { x: number; count: number })[] = [];
  for (const mark of [...marks].sort((a, b) => Date.parse(a.at) - Date.parse(b.at))) {
    const mx = x(Date.parse(mark.at));
    const last = merged[merged.length - 1];
    if (last && last.kind === mark.kind && last.tone === mark.tone && mx - last.x < 8) {
      last.count += 1;
      last.active ||= mark.active;
      last.hl ||= mark.hl;
    } else merged.push({ ...mark, x: mx, count: 1 });
  }
  // Two kinds at one moment stack: the other mark rises and an event's tick shortens under it.
  const near = (i: number, test: (m: (typeof merged)[number]) => boolean) =>
    merged.some((m, j) => j !== i && Math.abs(m.x - merged[i]!.x) < 8 && test(m));
  const stack = merged.map((m, i) =>
    m.kind === "event" ? (near(i, (o) => o.kind !== "event") ? "under" : undefined) : near(i, (o) => o.kind === "event") ? "over" : undefined,
  );
  // Events come in runs, so their counts would read "3 3 3 3": they say theirs in the label only.
  const counted = new Set<number>();
  let lastCount = -Infinity;
  merged.forEach((m, i) => {
    if (m.count < 2 || m.kind === "event" || m.x - lastCount < COUNT_ROOM) return;
    counted.add(i);
    lastCount = m.x;
  });

  const items: Item[] = bars
    ? bars.map((b) => ({
        key: b.key,
        x: x(Date.parse(b.from)),
        t: Date.parse(b.from),
        label: `${bucketName(b, range)}: ${b.parts
          .filter((p) => p.value)
          .map((p) => `${p.value} ${p.label}`)
          .join(", ") || "none"}`,
        open: () => onBucket?.(b),
      }))
    : merged.map((m) => ({
        key: m.key,
        x: m.x,
        t: Date.parse(m.at),
        label: m.count > 1 ? `${m.label} and ${m.count - 1} more` : m.label,
        open: () => onPick?.(m),
      }));

  const commit = (next: { t0: number; t1: number } | null) => {
    setOwn(next);
    onBrush?.(next ? { from: new Date(next.t0).toISOString(), to: new Date(next.t1).toISOString() } : null);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!items.length) return;
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (step) {
      event.preventDefault();
      const next = Math.max(0, Math.min(items.length - 1, active < 0 ? 0 : active + step));
      if (event.shiftKey) {
        const start = anchor ?? (active < 0 ? next : active);
        setAnchor(start);
        const a = items[Math.min(start, next)]!.t;
        const b = items[Math.max(start, next)]!.t;
        commit({ t0: a, t1: Math.max(b, a + 1) });
      } else setAnchor(null);
      setActive(next);
      onPoint?.(items[next]!.key);
    } else if (event.key === "Enter" && active >= 0) {
      event.preventDefault();
      items[active]?.open();
    } else if (event.key === "Escape" && sel) {
      event.preventDefault();
      event.stopPropagation();
      setAnchor(null);
      commit(null);
    }
  };

  const at = (event: PointerEvent<HTMLDivElement>) =>
    Math.max(gutter, Math.min(width - right, event.clientX - event.currentTarget.getBoundingClientRect().left));

  // A drag from empty plot brushes at once; one from a bar or a mark only once it moves, so a click still opens it.
  const begin = (event: PointerEvent<HTMLDivElement>) => {
    drag.current!.on = true;
    event.currentTarget.setPointerCapture?.(event.pointerId);
    if (controlled) setOwn(held);
    setDragging(true);
  };
  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if (!onBrush || event.button !== 0) return;
    drag.current = { x: at(event), on: false };
    if (!(event.target as HTMLElement).closest("button")) begin(event);
  };
  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const px = at(event);
    setCursor(px);
    const d = drag.current;
    if (!d) return;
    if (!d.on) {
      if (Math.abs(px - d.x) < DRAG) return;
      begin(event);
    }
    const a = Math.min(d.x, px);
    const b = Math.max(d.x, px);
    if (b - a >= DRAG) setOwn({ t0: tAt(a), t1: tAt(b) });
  };
  const onPointerUp = (event: PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    drag.current = null;
    if (!d?.on) return;
    setDragging(false);
    const px = at(event);
    const a = Math.min(d.x, px);
    const b = Math.max(d.x, px);
    commit(b - a >= DRAG ? { t0: tAt(a), t1: tAt(b) } : null);
  };
  const onPointerCancel = () => {
    drag.current = null;
    setDragging(false);
  };
  const onDoubleClick = (event: MouseEvent<HTMLDivElement>) => {
    if (!onBrush || !sel) return;
    event.preventDefault();
    setAnchor(null);
    commit(null);
  };

  const plotW = Math.max(0, width - gutter - right);
  // A gap's length is shown only where it clears the one before it; the rest say theirs in a tip.
  const gapText = (g: Seg) => span((g.t1 - g.t0) / 1000).replace(/(\d+h)\d+m$/, "$1");
  const quietGaps = new Set<number>();
  // The shown gap labels' extents on the bar, so the ticks give way to them as they give way to each other.
  const gapLabels: [number, number][] = [];
  let gapEnd = -Infinity;
  for (const g of segs.filter((seg) => seg.gap)) {
    const half = (gapText(g).length * CHAR) / 2;
    const mid = (g.x0 + g.x1) / 2;
    if (mid - half < gapEnd + 4) quietGaps.add(g.t0);
    else {
      gapEnd = mid + half;
      const at = gutter + g.x0 + GAP / 2;
      gapLabels.push([at - half, at + half]);
    }
  }
  // Labels read days past a day and a half, so ticks are never finer than a day there.
  const least = range > 36 * HOUR ? DAY : range > 10 * MINUTE ? MINUTE : 0;
  const ticks =
    kind === "spark" || !width
      ? []
      : segs.length > 1
        ? // Compressed: round ticks inside each span wide enough, else one in its middle; clear of the gap lengths.
          segs
            .filter((s) => !s.gap && s.x1 - s.x0 >= 56)
            .flatMap((s) => {
              const round = roundTicks(s.t0, s.t1, Math.min(8, Math.floor((s.x1 - s.x0) / TICK_ROOM)), least);
              return (round.length ? round : [(s.t0 + s.t1) / 2]).map((t) => ({ x: x(t), t }));
            })
        : roundTicks(t0, t1, Math.max(3, Math.min(8, Math.floor(plotW / TICK_ROOM))), least).map((t) => ({ x: x(t), t }));
  // A label centred on the plot's very edge would hang off it.
  const inside = ticks.filter((tick) => tick.x >= gutter + 14 && tick.x <= width - right - 14);
  const clear = inside.filter((tick) => !gapLabels.some(([a, b]) => tick.x + TICK_HALF + 4 > a && tick.x - TICK_HALF - 4 < b));
  const shownTicks = clear.filter((tick, i) => i === 0 || tick.x - clear[i - 1]!.x >= 56);

  const cursorText = (() => {
    if (cursor === null) return "";
    const t = tAt(cursor);
    if (bars) {
      const bucket = bars.find((b) => Date.parse(b.from) <= t && t < Date.parse(b.to));
      const n = bucket ? bucket.parts.reduce((sum, p) => sum + p.value, 0) : 0;
      return `${bucket ? bucketName(bucket, range) : moment(t, range)} · ${n.toLocaleString()}`;
    }
    const near = merged.filter((m) => Math.abs(m.x - cursor) <= 4).reduce((sum, m) => sum + m.count, 0);
    return `${moment(t, range)}${near ? ` · ${near}` : ""}`;
  })();

  return (
    <div
      ref={box}
      className={cn("sh-timebar", kind !== "marks" && `sh-timebar--${kind}`)}
      // A listbox needs its options; an empty bar is only a labelled group.
      role={items.length ? "listbox" : "group"}
      aria-label={label}
      tabIndex={0}
      aria-activedescendant={active >= 0 ? `${id}-${active}` : undefined}
      onKeyDown={onKeyDown}
      onBlur={() => onPoint?.(null)}
    >
      <div
        className="sh-timebar__plot"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerCancel}
        onPointerLeave={() => setCursor(null)}
        onDoubleClick={onDoubleClick}
      >
        {kind === "bars" ? (
          <span className="sh-timebar__ymax" style={{ width: gutter - 4 }} aria-hidden>
            {max.toLocaleString()}
          </span>
        ) : null}
        {width
          ? segs
              .filter((s) => s.gap)
              .map((s) => {
                const late =
                  responseGap !== undefined &&
                  responseGap !== null &&
                  s.t0 >= Date.parse(responseGap.from) &&
                  s.t1 <= Date.parse(responseGap.to);
                return (
                  <span
                    key={s.t0}
                    className={cn("sh-timebar__gap", late && "sh-timebar__gap--warn")}
                    style={{ left: gutter + s.x0, width: GAP }}
                    title={quietGaps.has(s.t0) ? gapText(s) : undefined}
                    aria-hidden
                  >
                    {quietGaps.has(s.t0) ? null : <span>{gapText(s)}</span>}
                  </span>
                );
              })
          : null}
        {sel ? (
          <span className="sh-timebar__brush" style={{ left: x(sel.t0), width: Math.max(1, x(sel.t1) - x(sel.t0)) }} aria-hidden />
        ) : null}
        {width && bars
          ? bars.map((bucket, i) => {
              const total = bucket.parts.reduce((sum, p) => sum + p.value, 0);
              const x0 = x(Date.parse(bucket.from));
              const x1 = x(Date.parse(bucket.to));
              return (
                <button
                  key={bucket.key}
                  id={`${id}-${i}`}
                  type="button"
                  role="option"
                  aria-selected={active === i}
                  tabIndex={-1}
                  className={cn("sh-timebar__bar", !total && "is-empty")}
                  data-active={bucket.active || active === i ? "" : undefined}
                  style={{ left: x0, width: Math.max(1, x1 - x0 - 1) }}
                  aria-label={items[i]?.label}
                  onClick={(event) => {
                    setActive(i);
                    const part = (event.target as HTMLElement).closest<HTMLElement>("i[data-part]")?.dataset.part;
                    onBucket?.(bucket, part === undefined ? undefined : bucket.parts[Number(part)]);
                  }}
                >
                  {total ? (
                    bucket.parts.map((part, index) =>
                      part.value ? (
                        <i
                          key={part.label}
                          data-part={index}
                          data-tone={part.tone}
                          style={{ height: Math.max(1, (part.value / max) * (plotH - 2)) }}
                        />
                      ) : null,
                    )
                  ) : (
                    <i />
                  )}
                </button>
              );
            })
          : null}
        {width && !bars
          ? merged.map((mark, i) => (
              <button
                key={mark.key}
                id={`${id}-${i}`}
                type="button"
                role="option"
                aria-selected={active === i}
                tabIndex={-1}
                className={cn("sh-timebar__mark", mark.hl && "is-hl")}
                data-kind={mark.kind}
                data-tone={mark.tone}
                data-stack={stack[i]}
                data-active={mark.active || active === i ? "" : undefined}
                style={{ left: mark.x }}
                aria-label={items[i]?.label}
                onClick={() => {
                  setActive(i);
                  onPick?.(mark);
                }}
                onPointerEnter={() => onPoint?.(mark.key)}
                onPointerLeave={() => onPoint?.(null)}
              >
                {counted.has(i) ? <span className="sh-timebar__count">{mark.count}</span> : null}
              </button>
            ))
          : null}
        {cursor !== null && !dragging ? (
          <span className="sh-timebar__cursor" style={{ left: cursor }} aria-hidden>
            <span>{cursorText}</span>
          </span>
        ) : null}
        <span className="sh-timebar__axis" style={{ left: gutter }} aria-hidden>
          {shownTicks.map((tick) => (
            <span key={tick.x} className="sh-timebar__tick" style={{ left: tick.x - gutter }}>
              {moment(tick.t, range)}
            </span>
          ))}
        </span>
      </div>
    </div>
  );
}
