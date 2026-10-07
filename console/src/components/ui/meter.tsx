/**
 * Amounts drawn, not coloured numbers. Meter is one value against a range,
 * its tone from thresholds, with ticks for a threshold, cap, budget or
 * ceiling; `parts` stacks several (a severity mix). Share splits a whole into
 * segments that add to 100%; a segment with `onClick` is a button that
 * filters to its slice, the rest are plain.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Tip } from "./tip";

export type MeterTone =
  | "good"
  | "warn"
  | "bad"
  | "crew"
  | "neutral"
  | "muted"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "idle"
  | "idle-dashed"
  | "idle-hatched"
  | "good-hollow"
  | "seq-1"
  | "seq-2"
  | "seq-3"
  | "seq-4";

const clamp = (n: number) => Math.max(0, Math.min(1, n));

export function Meter({
  value,
  min = 0,
  max = 1,
  tone = "neutral",
  marks,
  parts,
  size = "sm",
  label,
  valueText,
  format,
  showValue = true,
  badge,
  width,
  className,
}: {
  value: number;
  min?: number;
  max?: number;
  /** A tone, or a function of the value ("bad below 0.5"). */
  tone?: MeterTone | ((value: number) => MeterTone);
  /** 1px ticks: a threshold, a cap, a budget, a ceiling. */
  marks?: { at: number; label: string }[];
  /** Stacked fills, left to right; `value` is then their total. */
  parts?: { value: number; tone: MeterTone; label: string }[];
  size?: "sm" | "md";
  /** The accessible name ("Quality", "Tokens against cap"). */
  label: string;
  valueText?: string;
  /** The number beside the track; a percent of the range by default. */
  format?: (value: number) => ReactNode;
  showValue?: boolean;
  /** A 48px track and its value in a badge-sized box, for a row. */
  badge?: boolean;
  /** Track width in px; it grows to fill otherwise. */
  width?: number;
  className?: string;
}) {
  const span = max - min || 1;
  const at = (n: number) => `${clamp((n - min) / span) * 100}%`;
  const shown = format ? format(value) : `${Math.round(clamp((value - min) / span) * 100)}%`;
  const text =
    valueText ??
    (parts
      ? parts
          .filter((p) => p.value)
          .map((p) => `${p.value} ${p.label}`)
          .join(", ")
      : typeof shown === "string"
        ? shown
        : String(value));
  const fillTone = typeof tone === "function" ? tone(value) : tone;
  return (
    <span
      className={cn(
        "sh-meter",
        size === "md" && "sh-meter--md",
        parts && "sh-meter--stacked",
        badge && "sh-meter--badge",
        className,
      )}
      role="meter"
      aria-label={label}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={Math.max(min, Math.min(max, value))}
      aria-valuetext={text}
    >
      <span className="sh-meter__track" style={width ? { width, flex: "none" } : undefined} aria-hidden>
        {parts ? (
          parts.map((part) =>
            part.value > 0 ? (
              <i
                key={part.label}
                className="sh-meter__fill"
                data-tone={part.tone}
                style={{ width: `${clamp(part.value / span) * 100}%` }}
              />
            ) : null,
          )
        ) : (
          <i className="sh-meter__fill" data-tone={fillTone} style={{ width: at(value) }} />
        )}
        {marks?.map((mark) => (
          <i key={mark.label} className="sh-meter__mark" style={{ left: at(mark.at) }} />
        ))}
      </span>
      {showValue ? (
        <span className="sh-meter__value" aria-hidden>
          {shown}
        </span>
      ) : null}
    </span>
  );
}

/**
 * A whole split into segments; one with `onClick` is a button that filters to
 * its slice. Under the bar a segment says its count (`count`, the default),
 * its word ("12 live", `word`) or nothing (`none`): only non-zero segments,
 * the five largest at most, and only where the label fits; the rest say it in
 * the tip.
 */
export function Share({
  segments,
  label,
  labels = "count",
}: {
  segments: {
    key: string;
    label: string;
    value: number;
    tone?: MeterTone;
    onClick?: () => void;
    pressed?: boolean;
  }[];
  /** The group's accessible name ("Rules by state"). */
  label: string;
  labels?: "count" | "word" | "none";
}) {
  const shown = segments.filter((s) => s.value > 0);
  const total = shown.reduce((sum, s) => sum + s.value, 0);
  // A count fits a segment of about 6% of the bar; the rest say theirs in the tip.
  const labelled = new Set(
    [...shown]
      .sort((a, b) => b.value - a.value)
      .slice(0, 5)
      // A word needs about three times a count's room.
      .filter((s) => s.value / total >= (labels === "word" ? 0.18 : 0.06))
      .map((s) => s.key),
  );
  return (
    <div className="sh-share" role="group" aria-label={label}>
      {shown.map((segment) => {
        const said = `${segment.value.toLocaleString()} ${segment.label}`;
        const text = labels === "none" || !labelled.has(segment.key) ? " " : labels === "word" ? said : segment.value.toLocaleString();
        const body = (
          <>
            <i data-tone={segment.tone ?? "muted"} />
            {labels === "none" ? null : <span aria-hidden>{text}</span>}
          </>
        );
        return (
          <Tip key={segment.key} label={said}>
            {segment.onClick ? (
              <button
                type="button"
                className="sh-share__seg"
                style={{ flex: `${segment.value} 1 0` }}
                onClick={segment.onClick}
                aria-pressed={segment.pressed}
                aria-label={said}
              >
                {body}
              </button>
            ) : (
              <span className="sh-share__seg sh-share__seg--static" style={{ flex: `${segment.value} 1 0` }} role="img" aria-label={said}>
                {body}
              </span>
            )}
          </Tip>
        );
      })}
    </div>
  );
}
