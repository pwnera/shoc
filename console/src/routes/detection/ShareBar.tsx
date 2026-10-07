/**
 * A whole split into segments, drawn here rather than with `ui/meter` Share:
 * that one has no word labels, no fill other than solid and no read-only
 * mode. Each segment has a tone and a fill (solid; dashed for "never sent";
 * hatched for "no source"), so idle states read quieter than live ones and
 * hue is never the only signal. With `legend`, a line of count + word per
 * non-zero segment follows the bar and each entry filters; without it the
 * segments are read-only and their counts live in tips.
 */
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";

export type Fill = "solid" | "dashed" | "hatched";

export type ShareSegment = {
  key: string;
  label: string;
  value: number;
  tone: "good" | "warn" | "bad" | "idle" | "muted" | "neutral";
  fill?: Fill;
  pressed?: boolean;
  onClick?: () => void;
};

const FILL: Record<Fill, string> = {
  solid: "bg-[var(--tone)]",
  dashed: "border border-dashed border-[var(--tone)]",
  hatched:
    "bg-[repeating-linear-gradient(135deg,var(--tone)_0_1px,transparent_1px_4px)] shadow-[inset_0_0_0_1px_var(--tone)]",
};

function Swatch({ segment, className }: { segment: ShareSegment; className?: string }) {
  return <i data-tone={segment.tone} className={cn("box-border block", FILL[segment.fill ?? "solid"], className)} />;
}

const said = (s: ShareSegment) => `${s.value.toLocaleString()} ${s.label}`;

export function ShareBar({
  segments,
  label,
  legend,
  className,
}: {
  segments: ShareSegment[];
  /** The accessible name ("Rules by state"). */
  label: string;
  legend?: boolean;
  className?: string;
}) {
  const shown = segments.filter((s) => s.value > 0);
  if (!shown.length) return null;
  const picked = shown.some((s) => s.pressed);
  const bar = (
    <span
      className="flex h-2 w-full min-w-0 gap-px"
      role={legend ? undefined : "img"}
      aria-label={legend ? undefined : `${label}: ${shown.map(said).join(", ")}`}
      aria-hidden={legend || undefined}
    >
      {shown.map((s) => (
        <Tip key={s.key} label={said(s)}>
          <span
            className={cn("flex min-w-[3px]", s.onClick && "cursor-pointer", picked && !s.pressed && "opacity-40")}
            style={{ flex: `${s.value} 1 0` }}
            onClick={s.onClick}
          >
            <Swatch segment={s} className="h-full w-full" />
          </span>
        </Tip>
      ))}
    </span>
  );
  if (!legend) return <span className={cn("flex min-w-0", className)}>{bar}</span>;
  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
      {bar}
      <div role="group" aria-label={label} className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {shown.map((s) => (
          <button
            key={s.key}
            type="button"
            onClick={s.onClick}
            aria-pressed={s.pressed ?? false}
            aria-label={said(s)}
            className="-mx-1.5 inline-flex items-center gap-1.5 rounded-[var(--radius-1)] border border-transparent px-1.5 whitespace-nowrap hover:bg-bg-2 aria-pressed:border-line-2 aria-pressed:bg-bg-2"
          >
            <Swatch segment={s} className="h-2 w-2 rounded-[1px]" />
            <span className="[font:var(--text-mono)] text-fg-1 tabular-nums">{s.value.toLocaleString()}</span>
            <span className="[font:var(--text-label)] text-fg-3">{s.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
