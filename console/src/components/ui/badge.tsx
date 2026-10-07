/**
 * Badges: an 18px mono tag, read rather than clicked. Severity is filled in
 * its hue; status is outlined and shaped (`sh-tone-good|warn|bad|idle`);
 * verdicts are neither, neutral ink with a glyph, so severity owns colour;
 * blue is only the crew's.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { verdictLabel } from "@/lib/labels";
import type { Severity, Verdict } from "@/types";
import { Tip } from "./tip";

export type Tone =
  | "critical"
  | "high"
  | "medium"
  | "good"
  | "warn"
  | "bad"
  | "idle"
  | "crew"
  | "muted"
  | "faint";

/** Always one line. `title` shows as a tip. */
export function Badge({
  children,
  tone,
  caps,
  title,
  className,
}: {
  children: ReactNode;
  tone?: Tone | null;
  caps?: boolean;
  title?: string;
  className?: string;
}) {
  return (
    <Tip label={title}>
      <span className={cn("sh-badge", caps && "sh-badge--caps", tone && `sh-tone-${tone}`, className)}>
        {children}
      </span>
    </Tip>
  );
}

const SEVERITY: Record<Severity, Tone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "muted",
  informational: "faint",
};

/** Filled in the severity hue. "info" for informational, so the badge never clips its column. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge caps tone={SEVERITY[severity] ?? "muted"}>
      {severity === "informational" ? "info" : severity}
    </Badge>
  );
}

/** Neutral ink and a glyph; "needs you" in the crew's tone. Confidence beside it when given. */
export function VerdictBadge({ verdict, confidence }: { verdict: Verdict; confidence?: number }) {
  const known = verdictLabel(verdict);
  return (
    <span className="sh-verdict">
      <Badge tone={"tone" in known && known.tone === "crew" ? "crew" : null}>
        <span aria-hidden>{known.glyph}</span>
        {known.word}
      </Badge>
      {typeof confidence === "number" && verdict !== "unknown" && verdict !== "needs_human" ? (
        <ConfidenceBar value={confidence} />
      ) : null}
    </span>
  );
}

/**
 * Confidence as five segments and "82%". Lit segments are crew blue only for
 * the crew's own confidence; `plain` is a finding's, a rule's or a playbook
 * floor's.
 */
export function ConfidenceBar({
  value,
  hideNumber,
  plain,
}: {
  value: number;
  hideNumber?: boolean;
  plain?: boolean;
}) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  const lit = Math.round(pct / 20);
  return (
    <span
      className={cn("sh-conf", plain && "sh-conf--plain")}
      role="meter"
      aria-label="confidence"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct}
      aria-valuetext={`${pct}%`}
    >
      <span className="sh-conf__seg" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => (
          <i key={i} className={i < lit ? "on" : undefined} />
        ))}
      </span>
      {hideNumber ? null : <span className="sh-conf__num">{pct}%</span>}
    </span>
  );
}
