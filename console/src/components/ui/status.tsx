/**
 * Status in shape and word, autonomy as a monochrome ramp, and the shell's
 * one-line banner. A status mark is shaped (good ■, warn ▲, bad ■ with a bar,
 * idle □, running a pulsing ■), so hue is never the only signal; severity
 * squares use the same mark with a severity tone. Idle has two variants for an
 * absence: dashed (never sent: the source is there, the value is not) and
 * hatched (no source, couldn't look). Crew is the crew asking ("waits").
 */
import type { ReactNode } from "react";
import { AlertTriangle, Bell, User, X, Zap } from "lucide-react";
import { cn } from "@/lib/cn";
import { AUTONOMY } from "@/lib/labels";
import { Tip } from "./tip";
import type { Severity } from "@/types";

export type StatusTone = "good" | "warn" | "bad" | "idle" | "running" | "crew" | "idle-dashed" | "idle-hatched";
/** `plain`: an fg-2 mark (a cited event); `good-hollow`: good, explained rather than clear. */
export type MarkTone = StatusTone | Severity | "human" | "muted" | "neutral" | "plain" | "good-hollow" | "seq-1" | "seq-2" | "seq-3" | "seq-4";

/** A 6px shaped square: a row glyph for status, severity or the crew. */
export function Mark({ tone, label, large }: { tone: MarkTone; label?: string; large?: boolean }) {
  return (
    <i
      className={cn("sh-mark", large && "sh-mark--lg")}
      data-tone={tone}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    />
  );
}

/** The mark and a mono word; `badge` outlines it. Without a word the mark is named by `label`. */
export function Status({
  tone,
  children,
  badge,
  label,
  className,
}: {
  tone: StatusTone;
  children?: ReactNode;
  badge?: boolean;
  label?: string;
  className?: string;
}) {
  const bare = children === undefined || children === null || children === "";
  return (
    <span
      className={cn("sh-status", badge && "sh-status--badge", className)}
      data-tone={tone}
      role={bare ? "img" : undefined}
      aria-label={bare ? (label ?? tone) : label}
    >
      <i className="sh-mark" data-tone={tone} aria-hidden />
      {children}
    </span>
  );
}

const LEVELS = {
  L0: { icon: Bell, tip: "Notifies only" },
  L1: { icon: Zap, tip: "Acts on its own" },
  L2: { icon: User, tip: "A person approves" },
} as const;

/** L0 notify, L1 auto, L2 you: who lets an act happen. Never coloured like severity or the crew. */
export function AutonomyBadge({ level }: { level: string }) {
  const known = LEVELS[level as keyof typeof LEVELS];
  if (!known) return null;
  const Icon = known.icon;
  return (
    <Tip label={known.tip}>
      <span className={`sh-badge sh-auto--${level.toLowerCase()}`}>
        <Icon aria-hidden />
        {AUTONOMY[level as keyof typeof LEVELS]}
      </span>
    </Tip>
  );
}

/** One full-width line under the top bar: an icon, a sentence, one action. */
export function Banner({
  tone = "warn",
  role,
  children,
  action,
  onClose,
}: {
  tone?: "warn" | "bad";
  /** A bad banner interrupts (alert) unless it repeats a standing fact on each screen it returns to (status). */
  role?: "alert" | "status";
  children: ReactNode;
  /** A link or button; give it the `sh-banner__action` class. */
  action?: ReactNode;
  /** Dismissible for the session when given. */
  onClose?: () => void;
}) {
  return (
    <div className={cn("sh-banner", tone === "bad" && "sh-banner--bad")} role={role ?? (tone === "bad" ? "alert" : "status")}>
      <AlertTriangle aria-hidden />
      <span className="sh-banner__text">{children}</span>
      {action}
      {onClose ? (
        <button type="button" className="sh-banner__close" onClick={onClose} aria-label="Dismiss">
          <X className="h-3.5 w-3.5" aria-hidden />
        </button>
      ) : null}
    </div>
  );
}
