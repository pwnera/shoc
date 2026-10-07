/**
 * Steps joined by a hairline: a case's lifecycle, a playbook run, an action's
 * life, a source's onboarding, the pipeline. A step's state is its shape (done
 * a good square, current filled, running pulsing, waiting a human ring, failed
 * a bad square, skipped dashed, todo hollow, always a neutral filled square)
 * and a word for screen readers; its time is in a tip. An optional step is
 * dashed and heard as "optional". `progress` collapses to "2/4" and a meter;
 * `stage` draws nodes with a status square and at most one number. `body`
 * lets a screen draw each step's own element (a popover trigger) around the
 * dot and label.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { stamp } from "@/lib/format";
import type { StepState } from "@/lib/labels";
import { Meter } from "./meter";
import { Mark, type StatusTone } from "./status";
import { Tip } from "./tip";

export type { StepState };

export type Step = {
  key: string;
  label: ReactNode;
  state: StepState;
  /** When it happened; shown in the step's tip. */
  time?: string | null;
  /** One number or word beside the label (vertical and stage). */
  value?: ReactNode;
  tip?: ReactNode;
  /** A 16px logo or glyph before the label (a playbook step's platform). */
  icon?: ReactNode;
  /** May not run: dashed, and heard as "optional" rather than as its state. */
  optional?: boolean;
};

const STAGE: Record<StepState, StatusTone> = {
  done: "good",
  current: "running",
  running: "running",
  waiting: "warn",
  failed: "bad",
  skipped: "idle",
  todo: "idle",
  always: "idle",
};

const WORD: Record<StepState, string> = {
  done: "done",
  current: "current",
  running: "running",
  waiting: "waiting on a person",
  failed: "failed",
  skipped: "skipped",
  todo: "not yet",
  always: "always runs",
};

export function Steps({
  steps,
  variant = "default",
  onPick,
  body,
  label,
}: {
  steps: Step[];
  variant?: "default" | "vertical" | "interactive" | "progress" | "stage";
  /** Makes steps buttons (the case stepper, a run's steps). */
  onPick?: (step: Step) => void;
  /**
   * Draws a step's element instead of the button or span: give it the props'
   * class and children. The step's tip is then the screen's to add.
   */
  body?: (step: Step, props: { className: string; children: ReactNode }) => ReactNode;
  label?: string;
}) {
  if (variant === "progress") {
    const done = steps.filter((s) => s.state === "done" || s.state === "skipped").length;
    const failed = steps.some((s) => s.state === "failed");
    return (
      <span className="sh-steps sh-steps--progress">
        {done}/{steps.length}
        <Meter
          value={done}
          max={Math.max(1, steps.length)}
          tone={failed ? "bad" : done === steps.length ? "good" : "neutral"}
          label={label ?? "Steps done"}
          valueText={`${done} of ${steps.length}${failed ? ", one failed" : ""}`}
          showValue={false}
        />
      </span>
    );
  }
  return (
    <ol
      className={cn(
        "sh-steps",
        variant !== "default" && variant !== "interactive" && `sh-steps--${variant}`,
        (onPick || body || variant === "interactive") && "sh-steps--interactive",
      )}
      aria-label={label}
    >
      {steps.map((step) => {
        const inner = (
          <>
            {variant === "stage" ? <Mark tone={STAGE[step.state]} /> : <i className="sh-steps__dot" aria-hidden />}
            {step.icon ? <span className="sh-steps__icon">{step.icon}</span> : null}
            <span className="sh-steps__label">{step.label}</span>
            {step.value !== undefined && step.value !== null ? <span className="sh-steps__value">{step.value}</span> : null}
            <span className="sr-only">, {step.optional && step.state !== "done" && step.state !== "failed" ? "optional" : WORD[step.state]}</span>
          </>
        );
        const tip = step.tip ?? (step.time ? stamp(step.time) : undefined);
        const own = body ? (
          body(step, { className: "sh-steps__body", children: inner })
        ) : (
          <Tip label={tip}>
            {onPick ? (
              <button type="button" className="sh-steps__body" onClick={() => onPick(step)}>
                {inner}
              </button>
            ) : (
              <span className="sh-steps__body">{inner}</span>
            )}
          </Tip>
        );
        return (
          <li
            key={step.key}
            className="sh-steps__step"
            data-state={step.state}
            data-optional={step.optional ? "" : undefined}
            aria-current={step.state === "current" || step.state === "running" ? "step" : undefined}
          >
            {own}
          </li>
        );
      })}
    </ol>
  );
}
