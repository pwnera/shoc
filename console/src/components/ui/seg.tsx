/**
 * A segmented control: one choice among a few, applied at once (a window, a
 * view, a mode). A radiogroup with one tab stop; arrow keys move and select.
 * Replaces tabs bent into toggles and every 7/30/90 select.
 */
import type { KeyboardEvent, ReactNode } from "react";
import { cn } from "@/lib/cn";

const SEG_KEYS: Record<string, number> = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };

export type SegOption<T extends string> =
  | T
  | { value: T; label?: ReactNode; count?: number; disabled?: boolean };

export function Seg<T extends string>({
  value,
  options,
  onChange,
  size = "sm",
  label,
  className,
}: {
  value: T;
  options: readonly SegOption<T>[];
  onChange: (value: T) => void;
  size?: "sm" | "md";
  /** The group's accessible name ("Window"). */
  label: string;
  className?: string;
}) {
  const items = options.map((option) => (typeof option === "string" ? { value: option } : option));
  const enabled = items.filter((item) => !item.disabled);
  // One tab stop: the checked item, or the first one when the value is not among them.
  const stop = items.some((item) => item.value === value) ? value : enabled[0]?.value;

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = SEG_KEYS[event.key];
    const jump = event.key === "Home" ? 0 : event.key === "End" ? enabled.length - 1 : null;
    if (step === undefined && jump === null) return;
    event.preventDefault();
    const at = enabled.findIndex((item) => item.value === value);
    const next = enabled[jump ?? (at + (step ?? 0) + enabled.length) % enabled.length];
    if (!next) return;
    onChange(next.value);
    event.currentTarget.querySelector<HTMLElement>(`[data-value="${CSS.escape(next.value)}"]`)?.focus();
  };

  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn("sh-seg", size === "md" && "sh-seg--md", className)}
      onKeyDown={onKeyDown}
    >
      {items.map((item) => {
        const checked = item.value === value;
        return (
          <button
            key={item.value}
            type="button"
            role="radio"
            aria-checked={checked}
            data-value={item.value}
            tabIndex={item.value === stop ? 0 : -1}
            disabled={item.disabled}
            onClick={() => onChange(item.value)}
            className="sh-seg__item"
          >
            {item.label ?? item.value}
            {typeof item.count === "number" ? (
              <span className="sh-seg__count">{item.count.toLocaleString()}</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
