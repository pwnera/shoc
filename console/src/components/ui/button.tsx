import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/cn";
import { useSingleKeys } from "@/lib/commands";

/**
 * primary is the one thing the screen is for; crew hands work to the crew and
 * carries its mark once (`<CrewMark/>`, rendered by the caller, never by CSS);
 * danger changes something outside shoc; ghost for toolbars and rows; default
 * for the rest. md (32px) in headers and dialogs, sm (24px) in panels and rows,
 * icon for a glyph alone (with an aria-label).
 */
export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "danger" | "ghost" | "crew";
  size?: "sm" | "md" | "icon";
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = "default", size = "md", type = "button", "aria-keyshortcuts": keys, ...props },
  ref,
) {
  // A one-key shortcut is announced only while single keys are on (the account menu turns them off).
  const [single] = useSingleKeys();
  return (
    <button
      ref={ref}
      type={type}
      className={cn("sh-btn", `sh-btn--${variant}`, `sh-btn--${size}`, className)}
      aria-keyshortcuts={keys && (single || keys.length > 1) ? keys : undefined}
      {...props}
    />
  );
});

/** The crew's "›", once per crew control: "› Ask the crew". */
export function CrewMark() {
  return (
    <span className="sh-crewmark" aria-hidden>
      ›
    </span>
  );
}
