import type { HTMLAttributes, ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/cn";

/**
 * A panel: opaque, one hairline, 8px corners. Depth is drawn, not lit. Every
 * other prop reaches the element, so `aria-busy` and `aria-labelledby` land.
 */
export function Card({ className, children, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <section className={cn("sh-card", className)} {...props}>
      {children}
    </section>
  );
}

/**
 * A 32px header: a sans title that is a noun, a mono subtitle that is a count
 * or a time, and actions to the right. The title is an h2, an h3 with `level`
 * under a section's own heading.
 */
export function CardHeader({
  title,
  level,
  subtitle,
  action,
  className,
}: {
  title: ReactNode;
  level?: 3;
  subtitle?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  const Title = level === 3 ? "h3" : "h2";
  return (
    <header className={cn("sh-card__header", className)}>
      <Title className="sh-card__title">{title}</Title>
      {subtitle !== undefined && subtitle !== null && subtitle !== "" ? (
        <span className="sh-card__subtitle">{subtitle}</span>
      ) : null}
      {action ? <div className="sh-card__actions">{action}</div> : null}
    </header>
  );
}

export function CardBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("sh-card__body", className)}>{children}</div>;
}

/** A 40px second row under a card header (or its first row when a tab names the card): filters, a window. */
export function CardToolbar({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("sh-card__toolbar", className)}>{children}</div>;
}

/** KPI cells in an auto-fit grid, separated by hairlines: the report print view only; screens use a strip. */
export function Stats({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("sh-stats", className)}>{children}</div>;
}

/** A KPI; with `to` it is a link to the screen that lists what it counts, filtered. */
export function Stat({
  label,
  value,
  hint,
  tone,
  to,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "warn" | "bad" | "good" | "crew";
  to?: string;
}) {
  const body = (
    <>
      <span className="sh-stat__label">{label}</span>
      <span
        className={cn("sh-stat__value", tone && tone !== "default" && `sh-stat__value--${tone}`)}
      >
        {value}
      </span>
      {hint ? (
        <span className="sh-stat__hint" title={typeof hint === "string" ? hint : undefined}>
          {hint}
        </span>
      ) : null}
    </>
  );
  return to ? (
    <Link to={to} className="sh-stat sh-stat--link">
      {body}
    </Link>
  ) : (
    <div className="sh-stat">{body}</div>
  );
}
