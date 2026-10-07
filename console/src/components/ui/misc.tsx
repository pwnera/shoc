/**
 * The small things every screen uses: states (spinner, loading, empty, error),
 * text roles (label, kbd), inputs, tabs, the switch, the "new" pill and the
 * polite region.
 */
import { useEffect, useId, useLayoutEffect, useRef, useState, type ComponentProps, type KeyboardEvent, type ReactNode } from "react";
import { AlertTriangle, ArrowUp, Check, Loader2, type LucideIcon } from "lucide-react";
import { announce, useAnnounced } from "@/lib/announce";
import { ApiError, useUnreachable } from "@/lib/api";
import { cn } from "@/lib/cn";
import { refusal } from "@/lib/labels";
import { Button } from "./button";

/** Appears after 300ms, so a fast answer never flashes it; a static "…" under reduced motion. */
export function Spinner({ className }: { className?: string }) {
  return (
    <>
      <Loader2 className={cn("sh-spin text-fg-4", className)} aria-hidden />
      <span className="sh-spin__dots" aria-hidden>
        …
      </span>
    </>
  );
}

/** A spinner and a lower-case mono word, for a whole-page wait only; panels use skeletons. */
export function Loading({ label = "loading" }: { label?: string }) {
  return (
    <div className="sh-loading" role="status">
      <Spinner />
      {label}
    </div>
  );
}

/**
 * One quiet line that says what is true. `clear` is good news (a check in the
 * good tone), `filtered` shows the chips that hide everything and a way out,
 * `row` sits inside a table body, `page` is a missing record with one link back.
 */
export function Empty({
  title,
  center,
  kind,
  icon,
  meta,
  action,
  chips,
  onClear,
}: {
  title: string;
  center?: boolean;
  kind?: "clear" | "filtered" | "row" | "page";
  icon?: LucideIcon;
  /** Mono fact: "last decision 3h ago". */
  meta?: ReactNode;
  /** One sm button or link. */
  action?: ReactNode;
  /** The active filter chips, for `filtered`. */
  chips?: ReactNode;
  onClear?: () => void;
}) {
  const Icon = icon ?? (kind === "clear" ? Check : null);
  return (
    <div
      className={cn("sh-empty", kind && `sh-empty--${kind}`, center && "sh-empty--center")}
      role={kind === "row" ? undefined : "status"}
    >
      {Icon ? <Icon className="sh-empty__icon" aria-hidden /> : null}
      <p className="sh-empty__title">{title}</p>
      {meta ? <span className="sh-empty__meta">{meta}</span> : null}
      {chips ? <span className="sh-empty__chips">{chips}</span> : null}
      {action ? <span className="sh-empty__action">{action}</span> : null}
      {kind === "filtered" && onClear ? (
        <span className="sh-empty__action">
          <button type="button" className="sh-filterbar__clear" onClick={onClear}>
            Clear filters
          </button>
        </span>
      ) : null}
    </div>
  );
}

/**
 * What failed, in the error's own words, and a way to try again. `inline` is
 * one row under a control. A signed-out browser reads "—": the shell's banner
 * is the one home of that fact, and Retry cannot help until it signs in. A
 * missing scope says what the caller's role cannot do, with no Retry either.
 */
export function ErrorNote({
  error,
  onRetry,
  inline,
}: {
  error: unknown;
  onRetry?: () => void;
  inline?: boolean;
}) {
  const down = useUnreachable();
  // Signed out, or shoc unreachable, has its one home in the shell's banner: the panel only says it cannot tell.
  if (error instanceof ApiError && (error.isSignedOut || (down && error.isNetwork)))
    return (
      <span className="sh-mono">
        —<span className="sr-only">{error.isNetwork ? " shoc unreachable" : " signed out"}</span>
      </span>
    );
  const refused = error instanceof ApiError && error.isAuth;
  const message = refused
    ? (refusal(error.message) ?? "Not allowed")
    : error instanceof Error
      ? error.message
      : String(error);
  return (
    <div role="alert" className={cn("sh-error", inline && "sh-error--inline")}>
      <AlertTriangle aria-hidden />
      <span className="sh-error__text">{message}</span>
      {onRetry && !refused ? (
        <Button variant="ghost" size="sm" className="sh-error__retry" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

/** 11px uppercase mono: field labels, group names. */
export function Label({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn("sh-label", className)}>{children}</span>;
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="sh-kbd">{children}</kbd>;
}

type Small = { small?: boolean };

/** `ref` is a prop in React 19, so a screen can focus or measure it. */
export function Input({
  className,
  mono,
  small,
  ...props
}: ComponentProps<"input"> & Small & { mono?: boolean }) {
  return (
    <input
      className={cn("sh-input", mono && "sh-input--mono", small && "sh-input--sm", className)}
      {...props}
    />
  );
}

export function Select({
  className,
  small,
  ...props
}: ComponentProps<"select"> & Small) {
  return <select className={cn("sh-select", small && "sh-select--sm", className)} {...props} />;
}

const TAB_KEYS: Record<string, number> = { ArrowRight: 1, ArrowLeft: -1, Home: -Infinity, End: Infinity };

/**
 * Underline tabs: each tab is a disjoint slice of one list. Arrow keys move
 * between tabs and select them; with `id`, each tab controls the `TabPanel`
 * of the same value. A count of null reads "—" while it is unknown; a string
 * count is shown as it is ("200+" at a kernel cap), in the count's own style.
 */
type Edges = { left: boolean; right: boolean };

/** Whether a sideways scroller hides content to its left and to its right; unchanged, the old value, so nothing redraws. */
const edgesOf =
  (el: HTMLElement) =>
  (was: Edges): Edges => {
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    return left === was.left && right === was.right ? was : { left, right };
  };

/** A 24px fade on each edge that hides more; none when nothing is hidden. */
function fade({ left, right }: Edges): string | undefined {
  if (!left && !right) return undefined;
  return `linear-gradient(to right, ${left ? "transparent, #000 24px" : "#000"}, ${right ? "#000 calc(100% - 24px), transparent" : "#000"})`;
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  id,
  label,
  className,
}: {
  tabs: { value: T; label: string; count?: number | string | null; crew?: boolean }[];
  value: T;
  onChange: (value: T) => void;
  /** Ties tabs to their panels (`aria-controls`). */
  id?: string;
  label?: string;
  className?: string;
}) {
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = TAB_KEYS[event.key];
    if (step === undefined) return;
    event.preventDefault();
    const at = tabs.findIndex((tab) => tab.value === value);
    const next = Number.isFinite(step)
      ? (at + step + tabs.length) % tabs.length
      : step > 0
        ? tabs.length - 1
        : 0;
    const tab = tabs[next];
    if (!tab) return;
    onChange(tab.value);
    (event.currentTarget.children[next] as HTMLElement | undefined)?.focus();
  };
  // The row scrolls sideways on a narrow screen: the picked tab (a number key's, a shared ?tab=) comes into view, the
  // page stays put, and a faded edge says more tabs lie that way, following the row's scroll and width.
  const list = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState<Edges>({ left: false, right: false });
  useLayoutEffect(() => {
    const box = list.current;
    const tab = box?.querySelector<HTMLElement>('[aria-selected="true"]');
    if (!box || !tab) return;
    const b = box.getBoundingClientRect();
    const t = tab.getBoundingClientRect();
    if (t.left < b.left) box.scrollLeft -= b.left - t.left;
    else if (t.right > b.right) box.scrollLeft += t.right - b.right;
    setEdges(edgesOf(box));
  }, [value]);
  useEffect(() => {
    const box = list.current;
    if (!box) return;
    const sync = () => setEdges(edgesOf(box));
    const watch = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(sync);
    box.addEventListener("scroll", sync, { passive: true });
    // The row's width, and each tab's as its count arrives.
    for (const el of [box, ...box.children]) watch?.observe(el);
    return () => {
      box.removeEventListener("scroll", sync);
      watch?.disconnect();
    };
  }, [tabs.length]);
  return (
    <div
      ref={list}
      role="tablist"
      aria-label={label}
      className={cn("sh-tabs", className)}
      style={{ maskImage: fade(edges) }}
      onKeyDown={onKeyDown}
    >
      {tabs.map((tab) => {
        const selected = tab.value === value;
        return (
          <button
            key={tab.value}
            type="button"
            role="tab"
            id={id ? `${id}-tab-${tab.value}` : undefined}
            // Only the selected tab's panel is mounted.
            aria-controls={id && selected ? `${id}-panel-${tab.value}` : undefined}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.value)}
            className={cn("sh-tab", tab.crew && "sh-tab--crew")}
          >
            {tab.label}
            {tab.count === null ? (
              <span className="sh-tab__count">—</span>
            ) : typeof tab.count === "number" ? (
              <span className="sh-tab__count">{tab.count.toLocaleString()}</span>
            ) : typeof tab.count === "string" && tab.count ? (
              <span className="sh-tab__count">{tab.count}</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

/** The panel a tab of the same `id` and value controls. */
export function TabPanel({
  id,
  value,
  children,
  className,
}: {
  id: string;
  value: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div role="tabpanel" id={`${id}-panel-${value}`} aria-labelledby={`${id}-tab-${value}`} className={className}>
      {children}
    </div>
  );
}

/** A setting that takes effect at once. */
export function Switch({
  checked,
  onChange,
  disabled,
  children,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
  children?: ReactNode;
}) {
  const id = useId();
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-labelledby={children ? id : undefined}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="sh-switch"
    >
      <span className="sh-switch__track" />
      {children ? <span id={id}>{children}</span> : null}
    </button>
  );
}

/** "3 new ↑": rows that arrived while the reader was elsewhere in the list; the list never moves itself. Said at most every 10s. */
export function NewPill({ count, onClick, crew }: { count: number; onClick: () => void; crew?: boolean }) {
  const last = useRef(0);
  useEffect(() => {
    if (count <= 0 || Date.now() - last.current < 10_000) return;
    last.current = Date.now();
    announce(`${count.toLocaleString()} new`);
  }, [count]);
  if (count <= 0) return null;
  return (
    <button type="button" className={cn("sh-newpill", crew && "sh-newpill--crew")} onClick={onClick}>
      {count.toLocaleString()} new
      <ArrowUp className="h-3 w-3" aria-hidden />
    </button>
  );
}

/**
 * The polite region `announce` writes into: the page's, mounted once above the
 * sign-in gate, and one in each dialog, which speaks while its dialog is on top.
 */
export function Announcer() {
  const said = useAnnounced();
  // Undefined until mounted: a region that does not yet know its dialog says nothing.
  const [box, setBox] = useState<Element | null>();
  const here = box !== undefined && said.where === box;
  return (
    <div
      ref={(el) => {
        if (el) setBox(el.closest("dialog"));
      }}
      role="status"
      aria-live="polite"
      className="sr-only"
    >
      {here ? said.text : ""}
    </div>
  );
}
