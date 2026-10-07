/**
 * The popup a list row opens: the native <dialog>, so Escape, focus trapping
 * and the backdrop come from the browser. Mounted only while something is
 * picked. One popup pattern: sm (28rem), default (44rem) or wide (64rem); the
 * body is the only scroller; actions sit in the footer; under 768px it is a
 * bottom sheet. Opened from a list, it steps through that list with J and K,
 * also when the focused control has gone (a button that turned into a word)
 * and focus fell back to the page; a widget inside that already took the key
 * (a Seg, a graph, a list's row) keeps it. Closed after stepping, it hands
 * focus to the row its list followed it to, not the row that opened it. The
 * head holds the title, a badge and the stepper; the record's id is a copy
 * chip at the top of the body. A click on the backdrop closes it only when the
 * press began there too, so a selection dragged out of a field keeps the draft.
 * It holds its own polite region, since a modal leaves the page's inert.
 */
import { useEffect, useId, useLayoutEffect, useRef, type KeyboardEvent, type ReactNode } from "react";
import { ChevronLeft, ChevronRight, Minus, Plus, X } from "lucide-react";
import { cn } from "@/lib/cn";
import { useSingleKeys } from "@/lib/commands";
import { shortId } from "@/lib/format";
import { Copy, CopyButton } from "./field";
import { Announcer } from "./misc";

function typing(target: EventTarget): boolean {
  const el = target as HTMLElement;
  return /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable;
}

/** Widgets that move on the vertical arrows themselves: a radio group, tabs, a graph, a time bar, a list's row. */
const OWN_ARROWS = '[role="radiogroup"], [role="tablist"], .sh-graph, .sh-timebar, [data-row-key]';

/** A uid ("ACT-cd89…") shows short and copies whole; any other id shows as it is. */
const UID = /^[A-Z]{2,5}-[0-9a-f]{8,}$/i;

function popoverOpen(within: HTMLElement | null): boolean {
  try {
    return within?.querySelector(":popover-open") != null;
  } catch {
    return false;
  }
}

export function Dialog({
  title,
  id,
  footer,
  onClose,
  children,
  size,
  step,
  head,
  className,
}: {
  title: ReactNode;
  /** The record's own id, mono, beside the title. */
  id?: string;
  footer?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  size?: "sm" | "wide";
  /** "3 / 25" and ‹ ›, for the list that opened the dialog; J and K step too. */
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  /** Badges or a status after the title. */
  head?: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const opener = useRef<Element | null>(null);
  const returnTo = useRef<HTMLElement | null>(null);
  const pressed = useRef<EventTarget | null>(null);
  const titleId = useId();
  const [single] = useSingleKeys();
  /*
   * After a close that left focus nowhere (inside the closing dialog, or on the
   * page body: a link opened it on load, or Back unmounted it with no close
   * event), focus goes to the opener list's active row, else the opener, else
   * the page's heading, as after a route change, so the next Tab starts there.
   */
  const settle = (box: HTMLElement | null) =>
    requestAnimationFrame(() => {
      const held = document.activeElement;
      if ((held && held !== document.body && !box?.contains(held)) || document.querySelector("dialog[open]")) return;
      const was = opener.current;
      const from = was instanceof HTMLElement && was.isConnected && was !== document.body ? was : null;
      const list = from?.getAttribute("data-list");
      const row = list ? document.querySelector<HTMLElement>(`[data-list="${CSS.escape(list)}"][data-active]`) : null;
      (row ?? from ?? document.querySelector<HTMLElement>("main .sh-page__title"))?.focus({ preventScroll: true });
    });
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    // Strict mode mounts twice, and showModal on an open dialog throws; jsdom has no showModal.
    if (!dialog.open && dialog.showModal) {
      opener.current = document.activeElement;
      dialog.showModal();
      // React's autoFocus fires while the dialog is still closed, so a control asks
      // with data-autofocus; otherwise the dialog itself takes focus, not its first button.
      (dialog.querySelector<HTMLElement>("[data-autofocus]") ?? dialog).focus();
    }
    // Unmounted without a close event (Back over a popup kept in the URL), or the page re-rendered the row under a
    // close: focus would fall to the body.
    return () => void settle(dialog);
  }, []);
  // A close and a pick of another record in one render keep this instance with its <dialog> shut: show it again.
  const record = `${id ?? ""}#${step?.index ?? ""}`;
  const shown = useRef(record);
  useEffect(() => {
    const dialog = ref.current;
    if (shown.current === record) return;
    shown.current = record;
    if (!dialog || dialog.open || !dialog.showModal) return;
    dialog.showModal();
    dialog.focus();
  }, [record]);

  // Through the native close, so the browser returns focus to the opener; the
  // close event then calls onClose.
  const shut = () => {
    // After J and K the opener's list has followed to another row: remember it before the browser refocuses the opener.
    const list = step ? opener.current?.getAttribute("data-list") : null;
    returnTo.current = list ? document.querySelector<HTMLElement>(`[data-list="${CSS.escape(list)}"][data-active]`) : null;
    if (ref.current?.open && ref.current.close) ref.current.close();
    else onClose();
  };

  const stepKey = (event: { key: string; metaKey: boolean; ctrlKey: boolean; altKey: boolean; target: EventTarget | null }) => {
    if (!step || event.metaKey || event.ctrlKey || event.altKey || (event.target && typing(event.target))) return false;
    if ((event.target as HTMLElement | null)?.closest?.(OWN_ARROWS)) return false;
    const key = event.key.toLowerCase();
    const next = key === "arrowdown" || (single && key === "j");
    const prev = key === "arrowup" || (single && key === "k");
    if (next && step.onNext) step.onNext();
    else if (prev && step.onPrev) step.onPrev();
    else return false;
    return true;
  };
  const latestStep = useRef(stepKey);
  useLayoutEffect(() => {
    latestStep.current = stepKey;
  });

  // Focus on the page itself while this is the topmost modal: the control that held it unmounted.
  useEffect(() => {
    const onPageKey = (event: globalThis.KeyboardEvent) => {
      if (event.defaultPrevented || (event.target !== document.body && event.target !== document.documentElement)) return;
      const modals = [...document.querySelectorAll("dialog[open]")];
      if (modals.at(-1) !== ref.current) return;
      if (latestStep.current(event)) {
        event.preventDefault();
        ref.current?.focus();
      }
    };
    document.addEventListener("keydown", onPageKey);
    return () => document.removeEventListener("keydown", onPageKey);
  }, []);

  const onKeyDown = (event: KeyboardEvent<HTMLDialogElement>) => {
    // A dialog opened from this one (an action's run) handles its own keys; React bubbles them here.
    if ((event.target as HTMLElement).closest?.("dialog") !== ref.current) return;
    // Escape closes this dialog only: the browser would close every modal it
    // opened together (a deep link's stack) on one press. An open popover inside
    // closes itself first.
    if (event.key === "Escape") {
      if (event.defaultPrevented || popoverOpen(ref.current)) return;
      event.preventDefault();
      shut();
      return;
    }
    const mod = event.metaKey || event.ctrlKey;
    if (mod && event.key === "Enter") {
      const form = ref.current?.querySelector("form");
      if (form) {
        event.preventDefault();
        form.requestSubmit();
      }
      return;
    }
    // A control inside already handled it (a Seg's arrows, a graph's move).
    if (event.defaultPrevented || !stepKey(event)) return;
    event.preventDefault();
    event.stopPropagation();
  };

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      // React bubbles a nested dialog's close, which would shut this one too.
      onClose={(event) => {
        if (event.target !== event.currentTarget) return;
        const box = event.currentTarget;
        onClose();
        const row = returnTo.current;
        returnTo.current = null;
        if (row && row !== opener.current) requestAnimationFrame(() => row.isConnected && row.focus());
        else settle(box);
      }}
      onPointerDown={(event) => (pressed.current = event.target)}
      onClick={(event) => event.target === ref.current && pressed.current === ref.current && shut()}
      onKeyDown={onKeyDown}
      tabIndex={-1}
      className={cn("sh-dialog", size && `sh-dialog--${size}`, className)}
    >
      <div className="sh-dialog__head">
        <h2 id={titleId} className="sh-dialog__title">
          {title}
        </h2>
        {head}
        {step && step.total > 1 ? (
          <span className="sh-dialog__step">
            <button
              type="button"
              className="sh-dialog__close"
              onClick={step.onPrev}
              disabled={!step.onPrev}
              aria-label="Previous"
              aria-keyshortcuts={single ? "K" : undefined}
            >
              <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            </button>
            {step.index + 1} / {step.total}
            <button
              type="button"
              className="sh-dialog__close"
              onClick={step.onNext}
              disabled={!step.onNext}
              aria-label="Next"
              aria-keyshortcuts={single ? "J" : undefined}
            >
              <ChevronRight className="h-3.5 w-3.5" aria-hidden />
            </button>
          </span>
        ) : null}
        <button type="button" onClick={shut} aria-label="Close" className="sh-dialog__close">
          <X className="h-3.5 w-3.5" aria-hidden />
        </button>
      </div>
      <div className="sh-dialog__body scrollbar-thin">
        {id ? (
          <Copy value={id} label={`Copy ${id}`} className="sh-dialog__id">
            {UID.test(id) ? shortId(id) : id}
          </Copy>
        ) : null}
        {children}
      </div>
      {footer ? <footer className="sh-dialog__foot">{footer}</footer> : null}
      <Announcer />
    </dialog>
  );
}

/** Hover and focus buttons on a value: filter in, filter out, copy. */
export type Pivot = { in?: () => void; out?: () => void; copy?: string };

/**
 * Label/value pairs for a handful of facts about one thing; an empty value
 * drops its row. A third element adds pivots: + and − open Explore over the
 * window the host chose, or edit the running query when already there.
 */
export function Fields({
  rows,
  ruled,
}: {
  rows: ([string, ReactNode] | [string, ReactNode, Pivot | undefined])[];
  ruled?: boolean;
}) {
  return (
    <dl className={cn("sh-fields", ruled && "sh-fields--ruled")}>
      {rows
        .filter(([, value]) => value !== null && value !== undefined && value !== "")
        .map(([label, value, pivot], i) => (
          // A label can repeat: a hunt finding may observe two actors.
          <div key={`${i}:${label}`} className="contents">
            <dt>{label}</dt>
            <dd>
              {pivot ? <span className="min-w-0">{value}</span> : value}
              {pivot ? (
                <span className="sh-fields__pivot">
                  {pivot.in ? (
                    <button type="button" onClick={pivot.in} aria-label={`Filter in ${label}`}>
                      <Plus aria-hidden />
                    </button>
                  ) : null}
                  {pivot.out ? (
                    <button type="button" onClick={pivot.out} aria-label={`Filter out ${label}`}>
                      <Minus aria-hidden />
                    </button>
                  ) : null}
                  {pivot.copy !== undefined ? <CopyButton value={pivot.copy} label={`Copy ${label}`} /> : null}
                </span>
              ) : null}
            </dd>
          </div>
        ))}
    </dl>
  );
}

const TOKEN = /("[^"]*")(\s*:)?|(-?\d+(?:\.\d+)?)|(true|false|null)/g;

/** JSON text indented by two, token for token: a parse round trip would round 64-bit IDs. */
function indent(text: string): string {
  let out = "";
  let depth = 0;
  let inString = false;
  const pad = () => "\n" + "  ".repeat(depth);
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (inString) {
      out += c;
      if (c === "\\") out += text.charAt(++i);
      else if (c === '"') inString = false;
    } else if (c === '"') {
      out += c;
      inString = true;
    } else if (c === "{" || c === "[") {
      const close = text.slice(i + 1).trimStart()[0];
      if (close === "}" || close === "]") {
        out += c + close;
        i = text.indexOf(close, i + 1);
      } else {
        depth++;
        out += c + pad();
      }
    } else if (c === "}" || c === "]") {
      depth--;
      out += pad() + c;
    } else if (c === ",") out += c + pad();
    else if (c === ":") out += ": ";
    else if (!/\s/.test(c)) out += c;
  }
  return out;
}

/** A string that holds a JSON object or array, else null. */
function jsonText(value: string): string | null {
  if (!/^\s*[[{]/.test(value)) return null;
  try {
    JSON.parse(value);
    return indent(value);
  } catch {
    return null;
  }
}

/** Raw kernel output: numbered lines, keys, strings and numbers told apart. */
export function Json({ value }: { value: unknown }) {
  const text =
    typeof value === "string" ? (jsonText(value) ?? value) : (JSON.stringify(value, null, 2) ?? "");
  return (
    <pre className="sh-json scrollbar-thin">
      {text.split("\n").map((line, index) => {
        const parts: ReactNode[] = [];
        let last = 0;
        for (const match of line.matchAll(TOKEN)) {
          const at = match.index ?? 0;
          if (at > last) parts.push(line.slice(last, at));
          if (match[1])
            parts.push(
              <span key={at} className={match[2] ? "k" : "s"}>
                {match[1]}
              </span>,
              match[2] ?? "",
            );
          else
            parts.push(
              <span key={at} className="n">
                {match[0]}
              </span>,
            );
          last = at + match[0].length;
        }
        if (last < line.length) parts.push(line.slice(last));
        return (
          <span key={index} className="ln">
            {parts.length ? parts : " "}
          </span>
        );
      })}
    </pre>
  );
}
