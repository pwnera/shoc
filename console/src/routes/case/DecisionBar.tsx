/**
 * What waits on a person in this case, only when something does: one
 * approval card per proposed action (the inbox's own component, without the
 * severity the header carries), "Close as" when the crew handed the verdict
 * to a person, and "Decide again" for an approval nobody decided in time.
 * From 768px it sticks at the top of the main column, one line per item while
 * stuck and three lines at most, the last a "+N" that unsticks it; on a phone
 * it scrolls away and the bottom bar carries Reject | Approve. A and R act on
 * the first card; `?decide=` focuses its card's Approve, or says it is
 * already decided. Approve calls `action.approve` only: the worker resumes a
 * waiting playbook run on its own.
 *
 * Capabilities used: action.approve and action.reject, through ApprovalCard.
 */
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { useSearchParams } from "react-router-dom";
import { Gavel, Hourglass, type LucideIcon } from "lucide-react";
import { ApprovalCard, type ApprovalHandle } from "@/components/ui/approval";
import { Button } from "@/components/ui/button";
import { Entity } from "@/components/ui/entity";
import { cn } from "@/lib/cn";
import { useCommand } from "@/lib/commands";
import { DISPOSITIONS, actionLabel } from "@/lib/labels";
import { inbox } from "@/lib/needs";
import { toast } from "@/lib/toast";
import type { Action, Case, Disposition, Playbook, PlaybookRun } from "@/types";
import { focusDecision } from "./links";
import type { Open } from "./moments";

const CLOSE_AS = Object.entries(DISPOSITIONS) as [Disposition, string][];

/** Stuck, the bar holds at most three 40px rows and its hairline (px); Discussion keeps Steer clear of it. */
const STUCK_ROWS = 3;
export const STUCK_MAX = 121;

const topBar = () => parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--topbar-h")) || 48;

const popoverOpen = (el: HTMLElement | null) => {
  try {
    return Boolean(el?.querySelector(":popover-open"));
  } catch {
    return false;
  }
};

/** Whether the bar sits stuck under the top bar: its sentinel has scrolled above it, from 768px only. */
function useStuck(sentinel: RefObject<HTMLElement | null>, bar: RefObject<HTMLElement | null>, on: boolean) {
  const [stuck, setStuck] = useState(false);
  useEffect(() => {
    const el = sentinel.current;
    if (!on || !el || typeof IntersectionObserver === "undefined") return;
    const top = topBar();
    const wide = window.matchMedia("(min-width: 768px)");
    const watch = new IntersectionObserver(
      ([entry]) => {
        // An open confirm holds the bar as it is, so its popover keeps its anchor.
        if (!entry || popoverOpen(bar.current)) return;
        setStuck(wide.matches && !entry.isIntersecting && entry.boundingClientRect.top < top);
      },
      { rootMargin: `-${top}px 0px 0px 0px` },
    );
    watch.observe(el);
    return () => watch.disconnect();
  }, [sentinel, bar, on]);
  return on && stuck;
}

export function DecisionBar({
  record,
  actions,
  runs,
  playbooks,
  open,
}: {
  record: Case;
  actions: Action[];
  runs: PlaybookRun[];
  playbooks: Playbook[];
  open: Open;
}) {
  const [params, setParams] = useSearchParams();
  const sentinel = useRef<HTMLDivElement>(null);
  const bar = useRef<HTMLDivElement>(null);
  const first = useRef<ApprovalHandle>(null);
  const closed = record.state === "closed";
  const pending = actions.filter((a) => a.state === "proposed");
  const expired = inbox({ actions, cases: [record] }).flatMap((item) => (item.kind === "expired" && item.action ? [item.action] : []));
  const asking = !closed && record.verdict === "needs_human";
  const shown = !closed && (pending.length > 0 || asking || expired.length > 0);
  const stuck = useStuck(sentinel, bar, shown);

  // The first card comes on screen first: on a phone the bar has scrolled away when the bottom bar asks.
  const deciding = pending.length > 0 && !closed;
  const onFirst = (act: (card: ApprovalHandle) => void) => () => {
    focusDecision(pending[0]?.action_uid);
    if (first.current) act(first.current);
  };
  useCommand("case.approve", onFirst((card) => card.approve()), deciding);
  useCommand("case.reject", onFirst((card) => card.reject()), deciding);

  // `?decide=` focuses its card and leaves the URL, or says it is settled when it no longer waits;
  // a case link landing on a waiting case focuses the first.
  const decide = params.get("decide");
  const landed = useRef(false);
  const handled = useRef<string | null>(null);
  const ready = pending.length > 0;
  useEffect(() => {
    if (decide) {
      // Once per param, though the effect runs twice in development.
      if (handled.current === decide) return;
      handled.current = decide;
      if (pending.some((a) => a.action_uid === decide)) focusDecision(decide);
      else {
        const row = actions.find((a) => a.action_uid === decide);
        toast({ tone: "neutral", text: "Already decided", ...(row ? { action: { label: "Open", run: () => open.action(row) } } : {}) });
      }
      setParams(
        (current) => {
          const out = new URLSearchParams(current);
          out.delete("decide");
          return out;
        },
        { replace: true },
      );
    } else if (ready && !landed.current) focusDecision();
    if (ready) landed.current = true;
    // The page's `open` and the rows change every render; the param and the pending set decide.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decide, ready]);

  // Stuck, the bar shrinks; a bottom margin keeps its place in the page, so nothing under it jumps.
  const full = useRef(0);
  useLayoutEffect(() => {
    const el = bar.current;
    if (!el) return;
    if (stuck) el.style.marginBottom = `${Math.max(0, full.current - el.offsetHeight)}px`;
    else {
      el.style.marginBottom = "";
      full.current = el.offsetHeight;
    }
  });

  // "+N" scrolls the bar back to its place in the page, where it unsticks and shows every item; the focus goes to the first one it hid.
  const reveal = useRef<number | null>(null);
  useLayoutEffect(() => {
    if (stuck || reveal.current === null) return;
    bar.current?.children[reveal.current]?.querySelector<HTMLElement>("button")?.focus({ preventScroll: true });
    reveal.current = null;
  }, [stuck]);

  if (!shown) return null;

  const resumes = (action: Action) => {
    const run = action.run_uid ? runs.find((r) => r.run_uid === action.run_uid && r.state === "waiting_approval") : undefined;
    return run ? { title: playbooks.find((p) => p.id === run.playbook_id)?.title ?? run.playbook_id } : null;
  };
  const line = cn("flex min-w-0 flex-1 items-center gap-2", stuck ? "flex-nowrap" : "flex-wrap");
  // Stuck, a row lines up with the compact approvals: their glyph slot and 40px, never squeezed by the bar.
  const row = (settled = false) => cn("sh-approval", settled && "sh-approval--settled", stuck && "sh-approval--compact shrink-0");
  const glyph = (Icon: LucideIcon) => (stuck ? <Icon className="h-3.5 w-3.5 shrink-0 text-crew" aria-hidden /> : null);

  const items: ReactNode[] = [
    ...pending.map((action, index) => (
      <div key={action.action_uid} data-action={action.action_uid} className="shrink-0 scroll-mt-[calc(var(--topbar-h)+8px)]">
        <ApprovalCard
          ref={index === 0 ? first : undefined}
          action={action}
          variant={stuck ? "compact" : "case"}
          run={resumes(action)}
        />
      </div>
    )),
    ...(asking
      ? [
          <div key="close-as" className={row()}>
            {glyph(Gavel)}
            <div className={line}>
              <span className="sh-approval__title">Close as</span>
              <span className={cn("ml-auto flex gap-2", !stuck && "flex-wrap")}>
                {CLOSE_AS.map(([disposition, label]) => (
                  <Button key={disposition} size="sm" onClick={() => open.close(disposition)}>
                    {label}
                  </Button>
                ))}
              </span>
            </div>
          </div>,
        ]
      : []),
    ...expired.map((action) => (
      <div key={action.action_uid} className={row(true)}>
        {glyph(Hourglass)}
        <div className={line}>
          <span className="sh-approval__title">Decide again: {actionLabel(action.type)}</span>
          <Entity value={action.target} />
          <Button size="sm" className="ml-auto" onClick={() => open.propose({ type: action.type, params: action.params })}>
            Propose again
          </Button>
        </div>
      </div>
    )),
  ];
  const cut = stuck && items.length > STUCK_ROWS ? STUCK_ROWS - 1 : items.length;
  const unstick = () => {
    const el = sentinel.current;
    if (!el) return;
    reveal.current = cut;
    window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - topBar() - 8 });
  };

  return (
    <>
      <div ref={sentinel} aria-hidden className="-mb-4 h-0" />
      <div
        ref={bar}
        className={cn(
          "-mx-1 flex flex-col bg-bg-0 px-1 md:sticky md:top-[var(--topbar-h)] md:z-[var(--z-sticky)]",
          stuck ? "border-b border-line-2" : "gap-2",
        )}
        aria-label="Decisions"
        role="region"
      >
        {items.slice(0, cut)}
        {cut < items.length ? (
          <button
            type="button"
            className={cn(row(true), "w-full cursor-pointer text-left")}
            onClick={unstick}
          >
            <span className="h-3.5 w-3.5 shrink-0" aria-hidden />
            <span className="sh-mono text-fg-3">+{items.length - cut}</span>
            <span className="sr-only"> more</span>
          </button>
        ) : null}
      </div>
    </>
  );
}
