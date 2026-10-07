/**
 * Small things the case page does from more than one place: open Explore
 * over its timeline's window filtered to its entity, find an action's
 * platform logo, focus a card in the decision bar, and remember when this
 * viewer last saw the case.
 */
import { useEffect, useState } from "react";
import { exploreQuery, parseEntity } from "@/lib/entity";
import { exploreHref, word } from "@/lib/explore";
import type { Case } from "@/types";

/** Explore over the timeline's window, filtered to the case's entity. */
export function exploreOf(record: Case, window?: { window_start: string; window_end: string }) {
  const entity = parseEntity(record.entity_key);
  return exploreHref({
    q: entity ? exploreQuery(entity) : word(record.entity_key),
    since: window?.window_start ?? record.opened_at,
    until: window?.window_end ?? record.closed_at ?? undefined,
  });
}

/** Focus Approve on the decision bar's card for this action (the first card when it has none). */
export function focusDecision(uid?: string) {
  const bar = document.querySelector<HTMLElement>('[aria-label="Decisions"]');
  const card =
    (uid ? bar?.querySelector<HTMLElement>(`[data-action="${CSS.escape(uid)}"]`) : null) ??
    bar?.querySelector<HTMLElement>("[data-action]");
  card?.scrollIntoView?.({ block: "nearest" });
  card?.querySelector<HTMLElement>("[data-approve]")?.focus({ preventScroll: true });
}

const SEEN = "shoc.seen";

function seen(): Record<string, string> {
  try {
    const saved = JSON.parse(localStorage.getItem(SEEN) ?? "{}") as unknown;
    return saved && typeof saved === "object" && !Array.isArray(saved) ? (saved as Record<string, string>) : {};
  } catch {
    return {};
  }
}

/** When this viewer last opened the case (null on a first visit); the visit is recorded, 100 cases kept. */
export function useLastVisit(uid: string): string | null {
  const [last] = useState(() => seen()[uid] ?? null);
  useEffect(() => {
    const rest = Object.entries(seen()).filter(([key]) => key !== uid);
    const next = Object.fromEntries([[uid, new Date().toISOString()], ...rest].slice(0, 100));
    try {
      localStorage.setItem(SEEN, JSON.stringify(next));
    } catch {
      /* private window: every visit is a first one */
    }
  }, [uid]);
  return last;
}
