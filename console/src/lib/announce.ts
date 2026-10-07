/**
 * One polite voice for what appears without a focus change: a toast, "copied",
 * "3 new", a crew answer. A modal dialog leaves the page outside it inert, and
 * an inert region is never read, so the words go to the region inside the
 * topmost open dialog (`Announcer` in each), else to the page's one. It is
 * emptied first, so the same words twice are heard twice, and a region that
 * exists before its words is the one screen readers announce.
 */
import { useSyncExternalStore } from "react";

type Said = { text: string; where: Element | null };

const NONE: Said = { text: "", where: null };
let said = NONE;
const listeners = new Set<() => void>();
const emit = () => {
  for (const l of listeners) l();
};

/** The open dialog on top: the one holding focus, else the last opened in the page. */
function topDialog(): Element | null {
  const open = [...document.querySelectorAll("dialog[open]")];
  const held = document.activeElement?.closest("dialog");
  return held && open.includes(held) ? held : (open.at(-1) ?? null);
}

export function announce(text: string) {
  said = NONE;
  emit();
  requestAnimationFrame(() => {
    said = { text, where: topDialog() };
    emit();
  });
}

/** What was said and the dialog it was said in (null: the page). */
export const useAnnounced = () =>
  useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => said,
    () => NONE,
  );
