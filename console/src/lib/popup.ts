/**
 * A list's popup kept in the URL, that steps through its list and hands focus
 * back to the right row (Sources, Health, Measurement, API), and the trail of
 * history entries that lets closing one, or Escape on a page, step back
 * instead of adding an entry.
 */
import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore } from "react";
import { useLocation, useNavigate, useSearchParams, type NavigateFunction } from "react-router-dom";

/** A URL with its parameters in one order, so two spellings of the same place compare equal. */
function spot(pathname: string, search: string): string {
  const params = new URLSearchParams(search);
  params.sort();
  const query = params.toString();
  return query ? `${pathname}?${query}` : pathname;
}

/** The place each history entry of this tab showed, by the router's index; empty after a reload. */
const trail = new Map<number, string>();
export const entryIndex = () => (window.history.state as { idx?: number } | null)?.idx ?? 0;

/** Mounted once by the shell: records where each history entry is. */
export function useTrail(): void {
  const location = useLocation();
  useEffect(() => {
    trail.set(entryIndex(), spot(location.pathname, location.search));
  }, [location]);
}

/** How many entries back the nearest one on another path is (Escape on a record page), or 0 when none is known. */
export function stepsToLeave(pathname: string): number {
  const at = entryIndex();
  for (let to = at - 1; to >= 0; to--) {
    const place = trail.get(to);
    if (place === undefined) return at - to;
    if (place.split("?")[0] !== pathname) return at - to;
  }
  return 0;
}

/**
 * Close a popup kept in the URL: back over the entry its opening pushed, so
 * the list is in history once and the next Back leaves it; a popup a link
 * opened has no such entry, so its parameters go in place. `here` is the
 * router's location where it is not the window's (a memory router).
 */
export function closeParams(
  names: string[],
  navigate: NavigateFunction,
  here: { pathname: string; search: string; state?: unknown } = window.location,
) {
  const out = new URLSearchParams(here.search);
  if (!names.some((n) => out.has(n))) return;
  for (const n of names) out.delete(n);
  const behind = trail.get(entryIndex() - 1);
  if (behind !== undefined && behind === spot(here.pathname, out.toString())) return void navigate(-1);
  const query = out.toString();
  navigate(
    { pathname: here.pathname, search: query ? `?${query}` : "" },
    { replace: true, state: here === window.location ? (window.history.state as { usr?: unknown } | null)?.usr : here.state },
  );
}

/** The router's location for `closeParams`, which is the window's in the browser (a memory router keeps its own). */
export const routerHere = (location: { pathname: string; search: string; state: unknown }) =>
  location.pathname === window.location.pathname && location.search === window.location.search ? window.location : location;

/**
 * Set one popup parameter (`?run=`): a value opens it with a history entry
 * (`replace` swaps the entry, as a J or K step does), none closes it back over
 * that entry (`closeParams`). `drop` goes with it either way (an old `view`).
 */
export function usePopParam(name: string, drop: string[] = []) {
  const [, setParams] = useSearchParams();
  const navigate = useNavigate();
  // The page's router state (a list's `back`, a finding's stepper) stays while the popup is open.
  const location = useLocation();
  const { state } = location;
  return (value: string | null | undefined, replace = false) => {
    if (!value) return closeParams([name, ...drop], navigate, routerHere(location));
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        out.set(name, value);
        for (const n of drop) out.delete(n);
        return out;
      },
      { replace, state },
    );
  };
}

/** `usePopParam` with the value it holds: `[value, open]`, where open(v) pushes, open(v, true) steps and open(null) closes. */
export function usePopValue(name: string, drop: string[] = []): [string, (value: string | null | undefined, replace?: boolean) => void] {
  const [params] = useSearchParams();
  return [params.get(name) ?? "", usePopParam(name, drop)];
}

/**
 * Focus a list's row by its key. The browser hands focus back to the row that
 * opened a dialog; after J and K the row to return to is the one it ended on.
 * Rows inside a dialog that just closed are skipped.
 */
export function focusRow(key: string) {
  if (!key) return;
  const rows = document.querySelectorAll<HTMLElement>(`[data-row-key="${CSS.escape(key)}"]`);
  [...rows].find((row) => !row.closest("dialog") || row.closest("dialog")!.open)?.focus();
}

export type Step = { index: number; total: number; onPrev?: () => void; onNext?: () => void };

/**
 * A list's popup in the URL (`?role=Investigator`), so Back closes it and
 * another screen can link to it; with no name it is local state (a list inside
 * a dialog). Opening adds a history step, stepping replaces it, closing goes
 * back over it (`closeParams`). `keys` is the list in its shown order, for
 * "3 / 25" and J and K.
 */
export function useOpen(name: string | null, keys: string[]) {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const [local, setLocal] = useState("");
  const value = name ? (params.get(name) ?? "") : local;
  const write = (next: string, push = false) => {
    if (!name) return setLocal(next);
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        if (next) out.set(name, next);
        else out.delete(name);
        return out;
      },
      { replace: !push },
    );
  };
  const at = keys.indexOf(value);
  const step: Step = {
    index: at,
    total: keys.length,
    onPrev: at > 0 ? () => write(keys[at - 1]!) : undefined,
    onNext: at >= 0 && at < keys.length - 1 ? () => write(keys[at + 1]!) : undefined,
  };
  return {
    value,
    at,
    step,
    open: (key: string) => write(key, true),
    close: () => {
      if (name) closeParams([name], navigate, routerHere(location));
      else setLocal("");
      focusRow(value);
    },
  };
}

/**
 * The list's active row follows the record its dialog shows: J and K inside
 * it, or a deep link. Given the list's keys in order and its pager, the page
 * follows too, so a step past the page's edge turns it.
 */
export function useFollow(
  nav: { setActive: (key: string) => void },
  key: string,
  paged?: { keys: string[]; size: number; go: (index: number) => void },
) {
  const latest = useRef({ set: nav.setActive, paged });
  useLayoutEffect(() => {
    latest.current = { set: nav.setActive, paged };
  });
  useEffect(() => {
    if (!key) return;
    const { set, paged: p } = latest.current;
    const at = p ? p.keys.indexOf(key) : -1;
    if (p && at >= 0) p.go(Math.floor(at / p.size));
    set(key);
  }, [key]);
}

/** The parameters any screen answers with a shell dialog (`Shell.tsx` DeepLinks); no list filter may use one. */
export const DEEP_LINKS = ["decide", "action", "event", "entity"] as const;

/* Deep-link parameters a screen opens itself, with a stepper over its own rows, so the shell's copy stays shut. */
let claimed: string[] = [];
const claimListeners = new Set<() => void>();
const setClaimed = (next: string[]) => {
  claimed = next;
  for (const l of claimListeners) l();
};

/** While mounted, the shell leaves `?<name>=` to the calling screen (Activity's `action`, Posture's `entity`). */
export function useClaim(name: string): void {
  useEffect(() => {
    setClaimed([...claimed, name]);
    return () => {
      const at = claimed.indexOf(name);
      if (at >= 0) setClaimed([...claimed.slice(0, at), ...claimed.slice(at + 1)]);
    };
  }, [name]);
}

/** The parameters screens claim right now. */
export function useClaimed(): string[] {
  return useSyncExternalStore(
    (l) => (claimListeners.add(l), () => claimListeners.delete(l)),
    () => claimed,
  );
}
