/**
 * A popup over a list: which record is open, J and K through the list, and
 * the list behind following (its active row and page). Kept in the URL, an
 * open pushes a history entry, so Back closes and a link can open it; a step
 * replaces the entry. Closing goes back to the entry the open came from, so
 * Back never reopens the popup; a popup a link opened closes in place. On
 * close, focus goes to the row of the record last shown, not the one that
 * opened the popup.
 */
import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { closeParams, routerHere } from "@/lib/popup";

/** The open record's key, and how to set it ("" closes; `push` adds a history entry). */
export type Picked = [string, (key: string, push: boolean) => void];

/** The open record in `?<name>=`; closing goes back over the entry the open pushed (`closeParams`). */
export function useUrlPick(name: string): Picked {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  return [
    params.get(name) ?? "",
    (key, push) => {
      if (!key) return closeParams([name], navigate, routerHere(location));
      setParams(
        (current) => {
          const out = new URLSearchParams(current);
          out.set(name, key);
          return out;
        },
        { replace: !push },
      );
    },
  ];
}

/** The open record in component state, for records that do not outlive the page (a dry run's findings). */
export function useLocalPick(): Picked {
  const [key, setKey] = useState("");
  return [key, setKey];
}

/** What the list behind exposes: its page (`usePaged`) and its active row (`useListNav`). */
export type Follow = { start: number; size: number; prev: () => void; next: () => void; setActive: (key: string) => void };

export function useStepper<R>(rows: R[], key: (row: R) => string, [picked, write]: Picked, follow?: Follow) {
  const index = picked ? rows.findIndex((r) => key(r) === picked) : -1;
  // Focus moves once the popup has left the page: while it is modal the list is inert, and a
  // settle closes it without the native close (navigations render in a transition, after a frame).
  const refocus = useRef("");
  useEffect(() => {
    const row = refocus.current;
    if (picked || !row) return;
    refocus.current = "";
    document.querySelector<HTMLElement>(`main [data-row-key="${CSS.escape(row)}"]`)?.focus();
  }, [picked]);
  const go = (i: number) => {
    const row = rows[i];
    if (!row) return;
    if (follow) {
      if (i < follow.start) follow.prev();
      else if (i >= follow.start + follow.size) follow.next();
      follow.setActive(key(row));
    }
    write(key(row), false);
  };
  return {
    /** The open record when it is in `rows`. */
    row: index >= 0 ? rows[index] : undefined,
    picked,
    open: (row: R) => write(key(row), true),
    close: () => {
      refocus.current = picked;
      write("", false);
    },
    step:
      index >= 0
        ? {
            index,
            total: rows.length,
            onPrev: index > 0 ? () => go(index - 1) : undefined,
            onNext: index < rows.length - 1 ? () => go(index + 1) : undefined,
          }
        : undefined,
  };
}

/**
 * A step swaps the record under one open popup; when the focused control was
 * the old record's (Revert, an entity chip), focus falls to the page and J
 * and K stop reaching the popup. Put the returned ref inside the popup's body.
 */
export function useKeepFocus(key: string) {
  const inside = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const now = document.activeElement;
    if (!now || now === document.body) inside.current?.closest("dialog")?.focus();
  }, [key]);
  return inside;
}
