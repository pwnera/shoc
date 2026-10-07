/**
 * Toasts: what just happened, while someone is looking. Nothing here is the
 * only record of anything: every toast repeats an event the stream carries or
 * a mutation's answer that a screen already shows, so a missed toast loses
 * nothing. Ok and neutral toasts last 6s, crew toasts 12s, critical toasts stay
 * until dismissed. Events on one case within 5 seconds merge into one toast;
 * a critical toast merges only into the same words in its group ("Crew can't
 * reach its model ×5"), so one failing condition is one toast.
 */
import { useSyncExternalStore } from "react";
import { announce } from "./announce";
import { ApiError } from "./api";
import { refusal } from "./labels";

export type Tone = "ok" | "critical" | "crew" | "neutral";

export type Toast = {
  id: number;
  tone: Tone;
  /** The record it is about: a short id in mono, the full id in a tip, linking the record. */
  subject?: { label: string; to: string; title?: string };
  /** Who asked for it (an author string for `lib/crew.ts`), on action events. */
  who?: string;
  /** A verb phrase: "Disable AWS key ran". */
  text: string;
  at: string;
  /** One small button: `run` does it; `to`, when set, is where it leads. */
  action?: { label: string; run: () => void; to?: string };
  /** How many events this toast stands for ("×3"). */
  count: number;
  /** Events with the same group within 5 seconds merge; a case uid. */
  group?: string;
  /** Milliseconds it stays; Infinity until dismissed. */
  life: number;
};

export type ToastInput = Omit<Toast, "id" | "count" | "life" | "at"> & {
  at?: string;
  life?: number;
  /** The text once merged with others of its group: (3) → "3 actions ran". */
  merged?: (count: number) => string;
  /** The action uid this toast can undo, for the `Z` key. */
  undo?: string;
};

export const LIFE: Record<Tone, number> = { ok: 6_000, neutral: 6_000, crew: 12_000, critical: Infinity };
/** Toasts drawn at once; the rest read "+N". */
export const SHOWN = 3;
const MERGE = 5_000;
const RANK: Record<Tone, number> = { neutral: 0, ok: 1, crew: 2, critical: 3 };

let toasts: Toast[] = [];
let next = 1;
const merged = new Map<number, { born: number; text?: (n: number) => string }>();
const timers = new Map<number, { timer?: ReturnType<typeof setTimeout>; due: number; left: number }>();
/** Action uid → when its undo window closes (ms; Infinity until known), oldest first. */
const undoable = new Map<string, number>();
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

function arm(id: number, life: number) {
  if (!Number.isFinite(life)) return;
  const entry = { due: Date.now() + life, left: life, timer: setTimeout(() => dismiss(id), life) };
  clearTimeout(timers.get(id)?.timer);
  timers.set(id, entry);
}

export function dismiss(id: number) {
  clearTimeout(timers.get(id)?.timer);
  timers.delete(id);
  merged.delete(id);
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

/** Pause a toast's lifetime while it is hovered or focused, and resume it after. */
export function hold(id: number, on: boolean) {
  const entry = timers.get(id);
  if (!entry) return;
  if (on && entry.timer) {
    clearTimeout(entry.timer);
    timers.set(id, { due: 0, left: Math.max(0, entry.due - Date.now()) });
  } else if (!on && !entry.timer) {
    timers.set(id, { due: Date.now() + entry.left, left: entry.left, timer: setTimeout(() => dismiss(id), entry.left) });
  }
}

/** A modal dialog is open (jsdom knows no `:modal`). */
function modalOpen(): boolean {
  try {
    return document.querySelector("dialog:modal") !== null;
  } catch {
    return false;
  }
}

export function toast(input: ToastInput): number {
  const { merged: mergeText, undo, ...rest } = input;
  // A critical toast is its own alert, unless a modal leaves it inert; the rest are said once through the polite region.
  const say = (text: string) => {
    if (input.tone !== "critical" || modalOpen()) announce(input.subject ? `${input.subject.label} ${text}` : text);
  };
  if (undo) {
    undoable.delete(undo);
    undoable.set(undo, Infinity);
  }
  const now = Date.now();
  // A critical toast is never folded into a different one: each must be seen. The same one again only counts.
  const again =
    input.group && input.tone === "critical"
      ? toasts.find((t) => t.group === input.group && t.tone === "critical" && t.text === input.text)
      : undefined;
  if (again) {
    toasts = toasts.map((t) => (t.id === again.id ? { ...t, count: t.count + 1, at: input.at ?? t.at } : t));
    emit();
    return again.id;
  }
  if (input.group && input.tone !== "critical") {
    const into = toasts.find(
      (t) => t.group === input.group && t.tone !== "critical" && now - (merged.get(t.id)?.born ?? 0) < MERGE,
    );
    if (into) {
      const count = into.count + 1;
      const text = merged.get(into.id)?.text ?? mergeText;
      const tone = RANK[input.tone] > RANK[into.tone] ? input.tone : into.tone;
      const life = Math.max(into.life, input.life ?? LIFE[tone]);
      // Merged, one action no longer names one event; the subject still opens the case.
      const kept: Toast = { ...into };
      delete kept.action;
      const words = text ? text(count) : `${count} updates`;
      toasts = toasts.map((t) => (t.id === into.id ? { ...kept, tone, count, life, text: words } : t));
      say(words);
      arm(into.id, life);
      emit();
      return into.id;
    }
  }
  const id = next++;
  const life = input.life ?? LIFE[input.tone];
  toasts = [{ ...rest, id, count: 1, life, at: input.at ?? new Date(now).toISOString() }, ...toasts].slice(0, 20);
  merged.set(id, { born: now, ...(mergeText ? { text: mergeText } : {}) });
  say(input.text);
  arm(id, life);
  emit();
  return id;
}

/** Change a toast's words or action once more is known (a deadline, a TTL). */
export function update(id: number, patch: Partial<Pick<Toast, "text" | "action" | "who">>) {
  if (!toasts.some((t) => t.id === id)) return;
  toasts = toasts.map((t) => (t.id === id ? { ...t, ...patch } : t));
  emit();
}

/** Errors already raised, so a hook's toast and a screen's own `onError` never say one failure twice. */
const raised = new WeakSet<object>();

/**
 * A failed console mutation, in the kernel's own words: critical, so it stays.
 * The first call for an error wins: a hook raises it with its own label even
 * after the screen that asked has gone, and the screen's repeat is dropped.
 */
export function toastError(error: unknown, what = "Failed") {
  if (typeof error === "object" && error !== null) {
    if (raised.has(error)) return;
    raised.add(error);
  }
  // Signed out has its home in the shell's banner; a missing scope reads as what the role cannot do.
  const message =
    error instanceof ApiError && error.isSignedOut
      ? "signed out"
      : error instanceof ApiError && error.isAuth
        ? (refusal(error.message) ?? error.message)
        : error instanceof Error
          ? error.message
          : String(error);
  toast({ tone: "critical", text: `${what}: ${message}` });
}

/** The action's undo window closes at `until` (ISO); `Z` skips it after that. */
export function undoUntil(uid: string, until: string) {
  if (undoable.has(uid)) undoable.set(uid, Date.parse(until));
}

/** The action was undone (`action.rolled_back`): `Z` no longer offers it. */
export function forgetUndo(uid: string) {
  undoable.delete(uid);
}

/** The newest action this session's toasts offered to undo and still can, for the `Z` key. */
export function lastUndoable(): string | undefined {
  const now = Date.now();
  for (const [uid, until] of [...undoable].reverse()) {
    if (until > now) return uid;
    undoable.delete(uid);
  }
  return undefined;
}

/** Follow a link from outside React: the router hears the history change as a back/forward step. */
export function go(to: string) {
  const url = new URL(to, window.location.href);
  window.history.pushState({}, "", url.pathname + url.search + url.hash);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

/** The current location with one parameter set, for toasts that open a dialog over the screen. */
export function withParam(name: string, value: string, extra: Record<string, string> = {}): string {
  const params = new URLSearchParams(window.location.search);
  params.set(name, value);
  for (const [k, v] of Object.entries(extra)) params.set(k, v);
  return `${window.location.pathname}?${params.toString()}`;
}

function listen(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Every toast, newest first; the toaster draws `SHOWN` and counts the rest. */
export function useToasts(): Toast[] {
  return useSyncExternalStore(listen, () => toasts);
}
