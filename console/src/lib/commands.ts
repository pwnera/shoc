/**
 * Every key and every palette command, in one table. The shell's one keydown
 * listener (`useKeys`), the tooltips, `aria-keyshortcuts`, the palette and its
 * Keys scope all read it, so a shortcut is declared once. A screen binds the
 * command it owns with `useCommand`; the palette hands a command to its home
 * screen with `?do=<id>`, and the home runs its own handler, confirm included.
 */
import { useEffect, useId, useLayoutEffect, useRef, useState, useSyncExternalStore } from "react";
import { useLocation, useNavigate, useNavigationType, useSearchParams } from "react-router-dom";
import { copyAndSay } from "./copy";
import { SCREENS, tabHref, tabId } from "./nav";
import { stepsToLeave } from "./popup";

export type Scope = "global" | "list" | "dialog" | `dialog:${string}` | `route:${string}`;
export type Group = "Global" | "Go to" | "Lists" | "Dialogs" | "This screen";

export type Command = {
  id: string;
  label: string;
  /** "c", "g c" (a chord), "mod+k", "shift+arrowright"; modifiers in the order mod, alt, shift. */
  keys?: string;
  /** A second key doing the same ("arrowdown" beside "j"). */
  alt?: string;
  scope: Scope;
  group: Group;
  /** The owning path, for the palette hand-off (`?do=<id>`); a route pattern for page commands. */
  home?: string;
  /** Offered in the palette's Commands section from any screen. */
  palette?: boolean;
  /** Where a Go to command leads. */
  to?: string;
  /** Run this other command when nothing binds this one ("/" opens the palette). */
  fallback?: string;
  /** Also runs while a modal dialog is open (the crew chat opens over EntityDialog). */
  overModal?: boolean;
  level?: "L0" | "L1" | "L2";
  /** It writes or spends, and its handler runs it at once: a `?do=` from a link asks first. */
  confirm?: boolean;
};

const route = (path: string, commands: Omit<Command, "scope" | "group" | "home">[]): Command[] =>
  commands.map((c) => ({ ...c, scope: `route:${path}`, group: "This screen", home: path }));

const dialog = (name: string, commands: Omit<Command, "scope" | "group">[]): Command[] =>
  commands.map((c) => ({ ...c, scope: `dialog:${name}`, group: "Dialogs" }));

export const COMMANDS: Command[] = [
  // Over a record dialog too: the palette's scope chip and "This …" section come from it.
  { id: "shell.palette", label: "Search or jump", keys: "mod+k", scope: "global", group: "Global", overModal: true },
  { id: "shell.chat", label: "Ask the crew", keys: "mod+j", scope: "global", group: "Global", overModal: true },
  {
    id: "shell.chat-wide",
    label: "Chat wide or compact",
    keys: "mod+shift+j",
    scope: "global",
    group: "Global",
    overModal: true,
  },
  { id: "shell.rail", label: "Collapse the rail", keys: "mod+\\", scope: "global", group: "Global" },
  { id: "shell.keys", label: "Keyboard shortcuts", keys: "?", scope: "global", group: "Global" },
  {
    id: "shell.filter",
    label: "Filter",
    keys: "/",
    scope: "global",
    group: "Global",
    fallback: "shell.palette",
  },
  { id: "shell.undo", label: "Undo the last action", keys: "z", scope: "global", group: "Global" },
  { id: "shell.escape", label: "Close the top layer", keys: "escape", scope: "global", group: "Global" },

  ...SCREENS.map(
    (s): Command => ({
      id: `go.${tabId(s.label)}`,
      label: s.label,
      keys: `g ${s.chord}`,
      scope: "global",
      group: "Go to",
      to: s.to,
    }),
  ),

  { id: "list.down", label: "Next row", keys: "j", alt: "arrowdown", scope: "list", group: "Lists" },
  { id: "list.up", label: "Previous row", keys: "k", alt: "arrowup", scope: "list", group: "Lists" },
  { id: "list.open", label: "Open", keys: "enter", alt: "space", scope: "list", group: "Lists" },
  { id: "list.first", label: "First row", keys: "home", scope: "list", group: "Lists" },
  { id: "list.last", label: "Last row", keys: "end", scope: "list", group: "Lists" },
  { id: "list.prev-page", label: "Previous page", keys: "[", scope: "list", group: "Lists" },
  { id: "list.next-page", label: "Next page", keys: "]", scope: "list", group: "Lists" },
  { id: "list.tab", label: "Tab n (1–9)", keys: "1", scope: "list", group: "Lists" },
  { id: "list.copy", label: "Copy id", keys: "c", scope: "list", group: "Lists" },

  { id: "dialog.next", label: "Next record", keys: "j", alt: "arrowdown", scope: "dialog", group: "Dialogs" },
  { id: "dialog.prev", label: "Previous record", keys: "k", alt: "arrowup", scope: "dialog", group: "Dialogs" },
  { id: "dialog.submit", label: "Submit", keys: "mod+enter", scope: "dialog", group: "Dialogs" },

  ...route("/", [
    { id: "overview.approve", label: "Approve", keys: "a", level: "L2" },
    { id: "overview.reject", label: "Reject", keys: "r" },
    { id: "overview.since", label: "Since…", keys: "s" },
  ]),
  ...route("/cases", [{ id: "cases.copy-id", label: "Copy id", keys: "c" }]),
  ...route("/cases/:caseUid", [
    { id: "case.approve", label: "Approve pending", keys: "a", level: "L2" },
    { id: "case.reject", label: "Reject pending", keys: "r" },
    { id: "case.close", label: "Close…", keys: "c", level: "L2" },
    { id: "case.move", label: "Move to…", keys: "m" },
    { id: "case.propose", label: "New action", keys: "p" },
    { id: "case.run-playbook", label: "Run a playbook", keys: "y" },
    { id: "case.steer", label: "Steer the crew", keys: "s" },
    { id: "case.first-cite", label: "First evidence", keys: "e" },
    { id: "case.menu", label: "More", keys: "." },
    { id: "case.investigate", label: "Re-investigate", level: "L1" },
    { id: "case.slack", label: "Post to Slack" },
    { id: "case.copy-id", label: "Copy id" },
    { id: "case.explore", label: "Events in Explore" },
  ]),
  ...route("/findings", [{ id: "findings.copy-id", label: "Copy id", keys: "c" }]),
  ...route("/findings/:findingUid", [
    // J and K step through the list that opened the page; a page command beats the evidence table's list keys.
    { id: "finding.next", label: "Next finding", keys: "j" },
    { id: "finding.prev", label: "Previous finding", keys: "k" },
    { id: "finding.status", label: "Set status…", keys: "s" },
    { id: "finding.open-case", label: "Open case", keys: "o" },
    { id: "finding.explore", label: "Events in Explore", keys: "e" },
  ]),
  ...route("/explore", [
    { id: "explore.run", label: "Run", keys: "mod+enter" },
    { id: "explore.time", label: "Time range", keys: "t" },
    { id: "explore.add-field", label: "Add field", keys: "f" },
  ]),
  ...route("/detection", [
    { id: "detection.run-all", label: "Run every rule now", palette: true, level: "L1" },
    { id: "detection.copy-id", label: "Copy id", keys: "c" },
    { id: "detection.menu", label: "More", keys: "." },
  ]),
  {
    id: "detection.work",
    label: "Let the Detection Engineer work",
    keys: "w",
    scope: "route:/detection",
    group: "This screen",
    home: "/detection?tab=changes",
    palette: true,
    level: "L1",
  },
  ...route("/detection/rules/:ruleId", [
    { id: "rule.replay", label: "Replay 7d", keys: "r" },
    { id: "rule.menu", label: "More", keys: "." },
    { id: "rule.run", label: "Run now", level: "L1" },
    { id: "rule.copy-id", label: "Copy id" },
    { id: "rule.copy-yaml", label: "Copy YAML" },
  ]),
  ...route("/response/playbooks/:playbookId", [{ id: "playbook.menu", label: "More", keys: "." }]),
  {
    id: "detection.new-rule",
    label: "New rule",
    keys: "n",
    scope: "route:/detection",
    group: "This screen",
    home: "/detection?tab=rules",
    palette: true,
  },
  ...route("/hunts", [{ id: "hunts.daily", label: "Run today's hunts", palette: true, level: "L1" }]),
  {
    id: "hunts.new-pack",
    label: "New pack",
    keys: "n",
    scope: "route:/hunts",
    group: "This screen",
    home: "/hunts?tab=packs",
    palette: true,
  },
  {
    id: "response.new-playbook",
    label: "New playbook",
    keys: "n",
    scope: "route:/response",
    group: "This screen",
    home: "/response?tab=playbooks",
    palette: true,
  },
  ...route("/intel", [{ id: "intel.add", label: "Add indicators", keys: "n", palette: true }]),
  ...route("/posture", [
    { id: "posture.resurvey", label: "Re-survey", palette: true },
    { id: "posture.rebuild", label: "Rebuild the graph", palette: true },
  ]),
  ...route("/memory", [{ id: "memory.add", label: "Add fact", keys: "n", palette: true }]),
  ...route("/connections", [
    { id: "sources.add", label: "Add source", keys: "n", palette: true },
    {
      id: "sources.onboard-all",
      label: "Let the Integrator work every source",
      palette: true,
      level: "L1",
    },
    { id: "source.pull", label: "Pull now", keys: "p", confirm: true },
  ]),
  {
    id: "intel.refresh",
    label: "Pull feeds",
    scope: "route:/connections",
    group: "This screen",
    home: "/connections?tab=intel",
    palette: true,
  },
  ...route("/access", [
    { id: "access.invite", label: "Invite", keys: "i", palette: true, level: "L2" },
    { id: "access.copy-name", label: "Copy name", keys: "c" },
  ]),
  {
    id: "access.new-token",
    label: "New token",
    keys: "n",
    scope: "route:/access",
    group: "This screen",
    home: "/access?tab=tokens",
    palette: true,
    level: "L2",
  },

  ...dialog("backlog", [
    { id: "backlog.done", label: "Done", keys: "d" },
    { id: "backlog.reject", label: "Reject", keys: "r" },
    { id: "backlog.reopen", label: "Reopen", keys: "o" },
    { id: "backlog.revert", label: "Revert", keys: "v", level: "L2" },
    { id: "backlog.merge", label: "Merge", keys: "m" },
  ]),
  ...dialog("pack", [{ id: "pack.run", label: "Run now", keys: "r", confirm: true }]),
  ...dialog("indicator", [
    { id: "indicator.sweep", label: "Sweep 90 days", keys: "s", confirm: true },
    { id: "indicator.lookup", label: "Look up", keys: "l" },
    { id: "indicator.remove", label: "Remove", keys: "x" },
  ]),
  ...dialog("action", [{ id: "action.undo", label: "Undo", keys: "u", level: "L2" }]),
  ...dialog("decide", [
    { id: "decide.approve", label: "Approve", keys: "a", level: "L2" },
    { id: "decide.reject", label: "Reject", keys: "r" },
  ]),
];

const BY_ID = new Map(COMMANDS.map((c) => [c.id, c]));

export function command(id: string): Command | undefined {
  return BY_ID.get(id);
}

/* -- keys as text ---------------------------------------------------------- */

const MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
const NAMES: Record<string, string> = {
  arrowdown: "↓",
  arrowup: "↑",
  arrowleft: "←",
  arrowright: "→",
  enter: "↵",
  escape: "Esc",
  space: "Space",
  home: "Home",
  end: "End",
};

/** For tips and menus: "⌘K", "G C", "Ctrl+Shift+J". */
export function keyLabel(keys: string): string {
  return keys
    .split(" ")
    .map((step) =>
      step
        .split("+")
        .map((part) => {
          if (part === "mod") return MAC ? "⌘" : "Ctrl+";
          if (part === "shift") return MAC ? "⇧" : "Shift+";
          if (part === "alt") return MAC ? "⌥" : "Alt+";
          return NAMES[part] ?? part.toUpperCase();
        })
        .join(""),
    )
    .join(" ");
}

/** For `aria-keyshortcuts`: "Meta+K Control+K", "G C". */
export function ariaKeys(keys: string): string {
  const part = (p: string, mod: string) =>
    p === "mod" ? mod : p.length > 1 ? p.charAt(0).toUpperCase() + p.slice(1) : p.toUpperCase();
  const spell = (mod: string) =>
    keys
      .split(" ")
      .map((step) => step.split("+").map((p) => part(p, mod)).join("+"))
      .join(" ");
  return keys.includes("mod") ? `${spell("Meta")} ${spell("Control")}` : spell("");
}

/** A keydown as the table spells it. Shift is spelled only beside a modifier or a named key. */
export function keyOf(event: Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey">): string {
  let key = event.key.toLowerCase();
  if (key === " ") key = "space";
  const parts: string[] = [];
  if (event.metaKey || event.ctrlKey) parts.push("mod");
  if (event.altKey) parts.push("alt");
  if (event.shiftKey && (key.length > 1 || parts.length)) parts.push("shift");
  parts.push(key);
  return parts.join("+");
}

const matches = (c: Command, key: string) => c.keys === key || c.alt === key;

/* -- the single-key switch (WCAG 2.1.4) ------------------------------------- */

const SINGLE = "shoc.keys";
let single = (() => {
  try {
    return localStorage.getItem(SINGLE) !== "off";
  } catch {
    return true;
  }
})();
const singleListeners = new Set<() => void>();

/** Whether single-character shortcuts are on; chords and ⌘ keys always are. */
export function useSingleKeys(): [boolean, (on: boolean) => void] {
  const on = useSyncExternalStore(
    (l) => (singleListeners.add(l), () => singleListeners.delete(l)),
    () => single,
  );
  return [
    on,
    (next) => {
      single = next;
      try {
        localStorage.setItem(SINGLE, next ? "on" : "off");
      } catch {
        /* the choice lasts until the tab closes */
      }
      for (const l of singleListeners) l();
    },
  ];
}

/* -- bindings -------------------------------------------------------------- */

type Binding = { id: string; run: () => void };

/** Bound commands, the latest mount last, so a dialog's binding wins over its page's. */
let bound: Binding[] = [];
const boundListeners = new Set<() => void>();
function setBound(next: Binding[]) {
  bound = next;
  for (const l of boundListeners) l();
}

/** Run a bound command, or follow a Go to; false when nothing answers. */
export function runCommand(id: string): boolean {
  const binding = [...bound].reverse().find((b) => b.id === id);
  if (binding) {
    binding.run();
    return true;
  }
  const fallback = command(id)?.fallback;
  return fallback ? runCommand(fallback) : false;
}

/** The commands bound right now, for the palette's This page section. */
export function useBound(): Command[] {
  const now = useSyncExternalStore(
    (l) => (boundListeners.add(l), () => boundListeners.delete(l)),
    () => bound,
  );
  const ids = [...new Set(now.map((b) => b.id))];
  return ids.flatMap((id) => {
    const c = command(id);
    return c && (c.scope.startsWith("route:") || c.scope.startsWith("dialog:")) ? [c] : [];
  });
}

/** `?do=` hand-offs already run, by history entry, so StrictMode's second effect does not repeat one. */
const handled = new Set<string>();

/* A `?do=` for a command that writes waits here for the shell's confirm. */
export type Asking = { command: Command; run: () => void };
let asking: Asking | null = null;
const askingListeners = new Set<() => void>();
function setAsking(next: Asking | null) {
  asking = next;
  for (const l of askingListeners) l();
}

/** The hand-off waiting on a confirm, and how to let it go. */
export function useAsking(): [Asking | null, () => void] {
  const now = useSyncExternalStore(
    (l) => (askingListeners.add(l), () => askingListeners.delete(l)),
    () => asking,
  );
  return [now, () => setAsking(null)];
}

/**
 * Bind a command while the calling component is mounted (and `enabled`). When
 * the URL carries `?do=<id>`, drop `do` from the URL first and run the command
 * once it is gone: a handler that writes the URL itself then starts from a
 * location without `do`, so its write can neither bring `do` back nor run the
 * command again on the next history entry. A `do` that arrives while the
 * command cannot run (no row picked, its record still loading) is dropped,
 * never run later; one for a command that writes asks the shell's confirm.
 */
export function useCommand(id: string, run: () => void, enabled = true): void {
  const latest = useRef(run);
  useLayoutEffect(() => {
    latest.current = run;
  });
  useEffect(() => {
    if (!enabled) return;
    const binding = { id, run: () => latest.current() };
    setBound([...bound, binding]);
    return () => setBound(bound.filter((b) => b !== binding));
  }, [id, enabled]);

  const [params, setParams] = useSearchParams();
  const location = useLocation();
  const asked = params.get("do") === id;
  const due = useRef(false);
  useEffect(() => {
    // Another binding of the same command that can run takes it.
    if (!asked || (!enabled && bound.some((b) => b.id === id))) return;
    const once = `${location.key}:${id}`;
    if (handled.has(once)) return;
    handled.add(once);
    due.current = enabled;
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        out.delete("do");
        return out;
      },
      { replace: true },
    );
  }, [asked, enabled, id, location.key, setParams]);
  useEffect(() => {
    if (asked || !due.current) return;
    due.current = false;
    const c = command(id);
    if (c?.confirm) setAsking({ command: c, run: () => latest.current() });
    else latest.current();
  }, [asked, id]);
}

/**
 * Escape on a detail page goes back to where the reader came from, filters
 * and page kept: the list that pushed it with `back` in the router state, else
 * the nearest history entry on another path, past the page's own tab changes
 * (stepping replaces the entry, so the list stays behind). A page a link
 * opened in a fresh tab has nothing behind it and goes to `fallback`.
 */
export function useEscBack(fallback: string, state?: unknown): void {
  const navigate = useNavigate();
  const location = useLocation();
  const listed = Boolean((location.state as { back?: string } | null)?.back);
  useCommand("shell.escape", () => {
    const back = listed ? 1 : stepsToLeave(location.pathname);
    if (back) navigate(-back);
    else navigate(fallback, state === undefined ? undefined : { state });
  });
}

/* -- lists ----------------------------------------------------------------- */

/** An attribute value for a selector; jsdom has no `CSS.escape`. */
const attr = (value: string) =>
  typeof CSS !== "undefined" && CSS.escape ? CSS.escape(value) : value.replace(/["\\]/g, "\\$&");

type ListHandler = { id: string; handle: (key: string, event: KeyboardEvent) => boolean };
let lists: ListHandler[] = [];
let tabs: { select: (n: number) => void }[] = [];

function raise(id: string) {
  const at = lists.findIndex((l) => l.id === id);
  if (at >= 0 && at !== lists.length - 1) lists = [...lists.filter((l) => l.id !== id), lists[at]!];
}

/** The row each URL last opened something from, so Back to that URL hands focus to the row again. */
const opened = new Map<string, string>();
const here = () => window.location.pathname + window.location.search;

/** A page that steps through its list (J and K on a finding) names the row Back should land on. */
export function rememberRow(url: string, key: string) {
  opened.set(url, key);
}

/**
 * Nothing holds focus but the page, its heading, a strip fact that filtered
 * the list, or a row of this list: moving the list may take it, so J then
 * Enter opens the row rather than pressing the fact again.
 */
function idle(list: string): boolean {
  const held = document.activeElement as HTMLElement | null;
  return (
    !held ||
    held === document.body ||
    held.id === "main" ||
    held.classList.contains("sh-page__title") ||
    held.classList.contains("sh-strip__fact") ||
    Boolean(held.closest?.(`[data-list="${attr(list)}"]`))
  );
}

/**
 * Keyboard and pointer state for one list. The active row is held by id, so a
 * refresh that reorders rows keeps it; when its row leaves, the row now at its
 * position takes over. The most recently used list on a page answers the keys.
 */
export function useListNav<R>(
  rows: R[],
  key: (row: R) => string,
  opts: {
    onOpen: (row: R) => void;
    /** What C copies; off when absent. */
    copy?: (row: R) => string;
    onPrevPage?: () => void;
    onNextPage?: () => void;
  },
): {
  activeKey: string;
  setActive: (key: string) => void;
  rowProps: (row: R) => Record<string, unknown>;
} {
  const id = useId();
  const [active, setActiveState] = useState<{ key: string; index: number }>({ key: "", index: -1 });
  const keys = rows.map(key);
  const at = keys.indexOf(active.key);
  const index = at >= 0 ? at : active.index >= 0 ? Math.min(active.index, keys.length - 1) : -1;
  const activeKey = index >= 0 ? keys[index]! : "";

  const setActive = (k: string) => setActiveState({ key: k, index: keys.indexOf(k) });
  const state = useRef({ rows, keys, index, opts, setActive, id });
  useLayoutEffect(() => {
    state.current = { rows, keys, index, opts, setActive, id };
  });
  const open = (row: R) => {
    opened.set(here(), key(row));
    opts.onOpen(row);
  };

  // Back to the URL a row opened a page from: that row is active and focused again, once its rows are in.
  const pop = useNavigationType() === "POP";
  const restore = useRef(pop ? (opened.get(here()) ?? "") : "");
  const joined = keys.join("\n");
  useEffect(() => {
    const want = restore.current;
    if (!want || !keys.length) return;
    restore.current = "";
    if (!keys.includes(want) || !idle(id)) return;
    opened.delete(here());
    setActive(want);
    document.querySelector<HTMLElement>(`[data-list="${attr(id)}"][data-row-key="${attr(want)}"]`)?.focus();
    // Keyed by the rows, so it runs once they arrive; `keys` and `setActive` change with them.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [joined, id]);

  useEffect(() => {
    // Focus follows the active row while it is in this list or nowhere, so Shift+Tab and Escape start from it.
    const move = (to: number) => {
      const { keys: ks, setActive: set, id: list } = state.current;
      if (!ks.length) return;
      const k = ks[Math.max(0, Math.min(ks.length - 1, to))]!;
      set(k);
      const row = document.querySelector<HTMLElement>(`[data-list="${attr(list)}"][data-row-key="${attr(k)}"]`);
      if (idle(list)) row?.focus({ preventScroll: true });
      row?.scrollIntoView?.({ block: "nearest" });
    };
    const handler: ListHandler = {
      id,
      handle(key) {
        const { rows: rs, index: i, opts: o } = state.current;
        const c = COMMANDS.find((cmd) => cmd.scope === "list" && matches(cmd, key));
        switch (c?.id) {
          case "list.down":
            move(i + 1);
            return true;
          case "list.up":
            move(i < 0 ? 0 : i - 1);
            return true;
          case "list.first":
            move(0);
            return true;
          case "list.last":
            move(rs.length - 1);
            return true;
          case "list.open":
            if (i < 0 || !rs[i]) return false;
            opened.set(here(), state.current.keys[i]!);
            o.onOpen(rs[i]);
            return true;
          case "list.prev-page":
            if (!o.onPrevPage) return false;
            o.onPrevPage();
            return true;
          case "list.next-page":
            if (!o.onNextPage) return false;
            o.onNextPage();
            return true;
          case "list.copy":
            if (!o.copy || i < 0 || !rs[i]) return false;
            void copyAndSay(o.copy(rs[i]));
            return true;
          default:
            return false;
        }
      },
    };
    lists = [...lists, handler];
    return () => {
      lists = lists.filter((l) => l !== handler);
    };
  }, [id]);

  return {
    activeKey,
    setActive,
    rowProps: (row: R) => {
      const k = key(row);
      return {
        "data-list": id,
        "data-row-key": k,
        "data-active": k === activeKey ? "" : undefined,
        tabIndex: k === activeKey || (activeKey === "" && k === keys[0]) ? 0 : -1,
        onFocus: () => {
          raise(id);
          if (k !== activeKey) setActive(k);
        },
        onPointerDown: () => raise(id),
        onClick: () => {
          setActive(k);
          open(row);
        },
      };
    },
  };
}

/** `1`–`9` select the screen's tabs while it is mounted. */
export function useTabKeys(count: number, select: (index: number) => void): void {
  const latest = useRef(select);
  useLayoutEffect(() => {
    latest.current = select;
  });
  useEffect(() => {
    const entry = { select: (n: number) => n < count && latest.current(n) };
    tabs = [...tabs, entry];
    return () => {
      tabs = tabs.filter((t) => t !== entry);
    };
  }, [count]);
}

/* -- the listener ---------------------------------------------------------- */

function typing(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el?.tagName) return false;
  return /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable;
}

/** A row or the page holds focus, not a control that Enter and Space already press. */
function pressable(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el?.closest) return false;
  return Boolean(el.closest("button, a[href], summary, [role=button], [role=menuitem], [role=tab]")) && !el.hasAttribute("data-row-key");
}

/** A modal dialog is open: only its keys run. The chat window is not modal. */
function modalOpen(): boolean {
  return [...document.querySelectorAll("dialog[open]")].some((d) => {
    try {
      return d.matches(":modal");
    } catch {
      return !d.classList.contains("sh-chat");
    }
  });
}

/** Something native will close on Escape by itself: a modal dialog or an open popover. */
function layerOpen(): boolean {
  if (modalOpen()) return true;
  try {
    return document.querySelector(":popover-open") !== null;
  } catch {
    return false;
  }
}

const CHORD_STARTS = new Set(COMMANDS.flatMap((c) => (c.keys?.includes(" ") ? [c.keys.split(" ")[0]!] : [])));

let chordHint = "";
const hintListeners = new Set<() => void>();
function setHint(next: string) {
  chordHint = next;
  for (const l of hintListeners) l();
}

/** The first key of a chord while it waits for the second ("g"), for the "g…" hint. */
export function useChordHint(): string {
  return useSyncExternalStore(
    (l) => (hintListeners.add(l), () => hintListeners.delete(l)),
    () => chordHint,
  );
}

/** Decide what one key does. Exported for the tests; the shell calls it through `useKeys`. */
export function dispatch(key: string, event: KeyboardEvent, go: (to: string) => void): boolean {
  const run = (c: Command) => {
    if (runCommand(c.id)) return true;
    if (c.to) {
      go(c.to);
      return true;
    }
    return false;
  };
  const latestFirst = [...bound].reverse();
  const hit = (scope: (s: Scope) => boolean) =>
    latestFirst.find((b) => {
      const c = command(b.id);
      return c && scope(c.scope) && matches(c, key);
    });

  if (modalOpen()) {
    const own = hit((s) => s === "dialog" || s.startsWith("dialog:"));
    if (own) {
      own.run();
      return true;
    }
    // A list inside the topmost dialog (a pack's runs, a source's samples) answers for its focused row.
    const row = (event.target as HTMLElement | null)?.closest?.("[data-list]");
    const owner = row ? lists.find((l) => l.id === row.getAttribute("data-list")) : undefined;
    const top = [...document.querySelectorAll("dialog[open]")].at(-1);
    if (row && owner && row.closest("dialog") === top && owner.handle(key, event)) return true;
    const over = COMMANDS.find((c) => c.scope === "global" && c.overModal && matches(c, key));
    return over ? run(over) : false;
  }
  const page = hit((s) => s.startsWith("route:"));
  if (page) {
    page.run();
    return true;
  }
  if (/^[1-9]$/.test(key) && tabs.length) {
    tabs.at(-1)!.select(Number(key) - 1);
    return true;
  }
  const list = lists.at(-1);
  if (list && !((key === "enter" || key === "space") && pressable(event.target)) && list.handle(key, event))
    return true;
  const global = COMMANDS.find((c) => c.scope === "global" && matches(c, key));
  return global ? run(global) : false;
}

/**
 * The one keydown listener, mounted once by the shell inside the router.
 * Precedence: an open modal dialog, then the page, then the screen's tabs, then
 * the focused list, then global keys and chords.
 */
export function useKeys(): void {
  const navigate = useNavigate();
  const go = useRef(navigate);
  useLayoutEffect(() => {
    go.current = navigate;
  });
  useEffect(() => {
    let pending = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const clear = () => {
      pending = "";
      clearTimeout(timer);
      setHint("");
    };
    function onKey(event: KeyboardEvent) {
      if (event.isComposing) return;
      // Tab is moving focus: fields that open focused quietly (the chat's composer) show the full ring again.
      if (event.key === "Tab") document.documentElement.setAttribute("data-kbd", "");
      const key = keyOf(event);
      if (key === "escape") {
        // Native dialogs and popovers close themselves; the chat stops its own Escape.
        if (event.defaultPrevented || layerOpen()) return;
        if (runCommand("shell.escape")) event.preventDefault();
        return;
      }
      if (event.defaultPrevented) return;
      const plain = !key.includes("+") || key.startsWith("shift+");
      if (plain && typing(event.target)) return;
      if (pending) {
        const chord = COMMANDS.find((c) => c.keys === `${pending} ${key}`);
        clear();
        if (chord && (runCommand(chord.id) || (chord.to && (go.current(chord.to), true))))
          event.preventDefault();
        return;
      }
      if (!key.includes("+") && CHORD_STARTS.has(key) && !modalOpen()) {
        pending = key;
        setHint(key);
        timer = setTimeout(clear, 1200);
        event.preventDefault();
        return;
      }
      if (!key.includes("+") && key.length === 1 && !single) return;
      if (dispatch(key, event, (to) => go.current(to))) event.preventDefault();
    }
    const onPointer = () => document.documentElement.removeAttribute("data-kbd");
    window.addEventListener("keydown", onKey);
    window.addEventListener("pointerdown", onPointer);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("pointerdown", onPointer);
      clear();
    };
  }, []);
}

/* -- the palette's Go to list ---------------------------------------------- */

/** Every screen and every tab, for the palette: "Response › Pages" with its chord on the screen rows. */
export const GO_TO: { label: string; to: string; keys?: string }[] = SCREENS.flatMap((s) => [
  { label: s.label, to: s.to, keys: `g ${s.chord}` },
  ...(s.tabs ?? []).slice(1).map((t) => ({ label: `${s.label} › ${t}`, to: tabHref(s, t) })),
]);

/** A palette command's row label: its home screen, then the command ("Detection › Run every rule now"). */
export function paletteLabel(c: Command): string {
  const path = (c.home ?? "").split("?")[0];
  const screen = SCREENS.find((s) => s.to === path);
  return screen ? `${screen.label} › ${c.label}` : c.label;
}

/** Where the palette sends a command: its home with `do`. */
export function handOff(c: Command): string {
  const home = c.home ?? "/";
  return `${home}${home.includes("?") ? "&" : "?"}do=${encodeURIComponent(c.id)}`;
}

/* -- the palette's Recent list ----------------------------------------------- */

export type Recent = { kind: "case" | "finding" | "rule" | "playbook"; id: string; to: string };

const RECENT = "shoc.recent";

/** The record a path is the page of, or null. */
export function recordOf(pathname: string): Recent | null {
  const m = /^\/(cases|findings|detection\/rules|response\/playbooks)\/([^/]+)$/.exec(pathname);
  if (!m) return null;
  const kind = ({ cases: "case", findings: "finding", "detection/rules": "rule", "response/playbooks": "playbook" } as const)[
    m[1] as "cases"
  ];
  return { kind, id: decodeURIComponent(m[2]!), to: pathname };
}

/** The last six records this viewer opened, newest first. */
export function recentRecords(): Recent[] {
  try {
    const saved = JSON.parse(localStorage.getItem(RECENT) ?? "[]") as Recent[];
    return Array.isArray(saved) ? saved.slice(0, 6) : [];
  } catch {
    return [];
  }
}

/** Mounted once by the shell: remembers each record page the viewer opens. */
export function useRememberRecent(): void {
  const { pathname } = useLocation();
  useEffect(() => {
    const record = recordOf(pathname);
    if (!record) return;
    const next = [record, ...recentRecords().filter((r) => r.to !== record.to)].slice(0, 6);
    try {
      localStorage.setItem(RECENT, JSON.stringify(next));
    } catch {
      /* private window: the list lasts as long as the page */
    }
  }, [pathname]);
}
