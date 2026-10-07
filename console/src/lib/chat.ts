/**
 * The crew chat's thread, kept outside React so it survives moving between
 * screens, and mirrored to this tab's sessionStorage so it survives a reload.
 * The window (`components/Chat.tsx`) draws it; anything can open it with a
 * draft. Sending is always a deliberate second step, because `ask` may spend
 * tokens. Answers never write: the chat never posts into a case.
 *
 * Capabilities used: ask.
 */
import { useSyncExternalStore } from "react";
import { announce } from "./announce";
import { call } from "./api";
import { recordOf } from "./commands";
import { bare, parseEntity } from "./entity";
import { middle, shortId } from "./format";
import type { Answer } from "@/types";

/** What the reader is looking at, sent as the first turn: `ask` has no structured context yet. */
export type About = {
  kind: "case" | "finding" | "rule" | "playbook" | "entity" | "event" | "action" | "source" | "query";
  id: string;
};

export type Turn = {
  id: number;
  role: "operator" | "crew";
  text: string;
  at: string;
  /** Crew turns: in flight, failed, cut off by a reload, or the envelope that answered. */
  state?: "pending" | "error" | "interrupted";
  answer?: Answer;
  citations?: string[];
  /** Operator turns: what was attached when it was asked, so Retry sends the same. */
  about?: About | null;
};

export type ChatState = {
  turns: Turn[];
  open: boolean;
  wide: boolean;
  /** An answer landed while the window was minimised. */
  unread: boolean;
  draft: string;
  /** The context key the reader removed, so the chip stays gone on that record. */
  dropped: string;
};

const KEY = "shoc.chat";
const WIDE = "shoc.chat.wide";
/** How many earlier turns `ask` is handed (`shoc/agents/manager.py` HISTORY_TURNS). */
const HISTORY = 12;

function load(): ChatState {
  const empty: ChatState = { turns: [], open: false, wide: false, unread: false, draft: "", dropped: "" };
  try {
    const saved = JSON.parse(sessionStorage.getItem(KEY) ?? "null") as Partial<ChatState> | null;
    const wide = localStorage.getItem(WIDE) === "1";
    // A question in flight when the tab reloaded will never be answered: say so.
    const turns = (saved?.turns ?? []).map((t) => (t.state === "pending" ? { ...t, state: "interrupted" as const } : t));
    return { ...empty, ...saved, turns, wide, unread: false };
  } catch {
    return empty;
  }
}

let state = load();
/** Set while the tab unloads, whose aborted fetch is not the crew failing. */
let leaving = false;
window.addEventListener("pagehide", () => (leaving = true));
window.addEventListener("pageshow", () => (leaving = false));
let nextId = state.turns.reduce((max, t) => Math.max(max, t.id), 0) + 1;
const listeners = new Set<() => void>();

function set(patch: Partial<ChatState>) {
  state = { ...state, ...patch };
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ ...state, open: false }));
  } catch {
    /* storage off: the thread lasts as long as the page */
  }
  for (const l of listeners) l();
}

export function useChatState(): ChatState {
  return useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => state,
  );
}

/** The words the context chip shows and `ask` receives. */
export function aboutText(about: About): string {
  return about.kind === "query" ? `I am looking at the events for ${about.id}.` : `I am looking at ${about.kind} ${about.id}.`;
}

export const aboutKey = (about: About | null) => (about ? `${about.kind}:${about.id}` : "");

/** What a context or scope chip shows: a record's short id, an entity's value cut in the middle. */
export function aboutLabel(about: About): string {
  if (about.kind === "query") return about.id;
  if (about.kind === "entity" || about.kind === "event") return middle(bare(about.id), 6);
  return shortId(about.id);
}

/** A record id, event uid or source name: one token, so a crafted link cannot put a sentence in the operator's mouth. */
const ID = /^[\w.:-]{1,200}$/;
const LONGEST = 200;

/** The context of a URL: an open record dialog first, then the record page, then Explore's query. */
export function aboutOf(pathname: string, search: string): About | null {
  const params = new URLSearchParams(search);
  const entity = params.get("entity");
  if (entity && entity.length <= LONGEST && parseEntity(entity)) return { kind: "entity", id: entity };
  for (const [param, kind] of [
    ["event", "event"],
    ["action", "action"],
    ["decide", "action"],
    ["source", "source"],
  ] as const) {
    const id = params.get(param);
    if (id && ID.test(id)) return { kind, id };
  }
  const page = recordOf(pathname);
  if (page && ID.test(page.id)) return { kind: page.kind, id: page.id };
  const q = params.get("q");
  if (pathname === "/explore" && q) {
    const window = [params.get("since"), params.get("until")].filter(Boolean).join(" → ");
    const id = `${q}${window ? ` (${window})` : ""}`;
    if (id.length <= LONGEST) return { kind: "query", id };
  }
  return null;
}

/** Open the window, optionally with a draft to send; focus is the window's job. */
export function openChat(draft?: string) {
  set({ open: true, unread: false, ...(draft !== undefined ? { draft } : {}) });
}

export function minimiseChat() {
  set({ open: false });
}

/** The open window's way forward, registered by the window: true when it was behind a later modal and came up. */
let raiser: (() => boolean) | null = null;
export function setRaiser(raise: (() => boolean) | null) {
  raiser = raise;
}

/** ⌘J: open, or close; a window a dialog opened over comes forward instead of closing. */
export function toggleChat() {
  if (state.open && raiser?.()) return;
  if (state.open) minimiseChat();
  else openChat();
}

export function toggleWide() {
  try {
    localStorage.setItem(WIDE, state.wide ? "0" : "1");
  } catch {
    /* kept for this page only */
  }
  set({ wide: !state.wide });
}

export function setDraft(draft: string) {
  set({ draft });
}

export function dropContext(about: About | null) {
  set({ dropped: aboutKey(about) });
}

export function newConversation() {
  set({ turns: [], draft: "", dropped: "" });
}

export type HistoryTurn = { role: "operator" | "manager"; text: string };

/** The history `ask` takes: the context turn first, then the thread's settled turns, oldest first. */
export function historyFor(turns: Turn[], about: About | null): HistoryTurn[] {
  const said = turns
    .filter((t) => !t.state)
    .map((t): HistoryTurn => ({ role: t.role === "crew" ? "manager" : "operator", text: t.text }));
  if (!about) return said.slice(-HISTORY);
  return [{ role: "operator", text: aboutText(about) }, ...said.slice(-(HISTORY - 1))];
}

/** Ask the crew. The operator's turn shows at once; the crew's arrives, or fails with Retry. */
export async function ask({ question, about = null }: { question: string; about?: About | null }): Promise<void> {
  const text = question.trim();
  if (!text) return;
  const history = historyFor(state.turns, about);
  const now = new Date().toISOString();
  const mine: Turn = { id: nextId++, role: "operator", text, at: now, about };
  const theirs: Turn = { id: nextId++, role: "crew", text: "", at: now, state: "pending" };
  set({ turns: [...state.turns, mine, theirs], draft: "" });
  const settle = (patch: Partial<Turn>) =>
    set({
      turns: state.turns.map((t) => (t.id === theirs.id ? { ...t, ...patch, at: new Date().toISOString() } : t)),
      unread: !state.open,
    });
  try {
    const envelope = await call<Answer>("ask", { question: text, history, since: "-7d" });
    settle({ state: undefined, text: envelope.summary, answer: envelope.data, citations: envelope.citations });
    // The log itself is quiet (its evidence chips would make the answer long to hear): the answer alone is said.
    announce(`Manager: ${envelope.summary}`);
  } catch (error) {
    // Left pending, so the reloaded thread says "Interrupted" rather than "Can't reach".
    if (leaving) return;
    settle({ state: "error", text: error instanceof Error ? error.message : String(error) });
    announce("Couldn't answer");
  }
}

/** Ask a failed question again, with the same context, in place of the failed pair. */
export function retry(crewTurnId: number) {
  const at = state.turns.findIndex((t) => t.id === crewTurnId);
  const mine = state.turns[at - 1];
  if (at < 1 || !mine || mine.role !== "operator") return;
  set({ turns: state.turns.filter((t) => t.id !== crewTurnId && t.id !== mine.id) });
  void ask({ question: mine.text, about: mine.about ?? null });
}

/** The question the operator asked last, for ↑ in an empty composer. */
export function lastQuestion(): string {
  return [...state.turns].reverse().find((t) => t.role === "operator")?.text ?? "";
}
