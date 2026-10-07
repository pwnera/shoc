/**
 * Who in the crew is speaking where, right now: the roles that posted an
 * openspace message in the last two minutes. Seeded once from `stream.tail`
 * when the console starts, then fed by the live stream (`lib/live.ts`), so the
 * crew pulse, the Cases glyphs and the case header read one store and no
 * screen polls for it.
 *
 * Capabilities used: stream.tail.
 */
import { useSyncExternalStore } from "react";
import { callData } from "./api";
import { who, type Who } from "./crew";
import { useNow } from "./now";
import type { StreamEvent } from "./stream";

/** How long a message keeps its role "working". */
export const WINDOW = 120_000;

export type Active = {
  who: Who;
  caseUid: string;
  kind: string;
  round: number;
  /** When the message was seen, in ms. */
  at: number;
  /** When this round of this case was first seen this session, for "r7 · 2m". */
  since: number;
};

type State = {
  /** Newest message per role and case. */
  messages: Map<string, Active>;
  rounds: Map<string, number>;
  /** Cases that ran out of budget this session. */
  budget: Set<string>;
  /** When the model last failed, cleared by any later message from a model-backed role. */
  downAt: number;
  seeded: boolean;
};

const empty = (): State => ({
  messages: new Map(),
  rounds: new Map(),
  budget: new Set(),
  downAt: 0,
  seeded: false,
});
let state = empty();
const listeners = new Set<() => void>();

/** Forget everything, when the token changes or a test starts. */
export function resetPresence() {
  state = empty();
  for (const l of listeners) l();
}

function update(change: (draft: State) => void) {
  const draft: State = {
    ...state,
    messages: new Map(state.messages),
    rounds: new Map(state.rounds),
    budget: new Set(state.budget),
  };
  change(draft);
  state = draft;
  for (const l of listeners) l();
}

function message(draft: State, event: StreamEvent, at: number) {
  const p = event.payload;
  const author = who(typeof p.agent === "string" ? p.agent : "");
  if (author.kind !== "crew" && author.kind !== "code") return;
  const round = Number(p.round ?? 0);
  const roundKey = `${event.subject}#${round}`;
  if (!draft.rounds.has(roundKey)) draft.rounds.set(roundKey, at);
  draft.messages.set(`${author.key}@${event.subject}`, {
    who: author,
    caseUid: event.subject,
    kind: String(p.kind ?? ""),
    round,
    at,
    since: draft.rounds.get(roundKey)!,
  });
  if (author.role?.tier !== "code" && at > draft.downAt) draft.downAt = 0;
}

/** Feed one live event. Only the events presence cares about change anything. */
export function notePresence(event: StreamEvent, at = Date.now()) {
  if (event.type === "openspace.message") update((d) => message(d, event, at));
  else if (event.type === "case.budget_exhausted") update((d) => void d.budget.add(event.subject));
  else if (event.type === "health.llm.failing") update((d) => void (d.downAt = at));
}

/** Read the messages of the last few minutes, so the pulse is right before the first live event. */
export async function seedPresence(latestSeq: number): Promise<void> {
  try {
    const tail = await callData<{ events: StreamEvent[] }>("stream.tail", {
      since_seq: Math.max(0, latestSeq - 300),
      types: ["openspace.message"],
      limit: 300,
    });
    const cutoff = Date.now() - WINDOW;
    update((d) => {
      for (const event of tail.events) {
        const at = Date.parse(event.created_at);
        if (at >= cutoff) message(d, event, at);
      }
      d.seeded = true;
    });
  } catch {
    update((d) => void (d.seeded = true));
  }
}

function listen(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export type Presence = {
  /** The newest message per role, among those of the last two minutes, newest first. */
  roles: Active[];
  /** Every role and case pair active in the window, newest first. */
  active: Active[];
  /** The roles active on one case, newest first. */
  onCase: (caseUid: string) => Active[];
  /** The newest message seen on one case this session, however old: the idle glyph's "who worked last". */
  last: (caseUid: string) => Active | undefined;
  working: boolean;
  /** The model failed and no model-backed role has spoken since. */
  down: boolean;
  budget: ReadonlySet<string>;
  /** False until the seed answered or failed. */
  ready: boolean;
};

/** Presence as of the shared tick, so "working" lapses without a timer per row. */
export function usePresence(): Presence {
  const current = useSyncExternalStore(listen, () => state);
  const now = useNow();
  const cutoff = now - WINDOW;
  const active = [...current.messages.values()].filter((m) => m.at >= cutoff).sort((a, b) => b.at - a.at);
  const seen = new Set<string>();
  const roles = active.filter((m) => !seen.has(m.who.key) && seen.add(m.who.key));
  return {
    roles,
    active,
    onCase: (caseUid) => active.filter((m) => m.caseUid === caseUid),
    last: (caseUid) =>
      [...current.messages.values()].filter((m) => m.caseUid === caseUid).sort((a, b) => b.at - a.at)[0],
    working: active.length > 0,
    down: current.downAt > 0,
    budget: current.budget,
    ready: current.seeded,
  };
}
