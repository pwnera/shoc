/**
 * Who: a square avatar per identity, a stack of them, and the crew's state on
 * one case. Every identity comes from `lib/crew.ts` `who()`: all crew share the
 * blue and differ by monogram; the Integrator is crew work without a model
 * (dashed); people are outlined in the human ink; shoc's own authors draw a
 * glyph; an author the console does not know is a neutral "?", never crew.
 * CrewState reads `usePresence()` (fed by `stream.tail` and the live stream).
 */
import { Clock, Cog, Hourglass, Plug, User } from "lucide-react";
import { cn } from "@/lib/cn";
import { who as identify, type Who } from "@/lib/crew";
import { useNow } from "@/lib/now";
import { usePresence } from "@/lib/presence";
import type { Case } from "@/types";
import { Tip } from "./tip";

export type Presence = "working" | "idle" | "down";

function ShocMark() {
  return <img src="/favicon.svg" alt="" width={12} height={12} />;
}

const GLYPH = { mark: ShocMark, cog: Cog, clock: Clock, hourglass: Hourglass, person: User };

const resolve = (author: string | Who | null | undefined): Who =>
  typeof author === "object" && author ? author : identify(author);

/** 16, 20 or 24px. The accessible name is the role and its state ("Investigator, working"). */
export function Avatar({
  who: author,
  size = 20,
  presence,
  tip = true,
}: {
  who: string | Who | null | undefined;
  size?: 16 | 20 | 24;
  presence?: Presence;
  /** Off where a row already names the author beside the avatar. */
  tip?: boolean;
}) {
  const id = resolve(author);
  const Glyph = id.kind === "external" ? Plug : id.glyph ? GLYPH[id.glyph] : null;
  const name = presence ? `${id.name}, ${presence}` : id.name;
  const avatar = (
    <span
      className={cn("sh-avatar", size !== 20 && `sh-avatar--${size}`, `sh-avatar--${id.kind}`)}
      role="img"
      aria-label={name}
    >
      {Glyph ? <Glyph aria-hidden /> : id.mono}
      {presence ? <i className={`sh-presence sh-presence--${presence}`} aria-hidden /> : null}
    </span>
  );
  if (!tip) return avatar;
  return <Tip label={id.legacy ? `${id.name} · legacy name ${id.legacy}` : name}>{avatar}</Tip>;
}

/** Overlapping avatars, one per identity, then "+2". */
export function AvatarStack({
  who: authors,
  max = 3,
  size = 16,
  tip = true,
}: {
  who: (string | Who)[];
  max?: number;
  size?: 16 | 20 | 24;
  /** Off inside a trigger whose own popover names the roles. */
  tip?: boolean;
}) {
  const seen = new Set<string>();
  const ids = authors.map(resolve).filter((id) => !seen.has(id.key) && seen.add(id.key));
  if (!ids.length) return null;
  const extra = ids.length - max;
  return (
    <span className="sh-avatar-stack">
      {ids.slice(0, max).map((id) => (
        <Avatar key={id.key} who={id} size={size} tip={tip} />
      ))}
      {extra > 0 ? <span className="sh-avatar-stack__more">+{extra}</span> : null}
    </span>
  );
}

const minutes = (ms: number) => Math.max(0, Math.round(ms / 60_000));

function since(ms: number): string {
  const m = minutes(ms);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h}h` : `${Math.round(h / 24)}d`;
}

/**
 * The crew's state on one case: working (a role posted in the last two
 * minutes), waiting (a proposed action or a needs-you verdict), stalled (an
 * ops alert), budget (the token cap is spent), or idle (when it last worked).
 * `waiting` and `stalled` come from the caller, which already holds the
 * proposals and alerts for the whole list. Idle draws an empty glyph whose tip
 * names the role that spoke last this session and when the crew last worked.
 */
export function CrewState({
  row,
  variant = "glyph",
  waiting,
  stalled,
}: {
  row: Pick<Case, "case_uid" | "verdict" | "tokens_used" | "token_cap" | "worked_at">;
  variant?: "glyph" | "full";
  waiting?: boolean;
  stalled?: boolean;
}) {
  const presence = usePresence();
  const now = useNow();
  const active = presence.onCase(row.case_uid)[0];
  const budget =
    presence.budget.has(row.case_uid) || (row.token_cap ? row.tokens_used >= row.token_cap : false);

  let state: "working" | "waiting" | "stalled" | "budget" | "idle";
  let text: string;
  if (active) {
    state = "working";
    text = `${active.who.mono} working · round ${active.round} · ${since(now - active.since)}`;
  } else if (waiting || row.verdict === "needs_human") {
    state = "waiting";
    text = "waits on you";
  } else if (stalled) {
    state = "stalled";
    text = "stalled";
  } else if (budget) {
    state = "budget";
    text = "stopped · budget";
  } else {
    state = "idle";
    const worked = row.worked_at ?? null;
    text = worked ? `worked ${since(now - Date.parse(worked))}` : "";
  }

  if (variant === "glyph") {
    const last = state === "idle" ? presence.last(row.case_uid) : undefined;
    const said = last ? [last.who.name, text || `spoke ${since(now - last.at)}`].join(" · ") : text;
    if (!said) return null;
    return (
      <Tip label={said}>
        <span className={`sh-live sh-live--glyph sh-live--${state}`} role="img" aria-label={said}>
          <i className="sh-live__glyph" aria-hidden />
        </span>
      </Tip>
    );
  }
  return (
    <span className={`sh-live sh-live--${state}`}>
      <i className="sh-live__glyph" aria-hidden />
      {text ? <span className="sh-live__text">{text}</span> : null}
    </span>
  );
}
