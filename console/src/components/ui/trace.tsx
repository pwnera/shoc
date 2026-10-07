/**
 * A trace: a crew discussion or a run as rows on one rail. Each row is a
 * glyph for its kind, the author's avatar, a kind badge, one line of text and
 * a time; a row opens a popup and never grows. Round dividers carry the
 * round's token count. Dialog traces add chips under the line (tools,
 * stances, struck ruled-out values, dashed unseen ones). Without `onOpen` or
 * `rowProps` the rows are static, so chips holding links never sit inside a
 * button.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { who } from "@/lib/crew";
import { clock } from "@/lib/format";
import { kindWord } from "@/lib/labels";
import { Avatar } from "./avatar";
import { Badge } from "./badge";
import { Spinner } from "./misc";

export type TraceKind =
  | "hypothesis"
  | "evidence"
  | "challenge"
  | "concede"
  | "proposal"
  | "decision"
  | "inject"
  | "observation"
  | "request"
  | "answer"
  | "tool"
  | "error";

const NODE: Record<TraceKind, string> = {
  hypothesis: "○",
  evidence: "●",
  challenge: "✕",
  concede: "↩",
  proposal: "→",
  decision: "◆",
  inject: "□",
  observation: "·",
  request: "↗",
  answer: "↘",
  tool: "⌁",
  error: "■",
};

export type TraceRow = {
  key: string;
  kind: TraceKind | string;
  /** The author string, as `who()` reads it. */
  author?: string | null;
  text: string;
  /** Replaces the kind badge. */
  badge?: ReactNode;
  chips?: ReactNode;
  time?: string | null;
  /** One number beside the time (tokens, rows). */
  meta?: ReactNode;
  human?: boolean;
  error?: boolean;
  /** An optimistic row waiting for its write. */
  pending?: boolean;
  /** A challenge later conceded: muted and struck. */
  dead?: boolean;
  isNew?: boolean;
  active?: boolean;
};

export type TraceRound = { key: string; round: number; tokens?: number | null };

const isRound = (item: TraceRow | TraceRound): item is TraceRound => "round" in item;

export function Trace({
  items,
  onOpen,
  rowProps,
  label,
}: {
  items: (TraceRow | TraceRound)[];
  onOpen?: (row: TraceRow) => void;
  /** `useListNav().rowProps`, for J/K and Enter over the rows. */
  rowProps?: (row: TraceRow) => Record<string, unknown>;
  label?: string;
}) {
  return (
    <ol className="sh-trace" aria-label={label}>
      {items.map((item) => {
        if (isRound(item))
          return (
            <li key={item.key} className="sh-trace__round">
              round {item.round}
              {item.tokens ? ` · ${Math.round(item.tokens / 1000)}k tokens` : ""}
            </li>
          );
        const glyph = NODE[item.kind as TraceKind] ?? "·";
        const human = item.human ?? item.kind === "inject";
        const error = item.error ?? item.kind === "error";
        const kind = item.author ? who(item.author).kind : "unknown";
        const content = (
          <>
            <span className="sh-trace__node" data-tone={kind === "crew" || kind === "code" ? "crew" : undefined} aria-hidden>
              {glyph}
            </span>
            <span className="min-w-0">
              <span className="sh-trace__head">
                {item.author ? <Avatar who={item.author} size={16} /> : null}
                {item.badge ?? <Badge tone="faint">{kindWord(item.kind)}</Badge>}
                <span className="sh-trace__text">{item.text}</span>
              </span>
              {item.chips ? <span className="sh-trace__chips">{item.chips}</span> : null}
            </span>
            <span className="sh-trace__meta">
              {item.pending ? <Spinner /> : null}
              {item.meta ? <>{item.meta} · </> : null}
              {item.time ? clock(item.time) : null}
            </span>
          </>
        );
        return (
          <li
            key={item.key}
            className={cn(
              "sh-trace__item",
              human && "sh-trace__item--human",
              error && "sh-trace__item--error",
              item.pending && "sh-trace__item--pending",
              item.dead && "sh-trace__item--dead",
            )}
            data-new={item.isNew ? "" : undefined}
            data-active={item.active ? "" : undefined}
          >
            {onOpen || rowProps ? (
              <button
                type="button"
                className="sh-trace__row"
                onClick={onOpen ? () => onOpen(item) : undefined}
                {...rowProps?.(item)}
              >
                {content}
              </button>
            ) : (
              <div className="sh-trace__row sh-trace__row--static">{content}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
