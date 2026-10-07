/**
 * The crew's discussion on the case as a trace, grouped by round with a rail
 * of round links: Outcomes (decisions and proposals) by default, Debate adds
 * the arguing, All every message; a person's message shows in every mode.
 * A re-investigation is a new pass that starts its rounds again, so when the
 * case had more than one pass, each opens with its number on the day row and
 * a hairline in the rail ("run" is a playbook's word); day rows split the
 * trace as in the Timeline, and a round they split keeps its one divider. The
 * rail shows only while some pass shows more than one round: with one round a
 * pass, each link would sit beside its own divider. A row is one line and
 * opens the message dialog over the rows shown; the row of a person's post
 * reopens Steer. New crew rows wait behind a "new" pill unless the
 * reader is at the bottom. Steer posts into the case.
 *
 * Capabilities used: openspace.post (Steer); it reads `case.get`.
 */
import { Fragment, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { CardToolbar } from "@/components/ui/card";
import { Empty, NewPill } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { Tip } from "@/components/ui/tip";
import { Trace, type TraceRound, type TraceRow } from "@/components/ui/trace";
import { cn } from "@/lib/cn";
import { useListNav } from "@/lib/commands";
import { day, num, percent } from "@/lib/format";
import { kindWord } from "@/lib/labels";
import { useParam } from "@/lib/param";
import type { CaseRecord, OpenspaceMessage } from "@/types";
import { conceded, firstLine, isHuman, pickedUp, roundsOf, visibleMessages, type Mode, type Round } from "./messages";
import { STUCK_MAX } from "./DecisionBar";
import type { Open } from "./moments";
import { SteerPopover, type Post } from "./SteerPopover";

const MODES: { value: Mode; label: string }[] = [
  { value: "outcomes", label: "Outcomes" },
  { value: "debate", label: "Debate" },
  { value: "all", label: "All" },
];

const AT_BOTTOM = 24;
/** The height Steer's popover needs under its button. */
const POPOVER_ROOM = 320;

export function Discussion({
  data,
  steer,
  onSteer,
  open,
}: {
  data: CaseRecord;
  steer: boolean;
  onSteer: (open: boolean) => void;
  open: Open;
}) {
  const [mode, setMode] = useParam<Mode>("mode", "outcomes");
  const [draft, setDraft] = useState("");
  const [post, setPost] = useState<Post | null>(null);
  const messages = data.openspace;
  const visible = visibleMessages(messages, mode);
  const dead = conceded(messages);
  const placeOf = roundsOf(messages);
  const tokens = new Map<string, number>();
  for (const m of messages) {
    const key = placeOf.get(m.msg_id)!.key;
    tokens.set(key, (tokens.get(key) ?? 0) + m.tokens);
  }
  // The pending row goes once the posted message comes back with the case.
  const landed = post && !post.error && messages.some((m) => isHuman(m) && m.kind === "inject" && m.body === post.body);
  const pending = landed ? null : post;

  const byKey = new Map(visible.map((m) => [String(m.msg_id), m]));
  const ids = visible.map((m) => m.msg_id);
  const nav = useListNav(visible, (m) => String(m.msg_id), { onOpen: (m) => open.message(m.msg_id, ids) });

  // One trace per day and pass; a divider opens each round, once, even when midnight splits it.
  // When the case had more than one pass, a pass's first day row carries its number.
  const runs = new Set(visible.map((m) => placeOf.get(m.msg_id)!.run)).size > 1;
  const days: { day: string; run: number | null; items: (TraceRow | TraceRound)[] }[] = [];
  const rail: { key: string; run: number; first: boolean; round: number; at: string; index: number }[] = [];
  let dividers = 0;
  let last: Round | null = null;
  for (const m of visible) {
    const place = placeOf.get(m.msg_id)!;
    const today = day(m.created_at);
    const first = runs && place.run !== last?.run;
    if (first || days.at(-1)?.day !== today) days.push({ day: today, run: first ? place.run : null, items: [] });
    const items = days.at(-1)!.items;
    if (place.key !== last?.key) {
      rail.push({ key: place.key, run: place.run, first, round: place.round, at: m.created_at, index: dividers });
      items.push({ key: `round:${place.key}`, round: place.round, tokens: tokens.get(place.key) });
      dividers += 1;
    }
    last = place;
    items.push(traceRow(m, messages, dead.has(m.msg_id), String(m.msg_id) === nav.activeKey));
  }
  const railed = rail.length > new Set(rail.map((r) => r.run)).size;
  if (pending) {
    if (!days.length) days.push({ day: day(pending.at), run: null, items: [] });
    days.at(-1)!.items.push({
      key: "pending",
      kind: "inject",
      author: "human:you",
      text: pending.body,
      human: true,
      pending: !pending.error,
      error: Boolean(pending.error),
      time: pending.at,
      meta: pending.error ? "failed" : undefined,
    });
  }

  // Scroll: start at the newest; follow new rows only while the reader sits at the bottom.
  const box = useRef<HTMLDivElement>(null);
  const bottom = useRef(true);
  const seen = useRef({ mode, count: visible.length });
  const [fresh, setFresh] = useState(0);
  const toBottom = () => box.current?.scrollTo({ top: box.current.scrollHeight });
  useLayoutEffect(() => {
    toBottom();
  }, []);
  useEffect(() => {
    const grew = seen.current.mode === mode ? visible.length - seen.current.count : 0;
    if (seen.current.mode !== mode) toBottom();
    seen.current = { mode, count: visible.length };
    if (grew <= 0) return;
    if (bottom.current) toBottom();
    else setFresh((n) => n + grew);
  }, [mode, visible.length]);
  useEffect(() => {
    if (pending) toBottom();
  }, [pending]);

  // S from anywhere opens Steer here: when its button is not where the popover fits under it,
  // the toolbar comes to the top, below the top bar and a stuck decision bar, and only then the popover opens.
  const toolbar = useRef<HTMLDivElement>(null);
  const [placed, setPlaced] = useState(false);
  useLayoutEffect(() => {
    if (!steer) return setPlaced(false);
    const el = toolbar.current;
    if (el) {
      const bar = document.querySelector<HTMLElement>('[role="region"][aria-label="Decisions"]');
      const stuck = bar && getComputedStyle(bar).position === "sticky" ? Math.min(bar.offsetHeight, STUCK_MAX) : 0;
      const top = (parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--topbar-h")) || 48) + stuck + 8;
      const at = el.getBoundingClientRect();
      if (at.top < top || at.bottom > window.innerHeight - POPOVER_ROOM) {
        el.style.scrollMarginTop = `${top}px`;
        el.scrollIntoView({ block: "start" });
      }
    }
    setPlaced(true);
  }, [steer]);

  const jump = (index: number) =>
    box.current?.querySelectorAll(".sh-trace__round")[index]?.scrollIntoView({ block: "start" });

  return (
    <>
      <div ref={toolbar}>
        <CardToolbar>
          <Seg<Mode> label="Show" value={mode} options={MODES} onChange={setMode} />
          {data.openspace_total > messages.length ? (
            <span className="sh-mono text-fg-4">
              latest {num(messages.length)} of {num(data.openspace_total)}
            </span>
          ) : null}
          {data.case.state === "closed" ? null : (
            <span className="ml-auto">
              <SteerPopover
                caseUid={data.case.case_uid}
                open={steer && placed}
                onOpenChange={onSteer}
                draft={draft}
                onDraft={setDraft}
                onPost={setPost}
              />
            </span>
          )}
        </CardToolbar>
      </div>
      {days.length ? (
        <div className={cn("grid grid-cols-[minmax(0,1fr)]", railed && "md:grid-cols-[56px_minmax(0,1fr)]")}>
          {railed ? (
            <nav aria-label="Rounds" className="hidden max-h-[min(36rem,60vh)] flex-col overflow-y-auto border-r border-line-1 py-1 scrollbar-thin md:flex">
              {rail.map((r) => (
                <Fragment key={r.key}>
                  {/* A new pass starts its rounds again: a hairline, its number is on the day row. */}
                  {r.first && r.index ? <hr aria-hidden className="mx-2 my-1 shrink-0 border-line-1" /> : null}
                  <Tip label={`${runs ? `pass ${r.run + 1} · ` : ""}round ${r.round} · ${day(r.at)}${tokens.get(r.key) ? ` · ${num(tokens.get(r.key)!)} tokens` : ""}`}>
                    <button
                      type="button"
                      className="sh-mono h-6 shrink-0 px-2 text-left text-fg-4 hover:bg-bg-2 hover:text-fg-1"
                      onClick={() => jump(r.index)}
                    >
                      {/* The name starts with what shows, so "click R80" finds it. */}
                      R{r.round}
                      {runs ? <span className="sr-only">, pass {r.run + 1}</span> : null}
                    </button>
                  </Tip>
                </Fragment>
              ))}
            </nav>
          ) : null}
          <div
            ref={box}
            className="relative max-h-[min(36rem,60vh)] overflow-y-auto px-2 scrollbar-thin [&_.sh-trace__round]:scroll-mt-6"
            onScroll={(event) => {
              const el = event.currentTarget;
              bottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < AT_BOTTOM;
              if (bottom.current && fresh) setFresh(0);
            }}
          >
            <NewPill
              count={fresh}
              crew
              onClick={() => {
                setFresh(0);
                toBottom();
              }}
            />
            {days.map((d, index) => {
              const run = d.run !== null ? `pass ${d.run + 1}` : "";
              return (
                <Fragment key={index}>
                  {/* Above the trace's nodes, which stack at 1 too. */}
                  <div className="sh-tl__day z-[2] gap-2">
                    {d.day}
                    {run ? <span className="text-fg-4">· {run}</span> : null}
                  </div>
                  <Trace
                    items={d.items}
                    rowProps={(row) => {
                      const m = byKey.get(row.key);
                      // The posted row reopens Steer, where its text waits until the post lands.
                      return m ? nav.rowProps(m) : { onClick: () => onSteer(true) };
                    }}
                    label={`Discussion, ${d.day}${run ? `, ${run}` : ""}`}
                  />
                </Fragment>
              );
            })}
          </div>
        </div>
      ) : (
        <Empty title={messages.length ? "Nothing in this view" : "No messages yet"} />
      )}
    </>
  );
}

function traceRow(m: OpenspaceMessage, all: readonly OpenspaceMessage[], dead: boolean, active: boolean): TraceRow {
  const human = isHuman(m);
  const confident = (m.kind === "decision" || m.kind === "hypothesis") && m.confidence !== null;
  return {
    key: String(m.msg_id),
    kind: m.kind,
    author: m.agent,
    text: firstLine(m),
    badge: (
      <Badge tone="faint">
        {kindWord(m.kind)}
        {confident ? ` ${percent(m.confidence!)}` : ""}
      </Badge>
    ),
    time: m.created_at,
    meta: m.repeats > 0 ? `×${m.repeats + 1}` : human && pickedUp(all, m) ? "picked up ✓" : undefined,
    human,
    dead,
    active,
  };
}
