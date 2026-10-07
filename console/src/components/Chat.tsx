/**
 * The crew, on every screen: a launcher bottom-right (⌘J) that opens a
 * floating chat window there, your messages on the right and the crew's on the
 * left with the evidence under each answer. The thread lives in `lib/chat.ts`,
 * so it survives moving between screens and a reload. The context chip comes
 * from the URL (the record page, an open record dialog, Explore's query) and
 * is sent as the first turn; removing it sends nothing. Sending is always a
 * deliberate Enter, because `ask` may spend tokens. Answers never write.
 * While the crew is down the window says so at its top, where the reader looks.
 *
 * Capabilities used: ask (through `lib/chat.ts`).
 */
import { useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { Maximize2, Minimize2, Minus, MoreHorizontal, SendHorizontal, X } from "lucide-react";
import {
  aboutKey,
  aboutLabel,
  aboutOf,
  aboutText,
  ask,
  dropContext,
  lastQuestion,
  minimiseChat,
  newConversation,
  retry,
  setDraft,
  setRaiser,
  toggleChat,
  toggleWide,
  useChatState,
  type About,
  type Turn,
} from "@/lib/chat";
import { cn } from "@/lib/cn";
import { keyLabel } from "@/lib/commands";
import { bare, kindOf } from "@/lib/entity";
import { clock } from "@/lib/format";
import { useCrewDown } from "@/lib/needs";
import { Cites } from "./Citations";
import { Avatar, AvatarStack } from "./ui/avatar";
import { Badge, SeverityBadge } from "./ui/badge";
import { Button } from "./ui/button";
import { Entity } from "./ui/entity";
import { Announcer } from "./ui/misc";
import { Menu } from "./ui/pop";
import { Prose } from "./ui/prose";
import { Tip } from "./ui/tip";

const SUGGEST: Record<string, string[]> = {
  case: ["Why this verdict?", "What did you rule out?", "What should I do?"],
  finding: ["Is this normal here?", "What else did it do?"],
  any: ["What needs me?", "What happened today?", "Anything broken?"],
};

/* -- the window ------------------------------------------------------------- */

function modals(): HTMLDialogElement[] {
  try {
    return [...document.querySelectorAll("dialog[open]")].filter((d): d is HTMLDialogElement => d.matches(":modal"));
  } catch {
    return [];
  }
}

export function ChatPanel() {
  const state = useChatState();
  const location = useLocation();
  const launcher = useRef<HTMLButtonElement>(null);
  // Set when the window was put away with focus inside it: where focus was before it opened.
  const refocus = useRef<{ opener: Element | null } | null>(null);
  const about = aboutOf(location.pathname, location.search);
  const context = about && aboutKey(about) !== state.dropped ? about : null;
  const pending = state.turns.some((t) => t.state === "pending");

  // Put away (⌘J, Escape, −) with focus inside it: over a record dialog, back
  // to where focus was in that dialog (the launcher sits behind it); else the launcher.
  useEffect(() => {
    if (state.open || !refocus.current) return;
    const { opener } = refocus.current;
    refocus.current = null;
    const open = modals();
    const inside = opener instanceof HTMLElement && open.some((d) => d.contains(opener));
    // On a phone the launcher is hidden and the bottom bar's Ask opened the window.
    const hidden = launcher.current ? getComputedStyle(launcher.current).display === "none" : true;
    const back = hidden ? document.querySelector<HTMLElement>(".sh-bottombar__ask") : launcher.current;
    (inside ? opener : (open.at(-1) ?? back))?.focus();
  }, [state.open]);

  return (
    <>
      {state.open ? null : (
        <Tip label="Ask the crew" kbd={keyLabel("mod+j")}>
          <button
            ref={launcher}
            type="button"
            className="sh-chat__launcher"
            onClick={toggleChat}
            aria-label={state.unread ? "Ask the crew, new answer" : "Ask the crew"}
            aria-keyshortcuts="Meta+J Control+J"
            data-unread={state.unread ? "" : undefined}
            data-pending={pending ? "" : undefined}
          >
            ›
          </button>
        </Tip>
      )}
      {state.open ? <Window context={context} about={about} onGone={(opener) => (refocus.current = { opener })} /> : null}
    </>
  );
}

function Window({
  context,
  about,
  onGone,
}: {
  context: About | null;
  about: About | null;
  onGone: (opener: Element | null) => void;
}) {
  const state = useChatState();
  const ref = useRef<HTMLDialogElement>(null);
  const log = useRef<HTMLDivElement>(null);
  const composer = useRef<HTMLTextAreaElement>(null);
  const opener = useRef<Element | null>(null);
  const titleId = useId();
  const lastCrew = [...state.turns].reverse().find((t) => t.role === "crew" && t.answer);
  const consulted = lastCrew?.answer?.consulted ?? [];
  const busy = state.turns.some((t) => t.state === "pending");
  const crew = useCrewDown();

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog || dialog.open) return;
    opener.current = document.activeElement;
    // Over a modal dialog (⌘J from EntityDialog) the window must be modal too, or it is inert.
    try {
      if (modals().length) dialog.showModal();
      else dialog.show();
    } catch {
      /* jsdom has neither */
    }
    composer.current?.focus();
  }, []);

  // A dialog opened after the window leaves it inert behind its backdrop: ⌘J shows it again, modal, on top.
  useEffect(() => {
    setRaiser(() => {
      const dialog = ref.current;
      if (!dialog?.open || modals().includes(dialog) || !modals().length) return false;
      dialog.close();
      dialog.showModal();
      composer.current?.focus();
      return true;
    });
    return () => setRaiser(null);
  }, []);

  // A layout cleanup runs before the window leaves the DOM, so it can still see where focus is.
  useLayoutEffect(() => {
    const dialog = ref.current;
    return () => {
      if (dialog?.contains(document.activeElement)) onGone(opener.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    log.current?.scrollTo({ top: log.current.scrollHeight });
  }, [state.turns.length, busy]);

  const send = () => {
    if (!state.draft.trim() || busy) return;
    void ask({ question: state.draft, about: context });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDialogElement>) => {
    if (event.key !== "Escape") return;
    // The chat takes its own Escape; a dialog, menu or confirm opened from it closes itself first.
    const target = event.target as HTMLElement;
    if (target.closest("dialog") !== ref.current || target.closest("[popover]")) return;
    event.preventDefault();
    event.stopPropagation();
    minimiseChat();
  };

  const onComposer = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.nativeEvent.isComposing) return;
    if (event.key === "Enter" && !event.shiftKey && !event.metaKey && !event.ctrlKey) {
      event.preventDefault();
      send();
    } else if (event.key === "ArrowUp" && !state.draft) {
      const last = lastQuestion();
      if (last) {
        event.preventDefault();
        setDraft(last);
      }
    }
  };

  const suggestions = SUGGEST[context?.kind ?? ""] ?? SUGGEST.any!;

  return (
    <dialog
      ref={ref}
      className={cn("sh-chat", state.wide && "sh-chat--wide")}
      aria-labelledby={titleId}
      onKeyDown={onKeyDown}
      // React bubbles a nested dialog's close (an evidence chip's EventDialog); only this one's counts, and not
      // the close of a raise, which fires once the window is open again.
      onClose={(event) => event.target === event.currentTarget && !ref.current?.open && minimiseChat()}
    >
      <div className="sh-chat__head">
        <Avatar who="Manager" size={20} presence={busy ? "working" : undefined} />
        <h2 id={titleId} className="sh-chat__title">
          Crew
        </h2>
        {consulted.length ? <AvatarStack who={consulted} max={3} size={16} /> : null}
        <span className="sh-chat__tools">
          <Tip label={state.wide ? "Compact" : "Wide"} kbd={keyLabel("mod+shift+j")}>
            <Button variant="ghost" size="icon" className="max-md:hidden" onClick={toggleWide} aria-label={state.wide ? "Compact" : "Wide"} aria-keyshortcuts="Meta+Shift+J Control+Shift+J">
              {state.wide ? <Minimize2 aria-hidden /> : <Maximize2 aria-hidden />}
            </Button>
          </Tip>
          <Tip label="Minimise" kbd={keyLabel("mod+j")}>
            <Button variant="ghost" size="icon" onClick={minimiseChat} aria-label="Minimise">
              <Minus aria-hidden />
            </Button>
          </Tip>
          <Menu
            label="Chat"
            items={[{ label: "New conversation", onSelect: newConversation, disabled: busy || !state.turns.length }]}
            trigger={(props) => (
              <Button {...props} variant="ghost" size="icon" aria-label="More">
                <MoreHorizontal aria-hidden />
              </Button>
            )}
          />
        </span>
      </div>

      {crew.down ? (
        <div className="sh-banner sh-banner--bad sh-chat__down" role="status">
          <span className="sh-banner__text">Crew down</span>
          <Link to={crew.cause === "worker" ? "/health/jobs" : "/health/crew"}>
            {crew.cause === "worker" ? "Health › Jobs" : "Health › Crew"}
          </Link>
        </div>
      ) : null}
      <div ref={log} className="sh-chat__log" role="log" aria-live="off" aria-label="Conversation">
        {state.turns.map((turn) => (
          <Said key={turn.id} turn={turn} />
        ))}
        {!state.turns.length ? (
          // Asking cannot succeed while the crew is down: the suggestions stay readable and step out of the tab order.
          <div className="sh-chat__suggest">
            {suggestions.map((q) => (
              <button
                key={q}
                type="button"
                className="sh-chip"
                disabled={crew.down}
                onClick={() => {
                  setDraft(q);
                  composer.current?.focus();
                }}
              >
                <span className="sh-chip__value !font-sans">{q}</span>
              </button>
            ))}
          </div>
        ) : null}
      </div>

      {context ? (
        <div className="sh-chat__context">
          {/* The chip cuts the id; its tip is the exact turn `ask` receives. */}
          <Tip label={aboutText(context)} mono>
            <span className="sh-chip">
              <span className="sh-chip__label">{context.kind}</span>
              <span className="sh-chip__value">{aboutLabel(context)}</span>
              <button type="button" className="sh-chip__remove" onClick={() => dropContext(about)} aria-label="Remove the context">
                <X aria-hidden />
              </button>
            </span>
          </Tip>
        </div>
      ) : null}

      <form
        className="sh-chat__composer"
        onSubmit={(event) => {
          event.preventDefault();
          send();
        }}
      >
        <textarea
          ref={composer}
          rows={1}
          value={state.draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={onComposer}
          placeholder="Ask the crew…"
          aria-label="Ask the crew"
        />
        <Button type="submit" size="icon" variant="crew" aria-label="Send" disabled={busy || !state.draft.trim()}>
          <SendHorizontal aria-hidden />
        </Button>
      </form>
      <Announcer />
    </dialog>
  );
}

/** One turn: yours on the right; the crew's on the left with its evidence under it. */
function Said({ turn }: { turn: Turn }) {
  if (turn.role === "operator") return <p className="sh-chat__bubble sh-chat__bubble--you m-0">{turn.text}</p>;
  if (turn.state === "pending") return <Pending since={turn.at} />;
  if (turn.state === "error" || turn.state === "interrupted")
    return (
      <div className={cn("sh-chat__bubble sh-chat__bubble--crew", turn.state === "error" && "sh-chat__bubble--error")}>
        <span className="flex items-center gap-2">
          <span>{turn.state === "error" ? "Couldn't answer" : "Interrupted"}</span>
          <Button variant="ghost" size="sm" onClick={() => retry(turn.id)}>
            Retry
          </Button>
        </span>
        {turn.text ? <span className="sh-mono line-clamp-2 break-words">{turn.text}</span> : null}
      </div>
    );
  const answer = turn.answer;
  const findings = answer?.findings ?? [];
  // The text already chips a key it names, and a bare value with a pattern (an IP, an email; a domain stays a word).
  const inText = (key: string) => {
    const value = bare(key);
    const kind = kindOf(value);
    return turn.text.includes(key) || (kind !== null && kind !== "domain" && turn.text.includes(value));
  };
  const entities = (answer?.entities ?? []).filter((key) => !inText(key));
  return (
    <>
      <div className="sh-chat__bubble sh-chat__bubble--crew">
        <Prose text={turn.text} />
      </div>
      <div className="sh-chat__under">
        {turn.citations?.length ? <Cites uids={turn.citations} /> : null}
        {findings.slice(0, 5).map((f) => (
          <Link key={f.finding_uid} to={`/findings/${f.finding_uid}`} className="sh-chat__row min-w-0 !flex-nowrap text-fg-1 no-underline hover:underline">
            <SeverityBadge severity={f.severity} />
            <span className="min-w-0 truncate">{f.title}</span>
          </Link>
        ))}
        {entities.length ? (
          <span className="sh-chat__row">
            {entities.slice(0, 6).map((e) => (
              <Entity key={e} value={e} button />
            ))}
          </span>
        ) : null}
        <span className="sh-chat__row">
          {answer?.needs_human ? <Badge tone="crew">needs you</Badge> : null}
          {answer && answer.intent !== "manager" ? <Badge tone="faint">search · no model</Badge> : null}
          {answer?.consulted?.length ? <AvatarStack who={answer.consulted} max={4} size={16} /> : null}
          <span className="sh-chat__meta">{clock(turn.at)}</span>
        </span>
      </div>
    </>
  );
}

/** The Manager working: its avatar pulsing and the seconds counting up. */
function Pending({ since }: { since: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const seconds = Math.max(0, Math.round((now - Date.parse(since)) / 1000));
  return (
    // The log announces the bubble once; the seconds tick for the eye only.
    <div className="sh-chat__bubble sh-chat__bubble--crew sh-chat__bubble--pending flex items-center gap-2">
      <Avatar who="Manager" size={16} presence="working" tip={false} />
      <span className="sh-mono" aria-hidden>
        Manager · {seconds}s
      </span>
      <span className="sr-only">Manager is answering</span>
    </div>
  );
}
