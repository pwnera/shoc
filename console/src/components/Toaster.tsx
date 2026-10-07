/**
 * Toasts, bottom-left of the page: the bottom-right corner belongs to the crew
 * chat. Newest nearest the corner, three at once and "+N" for the rest. Each
 * is a tone square, who asked (action events), the record's short id, a verb
 * phrase, one action and a lifetime bar that pauses, with the timer, while the
 * toast is hovered or focused. Critical toasts stay and are announced at once;
 * the rest are said through the polite region (`Announcer`).
 * The chord hint ("g…") sits in the same corner. While the chat window is
 * open the column narrows to stay left of it.
 */
import { Link, useLocation } from "react-router-dom";
import { X } from "lucide-react";
import { useChatState } from "@/lib/chat";
import { cn } from "@/lib/cn";
import { useChordHint } from "@/lib/commands";
import { dismiss, hold, SHOWN, useToasts, type Toast } from "@/lib/toast";
import { Avatar } from "./ui/avatar";
import { Button } from "./ui/button";
import { Tip } from "./ui/tip";

/** A `?a=1` link merged into the screen the reader is on; a path as it is. */
function over(to: string, search: string): string {
  if (!to.startsWith("?")) return to;
  const params = new URLSearchParams(search);
  for (const [k, v] of new URLSearchParams(to.slice(1))) params.set(k, v);
  return `?${params.toString()}`;
}

export function Toaster() {
  const toasts = useToasts();
  const chord = useChordHint();
  const chat = useChatState();
  const shown = toasts.slice(0, SHOWN);
  const more = toasts.length - shown.length;
  return (
    <section
      className="sh-toaster"
      data-chat={chat.open ? (chat.wide ? "wide" : "open") : undefined}
      aria-label="Notifications"
    >
      {/* A critical toast is its own alert; the rest are said through `lib/announce.ts`. The chord hint is for the eye. */}
      {chord ? (
        <span className="sh-toaster__chord" aria-hidden>
          {chord}…
        </span>
      ) : null}
      {shown.map((item) => (
        <ToastRow key={item.id} item={item} />
      ))}
      {more > 0 ? <span className="sh-toaster__more">+{more}</span> : null}
    </section>
  );
}

function ToastRow({ item }: { item: Toast }) {
  const { search } = useLocation();
  const action = item.action;
  return (
    <div
      className={cn("sh-toast", item.tone !== "neutral" && `sh-toast--${item.tone}`)}
      role={item.tone === "critical" ? "alert" : undefined}
      onMouseEnter={() => hold(item.id, true)}
      onMouseLeave={() => hold(item.id, false)}
      onFocus={() => hold(item.id, true)}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) hold(item.id, false);
      }}
    >
      <i className="sh-toast__dot" aria-hidden />
      {item.who ? (
        <span className="sh-toast__who">
          <Avatar who={item.who} size={16} />
        </span>
      ) : null}
      {item.subject ? (
        <Tip label={item.subject.title} mono>
          <Link to={item.subject.to} className="sh-toast__subject" onClick={() => dismiss(item.id)}>
            {item.subject.label}
          </Link>
        </Tip>
      ) : null}
      <span className="sh-toast__text">{item.text}</span>
      {item.count > 1 ? (
        <span className="sh-toast__count" aria-hidden>
          ×{item.count}
        </span>
      ) : null}
      {action ? (
        action.to ? (
          <Link
            to={over(action.to, search)}
            className="sh-btn sh-btn--ghost sh-btn--sm sh-toast__action"
            onClick={() => dismiss(item.id)}
          >
            {action.label}
          </Link>
        ) : (
          <Button
            variant="ghost"
            size="sm"
            className="sh-toast__action"
            onClick={() => {
              action.run();
              dismiss(item.id);
            }}
          >
            {action.label}
          </Button>
        )
      ) : null}
      <button type="button" className="sh-toast__close" onClick={() => dismiss(item.id)} aria-label="Dismiss">
        <X aria-hidden />
      </button>
      {Number.isFinite(item.life) ? (
        <i key={`${item.count}:${item.life}`} className="sh-toast__life" style={{ "--life": `${item.life}ms` } as React.CSSProperties} aria-hidden />
      ) : null}
    </div>
  );
}
