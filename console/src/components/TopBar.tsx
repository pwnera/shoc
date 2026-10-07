/**
 * The 48px top bar: ≡ (under 768px), the palette trigger, the crew pulse, the
 * health pill and the account button. The pulse is the home of live presence:
 * who in the crew spoke in the last two minutes and on which case. The pill
 * mirrors Health: its state word in a shaped square, and the newest event's age.
 *
 * Capabilities used: health.status, ops.alerts; presence comes from
 * `stream.tail` and the live stream (`lib/presence.ts`), and a question in
 * flight in the chat (`lib/chat.ts`) shows the Manager working.
 */
import { Link } from "react-router-dom";
import { Menu as MenuIcon, Search } from "lucide-react";
import { openChat, useChatState } from "@/lib/chat";
import { keyLabel } from "@/lib/commands";
import { who } from "@/lib/crew";
import { age, clock, shortId } from "@/lib/format";
import { staleSince } from "@/lib/loaded";
import { useCrewDown } from "@/lib/needs";
import { useNow } from "@/lib/now";
import { usePresence } from "@/lib/presence";
import { useStreamStatus } from "@/lib/stream";
import { ApiError } from "@/lib/api";
import { usePipeline } from "@/routes/health/pipeline";
import { AccountMenu } from "./AccountMenu";
import { Avatar, AvatarStack } from "./ui/avatar";
import { Button } from "./ui/button";
import { Kbd } from "./ui/misc";
import { Popover } from "./ui/pop";
import { Mark, Status, type StatusTone } from "./ui/status";
import { Tip } from "./ui/tip";

export function TopBar({ onMenu, onSearch, onKeys }: { onMenu: () => void; onSearch: () => void; onKeys: () => void }) {
  return (
    <header className="sh-shell__top">
      <Button variant="ghost" size="icon" className="md:hidden" onClick={onMenu} aria-label="Screens">
        <MenuIcon aria-hidden />
      </Button>
      <button
        type="button"
        className="sh-shell__search"
        onClick={onSearch}
        aria-label="Search or jump"
        aria-keyshortcuts="Meta+K Control+K"
      >
        <Search aria-hidden />
        <span>Search or jump</span>
        <Kbd>{keyLabel("mod+k")}</Kbd>
      </button>
      <CrewPulse />
      <HealthPill />
      <AccountMenu onKeys={onKeys} />
    </header>
  );
}

const MANAGER = who("Manager");

/**
 * "[IN][CH] working": the roles that spoke in the last two minutes, and one
 * word. Never "idle" until the alerts, health and the presence seed answered.
 */
function CrewPulse() {
  const presence = usePresence();
  const crew = useCrewDown();
  const asking = useChatState().turns.some((t) => t.state === "pending");
  const now = useNow();
  const down = crew.down;
  const working = presence.working || asking;
  const unknown = crew.failed ? "—" : crew.pending || !presence.ready ? "…" : "";
  const state = down ? "down" : working ? "working" : unknown ? "unknown" : "idle";
  const word = down ? "crew down" : working ? "working" : unknown || "idle";
  const said = state === "unknown" ? (crew.failed ? "unknown" : "loading") : word;
  const faces = presence.roles.map((r) => r.who);
  if (asking && !faces.some((f) => f.key === MANAGER.key)) faces.unshift(MANAGER);
  const cause = crew.cause === "worker" ? "worker stalled" : "model failing";
  const causeTo = crew.cause === "worker" ? "/health/jobs" : "/health/crew";

  return (
    <Popover
      label="Crew"
      align="end"
      trigger={(props) => (
        <button {...props} type="button" className="sh-shell__crew" data-state={state} aria-label={down ? "Crew down" : `Crew ${said}`}>
          {faces.length ? (
            <AvatarStack who={faces} max={3} size={16} tip={false} />
          ) : (
            <Mark tone={down ? "bad" : "idle"} />
          )}
          <span className="max-md:hidden">{word}</span>
        </button>
      )}
    >
      {(close) => (
        <div className="sh-menu" role="presentation">
          {down ? (
            <Link className="sh-menu__item" to={causeTo}>
              <Mark tone="bad" />
              <span className="sh-menu__text">{cause}</span>
            </Link>
          ) : null}
          {asking && !presence.roles.some((r) => r.who.key === MANAGER.key) ? (
            <button
              type="button"
              className="sh-menu__item"
              onClick={() => {
                close();
                openChat();
              }}
            >
              <Avatar who={MANAGER} size={16} presence="working" tip={false} />
              <span className="sh-menu__text">{MANAGER.name}</span>
              <span className="sh-mono sh-menu__meta">answering</span>
            </button>
          ) : null}
          {presence.roles.map((role) => (
            <Link key={role.who.key} className="sh-menu__item" to={`/cases/${role.caseUid}?tab=discussion`}>
              <Avatar who={role.who} size={16} presence="working" tip={false} />
              <span className="sh-menu__text">{role.who.name}</span>
              <span className="sh-mono sh-menu__meta">{shortId(role.caseUid)}</span>
              {role.kind ? <span className="sh-mono sh-menu__meta">{role.kind}</span> : null}
              <span className="sh-menu__kbd">{age(new Date(role.at).toISOString(), Math.max(now, Date.now()))}</span>
            </Link>
          ))}
          {down || asking || presence.roles.length ? <hr className="sh-menu__sep" /> : null}
          <Link className="sh-menu__item" to="/health/crew">
            <span className="sh-menu__text">Health › Crew</span>
          </Link>
        </div>
      )}
    </Popover>
  );
}

/**
 * Health's own state word and tone (`usePipeline`) and the newest event's age;
 * never "degraded" on a failed call. Live updates are said in the label only:
 * their banner is their home.
 */
function HealthPill() {
  const { health, state, queries } = usePipeline();
  const stream = useStreamStatus();
  const now = useNow();
  const data = health.data;
  const failed = queries.find((q) => q.isLoadingError);

  let tone: StatusTone;
  let pipeline: string;
  if (failed || !state) {
    tone = "idle";
    pipeline = failed
      ? failed.error instanceof ApiError && failed.error.isAuth
        ? "unknown, token refused"
        : "unknown"
      : "loading";
  } else {
    tone = state.tone;
    pipeline = state.word.toLowerCase();
  }
  const latest = data?.store.latest_event ?? null;
  // A failed refresh keeps the last answer, as Health does, and says how old it is.
  const asOf = staleSince(health);
  const shown = !data ? (health.isError ? "—" : "…") : latest ? age(latest, Math.max(now, Date.now())) : "—";
  const said = `Pipeline ${pipeline}${latest && data ? `, last event ${shown} ago` : ""}${asOf ? `, as of ${clock(asOf)}` : ""}${
    stream.state === "live" ? ", live" : stream.state === "retrying" ? ", reconnecting" : stream.state === "connecting" ? "" : ", live updates paused"
  }`;

  return (
    <Tip label={said}>
      <Link to="/health" className="sh-shell__health" aria-label={said} data-stale={asOf ? "" : undefined}>
        <Status tone={tone} label={pipeline}>
          <span className="max-md:hidden tabular">{shown}</span>
        </Status>
      </Link>
    </Tip>
  );
}
