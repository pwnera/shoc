/**
 * The frame: the brand cell over the rail, a 48px top bar, one banner when one
 * applies, and the page. It mounts the one keydown listener (`lib/commands.ts`),
 * the live stream, the visit heartbeat, the tab's title and icon, and the
 * dialogs four URL parameters open over any screen: `?decide=`, `?action=`
 * (`&do=undo`), `?event=` and `?entity=` (`&view=`). Floating layers: the
 * palette, the crew chat bottom-right, toasts bottom-left and, under 768px,
 * the bottom bar and the ≡ drawer. A new page takes focus at its heading when
 * nothing else holds it, so the next Tab starts on the page.
 *
 * Capabilities used: health.status, ops.alerts and stream.tail via SSE; the
 * dialogs, palette and chat name their own.
 */
import { Suspense, useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";
import { toggleChat, toggleWide } from "@/lib/chat";
import { paletteLabel, recordOf, useAsking, useCommand, useKeys, useRememberRecent } from "@/lib/commands";
import { shortId } from "@/lib/format";
import { useLive } from "@/lib/live";
import { jobWord } from "@/lib/labels";
import { place } from "@/lib/nav";
import { useCrewDown } from "@/lib/needs";
import { closeParams, useClaimed, useTrail } from "@/lib/popup";
import { useHealth, usePrefetchRules } from "@/lib/reads";
import { useHeartbeat } from "@/lib/since";
import { retryNow, useStreamState, useStreamStatus } from "@/lib/stream";
import { useFavicon, useShellTitle } from "@/lib/title";
import { lazyNamed } from "@/lib/stale";
import { lastUndoable } from "@/lib/toast";
import { ApiError, recheck, setUnreachable, useSignedOut } from "@/lib/api";
import { browser, loginHere } from "@/lib/signin";
import { BottomBar } from "./BottomBar";
import { ChatPanel } from "./Chat";
import { ErrorBoundary } from "./ErrorBoundary";
import type { PaletteMode } from "./Palette";
import { Rail } from "./Rail";
import { Toaster } from "./Toaster";
import { TopBar } from "./TopBar";
import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Announcer } from "./ui/misc";
import { Confirm } from "./ui/pop";
import { AutonomyBadge, Banner } from "./ui/status";

const RAIL = "shoc.rail";

// The deep-link dialogs load on first use, so the main chunk holds only what every screen draws.
const ActionDialog = lazyNamed(() => import("./ActionDialog"), "ActionDialog");
const ApprovalDialog = lazyNamed(() => import("./ApprovalDialog"), "ApprovalDialog");
const EntityDialog = lazyNamed(() => import("./EntityDialog"), "EntityDialog");
const EventDialog = lazyNamed(() => import("./EventDialog"), "EventDialog");
// The palette and its command table load on the first ⌘K.
const Palette = lazyNamed(() => import("./Palette"), "Palette");

function storedRail(): boolean {
  try {
    return localStorage.getItem(RAIL) === "collapsed";
  } catch {
    return false;
  }
}

/** The tab's name from the path: a record page's short id, else the screen. */
function screenOf(pathname: string): string {
  const record = recordOf(pathname);
  if (record) return record.kind === "case" || record.kind === "finding" ? shortId(record.id) : record.id;
  return place(pathname)?.screen ?? "";
}

export function Shell({ children }: { children: ReactNode }) {
  useLive();
  useKeys();
  useHeartbeat();
  useFavicon();
  useRememberRecent();
  useTrail();
  usePrefetchRules();
  const location = useLocation();
  const navigate = useNavigate();
  useShellTitle(screenOf(location.pathname));

  const [collapsed, setCollapsed] = useState(storedRail);
  const [palette, setPalette] = useState<PaletteMode | null>(null);
  const [drawer, setDrawer] = useState(false);

  const collapse = () =>
    setCollapsed((was) => {
      try {
        localStorage.setItem(RAIL, was ? "open" : "collapsed");
      } catch {
        /* kept for this page */
      }
      return !was;
    });

  useCommand("shell.palette", () => setPalette((open) => (open ? null : "all")));
  useCommand("shell.keys", () => setPalette("keys"));
  useCommand("shell.chat", toggleChat);
  useCommand("shell.chat-wide", toggleWide);
  useCommand("shell.rail", collapse);
  useCommand("shell.undo", () => {
    const uid = lastUndoable();
    if (!uid) return;
    const params = new URLSearchParams(location.search);
    params.set("action", uid);
    params.set("do", "undo");
    navigate({ search: `?${params.toString()}` });
  });

  // The drawer closes once a screen is picked.
  useEffect(() => setDrawer(false), [location.pathname]);

  // A row that opened this page has gone, so focus fell to the body: the new page's heading takes it, once the
  // screen's chunk has drawn one. A list handing focus back to its row, a dialog, or a control that kept focus wins.
  // For two seconds a heading that took focus and was then replaced (a loading page's, then the record's) hands it
  // to the new one.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    let frame = 0;
    let tries = 0;
    const settle = () => {
      const held = document.activeElement;
      if (document.querySelector("dialog[open]")) return;
      if (held && held !== document.body && !held.matches(".sh-page__title")) return;
      const title = document.querySelector<HTMLElement>("main .sh-page__title");
      if (title && held !== title) title.focus({ preventScroll: true });
      if (tries++ < 120) frame = requestAnimationFrame(settle);
    };
    frame = requestAnimationFrame(settle);
    return () => cancelAnimationFrame(frame);
  }, [location.pathname]);

  return (
    <div className={cn("sh-shell", collapsed && "sh-shell--collapsed")}>
      <a className="sh-skip" href="#main">
        Skip to content
      </a>
      {/* Decorative: the document title already says shoc. */}
      <div className="sh-shell__brand" aria-hidden>
        <img src="/favicon.svg" alt="" />
        <span>shoc</span>
      </div>
      <TopBar onMenu={() => setDrawer(true)} onSearch={() => setPalette("all")} onKeys={() => setPalette("keys")} />
      <aside className="sh-shell__rail">
        <Rail collapsed={collapsed} onCollapse={collapse} />
      </aside>
      <Banners />
      <main id="main" tabIndex={-1} className="sh-shell__page">
        {/* A record page remounts per record, so no state leaks from one case into the next; Health's tabs are
            paths of one screen, so moving between them keeps it mounted and its queries warm. */}
        <ErrorBoundary key={location.pathname.replace(/^\/health\/.*/, "/health")} resetKey={location.pathname}>
          {children}
        </ErrorBoundary>
      </main>
      {/* The bar first, so the chat sheet rises over it on a phone. */}
      <BottomBar onSearch={() => setPalette("all")} />
      <ErrorBoundary quiet resetKey={location.pathname}>
        <ChatPanel />
      </ErrorBoundary>
      <Toaster />
      {drawer ? <Drawer onClose={() => setDrawer(false)} /> : null}
      {palette ? (
        <ErrorBoundary quiet>
          <Suspense fallback={null}>
            <Palette mode={palette} onClose={() => setPalette(null)} />
          </Suspense>
        </ErrorBoundary>
      ) : null}
      <ErrorBoundary quiet resetKey={location.search}>
        <DeepLinks />
      </ErrorBoundary>
      <LinkConfirm />
    </div>
  );
}

/** A `?do=` that writes or spends, from a link or the palette: one confirm before the screen's handler runs. */
function LinkConfirm() {
  const [asking, done] = useAsking();
  if (!asking) return null;
  const { command, run } = asking;
  return (
    <Dialog title="Confirm" size="sm" onClose={done}>
      <Confirm
        inline
        what={paletteLabel(command)}
        facts={command.level ? <AutonomyBadge level={command.level} /> : undefined}
        go="Run"
        onConfirm={() => {
          done();
          run();
        }}
        onCancel={done}
      />
    </Dialog>
  );
}

/** The rail as a modal sheet from the left, under 768px. */
function Drawer({ onClose }: { onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (ref.current && !ref.current.open) ref.current.showModal?.();
  }, []);
  return (
    <dialog
      ref={ref}
      className="sh-drawer"
      aria-label="Screens"
      onClose={(event) => event.target === event.currentTarget && onClose()}
      onClick={(event) => event.target === ref.current && onClose()}
    >
      <div className="sh-drawer__brand">
        <img src="/favicon.svg" alt="" />
        <span>shoc</span>
        <Button variant="ghost" size="icon" className="ml-auto" onClick={() => ref.current?.close()} aria-label="Close">
          <X aria-hidden />
        </Button>
      </div>
      <Rail onPick={onClose} />
      <Announcer />
    </dialog>
  );
}

/** One banner at a time, by priority: signed out, shoc unreachable, store, crew, live updates. */
function Banners() {
  const signedOut = useSignedOut();
  const health = useHealth();
  const crew = useCrewDown();
  const stream = useStreamStatus();
  const { pathname } = useLocation();
  const [dismissed, setDismissed] = useState(() => {
    try {
      return sessionStorage.getItem("shoc.banner.crew") ?? "";
    } catch {
      return "";
    }
  });
  const crewKey = crew.down ? `${crew.cause}:${crew.overdue.join(",")}` : "";
  // shoc itself is down: health.status failed at the network with nothing cached. One banner, not an error per panel.
  const down = !signedOut && health.isError && !health.data && health.error instanceof ApiError && health.error.isNetwork;
  useEffect(() => setUnreachable(down), [down]);
  // Signed in again in another tab: coming back to this one looks once more.
  useEffect(() => {
    if (!signedOut) return;
    const look = () => {
      if (document.visibilityState === "visible") void recheck();
    };
    window.addEventListener("focus", look);
    document.addEventListener("visibilitychange", look);
    return () => {
      window.removeEventListener("focus", look);
      document.removeEventListener("visibilitychange", look);
    };
  }, [signedOut]);
  const client = useQueryClient();

  let banner: ReactNode = null;
  if (signedOut)
    banner = (
      <Banner
        tone="bad"
        action={
          <button type="button" className="sh-banner__action" onClick={() => void recheck().then((back) => back || browser.assign(loginHere()))}>
            Log in
          </button>
        }
      >
        Signed out
      </Banner>
    );
  else if (down)
    banner = (
      <Banner
        tone="bad"
        action={
          <button
            type="button"
            className="sh-banner__action"
            onClick={() => {
              void client.refetchQueries({ type: "active" });
              retryNow();
            }}
          >
            Retry
          </button>
        }
      >
        Can't reach shoc
      </Banner>
    );
  else if (health.data?.store.ok === false)
    banner = (
      <Banner tone="bad" action={<Link className="sh-banner__action" to="/health">Health</Link>}>
        Event store unreachable
      </Banner>
    );
  // Overview says "Crew down" in its own heading, and Health is the fact's home.
  else if (crew.down && pathname !== "/" && !pathname.startsWith("/health") && dismissed !== crewKey)
    banner = (
      <Banner
        tone="bad"
        // A standing fact that returns with every screen: said politely, not as an interruption each time.
        role="status"
        action={
          <Link className="sh-banner__action" to={crew.cause === "worker" ? "/health/jobs" : "/health/crew"}>
            {crew.cause === "worker" ? "Health › Jobs" : "Health › Crew"}
          </Link>
        }
        onClose={() => {
          setDismissed(crewKey);
          try {
            sessionStorage.setItem("shoc.banner.crew", crewKey);
          } catch {
            /* dismissed for this page */
          }
        }}
      >
        {crew.cause === "worker" ? `Worker stalled: ${crew.overdue.map(jobWord).join(", ")}` : "Crew can't reach its model"}
      </Banner>
    );
  else if (stream.state === "offline" && health.isSuccess)
    banner = (
      <Banner
        action={
          <button type="button" className="sh-banner__action" onClick={retryNow}>
            Retry now
          </button>
        }
      >
        Live updates paused
        {/* The countdown ticks each second; the status region announces the sentence once. */}
        <span aria-hidden>
          <RetryIn />
        </span>
      </Banner>
    );

  return (
    <>
      {banner ? <div className="sh-shell__banner">{banner}</div> : null}
    </>
  );
}

/** " · retrying in 12s", counted down each second while the banner shows. */
function RetryIn() {
  const { retryAt } = useStreamState();
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return retryAt ? <> · retrying in {Math.max(0, Math.round((retryAt - now) / 1000))}s</> : null;
}

/**
 * The four parameters any screen answers with a dialog; closing one goes back
 * over the entry that opened it (`closeParams`). A case page focuses its own
 * decision bar for `decide`, Explore steps through its own rows for `event`,
 * and a screen that claims a parameter (`useClaim`) opens it itself.
 */
function DeepLinks() {
  const [params, setParams] = useSearchParams();
  const { pathname, state } = useLocation();
  const navigate = useNavigate();
  const claimed = useClaimed();
  const own = (name: string) => (claimed.includes(name) ? null : params.get(name));
  const casePage = /^\/cases\/[^/]+$/.test(pathname);
  const decide = casePage ? null : own("decide");
  const action = own("action");
  const event = pathname === "/explore" ? null : own("event");
  const entity = own("entity");
  const undo = params.get("do") === "undo";

  // From the live URL, not the render's: two dialogs closed in one tick (one
  // Escape can close a stack the browser opened together) each drop their own.
  // A replace keeps the router state, so a list's `back` survives a view change.
  const edit = (change: (out: URLSearchParams) => void, replace = false) => {
    const out = new URLSearchParams(window.location.search);
    change(out);
    setParams(out, replace ? { replace, state } : {});
  };
  // Back over the entry the opening pushed, so the list is in history once; a link's dialog drops its parameter in place.
  const drop = (...names: string[]) => closeParams(names, navigate);

  // `do=undo` is a one-shot: ActionDialog opens its confirm, the URL forgets it.
  useEffect(() => {
    if (undo && action) edit((out) => out.delete("do"), true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [undo, action]);
  const [undoFor, setUndoFor] = useState<string | null>(null);
  if (undo && action && undoFor !== action) setUndoFor(action);

  return (
    <Suspense fallback={null}>
      {entity ? (
        <EntityDialog
          key={entity}
          entity={entity}
          view={params.get("view") ?? undefined}
          onView={(view) => edit((out) => out.set("view", view), true)}
          onClose={() => drop("entity", "view")}
        />
      ) : null}
      {event ? <EventDialog key={event} uid={event} onClose={() => drop("event")} /> : null}
      {action ? (
        <ActionDialog
          key={action}
          uid={action}
          undo={undoFor === action}
          onClose={() => {
            setUndoFor(null);
            drop("action", "do");
          }}
          onDecide={(uid) =>
            edit((out) => {
              out.delete("action");
              out.set("decide", uid);
            })
          }
        />
      ) : null}
      {decide ? <ApprovalDialog key={decide} uid={decide} onClose={() => drop("decide")} /> : null}
    </Suspense>
  );
}
