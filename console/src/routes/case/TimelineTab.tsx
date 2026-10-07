/**
 * The case's moments in order, in a bounded box with sticky day rows: events
 * (cited ones carry their E-number, a burst of the same uncited call reads
 * ×N), findings, crew decisions, actions, the case opening and closing. A
 * "new" hairline marks the first moment since this viewer's last visit. A
 * brushed range on the time bar shows as a chip that clears it. A row opens
 * its record: an event steps through the visible events, a finding opens its
 * page, a decision the message (stepping through the visible decisions), an
 * action ActionDialog; the case opening and closing only mark the axis. Until
 * the events and actions the view shows have landed, skeleton rows stand in,
 * so rows already placed never move down. A failed load says so in the
 * toolbar (the story card above holds Retry).
 *
 * Capabilities used: none of its own (`timeline.build`, `case.get`,
 * `action.list`, read by the page).
 */
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { X } from "lucide-react";
import { ConfidenceBar, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CardToolbar } from "@/components/ui/card";
import { Empty } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { Skel } from "@/components/ui/state";
import { Timeline, type Moment, type MomentDot } from "@/components/ui/timeline";
import { citeLabel, type Cites } from "@/lib/cite";
import { useListNav } from "@/lib/commands";
import { useFollow } from "@/lib/popup";
import { num, span, time } from "@/lib/format";
import { actionLabel } from "@/lib/labels";
import { useParam } from "@/lib/param";
import type { Action, TimelineResult } from "@/types";
import { clearRange, lit, point, useBrush, within } from "./brush";
import { firstContainment, momentUids, showsIn, type CaseMoment, type MomentFilter, type Open } from "./moments";
import { ActionStatus } from "./ResponseTab";

const FILTERS: { value: MomentFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "events", label: "Events" },
  { value: "findings", label: "Findings" },
  { value: "crew", label: "Crew" },
  { value: "actions", label: "Actions" },
];

const ACTION_DOT: Partial<Record<Action["state"], MomentDot>> = { done: "done", failed: "failed", rolled_back: "undone" };

function row(m: CaseMoment, cites: Cites): Omit<Moment, "key" | "at"> {
  switch (m.type) {
    case "event": {
      const n = m.event.cited ? cites.of(m.event.event_uid) : undefined;
      return {
        dot: m.event.extended ? "extended" : m.event.cited ? "cited" : "event",
        what: (
          <span className={m.event.cited ? "text-fg-1" : "text-fg-3"}>
            {m.event.api_operation ?? m.event.activity_name ?? "event"}
            {m.event.actor_user_name ? <span className="sh-mono text-fg-4"> {m.event.actor_user_name}</span> : null}
          </span>
        ),
        count: m.count,
        end: n ? <span className="sh-cite">{citeLabel(n)}</span> : m.count > 1 ? <span className="sh-mono text-fg-4">{span(m.lasted)}</span> : null,
      };
    }
    case "finding":
      return { dot: "finding", tone: m.finding.severity, what: m.finding.title, end: <SeverityBadge severity={m.finding.severity} /> };
    case "decision":
      return {
        dot: "crew",
        who: m.message.agent,
        what: "decided",
        end: m.message.confidence !== null ? <ConfidenceBar value={m.message.confidence} /> : null,
      };
    case "action":
      return {
        dot: m.action.dry_run && m.action.state === "done" ? "undone" : (ACTION_DOT[m.action.state] ?? "system"),
        who: m.action.requested_by,
        what: actionLabel(m.action.type),
        end: <ActionStatus action={m.action} />,
      };
    case "case":
      return { dot: "system", what: m.what === "opened" ? "Case opened" : "Case closed" };
  }
}

export function TimelineTab({
  moments,
  cites,
  timeline,
  timelineError,
  actions,
  actionsPending,
  actionsError,
  openedAt,
  newAfter,
  open,
}: {
  moments: CaseMoment[];
  cites: Cites;
  timeline?: TimelineResult;
  timelineError: unknown;
  actions: Action[];
  actionsPending: boolean;
  /** `action.list` failed: its moments are missing. */
  actionsError: unknown;
  openedAt: string;
  newAfter: string | null;
  open: Open;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const brushed = useBrush();
  const [filter, setFilter] = useParam<MomentFilter>("show", "all");
  const shown = moments.filter((m) => showsIn(m, filter) && within(brushed, m.at));
  const events = shown.flatMap((m) => (m.type === "event" ? [m.event.event_uid] : []));
  const decisions = shown.flatMap((m) => (m.type === "decision" ? [m.message.msg_id] : []));
  const first = firstContainment(actions);

  const openMoment = (m: CaseMoment) => {
    if (m.type === "event") open.event(m.event.event_uid, events);
    else if (m.type === "finding")
      navigate(`/findings/${m.finding.finding_uid}`, { state: { back: `${location.pathname}${location.search}` } });
    else if (m.type === "decision") open.message(m.message.msg_id, decisions);
    else if (m.type === "action") open.action(m.action);
  };
  const nav = useListNav(
    shown.filter((m) => m.type !== "case"),
    (m) => m.key,
    { onOpen: openMoment },
  );
  // J and K in the event or action dialog move the active row with them, so Escape lands on the row it ended on.
  const [params] = useSearchParams();
  const ev = params.get("event");
  const act = params.get("action");
  const followed = shown.find(
    (m) => (m.type === "event" && m.event.event_uid === ev) || (m.type === "action" && m.action.action_uid === act),
  );
  useFollow(nav, followed?.key ?? "");
  const byKey = new Map(shown.map((m) => [m.key, m]));

  const rows: Moment[] = shown.map((m) => ({
    key: m.key,
    at: m.at,
    ...row(m, cites),
    active: m.key === nav.activeKey,
    hl: lit(brushed, momentUids(m)),
  }));
  const waiting =
    (!timeline && !timelineError && (filter === "all" || filter === "events")) ||
    (actionsPending && (filter === "all" || filter === "actions"));
  const range = brushed.range;

  return (
    <>
      <CardToolbar>
        <Seg<MomentFilter> label="Show" value={filter} options={FILTERS} onChange={setFilter} />
        {range ? (
          <button type="button" className="sh-chip" onClick={clearRange} aria-label="Clear the time range">
            <span className="sh-chip__value">
              {time(new Date(range.from).toISOString()).slice(0, 5)}–{time(new Date(range.to).toISOString()).slice(0, 5)}
            </span>
            <X className="h-3 w-3" aria-hidden />
          </button>
        ) : null}
        {timeline?.truncated ? <span className="sh-mono text-fg-4">first {num(timeline.limit)} events in the window</span> : null}
        {timelineError && !timeline ? <span className="sh-mono text-warn">events not loaded</span> : null}
        {actionsError ? <span className="sh-mono text-warn">actions not loaded</span> : null}
      </CardToolbar>
      <div className="max-h-[min(36rem,60vh)] overflow-y-auto px-2 py-1 scrollbar-thin">
        {waiting ? null : (
          <Timeline
            moments={rows}
            newAfter={newAfter}
            responseGap={first ? { from: openedAt, to: first.executed_at! } : null}
            rowProps={(moment) => {
              const m = byKey.get(moment.key)!;
              // The case opening and closing open nothing: a static mark, out of the keys' reach.
              if (m.type === "case") return { disabled: true, className: "sh-tl__row !cursor-default hover:!bg-transparent" };
              const uids = momentUids(m);
              const props = nav.rowProps(m) as Record<string, unknown> & { onFocus: () => void };
              // Hover and focus point at the row's events everywhere on the page.
              return {
                ...props,
                onFocus: () => (props.onFocus(), point(uids)),
                onBlur: () => point(null),
                onMouseEnter: () => point(uids),
                onMouseLeave: () => point(null),
              };
            }}
            label="Timeline"
          />
        )}
        {shown.length || waiting || (timelineError && !timeline) ? null : range ? (
          <Empty
            title="Nothing in this range"
            action={
              <Button variant="ghost" size="sm" onClick={clearRange}>
                Clear
              </Button>
            }
          />
        ) : (
          <Empty title="Nothing in this view" />
        )}
        {waiting ? (
          <div className="flex flex-col gap-3 py-3" aria-busy="true">
            <Skel kind="row" width="60%" />
            <Skel kind="row" width="45%" />
            <Skel kind="row" width="52%" />
          </div>
        ) : null}
      </div>
    </>
  );
}
