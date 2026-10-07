/**
 * The case as a picture, above the tabs whatever tab is open: the ATT&CK
 * tactics it touched, who touched what (from → who → key or session → account
 * → touched, ringed by finding severity and by what the response did, with
 * earlier cases on a shared entity as dashed ghosts), and every moment on one
 * time bar whose empty hours shrink. Pointing lights the same events in the
 * strip, the graph, the bar and the timeline; brushing the bar hides timeline
 * rows outside the range and dims the graph, and Escape or a double-click
 * clears it. Only the heaviest edge between two lanes carries its label. The
 * busiest lane sets the graph's height, six nodes a lane and then "+N". A
 * node opens EntityDialog in the case's context, where Extend timeline lives.
 *
 * Capabilities used: none of its own; it draws `timeline.build`, `case.get`,
 * `action.list` and `case.history`.
 */
import { useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Graph, type Ring } from "@/components/ui/graph";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { Tactics } from "@/components/ui/tactics";
import { TimeBar, type TimeMark } from "@/components/ui/timebar";
import { citeLabel, type Cites } from "@/lib/cite";
import { useCommand } from "@/lib/commands";
import { who } from "@/lib/crew";
import { bare } from "@/lib/entity";
import { shortId } from "@/lib/format";
import { actionLabel, actionState, verdictLabel } from "@/lib/labels";
import { usePopParam } from "@/lib/popup";
import { attackGraph, LANE_LABELS, type Node } from "@/lib/story";
import type { Action, CaseHistoryRow, CaseRecord, TimelineResult } from "@/types";
import { brush, clearRange, lit, point, useBrush, within } from "./brush";
import { firstContainment, momentUids, type CaseMoment, type Open } from "./moments";

type Lane = "ip" | "user" | "key" | "session" | "account" | "resource";
type StoryNode = Omit<Node, "kind"> & { kind: string; lane: Lane; ghost?: string; more?: number };
type StoryEdge = { src: string; dst: string; weight: number; label: string };

const LANE_HEAD: Record<Lane, string> = { ...LANE_LABELS, session: "SESSION" };
const SEVERITY_RING = new Set(["critical", "high", "medium"]);
const GHOSTS = 5;
/** Nodes a lane draws before its "+N" stub, and the height each row needs for its box and label. */
const PER_LANE = 6;
const ROW = 44;
/** An edge label longer than this sits on the node labels beside it. */
const EDGE_CHARS = 16;

/** "NODE.UPDATE.MACHI… ×3": the operation cut, the count kept. */
function shortEdge(label: string) {
  const [, op = label, times = ""] = /^(.*?)( ×\d+)?$/.exec(label) ?? [];
  return op.length > EDGE_CHARS ? `${op.slice(0, EDGE_CHARS - 1)}…${times}` : label;
}

/** The graph's nodes and edges, with earlier cases attached as ghosts to the entity they share. */
function story(data: CaseRecord, events: TimelineResult["events"], actions: Action[], history: CaseHistoryRow[]) {
  // case.get's findings carry no entity of their own; they name the case's.
  const findings = data.findings.map((f) => ({ ...f, entity_key: data.case.entity_key }));
  const graph = attackGraph(events, findings, actions);
  const keyLane: Lane = graph.keyLane === "KEY" ? "key" : "session";
  const nodes: StoryNode[] = graph.nodes.map((n) => ({ ...n, lane: n.kind === "key" ? keyLane : n.kind, kind: n.kind === "key" ? keyLane : n.kind }));
  // One label per pair of lanes, on its heaviest edge: more pile up over the nodes.
  const laneOf = new Map(nodes.map((n) => [n.id, n.lane]));
  const pair = (e: { src: string; dst: string }) => `${laneOf.get(e.src)}>${laneOf.get(e.dst)}`;
  const heaviest = new Map<string, { weight: number }>();
  for (const e of graph.edges) if (e.weight > (heaviest.get(pair(e))?.weight ?? -1)) heaviest.set(pair(e), e);
  const edges: StoryEdge[] = graph.edges.map((e) => ({
    src: e.src,
    dst: e.dst,
    weight: e.weight,
    label: heaviest.get(pair(e)) === e ? shortEdge(e.label) : "",
  }));

  const ghosts = history.flatMap((row) => {
    const at = nodes.find((n) => !n.ghost && row.shared.some((key) => bare(key) === n.label));
    return at ? [{ row, at }] : [];
  });
  for (const { row, at } of ghosts.slice(0, GHOSTS)) {
    const id = `case:${row.case_uid}`;
    nodes.push({ id, kind: "case", lane: at.lane, label: `${verdictLabel(row.verdict).glyph} ${shortId(row.case_uid)}`, events: 0, weight: 1, uids: [], ghost: row.case_uid });
    edges.push({ src: at.id, dst: id, weight: 1, label: "" });
  }
  if (ghosts.length > GHOSTS) {
    const at = ghosts[GHOSTS]!.at;
    nodes.push({ id: "case:more", kind: "case", lane: at.lane, label: `+${ghosts.length - GHOSTS}`, events: 0, weight: 1, uids: [], ghost: "more", more: ghosts.length - GHOSTS });
  }
  return { nodes, edges, lanes: ["ip", "user", keyLane, "account", "resource"] as Lane[] };
}

function ringOf(node: StoryNode): Ring | undefined {
  if (node.overlay) return node.overlay;
  return node.severity && SEVERITY_RING.has(node.severity) ? (node.severity as Ring) : undefined;
}

export function Story({
  data,
  timeline,
  timelineError,
  onRetry,
  actions,
  history,
  moments,
  cites,
  open,
}: {
  data: CaseRecord;
  timeline?: TimelineResult;
  timelineError: unknown;
  onRetry: () => void;
  actions: Action[];
  history: CaseHistoryRow[];
  /** The timeline's moments, drawn as marks. */
  moments: CaseMoment[];
  cites: Cites;
  open: Open;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const openEntity = usePopParam("entity", ["view"]);
  const brushed = useBrush();
  // A page opened from here comes back here on Escape.
  const back = { state: { back: `${location.pathname}${location.search}` } };
  const [more, setMore] = useState<string[] | null>(null);
  useCommand("shell.escape", clearRange, Boolean(brushed.range));
  const record = data.case;
  const events = timeline?.events ?? [];

  const { nodes, edges, lanes } = story(data, events, actions, history);
  // The busiest lane sets the height, so no box sits on the label above it.
  const busiest = Math.max(0, ...lanes.map((lane) => nodes.filter((n) => n.lane === lane).length));
  const rows = Math.min(busiest, PER_LANE) + (busiest > PER_LANE ? 1 : 0);
  const height = Math.max(240, 20 + ROW * rows);
  const time = new Map(events.map((e) => [e.event_uid, e.time]));
  const lighted = nodes
    .filter((n) =>
      brushed.point.length ? lit(brushed, n.uids) : brushed.range ? n.uids.some((uid) => within(brushed, time.get(uid) ?? "")) : false,
    )
    .map((n) => n.id);
  const rings: Record<string, Ring> = {};
  for (const n of nodes) {
    const ring = ringOf(n);
    if (ring) rings[n.id] = ring;
  }

  const openNode = (node: StoryNode) => {
    if (node.ghost === "more") return navigate(`/cases?on=${encodeURIComponent(record.entity_key)}`);
    if (node.ghost) return navigate(`/cases/${node.ghost}`, back);
    // A session id is not an AWS key: it opens as a bare value.
    const entity = node.kind === "session" ? node.label : `${node.kind}:${node.label}`;
    openEntity(entity);
  };

  // The bar draws the timeline's own moments (a burst is one mark), so both tell one story.
  const first = firstContainment(actions);
  const byKey = new Map(moments.map((m) => [m.key, m]));
  const marks = moments.flatMap((m): TimeMark[] => {
    const hl = lit(brushed, momentUids(m));
    switch (m.type) {
      case "event": {
        const n = m.event.cited ? cites.of(m.event.event_uid) : undefined;
        const what = m.event.api_operation ?? m.event.activity_name ?? "event";
        const label = n ? `${citeLabel(n)} ${what}` : m.count > 1 ? `${what} ×${m.count}` : what;
        // Cited events in the second ink, the rest muted.
        return [{ key: m.key, at: m.at, kind: "event", tone: m.event.cited ? "plain" : "muted", label, hl }];
      }
      case "finding":
        return [{ key: m.key, at: m.at, kind: "finding", tone: m.finding.severity, label: m.finding.title, hl }];
      case "decision":
        return [{ key: m.key, at: m.at, kind: "decision", tone: "crew", label: `${who(m.message.agent).name} decided`, hl }];
      case "action": {
        const a = m.action;
        if (!a.executed_at) return [];
        const tone = a.state === "failed" ? "bad" : a.state === "rolled_back" || a.dry_run ? "idle" : "good";
        return [{ key: m.key, at: m.at, kind: "action", tone, label: `${actionLabel(a.type)} ${actionState(a).word}` }];
      }
      case "case":
        return [{ key: m.key, at: m.at, kind: "case", tone: m.what === "opened" ? record.severity : "idle", label: `Case ${m.what}` }];
    }
  });
  // The bar spans the marks themselves; the timeline's margin hours would only add empty edges.
  const times = marks.map((m) => Date.parse(m.at)).filter(Number.isFinite);
  const from = new Date(Math.min(...times) - 1000).toISOString();
  const to = new Date(Math.max(...times) + 1000).toISOString();
  const range = brushed.range
    ? { from: new Date(brushed.range.from).toISOString(), to: new Date(brushed.range.to).toISOString() }
    : null;
  const eventList = moments.flatMap((m) => (m.type === "event" ? [m.event.event_uid] : []));
  const decisions = moments.flatMap((m) => (m.type === "decision" ? [m.message.msg_id] : []));

  const pick = (mark: TimeMark) => {
    const m = byKey.get(mark.key);
    if (m?.type === "event") open.event(m.event.event_uid, eventList);
    else if (m?.type === "finding") navigate(`/findings/${m.finding.finding_uid}`, back);
    else if (m?.type === "decision") open.message(m.message.msg_id, decisions);
    else if (m?.type === "action") open.action(m.action);
  };
  const pointMark = (key: string | null) => {
    const m = key ? byKey.get(key) : undefined;
    point(m ? momentUids(m) : null);
  };

  let picture: ReactNode;
  if (timelineError && !timeline) picture = <ErrorNote error={timelineError} onRetry={onRetry} inline />;
  else if (!timeline) picture = <Skel kind="block" className="!h-[240px]" />;
  else if (!events.length) picture = <Empty title="No events stored for this case" />;
  else
    picture = (
      <Graph<StoryNode, StoryEdge>
        nodes={nodes}
        edges={edges}
        layout="layered"
        height={height}
        perLane={PER_LANE}
        lanes={lanes}
        laneOf={(n) => n.lane}
        laneLabel={(lane) => LANE_HEAD[lane as Lane] ?? lane.toUpperCase()}
        focus={nodes.find((n) => n.label === bare(record.entity_key))?.id}
        rings={rings}
        ghost={(n) => Boolean(n.ghost)}
        highlight={lighted}
        // A brushed range with no event in it dims every node.
        dimmed={Boolean(brushed.range) && !brushed.point.length}
        onPoint={(id) => point(id ? (nodes.find((n) => n.id === id)?.uids ?? null) : null)}
        onOpen={openNode}
        onMore={setMore}
        name={(n) => (n.ghost ? `case ${n.label}` : `${LANE_HEAD[n.lane].toLowerCase()} ${n.label}, ${n.events} events`)}
        label="Who touched what"
      />
    );

  return (
    <Card className="flex flex-col gap-3 p-3">
      <div className="overflow-x-auto scrollbar-thin">
        <Tactics techniques={record.attack} named />
      </div>
      {picture}
      <TimeBar
        from={from}
        to={to}
        marks={marks}
        compress
        responseGap={first ? { from: record.opened_at, to: first.executed_at! } : null}
        onPick={pick}
        onPoint={pointMark}
        brush={range}
        onBrush={brush}
        label="Case time bar"
      />
      {more ? (
        <Dialog title="More entities" head={<span className="sh-mono">{more.length}</span>} onClose={() => setMore(null)} size="sm">
          <div className="flex flex-wrap gap-2">
            {more.map((id) => {
              const node = nodes.find((n) => n.id === id);
              if (!node) return null;
              const value = node.kind === "session" ? node.label : `${node.kind}:${node.label}`;
              return <Entity key={id} value={value} onOpen={() => (setMore(null), openNode(node))} />;
            })}
          </div>
        </Dialog>
      ) : null}
    </Card>
  );
}
