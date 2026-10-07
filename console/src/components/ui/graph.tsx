/**
 * A graph in SVG, laid out in pixels from a ResizeObserver so labels stay
 * 10px at any width. Layered (lanes of kinds: cases, findings, rules, reports)
 * or radial (a root and its hops: entities), from `lib/graph.ts`. Nodes are
 * 24px squares with their kind's glyph; a severity ring marks a node a
 * finding names, a response ring what was done to it, and `tone` edges a node
 * in a status or autonomy tone (a playbook step). A layered graph keeps 96px
 * a lane, so three lanes fit a 320px aside, and a box narrower than its lanes
 * scales the whole graph down rather than scrolling it sideways. Labels
 * shorten to the room between lanes, an id keeping its ends ("arn:…:acme-
 * backups", "AKIA…MPLE") and prose its start, with the full name in the tip.
 * An edge's label sits beside its line and gives way to any node or label it
 * would cover. Tab enters, arrows move to the nearest node that way, Enter
 * opens, Escape leaves the node for the graph and a second Escape the page.
 * Whatever a graph shows is also reachable as rows elsewhere, so a screen
 * reader loses nothing.
 */
import { useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import {
  Box,
  Building2,
  Circle,
  Crosshair,
  Database,
  GitBranch,
  Globe,
  KeyRound,
  Target,
  Ticket,
  User,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { middle } from "@/lib/format";
import { layered, radial, type GraphLink, type GraphNode } from "@/lib/graph";

const ICON: Record<string, LucideIcon> = {
  ip: Globe,
  user: User,
  key: KeyRound,
  account: Building2,
  resource: Database,
  repo: GitBranch,
  case: Box,
  rule: Crosshair,
  technique: Target,
  step: Zap,
  session: Ticket,
};

/** The narrowest a lane gets before the graph scrolls sideways (15 mono characters, an IPv4 address, fit), and the room under the bottom row for its labels. */
const LANE = 104;
const LABEL_ROOM = 14;
/** About one --text-micro character, for fitting a label between two lanes. */
const CHAR = 6;

export type Ring = "critical" | "high" | "medium" | "done" | "planned" | "undone" | "pending";

const SEVERITY_RING = new Set<Ring>(["critical", "high", "medium"]);

/**
 * A label cut to `room` characters. Prose keeps its start; an email its name;
 * an ARN or a path its first and last parts ("arn:…:acme-backups"); a key or
 * any other id both ends ("AKIA…MPLE"), the way an entity chip cuts it.
 */
function cut(text: string, room: number, kind: string): string {
  // An address is an indicator someone reads and types: it is never cut (its lane is wide enough for one).
  if (text.length <= room || kind === "ip") return text;
  if (/\s/.test(text)) return `${text.slice(0, room - 1)}…`;
  const keep = (n: number) => middle(text, Math.max(2, Math.min(n, Math.floor((room - 1) / 2))));
  if (kind === "key") return keep(4);
  const at = text.indexOf("@");
  if (at > 0 && at + 2 <= room) return `${text.slice(0, at + 1)}…`;
  const last = Math.max(text.lastIndexOf(":"), text.lastIndexOf("/"));
  const first = text.search(/[:/]/);
  if (last > 0) {
    const head = text.slice(0, first + 1);
    const tail = text.slice(last);
    if (first < last && head.length + tail.length + 1 <= room) return `${head}…${tail}`;
    if (tail.length < room) return `…${tail.slice(1)}`;
  }
  return keep(room);
}

type Box = { x0: number; y0: number; x1: number; y1: number };
const overlaps = (a: Box, b: Box) => a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

const DIRS: Record<string, readonly [number, number]> = {
  ArrowRight: [1, 0],
  ArrowLeft: [-1, 0],
  ArrowDown: [0, 1],
  ArrowUp: [0, -1],
};

export function Graph<N extends GraphNode, L extends GraphLink>({
  nodes,
  edges,
  layout,
  lanes = [],
  laneOf,
  laneLabel = (lane) => lane.toUpperCase(),
  root,
  focus,
  height = 240,
  perLane,
  onOpen,
  onMore,
  onPoint,
  highlight,
  dimmed,
  rings,
  tone,
  ghost,
  name,
  label,
}: {
  nodes: N[];
  edges: L[];
  layout: "layered" | "radial";
  /** Layered: the lanes, left to right. */
  lanes?: readonly string[];
  laneOf?: (node: N) => string;
  laneLabel?: (lane: string) => string;
  /** Radial: the centre. */
  root?: string;
  /** The root or the case's entity: a 2px ring. */
  focus?: string;
  height?: number;
  perLane?: number;
  onOpen?: (node: N) => void;
  /** A lane's "+N" stub: the ids it hides. */
  onMore?: (ids: string[]) => void;
  /** Hover or focus on a node, for brushing other views; null when it ends. */
  onPoint?: (id: string | null) => void;
  /** Lit nodes; the rest dim while any are lit. */
  highlight?: readonly string[];
  /** Dim every node not in `highlight`, even when none is lit (a brush that holds nothing). */
  dimmed?: boolean;
  rings?: Record<string, Ring>;
  /** A node's edge tone, as `data-tone` names it (a step's status or autonomy). */
  tone?: (node: N) => string | undefined;
  /** An earlier case on a shared entity: dashed. */
  ghost?: (node: N) => boolean;
  /** The node's accessible name ("user deploy-ci, 129 events"). */
  name?: (node: N) => string;
  label: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const svg = useRef<SVGSVGElement>(null);
  const [width, setWidth] = useState(0);
  const [hover, setHover] = useState<{ id: string; x: number; y: number } | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);

  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    setWidth(el.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const watch = new ResizeObserver(([entry]) => entry && setWidth(Math.round(entry.contentRect.width)));
    watch.observe(el);
    return () => watch.disconnect();
  }, []);

  // A lane with no node draws no head (a case with no key or session has no third lane).
  const filled = lanes.filter((lane) => nodes.some((n) => (laneOf ? laneOf(n) : n.kind) === lane));
  const w = Math.max(width, layout === "layered" ? filled.length * LANE : 240);
  // Narrower than its lanes (a phone, a slim aside): the graph scales to the box, but never below 0.8, so its 10px
  // labels stay readable; past that it scrolls sideways inside its own box.
  const scale = width > 0 && w > width ? Math.max(0.8, width / w) : 1;
  const top = layout === "layered" ? 16 : 0;
  // Room at the sides for the labels of the outer nodes, which centre on them.
  const side = 40;
  const placed =
    width === 0
      ? null
      : layout === "layered"
        ? layered(nodes, edges, { width: w - 2 * side, height: height - top - LABEL_ROOM, lanes: filled, laneOf, perLane })
        : radial(nodes, edges, { width: w - 2 * side, height, root: root ?? nodes[0]?.id ?? "", focus });
  // A layered label fits the room between two lanes; a radial one keeps 32 characters.
  const step = placed && placed.lanes.length > 1 ? placed.lanes[1]!.x - placed.lanes[0]!.x : Infinity;
  const fits = Math.max(6, Math.min(32, Math.floor((step - 8) / CHAR)));
  const short = (node: N) => cut(node.label, fits, node.kind);

  // A steep edge leaves (or reaches) a labelled node from under its label, so the line never strikes the text.
  const byId = new Map((placed?.nodes ?? []).map((n) => [n.id, n]));
  const lines = (placed?.links ?? []).map((link) => {
    let { x1, y1, x2, y2 } = link;
    const dx = x2 - x1;
    const dy = y2 - y1;
    if (Math.abs(dy) > Math.abs(dx)) {
      const upper = byId.get(dy > 0 ? link.src : link.dst);
      const off = upper?.labelled ? upper.size / 2 + LABEL_ROOM + 2 : 0;
      if (off && off < Math.abs(dy) - 8) {
        const t = off / Math.abs(dy);
        if (dy > 0) {
          x1 += dx * t;
          y1 += off;
        } else {
          x2 -= dx * t;
          y2 += off;
        }
      }
    }
    return { ...link, x1, y1, x2, y2 };
  });

  // Edge labels beside their line, kept only where they cover no node, no node label and no earlier edge label.
  const taken: Box[] = [];
  for (const n of placed?.nodes ?? []) {
    const half = n.size / 2 + 3;
    taken.push({ x0: n.x - half, y0: n.y - half, x1: n.x + half, y1: n.y + half });
    if (n.labelled) {
      const room = (short(n).length * CHAR) / 2 + 2;
      taken.push({ x0: n.x - room, y0: n.y + n.size / 2 + 2, x1: n.x + room, y1: n.y + n.size / 2 + 15 });
    }
  }
  const edgeLabels = lines.map((link) => {
    if (!link.label) return null;
    const dx = link.x2 - link.x1;
    const dy = link.y2 - link.y1;
    const length = Math.hypot(dx, dy) || 1;
    const wide = link.label.length * CHAR;
    // A label longer than the bare stretch of its edge would run into the nodes.
    if (wide > length - 32) return null;
    // The normal that points up (or left on a vertical edge), 9px off the line's middle, so the stroke stays clear of the letters.
    let nx = -dy / length;
    let ny = dx / length;
    if (ny > 0 || (ny === 0 && nx > 0)) [nx, ny] = [-nx, -ny];
    const x = (link.x1 + link.x2) / 2 + nx * 9;
    const y = (link.y1 + link.y2) / 2 + ny * 9;
    const box = { x0: x - wide / 2 - 2, y0: y - 6, x1: x + wide / 2 + 2, y1: y + 6 };
    if (taken.some((b) => overlaps(b, box))) return null;
    taken.push(box);
    return { x, y };
  });
  const lit = new Set(highlight ?? []);
  const dimming = Boolean(dimmed) || lit.size > 0;
  const nameOf = name ?? ((n: N) => `${n.kind} ${n.label}`);
  const active = cursor ?? focus ?? placed?.nodes[0]?.id ?? null;

  const move = (event: KeyboardEvent<SVGGElement>, from: string) => {
    if (!placed) return;
    const here = placed.nodes.find((n) => n.id === from);
    if (!here) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onOpen?.(here);
      return;
    }
    // Escape leaves the node for the graph itself; the page's own Escape waits for the next press.
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      svg.current?.focus({ preventScroll: true });
      return;
    }
    const dir = DIRS[event.key];
    if (!dir) return;
    event.preventDefault();
    let best: (typeof placed.nodes)[number] | null = null;
    let score = Infinity;
    for (const n of placed.nodes) {
      const dx = (n.x - here.x) * dir[0];
      const dy = (n.y - here.y) * dir[1];
      const along = dx + dy;
      if (n.id === here.id || along <= 0) continue;
      const across = Math.abs(dir[0] ? n.y - here.y : n.x - here.x);
      const s = along + 2 * across;
      if (s < score) {
        score = s;
        best = n;
      }
    }
    if (!best) return;
    setCursor(best.id);
    svg.current?.querySelector<SVGGElement>(`[data-node="${CSS.escape(best.id)}"]`)?.focus();
  };

  const point = (id: string | null, x = 0, y = 0) => {
    onPoint?.(id);
    if (!id || !svg.current) return setHover(null);
    const at = svg.current.getBoundingClientRect();
    setHover({ id, x: at.left + (side + x) * scale, y: at.top + (top + y) * scale });
  };
  const hovered = hover && placed?.nodes.find((n) => n.id === hover.id);

  return (
    <div ref={box} className="sh-graph scrollbar-thin" style={{ minHeight: height * scale }}>
      {placed ? (
        <svg
          ref={svg}
          width={w * scale}
          height={height * scale}
          viewBox={`0 0 ${w} ${height}`}
          role="group"
          aria-label={label}
          tabIndex={-1}
        >
          {placed.lanes.map((lane) => (
            <text key={lane.id} className="sh-graph__lane" x={lane.x + side} y={10} textAnchor="middle">
              {laneLabel(lane.id)}
            </text>
          ))}
          <g transform={`translate(${side} ${top})`}>
            {lines.map((link, index) => {
              const dim = dimming && !lit.has(link.src) && !lit.has(link.dst);
              const at = edgeLabels[index];
              return (
                <g key={index} className={cn(dim && "is-dim")}>
                  {/* A label that gave way stays in the edge's own tip. */}
                  {link.label && !at ? <title>{link.label}</title> : null}
                  <line
                    className="sh-graph__edge"
                    x1={link.x1}
                    y1={link.y1}
                    x2={link.x2}
                    y2={link.y2}
                    strokeWidth={link.width}
                  />
                  {link.label && at ? (
                    <text className="sh-graph__edge-label" x={at.x} y={at.y + 3} textAnchor="middle">
                      {link.label}
                    </text>
                  ) : null}
                </g>
              );
            })}
            {placed.nodes.map((node) => {
              const Icon = ICON[node.kind] ?? Circle;
              const half = node.size / 2;
              const ring = rings?.[node.id];
              return (
                <g
                  key={node.id}
                  data-node={node.id}
                  className={cn(
                    "sh-graph__node",
                    node.id === focus && "sh-graph__node--focus",
                    ghost?.(node) && "sh-graph__node--ghost",
                    lit.has(node.id) && "is-hl",
                    dimming && !lit.has(node.id) && "is-dim",
                  )}
                  data-tone={tone?.(node)}
                  transform={`translate(${node.x} ${node.y})`}
                  tabIndex={node.id === active ? 0 : -1}
                  role="button"
                  aria-label={nameOf(node)}
                  onClick={() => onOpen?.(node)}
                  onKeyDown={(event) => move(event, node.id)}
                  onFocus={() => {
                    setCursor(node.id);
                    point(node.id, node.x, node.y);
                  }}
                  onBlur={() => point(null)}
                  onMouseEnter={() => point(node.id, node.x, node.y)}
                  onMouseLeave={() => point(null)}
                >
                  {ring ? (
                    <rect
                      className={cn("sh-graph__ring", !SEVERITY_RING.has(ring) && `sh-graph__ring--${ring}`)}
                      data-tone={SEVERITY_RING.has(ring) ? ring : undefined}
                      x={-half - 3}
                      y={-half - 3}
                      width={node.size + 6}
                      height={node.size + 6}
                      rx={6}
                    />
                  ) : null}
                  <rect className="sh-graph__box" x={-half} y={-half} width={node.size} height={node.size} rx={4} />
                  <Icon x={-6} y={-6} size={12} aria-hidden />
                  {node.labelled ? (
                    <text className="sh-graph__label" y={half + 12} textAnchor="middle">
                      {short(node)}
                    </text>
                  ) : null}
                </g>
              );
            })}
            {placed.more.map((stub) => (
              <text
                key={stub.lane}
                className="sh-graph__more"
                x={stub.x}
                y={stub.y + 4}
                textAnchor="middle"
                role="button"
                tabIndex={0}
                aria-label={`${stub.ids.length} more`}
                onClick={() => onMore?.(stub.ids)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onMore?.(stub.ids);
                  }
                }}
              >
                +{stub.ids.length}
              </text>
            ))}
          </g>
        </svg>
      ) : null}
      {hovered && hover && (!hovered.labelled || short(hovered) !== hovered.label) ? (
        <div
          className="sh-tip sh-tip--mono"
          style={{ display: "flex", top: hover.y + (hovered.size / 2) * scale + 6, left: hover.x, transform: "translateX(-50%)" }}
          role="tooltip"
        >
          {nameOf(hovered)}
        </div>
      ) : null}
    </div>
  );
}
