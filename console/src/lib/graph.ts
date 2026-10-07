/**
 * Where graph nodes go, in pixels. Two layouts serve every graph in the
 * console: layered (columns by kind: cases, findings, rules, reports) and
 * radial (a root and its hops: entities). `ui/graph.tsx` draws the result; this
 * file only does arithmetic, so it is tested without a DOM.
 */
export type GraphNode = { id: string; kind: string; label: string; weight?: number };
export type GraphLink = { src: string; dst: string; weight?: number; label?: string };

export type Placed<N extends GraphNode> = N & {
  x: number;
  y: number;
  /** Side of the node's square, 16–28px by weight. */
  size: number;
  /** Whether the label is drawn; every other label lives in the node's tip. */
  labelled: boolean;
};
export type PlacedLink<L extends GraphLink> = L & {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  /** 1–3px by weight. */
  width: number;
};
export type Lane = { id: string; x: number };
/** The "+N" stub under a full lane, with the ids it hides. */
export type More = { lane: string; x: number; y: number; ids: string[] };

export type Layout<N extends GraphNode, L extends GraphLink> = {
  nodes: Placed<N>[];
  links: PlacedLink<L>[];
  lanes: Lane[];
  more: More[];
  width: number;
  height: number;
};

const PAD = 24;

function scale(values: number[]): (v: number) => number {
  const max = Math.max(1, ...values);
  return (v) => Math.sqrt(Math.max(0, v) / max);
}

function linksOf<N extends GraphNode, L extends GraphLink>(
  links: L[],
  at: Map<string, Placed<N>>,
): PlacedLink<L>[] {
  const weight = scale(links.map((l) => l.weight ?? 1));
  const out: PlacedLink<L>[] = [];
  for (const link of links) {
    const a = at.get(link.src);
    const b = at.get(link.dst);
    if (!a || !b) continue;
    out.push({ ...link, x1: a.x, y1: a.y, x2: b.x, y2: b.y, width: 1 + 2 * weight(link.weight ?? 1) });
  }
  return out;
}

/**
 * Columns by lane, the busiest nodes first. The first lane is ordered by
 * weight; each later lane by the mean height of its neighbours in the lanes
 * before it, which removes most crossings. Past `perLane`, a lane ends in a
 * "+N" stub.
 */
export function layered<N extends GraphNode, L extends GraphLink>(
  nodes: N[],
  links: L[],
  opts: {
    width: number;
    height: number;
    lanes: readonly string[];
    laneOf?: (node: N) => string;
    perLane?: number;
  },
): Layout<N, L> {
  const { width, height, lanes } = opts;
  const laneOf = opts.laneOf ?? ((n: N) => n.kind);
  const perLane = opts.perLane ?? 10;
  const size = scale(nodes.map((n) => n.weight ?? 1));
  const step = lanes.length > 1 ? (width - 2 * PAD) / (lanes.length - 1) : 0;
  const placed = new Map<string, Placed<N>>();
  const more: More[] = [];
  const neighbours = new Map<string, string[]>();
  for (const l of links) {
    neighbours.set(l.src, [...(neighbours.get(l.src) ?? []), l.dst]);
    neighbours.set(l.dst, [...(neighbours.get(l.dst) ?? []), l.src]);
  }

  lanes.forEach((lane, index) => {
    const x = lanes.length > 1 ? PAD + index * step : width / 2;
    const members = nodes
      .filter((n) => laneOf(n) === lane)
      .sort((a, b) => (b.weight ?? 1) - (a.weight ?? 1));
    const kept = members.slice(0, perLane);
    if (index > 0) {
      const mean = (n: N) => {
        const ys = (neighbours.get(n.id) ?? []).flatMap((id) => {
          const p = placed.get(id);
          return p ? [p.y] : [];
        });
        return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : height;
      };
      const order = new Map(kept.map((n) => [n.id, mean(n)]));
      kept.sort((a, b) => order.get(a.id)! - order.get(b.id)!);
    }
    const hidden = members.slice(perLane);
    const rows = kept.length + (hidden.length ? 1 : 0);
    const gap = rows ? (height - 2 * PAD) / Math.max(1, rows - 1) : 0;
    kept.forEach((node, row) => {
      const y = rows > 1 ? PAD + row * gap : height / 2;
      placed.set(node.id, { ...node, x, y, size: 16 + 12 * size(node.weight ?? 1), labelled: true });
    });
    if (hidden.length)
      more.push({ lane, x, y: rows > 1 ? PAD + kept.length * gap : height / 2, ids: hidden.map((n) => n.id) });
  });

  return {
    nodes: [...placed.values()],
    links: linksOf(links, placed),
    lanes: lanes.map((id, index) => ({ id, x: lanes.length > 1 ? PAD + index * step : width / 2 })),
    more,
    width,
    height,
  };
}

/**
 * The root in the middle and each hop on its own ring. A node sits near the
 * angle of the node that reached it, so a branch stays together. Labels go on
 * the root, the focused node and the `labels` busiest others only, so a dense
 * ring never overlaps.
 */
export function radial<N extends GraphNode, L extends GraphLink>(
  nodes: N[],
  links: L[],
  opts: { width: number; height: number; root: string; focus?: string; labels?: number },
): Layout<N, L> {
  const { width, height, root } = opts;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const adjacent = new Map<string, string[]>();
  for (const l of links) {
    adjacent.set(l.src, [...(adjacent.get(l.src) ?? []), l.dst]);
    adjacent.set(l.dst, [...(adjacent.get(l.dst) ?? []), l.src]);
  }
  // Breadth first from the root; nodes it never reaches form the outer ring.
  const hop = new Map<string, number>();
  const parent = new Map<string, string>();
  if (byId.has(root)) hop.set(root, 0);
  for (let queue = byId.has(root) ? [root] : []; queue.length; ) {
    const next: string[] = [];
    for (const id of queue)
      for (const n of adjacent.get(id) ?? [])
        if (byId.has(n) && !hop.has(n)) {
          hop.set(n, hop.get(id)! + 1);
          parent.set(n, id);
          next.push(n);
        }
    queue = next;
  }
  const deepest = Math.max(0, ...hop.values());
  for (const n of nodes) if (!hop.has(n.id)) hop.set(n.id, deepest + 1);
  const rings = Math.max(1, ...hop.values());
  const radius = Math.max(0, Math.min(width, height) / 2 - PAD);
  const size = scale(nodes.map((n) => n.weight ?? 1));
  const busiest = new Set(
    nodes
      .filter((n) => n.id !== root && n.id !== opts.focus)
      .sort((a, b) => (b.weight ?? 1) - (a.weight ?? 1))
      .slice(0, opts.labels ?? 8)
      .map((n) => n.id),
  );

  const angle = new Map<string, number>();
  const placed = new Map<string, Placed<N>>();
  for (let ring = 0; ring <= rings; ring++) {
    const members = nodes.filter((n) => hop.get(n.id) === ring);
    members.sort((a, b) => {
      const pa = angle.get(parent.get(a.id) ?? "") ?? 0;
      const pb = angle.get(parent.get(b.id) ?? "") ?? 0;
      return pa - pb || (b.weight ?? 1) - (a.weight ?? 1);
    });
    members.forEach((node, i) => {
      const theta = ring === 0 ? 0 : (2 * Math.PI * i) / members.length - Math.PI / 2;
      const r = (radius * ring) / rings;
      angle.set(node.id, theta);
      placed.set(node.id, {
        ...node,
        x: width / 2 + r * Math.cos(theta),
        y: height / 2 + r * Math.sin(theta),
        size: 16 + 12 * size(node.weight ?? 1),
        labelled: node.id === root || node.id === opts.focus || busiest.has(node.id),
      });
    });
  }

  return { nodes: [...placed.values()], links: linksOf(links, placed), lanes: [], more: [], width, height };
}
