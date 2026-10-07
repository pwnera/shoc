/**
 * A case, told twice from what it holds: in order (the timeline) and as who
 * touched what (the attack graph). Both are drawn from the case's own findings,
 * events, crew decisions and actions; nothing here asks the kernel for more.
 */
import { fieldWord } from "@/lib/explore";
import { actionLabel } from "@/lib/labels";
import type { Action, Case, CaseFinding, Finding, OcsfEvent, OpenspaceMessage, Severity } from "@/types";

export type Moment = {
  at: string;
  kind: "case" | "finding" | "event" | "crew" | "action";
  title: string;
  /** Who did it: the actor of an event, the agent that decided, who asked for an action. */
  who?: string;
  detail?: string;
  to?: string;
};

export function timeline(
  record: Case,
  findings: CaseFinding[],
  events: OcsfEvent[],
  openspace: OpenspaceMessage[],
  actions: Action[],
): Moment[] {
  const moments: Moment[] = [
    { at: record.opened_at, kind: "case", title: "Case opened" },
    ...findings.map((f): Moment => ({
      at: f.first_seen,
      kind: "finding",
      title: f.title,
      detail: f.rule_id,
      to: `/findings/${f.finding_uid}`,
    })),
    ...events.map((e): Moment => ({
      at: e.time,
      kind: "event",
      title: e.api_operation ?? e.activity_name ?? e.class_name ?? "event",
      who: e.actor_user_name ?? undefined,
      detail: [e.src_endpoint_ip, e.metadata_product].filter(Boolean).join(" · "),
    })),
    ...openspace
      .filter((m) => m.kind === "decision")
      .map((m): Moment => ({
        at: m.created_at,
        kind: "crew",
        title: "decided",
        who: m.agent,
        detail: m.body,
      })),
    ...actions.map((a): Moment => ({
      at: a.created_at,
      kind: "action",
      title: actionLabel(a.type),
      who: a.requested_by,
      detail: `${a.target} · ${a.state.replace(/_/g, " ")}`,
    })),
  ];
  if (record.closed_at) moments.push({ at: record.closed_at, kind: "case", title: "Case closed" });
  return moments.filter((m) => m.at).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

/** Left to right: where from, who, with what, in which account, on what. */
export const LAYERS = ["ip", "user", "key", "account", "resource"] as const;
export type Layer = (typeof LAYERS)[number];
export const COLUMNS: Record<Layer, keyof OcsfEvent> = {
  ip: "src_endpoint_ip",
  user: "actor_user_name",
  key: "actor_session_uid",
  account: "cloud_account_uid",
  resource: "resource_uid",
};
/** Lane heads; the third reads SESSION unless every value is an AWS access key id. */
export const LANE_LABELS: Record<Layer, string> = {
  ip: fieldWord("src_endpoint.ip").toUpperCase(),
  user: fieldWord("actor.user.name").toUpperCase(),
  key: "KEY",
  account: fieldWord("cloud.account.uid").toUpperCase(),
  resource: fieldWord("resource.uid").toUpperCase(),
};

/** The response overlay on a node: an action on it ran, ran as a dry run, was undone, or waits. */
export type Overlay = "done" | "planned" | "undone" | "pending";

export type Node = {
  id: string;
  kind: Layer;
  label: string;
  events: number;
  /** `events`, under the name `lib/graph.ts` sizes by. */
  weight: number;
  /** The worst severity of a finding whose entity is this node. */
  severity?: Severity;
  overlay?: Overlay;
  /** The event uids behind the node, for brushing. */
  uids: string[];
};
export type Edge = {
  src: string;
  dst: string;
  operations: string[];
  weight: number;
  /** The commonest operation along the edge and how often: "GetObject ×20". */
  label: string;
  uids: string[];
};

const SEVERITY: Severity[] = ["informational", "low", "medium", "high", "critical"];
const OVERLAY: Record<string, Overlay | undefined> = {
  done: "done",
  rolled_back: "undone",
  proposed: "pending",
  approved: "pending",
  running: "pending",
};

/**
 * Each event links its entities in layer order: ip → user → key → account →
 * resource. Findings ring the nodes they name; actions overlay their targets.
 */
export function attackGraph(
  events: OcsfEvent[],
  findings: (CaseFinding & Pick<Finding, "entity_key">)[] = [],
  actions: Action[] = [],
): { nodes: Node[]; edges: Edge[]; keyLane: "KEY" | "SESSION" } {
  const nodes = new Map<string, Node>();
  const edges = new Map<string, Edge & { counts: Map<string, number> }>();
  for (const event of events) {
    const chain: string[] = [];
    for (const kind of LAYERS) {
      const value = event[COLUMNS[kind]];
      if (value === null || value === undefined || value === "" || value === "-") continue;
      const id = `${kind}:${value}`;
      const node = nodes.get(id) ?? { id, kind, label: String(value), events: 0, weight: 0, uids: [] };
      node.events += 1;
      node.weight = node.events;
      node.uids.push(event.event_uid);
      nodes.set(id, node);
      chain.push(id);
    }
    const operation = event.api_operation ?? event.activity_name ?? "";
    for (let i = 1; i < chain.length; i++) {
      const key = `${chain[i - 1]}>${chain[i]}`;
      const edge = edges.get(key) ?? {
        src: chain[i - 1]!,
        dst: chain[i]!,
        operations: [],
        weight: 0,
        label: "",
        uids: [],
        counts: new Map<string, number>(),
      };
      edge.weight += 1;
      edge.uids.push(event.event_uid);
      if (operation) {
        if (!edge.operations.includes(operation)) edge.operations.push(operation);
        edge.counts.set(operation, (edge.counts.get(operation) ?? 0) + 1);
      }
      edges.set(key, edge);
    }
  }

  const byLabel = new Map<string, Node[]>();
  for (const node of nodes.values()) byLabel.set(node.label, [...(byLabel.get(node.label) ?? []), node]);
  const strip = (key: string) => key.replace(/^(user|key|ip|resource|account|host):/, "");
  for (const finding of findings)
    for (const node of byLabel.get(strip(finding.entity_key)) ?? [])
      if (!node.severity || SEVERITY.indexOf(finding.severity) > SEVERITY.indexOf(node.severity))
        node.severity = finding.severity;
  for (const action of actions) {
    const overlay = action.state === "done" && action.dry_run ? "planned" : OVERLAY[action.state];
    if (!overlay) continue;
    for (const node of byLabel.get(strip(action.target)) ?? [])
      // A pending decision outranks history: it is the one thing still to do.
      if (!node.overlay || overlay === "pending" || (overlay === "done" && node.overlay !== "pending"))
        node.overlay = overlay;
  }

  const keys = [...nodes.values()].filter((n) => n.kind === "key");
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()].map(({ counts, ...edge }) => {
      const [top, n] = [...counts].sort((a, b) => b[1] - a[1])[0] ?? ["", 0];
      return { ...edge, label: top ? (n > 1 ? `${top} ×${n}` : top) : "" };
    }),
    keyLane: keys.length && keys.every((n) => /^(AKIA|ASIA)[A-Z0-9]{16}$/.test(n.label)) ? "KEY" : "SESSION",
  };
}
