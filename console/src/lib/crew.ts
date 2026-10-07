/**
 * Who said or did something, from the author strings the kernel writes:
 * openspace `agent`, action `requested_by` and `approved_by`, audit principals.
 * Every avatar, tip and roster in the console reads its identity from `who()`,
 * so a role is drawn the same way everywhere and an author the console does not
 * know is never drawn as crew.
 */
import type { Role } from "@/types";

/** The eleven roles, in roster order (`shoc/agents/roles.py` ALL, plus the Integrator). */
export const ROLES: Role[] = [
  { name: "Manager", mono: "MG", tier: "cheap", inCase: false, legacy: ["Reporter"] },
  { name: "Sentinel", mono: "SE", tier: "cheap", inCase: false },
  { name: "Investigator", mono: "IN", tier: "strong", inCase: true, legacy: ["Orchestrator"] },
  { name: "Challenger", mono: "CH", tier: "cheap", inCase: true },
  { name: "IR Commander", mono: "IR", tier: "strong", inCase: true },
  { name: "CTI", mono: "CT", tier: "strong", inCase: true },
  { name: "Surveyor", mono: "SV", tier: "cheap", inCase: true },
  { name: "Hunter", mono: "HU", tier: "strong", inCase: false },
  { name: "Detection Engineer", mono: "DE", tier: "strong", inCase: false, legacy: ["Tuner"] },
  { name: "Ops", mono: "OP", tier: "cheap", inCase: false },
  { name: "Integrator", mono: "IG", tier: "code", inCase: false },
];

/** The roles that take part in a case; silence from any other role on a case is not a gap. */
export const IN_CASE = ROLES.filter((r) => r.inCase).map((r) => r.name);

export type Glyph = "mark" | "cog" | "clock" | "hourglass" | "person";

export type Who = {
  /** One key per identity: the role name, `human:<id>`, a system author, `agent:<id>`. */
  key: string;
  kind: "crew" | "code" | "human" | "system" | "external" | "unknown";
  /** What a tip or a row says. */
  name: string;
  /** The avatar's monogram. */
  mono: string;
  /** System avatars draw a glyph instead of a monogram; external ones a plug. */
  glyph?: Glyph;
  role?: Role;
  /** The retired name the author used, for the "legacy name" tip. */
  legacy?: string;
};

const SYSTEM: Record<string, { name: string; glyph: Glyph }> = {
  shoc: { name: "shoc", glyph: "mark" },
  service: { name: "shoc", glyph: "mark" },
  // `agent:worker`: the worker acting as an agent, shoc's own hand.
  worker: { name: "shoc", glyph: "mark" },
  "playbook-runner": { name: "Playbook runner", glyph: "cog" },
  unattended: { name: "Unattended", glyph: "clock" },
  expiry: { name: "Expiry", glyph: "hourglass" },
};

const BY_NAME = new Map<string, { role: Role; legacy?: string }>();
for (const role of ROLES) {
  BY_NAME.set(role.name.toLowerCase(), { role });
  for (const old of role.legacy ?? []) BY_NAME.set(old.toLowerCase(), { role, legacy: old });
}
// The Manager requests its own pages as "manager" (`shoc/agents/manager.py` PRINCIPAL).
BY_NAME.set("manager", { role: ROLES[0]! });

function crew(name: string): Who | null {
  const hit = BY_NAME.get(name.toLowerCase());
  if (!hit) return null;
  const { role, legacy } = hit;
  return {
    key: role.name,
    kind: role.tier === "code" ? "code" : "crew",
    name: role.name,
    mono: role.mono,
    role,
    ...(legacy ? { legacy } : {}),
  };
}

/**
 * The identity behind an author string. Accepts bare role names, `agent:<Role>`,
 * `human:<id>` (repeated prefixes from older rows are collapsed), the worker's
 * own names, and `external_agent:<id>`.
 */
export function who(author: string | null | undefined): Who {
  const raw = (author ?? "").trim();
  if (!raw) return { key: "", kind: "unknown", name: "unknown", mono: "?" };
  // `migration:019`, the schema migration that closed old items: shoc's own hand, named by its number.
  if (raw.startsWith("migration:")) return { key: raw, kind: "system", name: `migration ${raw.slice(10)}`, mono: "", glyph: "mark" };
  let kind = "";
  let id = raw;
  // `agent:agent:manager` and `human:human:jane` both happen: the kernel prefixes ids that already carry a kind.
  for (let m = /^(human|agent|external_agent|service):(.*)$/.exec(id); m; ) {
    kind = m[1]!;
    id = m[2]!;
    m = /^(human|agent|external_agent|service):(.*)$/.exec(id);
  }
  if (kind === "human") {
    const name = id || "person";
    return { key: `human:${name}`, kind: "human", name, mono: name.charAt(0).toUpperCase() };
  }
  const system = SYSTEM[id] ?? (kind === "service" ? SYSTEM.service : undefined);
  if (system) return { key: id || "shoc", kind: "system", name: system.name, mono: "", glyph: system.glyph };
  const role = crew(id);
  if (role) return role;
  if (kind === "agent" || kind === "external_agent")
    return { key: `${kind}:${id}`, kind: "external", name: id, mono: "" };
  return { key: raw, kind: "unknown", name: raw, mono: "?" };
}

export type Tool = { name: string; count: number };

/** Split the trailing "[Looked up: events.query x3, timeline.build]" off a message body. */
export function parseLookedUp(body: string): { text: string; tools: Tool[] } {
  const m = /\s*\[Looked up: ([^\]]*)\]\s*$/.exec(body);
  if (!m) return { text: body, tools: [] };
  const tools = m[1]!
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const [, name = part, n] = /^(\S+?)(?: x(\d+))?$/.exec(part) ?? [];
      return { name, count: n ? Number(n) : 1 };
    });
  return { text: body.slice(0, m.index), tools };
}

/** Split the Challenger's leading "[arguing benign, grounded in written_fact]" off a body. */
export function parseStance(body: string): { text: string; arguing?: string; grounded?: string } {
  const m = /^\s*\[arguing (\w+), grounded in (\w+)\]\s*/.exec(body);
  if (!m) return { text: body };
  return { text: body.slice(m[0].length), arguing: m[1]!, grounded: m[2]!.replace(/_/g, " ") };
}
