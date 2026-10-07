/**
 * The crew's discussion as the Discussion tab and the message dialog read it:
 * which kinds each mode shows, which run and round each message belongs to,
 * the first line of a body once the kernel's bracketed asides are cut off and
 * its page conditions put in words, a proposal's fields, and which challenges
 * the same agent later conceded.
 * Pure, so the tests feed it.
 */
import { parseLookedUp, parseStance, who } from "@/lib/crew";
import { bare } from "@/lib/entity";
import { actionLabel } from "@/lib/labels";
import { conditionWords } from "@/lib/policy";
import type { OpenspaceMessage } from "@/types";

export type Mode = "outcomes" | "debate" | "all";

const KINDS: Record<Exclude<Mode, "all">, readonly string[]> = {
  outcomes: ["decision", "proposal"],
  debate: ["decision", "proposal", "hypothesis", "evidence", "challenge", "concede"],
};

/** A person's message shows in every mode. */
export const isHuman = (m: OpenspaceMessage) => m.principal === "human";

export function visibleMessages(messages: readonly OpenspaceMessage[], mode: Mode): OpenspaceMessage[] {
  if (mode === "all") return [...messages];
  return messages.filter((m) => isHuman(m) || KINDS[mode].includes(m.kind));
}

/** A message's place in the discussion: `key` tells two runs' round 78 apart. */
export type Round = { key: string; run: number; round: number };

/**
 * The run and round of each message, by msg_id. A round that drops (80, then
 * 78 or 1) starts a new run: the case was investigated again, so its rounds
 * get their own dividers. A round-1 note (shoc's own, an inject, an
 * observation) joins the round it falls in rather than filing under round 1.
 */
export function roundsOf(messages: readonly OpenspaceMessage[]): Map<number, Round> {
  const out = new Map<number, Round>();
  let run = 0;
  let round: number | null = null;
  for (const m of messages) {
    const note = m.round <= 1 && (m.kind === "inject" || m.kind === "observation" || who(m.agent).kind !== "crew");
    if (round === null || !note) {
      if (round !== null && m.round < round) run += 1;
      round = m.round;
    }
    out.set(m.msg_id, { key: `${run}:${round}`, run, round });
  }
  return out;
}

/** What a proposal message carries (`shoc/agents/ir.py`), every field optional. */
export type Proposal = {
  action: string;
  target?: string;
  stage?: string;
  autonomy?: string;
  reversible?: boolean;
  rationale?: string;
  blast_radius?: { principals?: number } | null;
  fallback?: string;
  fallback_after_minutes?: number;
  destroys_evidence?: string;
  action_uid?: string;
};

export function proposalOf(m: Pick<OpenspaceMessage, "kind" | "body">): Proposal | null {
  if (m.kind !== "proposal") return null;
  try {
    const parsed = JSON.parse(m.body);
    return parsed && typeof parsed.action === "string" ? (parsed as Proposal) : null;
  } catch {
    return null;
  }
}

/**
 * The body without the trailing "[Looked up: …]" and the Challenger's leading
 * "[arguing …]", and a decision's "Paging a human (critical_severity)" in words.
 */
export function strip(body: string) {
  const looked = parseLookedUp(body);
  const stance = parseStance(looked.text);
  const text = stance.text
    .trim()
    .replace(/Paging a human \(([a-z_]+)\)/g, (all, code: string) => {
      const words = conditionWords(code);
      return words ? `Paging a human (${words.join(", ")})` : all;
    });
  return { text, tools: looked.tools, arguing: stance.arguing, grounded: stance.grounded };
}

/** One line for a trace row. */
export function firstLine(m: OpenspaceMessage): string {
  const proposal = proposalOf(m);
  if (proposal) return [actionLabel(proposal.action), proposal.target && bare(proposal.target)].filter(Boolean).join(" · ");
  return strip(m.body).text.split("\n")[0] ?? "";
}

/** Challenges their own author later conceded, by msg_id. */
export function conceded(messages: readonly OpenspaceMessage[]): Set<number> {
  const dead = new Set<number>();
  messages.forEach((m, i) => {
    if (m.kind !== "challenge") return;
    if (messages.slice(i + 1).some((later) => later.kind === "concede" && later.agent === m.agent)) dead.add(m.msg_id);
  });
  return dead;
}

/** A person's message some crew role spoke after: the crew has had it. */
export function pickedUp(messages: readonly OpenspaceMessage[], m: OpenspaceMessage): boolean {
  const at = messages.indexOf(m);
  return messages.slice(at + 1).some((later) => {
    const kind = who(later.agent).kind;
    return kind === "crew" || kind === "code";
  });
}
