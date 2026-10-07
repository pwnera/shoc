/**
 * What `policy.show` says about one action type, with the defaults filled in
 * where the policy leaves a field out, so every screen reads the same rule:
 * Response › Autonomy, the playbook page, the case's propose dialog, the
 * approval card's autonomy badge.
 */
import type { PolicyView, Severity } from "@/types";

export type Level = "L0" | "L1" | "L2";

/** One action type's rule, defaults filled in. */
export type ActionRule = {
  type: string;
  autonomy: Level;
  reversible: boolean;
  /** Set only where the action may run alone (L1); a zero floor is no floor. */
  min_confidence?: number;
  severity_at_least?: Severity;
  ttl_minutes?: number;
  research: boolean;
  review: boolean;
  required: string[];
};

const LEVELS = new Set(["L0", "L1", "L2"]);
const level = (value: unknown): Level | undefined =>
  typeof value === "string" && LEVELS.has(value) ? (value as Level) : undefined;
const number = (value: unknown) => (typeof value === "number" ? value : undefined);

export function ruleOf(policy: PolicyView | undefined, type: string): ActionRule {
  const own = policy?.actions[type] ?? {};
  const defaults = policy?.defaults ?? {};
  const params = policy?.action_params[type];
  const autonomy = level(own.autonomy) ?? level(defaults.autonomy) ?? "L2";
  // A floor matters only where the action may run alone.
  const floors = autonomy === "L1";
  return {
    type,
    autonomy,
    reversible: typeof own.reversible === "boolean" ? own.reversible : (params?.reversible ?? true),
    min_confidence: floors ? (number(own.min_confidence) ?? number(defaults.min_confidence)) || undefined : undefined,
    severity_at_least: floors ? (own.severity_at_least ?? defaults.severity_at_least) : undefined,
    ttl_minutes: number(own.ttl_minutes),
    research: own.research_before_action === true,
    review: own.review_before_action === true,
    required: params?.required ?? [],
  };
}

/** Every action type the policy knows, its rules and the catalogue together, sorted. */
export function actionTypes(policy: PolicyView | undefined): string[] {
  if (!policy) return [];
  return [...new Set([...Object.keys(policy.actions), ...policy.available_actions])].sort();
}

/* -- a proposal's rationale -------------------------------------------------- */

/** The policy's note after a proposal's words: `why [reason; reason]` (`shoc/cases/actions.py`). */
const NOTE = /\s*\[([^\]]*)\]\s*$/;

const pct = (value: string) => `${Math.round(Number(value) * 100)}%`;

/**
 * A rationale as its parts: the words the proposer wrote, and the policy's
 * objections, short ("below floor: 0% < 80%, medium < high"). The policy's
 * own verdict ("automatic", "needs a human") is the autonomy badge's, and an
 * objection a badge already states (one-way, target from a log line) is left out.
 */
export function splitRationale(
  rationale: string,
  row: { grounded?: boolean | null } = {},
): { said: string; guards: string[] } {
  const note = NOTE.exec(rationale);
  const said = (note ? rationale.slice(0, note.index) : rationale).trim();
  const floor: string[] = [];
  const guards: string[] = [];
  for (const reason of note?.[1]?.split("; ") ?? []) {
    let m: RegExpExecArray | null;
    if ((m = /^confidence ([\d.]+) is below ([\d.]+)$/.exec(reason))) floor.push(`${pct(m[1]!)} < ${pct(m[2]!)}`);
    else if ((m = /^severity (\w+) is below (\w+)$/.exec(reason))) floor.push(`${m[1]} < ${m[2]}`);
    else if ((m = /^this case already ran (\d+) automatic action/.exec(reason))) guards.push(`cap: ${m[1]} automatic ran`);
    else if (/^(automatic|needs a human)$/.test(reason) || reason === "the action is not reversible") continue;
    else if (/does not appear in the evidence this case cites$/.test(reason)) {
      if (row.grounded !== false) guards.push("target not in evidence");
    } else if (/is a protected target$/.test(reason)) guards.push("protected target");
    else if (/has not been researched/.test(reason)) guards.push("not researched");
    else if (/our own known egress/.test(reason)) guards.push("our own egress");
    else if (/is shared infrastructure/.test(reason)) guards.push("shared infrastructure");
    else if ((m = /^research came back '([^']+)'/.exec(reason))) guards.push(`research: ${m[1]}`);
    else if (/blast radius/.test(reason)) guards.push(/cites no events/.test(reason) ? "blast radius uncited" : "blast radius uncounted");
    else if (/cites no events/.test(reason)) guards.push("no cited events");
    else if (reason.trim()) guards.push(reason.trim());
  }
  if (floor.length) guards.unshift(`below floor: ${floor.join(", ")}`);
  return { said, guards };
}

/** The Manager's page conditions (`shoc/agents/manager.py` CONDITIONS), as words. */
const CONDITIONS: Record<string, string> = {
  deadline_expired: "deadline passed",
  critical_severity: "critical severity",
  uncontainable_and_active: "can't contain, still active",
  coverage_dark: "coverage dark",
};

/** A rationale that is only reason codes ("deadline_expired; coverage_dark"), as words; null for free text. */
export function conditionWords(said: string): string[] | null {
  if (!/^[a-z]+(_[a-z]+)*(; [a-z]+(_[a-z]+)*)*$/.test(said) || !said.includes("_")) return null;
  return said.split("; ").map((code) => CONDITIONS[code] ?? code.replace(/_/g, " "));
}
