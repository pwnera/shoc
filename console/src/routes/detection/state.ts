/**
 * What Detection and the rule page share: a rule joined with its health row,
 * the state it reads as (one per rule, in the precedence that partitions the
 * catalogue), where an id leads (`hunt:*` ids are hunt packs, not rules), the
 * words of the backlog, and how a person decides an item.
 */
import { useRef, useState } from "react";
import { RULE_STATES, ruleState, silentLabel, type RuleState } from "@/lib/labels";
import { useHuntResults, useRuleHealth, useRules } from "@/lib/queries";
import { severityRank } from "@/lib/sort";
import { toast } from "@/lib/toast";
import type { BacklogItem, Rule, RuleHealth } from "@/types";

export type RuleRow = Rule & { health?: RuleHealth; state?: RuleState };

/** `rule.list` joined with `health.rules` by id; `state` stays undefined while health is unknown. */
export function useRuleRows() {
  const rules = useRules();
  const health = useRuleHealth();
  const byId = new Map((health.data?.rules ?? []).map((h) => [h.rule_id, h]));
  const rows: RuleRow[] = (rules.data?.rules ?? []).map((rule) => {
    const h = byId.get(rule.id);
    return { ...rule, health: h, state: ruleState(h) };
  });
  return { rules, health, rows };
}

const STATE_RANK = new Map(RULE_STATES.map((s, i) => [s.id, i]));
export const stateOf = (id: RuleState) => RULE_STATES.find((s) => s.id === id)!;

/** Failing, noisy, field empty, live, armed, never sent, no source, then severity, then title. */
export function byAttention(a: RuleRow, b: RuleRow): number {
  const rank = (r: RuleRow) => (r.state ? STATE_RANK.get(r.state)! : RULE_STATES.length);
  return (
    rank(a) - rank(b) ||
    severityRank(b.severity) - severityRank(a.severity) ||
    a.title.localeCompare(b.title)
  );
}

/** Why a rule reads as it does, for the badge's tip. */
export function stateTip(health: RuleHealth): string {
  if (health.error) return health.error;
  if (health.noisy) return "too many findings";
  const reason = silentLabel(health.silent_reason);
  if (reason) return reason;
  return health.findings_7d > 0 ? `${health.findings_7d} findings in 7 days` : "can fire, quiet this week";
}

/* -- ids ------------------------------------------------------------------- */

export const isHunt = (id: string) => id.startsWith("hunt:");
export const packOf = (id: string) => id.slice("hunt:".length);

/** A rule's page, or a hunt pack's dialog on Hunts. */
export const ruleHref = (id: string) =>
  isHunt(id) ? `/hunts?pack=${encodeURIComponent(packOf(id))}` : `/detection/rules/${encodeURIComponent(id)}`;

/**
 * A muted id's name: the rule's title, or the hunt pack's (`hunt.results`
 * readiness), and whether the list that would name it is still loading.
 */
/* The intel sweeps file their findings as pseudo-packs that `hunt.results` never lists. */
const SWEEPS: Record<string, string> = {
  "hunt:ip": "IP sweep",
  "hunt:domain": "Domain sweep",
  "hunt:url": "URL sweep",
  "hunt:hash": "Hash sweep",
};

export function useTitles(): (id: string) => { title?: string; pending: boolean } {
  const rules = useRules();
  const packs = useHuntResults();
  const titles = new Map<string, string>();
  for (const r of rules.data?.rules ?? []) titles.set(r.id, r.title);
  for (const [id, title] of Object.entries(SWEEPS)) titles.set(id, title);
  for (const p of packs.data?.readiness ?? []) if (p.title) titles.set(`hunt:${p.pack_id}`, p.title);
  return (id) => ({ title: titles.get(id), pending: (isHunt(id) ? packs : rules).isPending });
}

/** The same person or thing whether or not the kernel prefixed it with `user:`. */
export const sameEntity = (entity: string) => entity.replace(/^user:/, "").toLowerCase();

/* -- backlog --------------------------------------------------------------- */

export type Segment = "open" | "gaps" | "accepted" | "closed";

export const SEGMENTS: { value: Segment; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "gaps", label: "Source gaps" },
  { value: "accepted", label: "Accepted" },
  { value: "closed", label: "Closed" },
];

/** Which slice of Changes an item belongs to. */
export function segmentOf(item: BacklogItem): Segment {
  if (item.state === "accepted") return "accepted";
  if (item.state === "done" || item.state === "rejected") return "closed";
  return item.observability === "none" ? "gaps" : "open";
}

export const ENGINEER = "Detection Engineer";

const DECISIONS: Record<string, string> = {
  merged: "merged",
  no_rule: "no rule",
  source_gap: "source gap",
  later: "later",
  stuck: "stuck",
};

const text = (value: unknown) => (typeof value === "string" ? value : "");

export type Decision = { word: string; because: string; by: string | null };

/**
 * Why the item stands where it does, and who said so. Closed: the decision and
 * its reason, the crew's or a person's. Open: why the crew put it off, or why
 * it came back; a decision from before it reopened no longer holds.
 */
export function decisionOf(item: BacklogItem): Decision | null {
  const e = item.evidence ?? {};
  if (item.state === "open") {
    if (e.later) return { word: "later", because: text(e.later), by: ENGINEER };
    if (e.reopened) return { word: "reopened", because: text(e.reopened), by: item.decided_by ?? null };
    return null;
  }
  const raw = text(e.decision);
  if (!raw) return null;
  return { word: DECISIONS[raw] ?? raw.replace(/_/g, " "), because: text(e.because), by: item.decided_by ?? ENGINEER };
}

/** Who took back the rule the item merged, when, and why. */
export function revertOf(item: BacklogItem): { by: string; because: string; at: string } | null {
  const r = item.evidence?.reverted;
  if (!r || typeof r !== "object") return null;
  const v = r as Record<string, unknown>;
  return { by: text(v.by), because: text(v.because), at: text(v.at) };
}

/** The rule a merge produced, while there is one to revert. */
export function mergedRule(item: BacklogItem): string | null {
  const e = item.evidence ?? {};
  return e.decision === "merged" && typeof e.rule_id === "string" && e.rule_id && !revertOf(item) ? e.rule_id : null;
}

/* -- deciding -------------------------------------------------------------- */

export type Ending = "rejected" | "done";

const SETTLED: Record<string, string> = { done: "Done", rejected: "Rejected", open: "Reopened" };

type Decide = {
  mutate: (input: { item_uid: string; state: string; reason: string }) => void;
  mutateAsync: (input: { item_uid: string; state: string; reason: string }) => Promise<unknown>;
  isPending: boolean;
};

/**
 * Reject, Done and Reopen on a backlog item, a detection one or a hunt one
 * (`detection.decide`, `hunt.decide`). Reject and Done ask why first: `ending`
 * is the confirm to show, keyed by the item, since J and K swap the item under
 * one open dialog. Reopen acts at once. The toast names what happened and
 * offers the way back. Cancel unmounts the focused reason field, so focus goes
 * back to the button that asked, and J and K still reach the dialog.
 */
export function useDecision(item: { item_uid: string; title: string }, decide: Decide, onClose: () => void) {
  const reject = useRef<HTMLButtonElement>(null);
  const done = useRef<HTMLButtonElement>(null);
  const [asking, setAsking] = useState<{ uid: string; state: Ending } | null>(null);
  const ending = asking?.uid === item.item_uid ? asking.state : null;
  const settle = (state: string, reason = "") => {
    const { item_uid, title } = item;
    return decide.mutateAsync({ item_uid, state, reason }).then(() => {
      toast({
        tone: "ok",
        text: `${SETTLED[state] ?? state} · ${title}`,
        ...(state === "open"
          ? {}
          : { action: { label: "Reopen", run: () => decide.mutate({ item_uid, state: "open", reason: "" }) } }),
      });
      onClose();
    });
  };
  return {
    ending,
    reject,
    done,
    settle,
    ask: (state: Ending) => setAsking({ uid: item.item_uid, state }),
    reopen: () => {
      if (!decide.isPending) settle("open").catch(() => undefined);
    },
    stop: () => {
      const back = ending === "done" ? done : reject;
      setAsking(null);
      requestAnimationFrame(() => back.current?.focus());
    },
  };
}
