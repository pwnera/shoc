/**
 * Where a memory came from, as `memory.search` says it: `source` is the
 * caller's kind (human, crew, agent, service), not a role, so a crew memory
 * draws the crew's mark rather than a monogram it cannot know. And the tab each
 * kind belongs to, and what a subject names.
 */
import { who, type Who } from "@/lib/crew";
import { parseEntity } from "@/lib/entity";
import { closedWord, DISPOSITIONS } from "@/lib/labels";
import type { Memory } from "@/types";

export type Origin = "human" | "crew" | "system";

/** The Surveyor writes its notes under its role name ("Surveyor") rather than "crew". */
export const originOf = (source: string): Origin =>
  source === "human" ? "human" : source === "crew" || source === "agent" || who(source).kind === "crew" ? "crew" : "system";

export const ORIGINS: Record<Origin, { who: Who; word: string }> = {
  human: { who: { key: "human", kind: "human", name: "told by a person", mono: "P" }, word: "a person" },
  crew: { who: { key: "crew", kind: "crew", name: "learned by the crew", mono: "›" }, word: "the crew" },
  system: { who: { ...who("shoc"), name: "written by shoc" }, word: "shoc" },
};

export const TABS = ["facts", "notes", "corrections"] as const;
export type Tab = (typeof TABS)[number];

/** Facts are semantic, notes episodic; a kind the console does not know reads as a fact. */
export const tabOf = (kind: string): Tab => (kind === "episodic" ? "notes" : kind === "correction" ? "corrections" : "facts");

/** The note `case.close` keeps when a case closes as expected: "… (case CASE-…, closed as expected activity)". */
const CASE = /\s*\(case (CASE-\S+), closed as ([^)]+)\)$/;
/** The role and day a crew note closes on, "… (Surveyor, 2026-10-06)": the dialog shows both. */
const SIGNED = /\s*\([A-Z][a-z]+(?: [A-Z][a-z]+)*, \d{4}-\d{2}-\d{2}\)$/;
/** A correction's "… UTC was benign_expected, said rettila: …", read as "… UTC: expected activity, said rettila: …". */
const VERDICT = / was (\w+), said /;
const disposition = (id: string) => (id in DISPOSITIONS ? DISPOSITIONS[id as keyof typeof DISPOSITIONS].toLowerCase() : "");

/** The case a note was written from, and how it closed; the dialog links it. */
export function caseOf(memory: Pick<Memory, "body">): { uid: string; closed: string } | null {
  const m = CASE.exec(memory.body);
  return m ? { uid: m[1]!, closed: closedWord(m[2]!) } : null;
}

/**
 * The body without what the subject beside it already says (the "<subject>: "
 * the kernel opens most with, or a correction's "<rule_id> on <resource> ")
 * and without the case it came from, which the dialog links, or the role and
 * day a crew note is signed with; a correction's verdict id in words.
 */
export function bodyOf(memory: Pick<Memory, "kind" | "subject" | "body">): string {
  const { rule, rest } = aboutOf(memory);
  const said = rule ? `${rule} on ${rest} ` : `${memory.subject}: `;
  const body = memory.subject && memory.body.startsWith(said) ? memory.body.slice(said.length) : memory.body;
  return body.replace(CASE, "").replace(SIGNED, "").replace(VERDICT, (whole, id: string) => (disposition(id) ? `: ${disposition(id)}, said ` : whole));
}

/** `case.close` writes a correction's subject as `<rule_id>:<resource>`; any other subject is what it is about. */
export function aboutOf(memory: Pick<Memory, "kind" | "subject">): { rule: string; rest: string } {
  const colon = memory.subject.indexOf(":");
  if (memory.kind !== "correction" || colon <= 0) return { rule: "", rest: memory.subject };
  return { rule: memory.subject.slice(0, colon), rest: memory.subject.slice(colon + 1) };
}

/** The entity "about" opens: a correction's resource is who its rule fired on, so a bare email there is the user. */
export function aboutKey(rule: string, rest: string): string | null {
  const typed = parseEntity(rest);
  return typed?.kind === "email" && rule ? `user:${typed.value}` : (typed?.key ?? null);
}
