/**
 * Findings as signals: one row per rule and entity, so fifty hourly firings of
 * one rule on one account read as one line with ×50. Grouping happens over the
 * rows `finding.list` returned; the kernel has no group-by yet.
 */
import type { Finding, Severity } from "@/types";

export type Signal = {
  key: string;
  rule_id: string;
  entity_key: string;
  title: string;
  /** The worst severity in the group. */
  severity: Severity;
  /** The newest `last_seen`. */
  last_seen: string;
  /** Newest first; the row opens the first. */
  findings: Finding[];
};

const RANK: Record<string, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };

export const severityRank = (severity: string) => RANK[severity] ?? 0;

/** The signal a finding belongs to: its rule and entity. */
export const signalKey = (finding: Finding) => `${finding.rule_id}|${finding.entity_key}`;

const newest = (a: Finding, b: Finding) => Date.parse(b.last_seen) - Date.parse(a.last_seen);

export function groupFindings(rows: Finding[]): Signal[] {
  const groups = new Map<string, Signal>();
  for (const finding of [...rows].sort(newest)) {
    const key = signalKey(finding);
    const group = groups.get(key);
    if (!group) {
      groups.set(key, {
        key,
        rule_id: finding.rule_id,
        entity_key: finding.entity_key,
        title: finding.title,
        severity: finding.severity,
        last_seen: finding.last_seen,
        findings: [finding],
      });
      continue;
    }
    group.findings.push(finding);
    if (severityRank(finding.severity) > severityRank(group.severity)) group.severity = finding.severity;
  }
  // Insertion order is newest first already, since the rows were sorted.
  return [...groups.values()];
}

/** Every finding uid of the signals in list order, for J/K on the finding page. */
export function stepOrder(signals: Signal[]): string[] {
  return signals.flatMap((s) => s.findings.map((f) => f.finding_uid));
}

/**
 * Where a finding came from: an indicator hit (`ioc_match:ip`, a retro-hunt's
 * `ioc_retrohunt:ip`, an old sweep's `hunt:ip`) opens its indicator on Intel,
 * a `hunt:<pack>` id its pack, anything else its rule page.
 */
export function sourceOf(finding: Pick<Finding, "rule_id" | "evidence">): {
  label: "Indicator" | "Hunt" | "Rule";
  href: string;
} {
  const ioc = finding.evidence?.indicator as { type?: string; value?: string } | undefined;
  if (ioc?.value) {
    const query = new URLSearchParams({ ...(ioc.type ? { type: ioc.type } : {}), q: ioc.value, ioc: ioc.value });
    return { label: "Indicator", href: `/intel?${query}` };
  }
  if (finding.rule_id.startsWith("hunt:"))
    return { label: "Hunt", href: `/hunts?pack=${encodeURIComponent(finding.rule_id.slice(5))}` };
  return { label: "Rule", href: `/detection/rules/${encodeURIComponent(finding.rule_id)}` };
}

/** An older hunt's observations, "actor.user.name=alice, src_endpoint.ip=203.0.113.7", as distinct field and value pairs. */
export function observed(list: unknown): [string, string][] {
  const seen = new Map<string, [string, string]>();
  for (const item of Array.isArray(list) ? (list as { summary?: unknown }[]) : []) {
    // A value may hold ", "; a pair starts only where a dotted name and "=" follow.
    for (const part of String(item?.summary ?? "").split(/, (?=[\w.]+=)/)) {
      const at = part.indexOf("=");
      if (at > 0 && at < part.length - 1) seen.set(part, [part.slice(0, at), part.slice(at + 1)]);
    }
  }
  return [...seen.values()];
}
