/**
 * Where an Ops alert belongs: each kind has one home screen (section 6), and
 * every link to an alert opens that home on the thing it names (OPS-1).
 * Health draws only the platform's own kinds: worker, model and spend.
 */
import type { OpsAlert } from "@/types";

/** The screen that owns an alert kind. */
export type Area = "cases" | "response" | "detection" | "hunts" | "connections" | "health" | "access" | "overview";

export type Origin = { area: Area; group: string; to: string };

const q = encodeURIComponent;

export function origin(alert: OpsAlert): Origin {
  const [prefix = "", what = ""] = alert.kind.split(".");
  const s = alert.subject;
  switch (prefix) {
    case "source":
      // Quality is keyed by product, not by configured source, so it opens the Quality tab.
      return what === "quality"
        ? { area: "connections", group: s, to: `/connections?tab=quality&product=${q(s)}` }
        : { area: "connections", group: s, to: `/connections?source=${q(s)}` };
    case "rule":
      return { area: "detection", group: "Rules", to: `/detection/rules/${q(s)}` };
    case "case":
      return { area: "cases", group: "Cases", to: `/cases/${q(s)}` };
    case "approval":
      return { area: "overview", group: "Approvals", to: "/" };
    case "action":
      return { area: "response", group: "Actions", to: `?action=${q(s)}` };
    case "hunt":
      return { area: "hunts", group: "Hunts", to: `/hunts?pack=${q(s)}` };
    case "audit":
      return { area: "access", group: "Audit", to: "/access?tab=audit" };
    case "jobs":
      return { area: "health", group: "Worker", to: "/health/jobs" };
    case "llm":
      return { area: "health", group: "Model", to: "/health/crew" };
    case "cost":
      return { area: "health", group: "Spend", to: "/health/spend" };
    default:
      return { area: "health", group: prefix || "Other", to: "/health" };
  }
}

/** The kinds Health › Problems draws; every other kind renders on its owner screen. */
export const ownedByHealth = (alert: OpsAlert) => /^(jobs|llm|cost)\./.test(alert.kind);

/** Alerts grouped by origin, the group with the most high-severity alerts first. */
export function byOrigin(alerts: OpsAlert[]): { group: string; to: string; alerts: OpsAlert[] }[] {
  const groups = new Map<string, { group: string; to: string; alerts: OpsAlert[] }>();
  for (const alert of alerts) {
    const { group, to } = origin(alert);
    const entry = groups.get(group) ?? { group, to, alerts: [] };
    entry.alerts.push(alert);
    groups.set(group, entry);
  }
  const high = (g: { alerts: OpsAlert[] }) => g.alerts.filter((a) => a.severity === "high").length;
  return [...groups.values()].sort(
    (a, b) => high(b) - high(a) || b.alerts.length - a.alerts.length,
  );
}
