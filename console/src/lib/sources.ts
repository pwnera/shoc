import type { Volume } from "@/lib/queries";
import type { ConfiguredSource, Rule } from "@/types";

type Push = { only: string[]; also: string[] };

/** The connector a source runs: `cloudflare:acme` is a second Cloudflare account. */
export const connectorOf = (source: string): string => source.replace(/:.*/, "");

/** How a connector can deliver: shoc polls it, it pushes to shoc, or either. */
export function modes(source: string, push: Push): "poll" | "push" | "poll or push" {
  const name = connectorOf(source);
  if (push.only.includes(name)) return "push";
  return push.also.includes(name) ? "poll or push" : "poll";
}

/** How a connected source delivers. One that can do either pushes when saved without a credential. */
export function modeOf(row: ConfiguredSource, push: Push): "poll" | "push" {
  const can = modes(row.source, push);
  return can === "push" || (can === "poll or push" && !row.has_secret) ? "push" : "poll";
}

/**
 * What Connections says of a connected source.
 *
 * A source saved before its credential is a step of onboarding, not a
 * delivery, and one that has never delivered is not delivering. A push source
 * needs no credential of ours, so that one is only said of a source shoc
 * polls; and a push source that went silent without a failure has "no recent
 * push", not late: nothing was sent, nothing broke. An error older than a push
 * source's last delivery is stale (the worker keeps a poll error on a source
 * that now pushes); the Delivery view still shows it. A source Ops holds a
 * `source.failing` alert on is failing whatever else holds.
 */
export function deliveryState(row: ConfiguredSource, push: Push, late: Set<string>, alerted = false): string {
  const polled = modeOf(row, push) === "poll";
  const stale = !polled && row.last_ok_at && row.last_run_at && Date.parse(row.last_ok_at) > Date.parse(row.last_run_at);
  if (!row.enabled) return "paused";
  // Ops raising `source.failing` outranks the staleness guess: a push source can still be failing.
  if (alerted || (row.last_error && !stale)) return "failing";
  if (polled && !row.has_secret) return "no credential";
  if (!row.last_ok_at) return "waiting";
  if (!late.has(row.source)) return "delivering";
  return polled ? "late" : "no recent push";
}

/* The `metadata_product` each connector's mapping writes (`shoc/ingest/mappings/*.yaml`). */
const PRODUCTS: Record<string, string> = {
  anthropic: "Anthropic",
  aws_cloudtrail: "AWS CloudTrail",
  aws_guardduty: "AWS GuardDuty",
  azure_activity: "Azure Activity Log",
  cloudflare: "Cloudflare Audit Log",
  cloudflare_logs: "Cloudflare Logpush",
  crowdstrike: "CrowdStrike Falcon",
  crowdstrike_fdr: "CrowdStrike Falcon Data Replicator",
  defender: "Microsoft Defender",
  defender_hunting: "Microsoft Defender Advanced Hunting",
  entra: "Microsoft Entra ID",
  gcp_audit: "GCP Cloud Audit",
  github: "GitHub Audit Log",
  gitlab: "GitLab Audit Events",
  google_workspace: "Google Workspace",
  m365: "Microsoft 365",
  okta: "Okta System Log",
  openai: "OpenAI",
  sentinelone: "SentinelOne",
  sentinelone_cloudfunnel: "SentinelOne Cloud Funnel",
  stripe: "Stripe",
  tailscale: "Tailscale Configuration Log",
  wazuh: "Wazuh",
};

/* Products whose name would not fit a catalog tile. */
const SHORT: Record<string, string> = { crowdstrike_fdr: "CrowdStrike FDR", defender_hunting: "Defender Hunting" };

/**
 * A source as every screen names it: its vendor's name, the product less the
 * log's own name ("okta" → "Okta", "aws_guardduty" → "AWS GuardDuty", so two
 * connectors of one vendor stay apart); a second account keeps its suffix
 * ("cloudflare:acme" → "Cloudflare · acme"). The raw id stays in a tip or an
 * id slot.
 */
export function sourceName(source: string): string {
  const connector = connectorOf(source);
  const words = connector.replace(/_/g, " ");
  const name =
    SHORT[connector] ??
    PRODUCTS[connector]?.replace(/ (Audit Log|System Log|Configuration Log|Audit Events)$/, "") ??
    words.charAt(0).toUpperCase() + words.slice(1);
  return connector === source ? name : `${name} · ${source.slice(connector.length + 1)}`;
}

export type ShownVolume = Omit<Volume, "mark"> & { mark: Volume["mark"] | "no recent push" };

/**
 * A product's volume mark as Sources shows it: a silent product every source
 * of which pushes has "no recent push", as those rows read (nothing was sent,
 * nothing broke).
 */
export function shownVolume(
  product: string,
  volume: Volume,
  sources: { source: string; mode: "poll" | "push" }[],
): ShownVolume {
  if (volume.mark !== "silent") return volume;
  const own = sources.filter((s) => PRODUCTS[connectorOf(s.source)] === product);
  return own.length && own.every((s) => s.mode === "push") ? { ...volume, mark: "no recent push" } : volume;
}

/** A quality score's tone: bad under 0.5, warn under 0.8. The meter marks sit at the same two points. */
export const qualityTone = (score: number): "bad" | "warn" | "good" =>
  score < 0.5 ? "bad" : score < 0.8 ? "warn" : "good";

/**
 * The catalog's groups, in the order small companies get breached through
 * them: identity first, then mail and SaaS, endpoints, cloud, code, AI.
 */
export const CATALOG: { group: string; connectors: string[] }[] = [
  { group: "Identity", connectors: ["okta", "entra", "google_workspace"] },
  { group: "Email and SaaS", connectors: ["m365", "stripe", "cloudflare", "cloudflare_logs", "tailscale"] },
  {
    group: "Endpoint",
    connectors: ["crowdstrike", "defender", "sentinelone", "wazuh", "crowdstrike_fdr", "defender_hunting", "sentinelone_cloudfunnel"],
  },
  { group: "Cloud", connectors: ["aws_cloudtrail", "aws_guardduty", "azure_activity", "gcp_audit"] },
  { group: "Code", connectors: ["github", "gitlab"] },
  { group: "AI", connectors: ["anthropic", "openai"] },
];

/** Connectors grouped in catalog order; any the table does not name close the list under "Other". */
export function catalog(connectors: string[]): { group: string; connectors: string[] }[] {
  const named = new Set(CATALOG.flatMap((g) => g.connectors));
  const groups = CATALOG.map((g) => ({ group: g.group, connectors: g.connectors.filter((c) => connectors.includes(c)) }));
  const other = connectors.filter((c) => !named.has(c)).sort();
  return [...groups, { group: "Other", connectors: other }].filter((g) => g.connectors.length);
}

/* The rule logsource a connector feeds, where it is not simply `product: <connector>`. */
const FEEDS: Record<string, [product: string, service?: string]> = {
  aws_cloudtrail: ["aws", "cloudtrail"],
  aws_guardduty: ["aws", "guardduty"],
  cloudflare: ["cloudflare", "audit_log"],
  cloudflare_logs: ["cloudflare", "logpush"],
  google_workspace: ["google"],
  azure_activity: ["azure"],
  gcp_audit: ["gcp"],
  crowdstrike: ["edr", "alerts"],
  defender: ["edr", "alerts"],
  sentinelone: ["edr", "alerts"],
  wazuh: ["edr", "alerts"],
  crowdstrike_fdr: ["edr", "telemetry"],
  defender_hunting: ["edr", "telemetry"],
  sentinelone_cloudfunnel: ["edr", "telemetry"],
};

/** How many rules read what a connector delivers ("carries 21 rules"). */
export function rulesCarried(connector: string, rules: Pick<Rule, "logsource">[]): number {
  const [product, service] = FEEDS[connector] ?? [connector];
  return rules.filter((r) => r.logsource?.product === product && (!service || r.logsource?.service === service)).length;
}

/** A source's last error without the kernel's exception class and source prefix ("ConfigError: github: "). */
export const sourceError = (text: string) => text.replace(/^\w+(?:Error|Exception): (?:[\w.-]+: )?/, "");
