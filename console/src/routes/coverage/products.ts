/**
 * Which arriving product each rule and hunt pack reads, and the matrix of
 * working rules (any that can fire) per product and tactic, tested without a DOM.
 *
 * A rule names a logsource (`aws`/`cloudtrail`); events name a product
 * (`AWS CloudTrail`). The kernel joins them through its mappings
 * (`shoc/store/ocsf.py` `products_for`), which no capability returns yet, so
 * MAPPINGS copies each mapping's `logsource` keys from
 * `shoc/ingest/mappings/*.yaml` (a mapping with none answers to its own
 * name). `tests/program.test.tsx` fails when a mapping changes without this.
 */
import { tacticsOf, type Tactic } from "@/lib/attack";
import { ruleState } from "@/lib/labels";
import type { HuntReadiness, Rule, RuleHealth } from "@/types";

export const MAPPINGS: Record<string, string[]> = {
  Anthropic: ["anthropic"],
  "AWS CloudTrail": ["aws", "aws/cloudtrail"],
  "AWS GuardDuty": ["aws", "aws/guardduty"],
  "Azure Activity Log": ["azure"],
  "Cloudflare Audit Log": ["cloudflare"],
  "Cloudflare Logpush": ["cloudflare/logpush", "dns"],
  "CrowdStrike Falcon": ["edr", "edr/alerts"],
  "CrowdStrike Falcon Data Replicator": ["edr", "edr/telemetry", "dns"],
  "Microsoft Defender": ["edr", "edr/alerts"],
  "Microsoft Defender Advanced Hunting": ["edr", "edr/telemetry", "dns"],
  "Microsoft Entra ID": ["entra"],
  "GCP Cloud Audit": ["gcp"],
  "GitHub Audit Log": ["github"],
  "GitLab Audit Events": ["gitlab"],
  "Google Workspace": ["google"],
  "Microsoft 365": ["m365"],
  "Okta System Log": ["okta"],
  OpenAI: ["openai"],
  SentinelOne: ["edr", "edr/alerts"],
  "SentinelOne Cloud Funnel": ["edr", "edr/telemetry", "dns"],
  Stripe: ["stripe"],
  "Tailscale Configuration Log": ["tailscale"],
  Wazuh: ["edr", "edr/alerts"],
};

const answering = (key: string) => Object.keys(MAPPINGS).filter((name) => MAPPINGS[name]!.includes(key));

/** The products a logsource covers: the product/service key, else the product alone (as the kernel looks them up). */
export function productsFor(product = "", service = ""): string[] {
  const p = product.toLowerCase();
  const exact = service ? answering(`${p}/${service.toLowerCase()}`) : [];
  return exact.length ? exact : answering(p);
}

/** The Detection filter value for a product: its logsource product. */
export const logsourceOf = (product: string) => (MAPPINGS[product]?.[0] ?? "").split("/")[0] ?? "";

/** A rule that can fire on what arrives: live, armed, or firing too often. Failing and blind rules see nothing. */
export const canFire = (health: RuleHealth | undefined) => {
  const state = ruleState(health);
  return state === "live" || state === "armed" || state === "noisy";
};

export type Cell = { rules: Rule[]; packs: HuntReadiness[] };

export type Coverage = {
  /** product → tactic → what covers it. */
  cells: Map<string, Map<Tactic, Cell>>;
  /** Working rules per product, whatever their tactics. */
  working: Map<string, number>;
  /** Tactics with at least one working rule on an arriving product. */
  lit: Set<Tactic>;
};

export function coverage(
  products: string[],
  rules: Rule[],
  health: Map<string, RuleHealth>,
  readiness: HuntReadiness[],
): Coverage {
  const arriving = new Set(products);
  const cells = new Map(products.map((p) => [p, new Map<Tactic, Cell>()]));
  const working = new Map(products.map((p) => [p, 0]));
  const lit = new Set<Tactic>();
  const at = (product: string, tactic: Tactic) => {
    const row = cells.get(product)!;
    if (!row.has(tactic)) row.set(tactic, { rules: [], packs: [] });
    return row.get(tactic)!;
  };
  for (const rule of rules) {
    if (!canFire(health.get(rule.id))) continue;
    const covers = productsFor(rule.logsource.product, rule.logsource.service).filter((p) => arriving.has(p));
    for (const product of covers) {
      working.set(product, (working.get(product) ?? 0) + 1);
      for (const tactic of tacticsOf(rule.attack)) {
        at(product, tactic).rules.push(rule);
        lit.add(tactic);
      }
    }
  }
  for (const pack of readiness) {
    if (pack.state !== "ready") continue;
    for (const product of productsFor(pack.product).filter((p) => arriving.has(p)))
      for (const tactic of tacticsOf(pack.attack ?? [])) at(product, tactic).packs.push(pack);
  }
  return { cells, working, lit };
}
