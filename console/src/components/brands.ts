/**
 * Official logos, served from `public/brands/`. Taken from the Iconify
 * collections (logos, selfhst, thesvg); SentinelOne is its wordmark cropped to
 * the symbol. Every row draws a product's or platform's mark through
 * `ProductLogo`, which falls back to the initial where there is no logo here.
 */
import { platformName } from "@/lib/labels";

export type Brand = { label: string; src: string };

const brand = (label: string, file: string): Brand => ({ label, src: `/brands/${file}.svg` });

export const BRANDS = {
  okta: brand("Okta", "okta"),
  entra: brand("Entra ID", "entra"),
  workspace: brand("Google Workspace", "workspace"),
  m365: brand("Microsoft 365", "m365"),
  defender: brand("Defender", "defender"),
  crowdstrike: brand("CrowdStrike", "crowdstrike"),
  sentinelone: brand("SentinelOne", "sentinelone"),
  aws: brand("AWS", "aws"),
  azure: brand("Azure", "azure"),
  gcp: brand("GCP", "gcp"),
  github: brand("GitHub", "github"),
  gitlab: brand("GitLab", "gitlab"),
  cloudflare: brand("Cloudflare", "cloudflare"),
  stripe: brand("Stripe", "stripe"),
  tailscale: brand("Tailscale", "tailscale"),
  wazuh: brand("Wazuh", "wazuh"),
  claude: brand("Claude", "claude"),
  chatgpt: brand("ChatGPT", "chatgpt"),
  cursor: brand("Cursor", "cursor"),
};

/* Most specific first: "Microsoft Defender" is Defender, not Microsoft 365. */
const PRODUCTS: [RegExp, Brand][] = [
  [/defender/i, BRANDS.defender],
  [/entra|azure ad/i, BRANDS.entra],
  [/azure/i, BRANDS.azure],
  [/microsoft|m365|office|exchange/i, BRANDS.m365],
  [/aws|amazon|cloudtrail|guardduty/i, BRANDS.aws],
  [/okta/i, BRANDS.okta],
  [/github/i, BRANDS.github],
  [/gitlab/i, BRANDS.gitlab],
  [/workspace|google/i, BRANDS.workspace],
  [/gcp|cloud audit/i, BRANDS.gcp],
  [/crowdstrike|falcon/i, BRANDS.crowdstrike],
  [/sentinelone/i, BRANDS.sentinelone],
  [/cloudflare/i, BRANDS.cloudflare],
  [/stripe/i, BRANDS.stripe],
  [/tailscale/i, BRANDS.tailscale],
  [/wazuh/i, BRANDS.wazuh],
  [/anthropic|claude/i, BRANDS.claude],
  [/openai|chatgpt/i, BRANDS.chatgpt],
];

/** The logo of an event's `metadata_product`, or null when the console has none. */
export function brandOf(product: string | null | undefined): Brand | null {
  if (!product) return null;
  return PRODUCTS.find(([test]) => test.test(product))?.[1] ?? null;
}

/** A product in words: its logo's name, its platform's ("cloudflare_logs" → Cloudflare), else as it is. */
export function productName(product: string): string {
  const logo = brandOf(product);
  if (logo) return logo.label;
  const id = product.toLowerCase().split(/[^a-z0-9]+/)[0] ?? "";
  const name = platformName(id);
  return name !== id ? name : product;
}

/**
 * The platform an action type acts on (its prefix): its name and its logo when
 * the console has one. OpenAI's logo is
 * ChatGPT's, Anthropic's is Claude's; the name stays the platform's. A prefix
 * the labels do not name takes its logo's ("cursor" → Cursor).
 */
export function platformOf(type: string): { id: string; name: string; logo: Brand | null } {
  const id = type.split(".")[0] ?? type;
  const logo = brandOf(id);
  const name = platformName(type);
  return { id, name: name === id && logo ? logo.label : name, logo };
}
