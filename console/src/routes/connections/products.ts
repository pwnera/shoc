/**
 * Connections › Products: one row per product shoc reads or acts on, its log
 * sources and its own response credential side by side (D124). A source
 * belongs to the product whose credential its connector calls for first
 * (`source.list` `response`, the kernel's RESPONDS), else to its connector:
 * CloudTrail and GuardDuty are AWS, Cloudflare's logs are Cloudflare.
 * Paging (PagerDuty) is a Service, not a product.
 */
import type { StatusTone } from "@/components/ui/status";
import { vendorLogo, vendorName } from "@/lib/credentials";
import { connectorOf, sourceName } from "@/lib/sources";
import type { ConfiguredSource, CredentialList, ResponseCredential, ResponseNeed } from "@/types";
import type { View } from "./state";

export type Product = {
  /** "aws", "okta", or a connector with no credential of its own ("file"). */
  key: string;
  /** Empty for a product shoc reads and cannot act on. */
  provider: string;
  sources: ConfiguredSource[];
  credentials: ResponseCredential[];
  /** Who covers it, and the accounts its sources named that none claims. */
  need?: ResponseNeed;
};

export const productOf = (row: ConfiguredSource): string =>
  row.response?.[0]?.provider ?? connectorOf(row.source);

/** A product by key, empty when nothing of it is connected yet. */
export function product(key: string, data: CredentialList | undefined): Product {
  return {
    key,
    provider: data?.providers[key] ? key : "",
    sources: [],
    credentials: [],
    need: data?.needs.find((n) => n.provider === key),
  };
}

/** Every product with a source or a credential. */
export function products(sources: ConfiguredSource[], data: CredentialList | undefined): Product[] {
  const out = new Map<string, Product>();
  const at = (key: string) => out.get(key) ?? out.set(key, product(key, data)).get(key)!;
  for (const row of sources) at(productOf(row)).sources.push(row);
  for (const c of data?.configured ?? []) if (c.provider !== "notify") at(c.provider).credentials.push(c);
  return [...out.values()];
}

export const productName = (p: Product) =>
  p.provider ? vendorName(p.provider) : sourceName(p.sources[0]?.source ?? p.key);

export const productLogo = (p: Product) => (p.provider ? vendorLogo(p.provider) : connectorOf(p.key));

/** Whether shoc can act on it, in the words the Response view uses; null when there is nothing to act with. */
export function responseState(p: Product): string | null {
  if (!p.provider) return null;
  if (!p.credentials.length) return "not connected";
  if (p.credentials.some((c) => c.missing.length || !c.has_secret)) return "incomplete";
  // The vendor refused its last read: it acts on nothing, whatever it covers.
  if (p.credentials.some((c) => c.check_ok === false)) return "refused";
  return p.need?.missing.length ? "not covered" : "connected";
}

export const RESPONSE_TONE: Record<string, StatusTone> = {
  refused: "bad",
  "not connected": "warn",
  incomplete: "warn",
  "not covered": "warn",
  connected: "good",
};

/* Logs first, worst first: a failing feed outranks a credential not yet given. */
const RANK: Record<string, number> = {
  failing: 0,
  refused: 0,
  late: 1,
  "no credential": 1,
  "not connected": 2,
  incomplete: 2,
  "not covered": 2,
  waiting: 3,
  "no recent push": 3,
  paused: 3,
};

/** The row's order: its worst logs word or response word, then its name. */
export function sortProducts(rows: Product[], logs: (p: Product) => string): Product[] {
  const rank = (p: Product) => Math.min(RANK[logs(p)] ?? 4, RANK[responseState(p) ?? ""] ?? 4);
  return [...rows].sort((a, b) => rank(a) - rank(b) || productName(a).localeCompare(productName(b)));
}

export const COLLECTION: View[] = ["delivery", "settings", "onboarding", "footprint"];
export const RESPONSE: View[] = ["response", "credential", "grant"];

/** A product's views: its sources' four (or, with none, the connectors to bring them in), then its credential's three. */
export function viewsOf(p: Product): View[] {
  return [...(p.sources.length ? COLLECTION : (["delivery"] as View[])), ...(p.provider ? RESPONSE : [])];
}

/* The same view on the other side: Settings stays Settings when the side changes. */
const TWIN: Record<View, View> = {
  delivery: "response",
  settings: "credential",
  onboarding: "grant",
  footprint: "response",
  response: "delivery",
  credential: "settings",
  grant: "onboarding",
};

/** Where switching side lands: the twin view, else that side's first. */
export function otherSide(p: Product, view: View): View | undefined {
  const views = viewsOf(p);
  const twin = TWIN[view];
  if (views.includes(twin)) return twin;
  return views.find((v) => RESPONSE.includes(v) !== RESPONSE.includes(view));
}
