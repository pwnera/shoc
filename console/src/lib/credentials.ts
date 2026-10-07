/**
 * Response credentials in words and marks. A credential is named like a source
 * (`aws`, `aws:staging`); its provider is the vendor it speaks to (RFC 0031).
 */
import { platformName } from "./labels";

export const providerOf = (name: string) => name.split(":")[0] ?? name;
export const labelOf = (name: string) => name.split(":")[1] ?? "";

/** "okta" → "Okta"; paging is PagerDuty. */
export const vendorName = (provider: string) =>
  provider === "notify" ? "PagerDuty" : platformName(provider);

/** What `ProductLogo` draws for it; a product it has no logo for draws its initial. */
export const vendorLogo = (provider: string) => (provider === "notify" ? "pagerduty" : provider);

/** "aws:staging" → "AWS · staging". */
export const credentialName = (name: string) =>
  [vendorName(providerOf(name)), labelOf(name)].filter(Boolean).join(" · ");
