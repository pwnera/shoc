import { describe, expect, it } from "vitest";
import { credentialName, vendorLogo, vendorName } from "@/lib/credentials";

describe("response credentials in words", () => {
  it("names the vendor a provider is", () => {
    expect(vendorName("okta")).toBe("Okta");
    expect(vendorName("crowdstrike")).toBe("CrowdStrike");
    expect(vendorName("aws")).toBe("AWS");
    expect(vendorName("notify")).toBe("PagerDuty");
  });

  it("adds a second tenant's label to the vendor", () => {
    expect(credentialName("aws:staging")).toBe("AWS · staging");
    expect(credentialName("entra")).toBe("Entra ID");
  });

  it("draws the provider's logo, and PagerDuty's for paging", () => {
    expect(vendorLogo("okta")).toBe("okta");
    expect(vendorLogo("cloudflare")).toBe("cloudflare");
    expect(vendorLogo("notify")).toBe("pagerduty");
  });
});
