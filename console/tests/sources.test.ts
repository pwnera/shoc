import { describe, expect, it } from "vitest";
import {
  catalog,
  connectorOf,
  deliveryState,
  modeOf,
  modes,
  qualityTone,
  rulesCarried,
  shownVolume,
  sourceName,
} from "@/lib/sources";
import { volumes } from "@/lib/queries";
import type { ConfiguredSource } from "@/types";

const row = (over: Partial<ConfiguredSource> = {}): ConfiguredSource => ({
  source: "tailscale",
  enabled: true,
  settings: {},
  interval_seconds: 300,
  has_secret: true,
  last_run_at: null,
  last_ok_at: "2026-09-30T08:00:00Z",
  last_error: null,
  events_seen: 12,
  ...over,
});
const push = { only: ["wazuh"], also: ["github"] };
const none = new Set<string>();

describe("delivery state", () => {
  it("says a polled source saved without a credential has none", () => {
    expect(deliveryState(row({ has_secret: false, last_ok_at: null }), push, none)).toBe(
      "no credential",
    );
  });

  it("says a polled source that never delivered is waiting, not delivering", () => {
    expect(deliveryState(row({ last_ok_at: null }), push, none)).toBe("waiting");
    expect(deliveryState(row(), push, none)).toBe("delivering");
    expect(deliveryState(row(), push, new Set(["tailscale"]))).toBe("late");
  });

  it("does not ask a push source for a credential, and waits for its first delivery", () => {
    const pushed = { has_secret: false, last_ok_at: null };
    expect(deliveryState(row({ source: "wazuh", ...pushed }), push, none)).toBe("waiting");
    expect(deliveryState(row({ source: "github", ...pushed }), push, none)).toBe("waiting");
    expect(deliveryState(row({ source: "github", has_secret: false }), push, none)).toBe("delivering");
  });

  it("says a silent push source has no recent push, not late", () => {
    const late = new Set(["github"]);
    expect(deliveryState(row({ source: "github", has_secret: false }), push, late)).toBe("no recent push");
    expect(deliveryState(row({ source: "github", has_secret: true }), push, late)).toBe("late");
    expect(deliveryState(row({ source: "github", has_secret: false, last_error: "boom" }), push, late)).toBe("failing");
  });

  it("reads a push source's error as stale once it delivered after the failed run", () => {
    const failed = { source: "github", has_secret: false, last_error: "ConfigError: settings need org" };
    const after = { last_run_at: "2026-09-30T03:00:00Z", last_ok_at: "2026-09-30T08:00:00Z" };
    expect(deliveryState(row({ ...failed, ...after }), push, none)).toBe("delivering");
    expect(deliveryState(row({ ...failed, last_run_at: "2026-09-30T09:00:00Z" }), push, none)).toBe("failing");
    // A polled source's error always counts: its own run failed.
    expect(deliveryState(row({ last_error: "401", ...after }), push, none)).toBe("failing");
    // Ops' source.failing alert wins over the staleness guess, and over a quiet push.
    expect(deliveryState(row({ ...failed, ...after }), push, none, true)).toBe("failing");
    expect(deliveryState(row({ source: "github", has_secret: false }), push, new Set(["github"]), true)).toBe("failing");
  });

  it("puts a pause and a failure before everything else", () => {
    expect(deliveryState(row({ enabled: false, has_secret: false }), push, none)).toBe("paused");
    expect(deliveryState(row({ last_error: "401", has_secret: false }), push, none)).toBe(
      "failing",
    );
  });
});

describe("delivery mode", () => {
  it("names what each connector can do", () => {
    expect(modes("wazuh", push)).toBe("push");
    expect(modes("github", push)).toBe("poll or push");
    expect(modes("okta", push)).toBe("poll");
    expect(modes("github:acme", push)).toBe("poll or push");
    expect(connectorOf("cloudflare:acme")).toBe("cloudflare");
  });

  it("names a source by its vendor, a second account by its suffix", () => {
    expect(sourceName("okta")).toBe("Okta");
    expect(sourceName("google_workspace")).toBe("Google Workspace");
    expect(sourceName("github")).toBe("GitHub");
    expect(sourceName("aws_cloudtrail")).toBe("AWS CloudTrail");
    expect(sourceName("cloudflare:acme")).toBe("Cloudflare · acme");
    expect(sourceName("aws_guardduty")).toBe("AWS GuardDuty");
    expect(sourceName("file")).toBe("File");
  });

  it("says a source that can do either pushes when it has no credential", () => {
    expect(modeOf(row({ source: "github", has_secret: false }), push)).toBe("push");
    expect(modeOf(row({ source: "github" }), push)).toBe("poll");
    expect(modeOf(row({ source: "wazuh" }), push)).toBe("push");
  });
});

describe("the volume mark Sources shows", () => {
  const silent = { day: 0, usual: 172, mark: "silent" as const };

  it("says a product its sources push has no recent push, as their rows read", () => {
    expect(shownVolume("GitHub Audit Log", silent, [{ source: "github", mode: "push" }]).mark).toBe("no recent push");
    // One polled account is enough for the silence to count.
    const both = [
      { source: "github", mode: "push" as const },
      { source: "github:acme", mode: "poll" as const },
    ];
    expect(shownVolume("GitHub Audit Log", silent, both).mark).toBe("silent");
    expect(shownVolume("GitHub Audit Log", silent, [{ source: "github", mode: "poll" }]).mark).toBe("silent");
  });

  it("reads a day with nothing from a product that sends under five a day as low, on every screen", () => {
    const month = [
      { product: "Cloudflare Audit Log", events: 27 },
      { product: "Okta System Log", events: 150 },
    ];
    const marks = volumes(month, 30, []);
    expect(marks["Cloudflare Audit Log"]!.mark).toBe("low");
    expect(marks["Okta System Log"]!.mark).toBe("silent");
  });

  it("leaves every other mark alone", () => {
    const low = { day: 3, usual: 40, mark: "low" as const };
    expect(shownVolume("GitHub Audit Log", low, [{ source: "github", mode: "push" }])).toBe(low);
  });
});

describe("the catalog", () => {
  it("groups connectors identity first and closes with the ones it does not name", () => {
    const groups = catalog(["github", "okta", "file", "aws_cloudtrail", "m365"]);
    expect(groups.map((g) => g.group)).toEqual(["Identity", "Email and SaaS", "Cloud", "Code", "Other"]);
    expect(groups[0]!.connectors).toEqual(["okta"]);
    expect(groups.at(-1)!.connectors).toEqual(["file"]);
  });

  it("counts the rules a connector carries from their logsource", () => {
    const rules = [
      { logsource: { product: "aws", service: "cloudtrail" } },
      { logsource: { product: "aws", service: "guardduty" } },
      { logsource: { product: "okta", service: "system_log" } },
      { logsource: { product: "edr", service: "alerts" } },
    ];
    expect(rulesCarried("aws_cloudtrail", rules)).toBe(1);
    expect(rulesCarried("aws_guardduty", rules)).toBe(1);
    expect(rulesCarried("okta", rules)).toBe(1);
    expect(rulesCarried("crowdstrike", rules)).toBe(1);
    expect(rulesCarried("crowdstrike_fdr", rules)).toBe(0);
  });

  it("tones a quality score bad under half and warn under four fifths", () => {
    expect([0.3, 0.6, 0.9].map(qualityTone)).toEqual(["bad", "warn", "good"]);
  });
});
