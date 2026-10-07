import { describe, expect, it } from "vitest";
import { bare, exploreQuery, intelType, isAwsKey, kindOf, parseEntity } from "@/lib/entity";

describe("entity kinds", () => {
  it("types values precisely: a URL is not a domain, a domain is not an IP", () => {
    expect(kindOf("https://cdn.example.com/payload.bin")).toBe("url");
    expect(kindOf("hxxp://cdn.example/payload.bin")).toBe("url");
    expect(kindOf("cdn.example.com")).toBe("domain");
    expect(kindOf("203.0.113.5")).toBe("ip");
    expect(kindOf("198.51.100.0/24")).toBe("cidr");
    expect(kindOf("jane@acme.example")).toBe("email");
    expect(kindOf("CVE-2024-3094")).toBe("cve");
  });

  it("knows IPv6 from a MAC address and an impossible IPv4", () => {
    expect(parseEntity("2001:db8::1")?.type).toBe("ipv6");
    expect(kindOf("00:1a:2b:3c:4d:5e")).toBeNull();
    expect(kindOf("300.1.1.1")).toBeNull();
  });

  it("names hashes by length and keys by their AWS shape", () => {
    expect(parseEntity("a".repeat(64))?.type).toBe("sha256");
    expect(parseEntity("a".repeat(40))?.type).toBe("sha1");
    expect(parseEntity("a".repeat(32))?.type).toBe("md5");
    expect(parseEntity("AKIAIOSFODNN7EXAMPLE")).toMatchObject({ kind: "key", type: "aws key" });
    expect(parseEntity("arn:aws:s3:::payroll")).toMatchObject({ kind: "resource", type: "arn" });
  });

  it("lets a kind prefix win, and keeps what is not a known shape as nothing", () => {
    expect(parseEntity("user:jane@acme.example")).toMatchObject({ kind: "user", value: "jane@acme.example", key: "user:jane@acme.example" });
    expect(parseEntity("key:okta-session-123")).toMatchObject({ kind: "key", type: "key" });
    expect(parseEntity("ip:203.0.113.5")?.type).toBe("ipv4");
    expect(parseEntity("deploy-ci")).toBeNull();
    expect(bare("user:alice")).toBe("alice");
    expect(isAwsKey("key:AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(isAwsKey("key:okta-session-123")).toBe(false);
  });

  it("asks intel only about what intel answers, with the bare value's exact type", () => {
    expect(intelType(parseEntity("ip:203.0.113.5")!)).toBe("ip");
    expect(intelType(parseEntity("a".repeat(64))!)).toBe("sha256");
    expect(intelType(parseEntity("a".repeat(40))!)).toBe("");
    expect(intelType(parseEntity("user:alice")!)).toBe("");
  });

  it("finds an entity's events by its field, or as an exact word", () => {
    expect(exploreQuery(parseEntity("user:jane doe")!)).toBe('actor.user.name="jane doe"');
    expect(exploreQuery(parseEntity("key:AKIAIOSFODNN7EXAMPLE")!)).toBe("actor.session.uid=AKIAIOSFODNN7EXAMPLE");
    expect(exploreQuery(parseEntity("cdn.example.com")!)).toBe("cdn.example.com");
  });
});
