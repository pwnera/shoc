import { describe, expect, it } from "vitest";
import { IN_CASE, ROLES, parseLookedUp, parseStance, who } from "@/lib/crew";

describe("who wrote it", () => {
  it("draws the eleven roles with their monograms, the Integrator as code", () => {
    expect(ROLES).toHaveLength(11);
    expect(who("Investigator")).toMatchObject({ kind: "crew", mono: "IN", key: "Investigator" });
    expect(who("agent:IR Commander")).toMatchObject({ kind: "crew", mono: "IR" });
    expect(who("Integrator")).toMatchObject({ kind: "code", mono: "IG" });
    // A schema migration that decided an item is shoc's own hand, never a bare "?".
    expect(who("migration:019")).toMatchObject({ kind: "system", name: "migration 019", glyph: "mark" });
    expect(IN_CASE).toEqual(["Investigator", "Challenger", "IR Commander", "CTI", "Surveyor"]);
  });

  it("reads retired names as their successors, with a tip saying so", () => {
    expect(who("Orchestrator")).toMatchObject({ name: "Investigator", legacy: "Orchestrator" });
    expect(who("Tuner")).toMatchObject({ name: "Detection Engineer", legacy: "Tuner" });
    expect(who("Reporter")).toMatchObject({ name: "Manager", legacy: "Reporter" });
    expect(who("manager")).toMatchObject({ name: "Manager", mono: "MG" });
    expect(who("manager").legacy).toBeUndefined();
  });

  it("tells people, the system and outside agents apart, and never guesses crew", () => {
    expect(who("human:rettila")).toMatchObject({ kind: "human", name: "rettila", mono: "R", key: "human:rettila" });
    expect(who("human:human:jane")).toMatchObject({ kind: "human", name: "jane" });
    expect(who("unattended")).toMatchObject({ kind: "system", glyph: "clock" });
    expect(who("playbook-runner")).toMatchObject({ kind: "system", glyph: "cog" });
    expect(who("expiry")).toMatchObject({ kind: "system", glyph: "hourglass" });
    expect(who("shoc")).toMatchObject({ kind: "system", glyph: "mark" });
    expect(who("external_agent:copilot")).toMatchObject({ kind: "external", name: "copilot" });
    expect(who("Someone New")).toMatchObject({ kind: "unknown", mono: "?" });
    expect(who(null).kind).toBe("unknown");
  });
});

describe("structure the kernel keeps in prose", () => {
  it("splits off what an agent looked up", () => {
    expect(parseLookedUp("Key used from a new ASN. [Looked up: events.query x3, timeline.build]")).toEqual({
      text: "Key used from a new ASN.",
      tools: [
        { name: "events.query", count: 3 },
        { name: "timeline.build", count: 1 },
      ],
    });
    expect(parseLookedUp("Nothing checked.")).toEqual({ text: "Nothing checked.", tools: [] });
  });

  it("splits off the Challenger's stance", () => {
    expect(parseStance("[arguing benign, grounded in written_fact] CI rotates keys weekly.")).toEqual({
      text: "CI rotates keys weekly.",
      arguing: "benign",
      grounded: "written fact",
    });
    expect(parseStance("plain")).toEqual({ text: "plain" });
  });
});
