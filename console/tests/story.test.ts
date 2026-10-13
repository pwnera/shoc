import { describe, expect, it } from "vitest";
import { attackGraph, timeline } from "@/lib/story";
import type { Case, OcsfEvent } from "@/types";

function event(uid: string, time: string, extra: Partial<OcsfEvent>): OcsfEvent {
  return {
    event_uid: uid,
    time,
    class_name: null,
    activity_name: null,
    severity_id: null,
    status: null,
    actor_user_name: null,
    actor_session_uid: null,
    src_endpoint_ip: null,
    api_operation: null,
    api_service_name: null,
    cloud_account_uid: null,
    cloud_region: null,
    resource_uid: null,
    metadata_product: null,
    message: null,
    ...extra,
  };
}

const leak = [
  event("E1", "2026-09-01T10:00:00Z", {
    src_endpoint_ip: "203.0.113.5",
    actor_user_name: "ci-bot",
    actor_session_uid: "AKIAEXAMPLE",
    cloud_account_uid: "111122223333",
    api_operation: "ListBuckets",
  }),
  event("E2", "2026-09-01T10:05:00Z", {
    src_endpoint_ip: "203.0.113.5",
    actor_user_name: "ci-bot",
    actor_session_uid: "AKIAEXAMPLE",
    cloud_account_uid: "111122223333",
    resource_uid: "arn:aws:s3:::payroll",
    api_operation: "GetObject",
  }),
];

describe("attack graph", () => {
  it("chains each event's entities from source address to resource", () => {
    const { nodes, edges } = attackGraph(leak);
    expect(nodes.map((n) => n.id)).toContain("resource:arn:aws:s3:::payroll");
    expect(edges.find((e) => e.src === "ip:203.0.113.5")?.dst).toBe("user:ci-bot");
    expect(edges.find((e) => e.src === "user:ci-bot")).toMatchObject({ weight: 2 });
    expect(edges.find((e) => e.dst.startsWith("resource:"))?.operations).toEqual(["GetObject"]);
  });

  it("keys a sign-in session in the key lane as session:, and rings it for a finding on it", () => {
    const guid = "102d3b1c-5a4e-4f0b-9c1d-7e8f9a0b1c2d";
    const key = "AKIAIOSFODNN7EXAMPLE";
    const signIn = event("E3", "2026-09-01T11:00:00Z", {
      actor_user_name: "jane",
      actor_session_uid: guid,
    });
    const aws = event("E4", "2026-09-01T11:01:00Z", { actor_session_uid: key });
    type Named = NonNullable<Parameters<typeof attackGraph>[1]>[number];
    const finding = { severity: "high", entity_key: `session:${guid}` } as Named;
    const { nodes } = attackGraph([signIn, aws], [finding]);
    expect(nodes.find((n) => n.label === guid)).toMatchObject({
      id: `session:${guid}`,
      kind: "key",
      severity: "high",
    });
    expect(nodes.find((n) => n.label === key)?.id).toBe(`key:${key}`);
  });
});

describe("timeline", () => {
  it("puts the case, its events and its closing in time order", () => {
    const record = {
      opened_at: "2026-09-01T10:10:00Z",
      closed_at: "2026-09-01T12:00:00Z",
    } as Case;
    const moments = timeline(record, [], leak, [], []);
    expect(moments.map((m) => m.title)).toEqual(["ListBuckets", "GetObject", "Case opened", "Case closed"]);
  });
});
