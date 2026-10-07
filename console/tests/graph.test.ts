import { describe, expect, it } from "vitest";
import { layered, radial } from "@/lib/graph";

const node = (id: string, kind: string, weight = 1) => ({ id, kind, label: id, weight });

describe("layered layout", () => {
  it("puts each lane in its own column and ends a full lane in a stub", () => {
    const nodes = [node("ip1", "ip", 5), node("u1", "user", 3), ...Array.from({ length: 12 }, (_, i) => node(`r${i}`, "resource", 12 - i))];
    const links = [{ src: "ip1", dst: "u1", weight: 4 }, { src: "u1", dst: "r0" }];
    const out = layered(nodes, links, { width: 600, height: 300, lanes: ["ip", "user", "resource"], perLane: 10 });
    const x = (id: string) => out.nodes.find((n) => n.id === id)?.x;
    expect(x("ip1")).toBeLessThan(x("u1")!);
    expect(x("u1")).toBeLessThan(x("r0")!);
    expect(out.nodes.filter((n) => n.kind === "resource")).toHaveLength(10);
    expect(out.more).toEqual([expect.objectContaining({ lane: "resource", ids: ["r10", "r11"] })]);
    expect(out.links).toHaveLength(2);
    expect(out.links[0]!.width).toBeGreaterThan(out.links[1]!.width);
    for (const n of out.nodes) {
      expect(n.size).toBeGreaterThanOrEqual(16);
      expect(n.size).toBeLessThanOrEqual(28);
    }
  });

  it("draws no link to a node it left in the stub", () => {
    const nodes = [node("u", "user"), node("a", "resource", 2), node("b", "resource", 1)];
    const out = layered(nodes, [{ src: "u", dst: "b" }], { width: 300, height: 200, lanes: ["user", "resource"], perLane: 1 });
    expect(out.links).toEqual([]);
  });
});

describe("radial layout", () => {
  it("centres the root, rings the hops and labels only the busiest", () => {
    const nodes = [node("root", "user"), ...Array.from({ length: 12 }, (_, i) => node(`n${i}`, "ip", i + 1)), node("far", "key")];
    const links = [...Array.from({ length: 12 }, (_, i) => ({ src: "root", dst: `n${i}` })), { src: "n0", dst: "far" }];
    const out = radial(nodes, links, { width: 400, height: 400, root: "root", labels: 8 });
    const at = (id: string) => out.nodes.find((n) => n.id === id)!;
    expect(at("root")).toMatchObject({ x: 200, y: 200, labelled: true });
    const r = (id: string) => Math.hypot(at(id).x - 200, at(id).y - 200);
    expect(r("far")).toBeGreaterThan(r("n0"));
    expect(out.nodes.filter((n) => n.labelled)).toHaveLength(9);
    expect(at("n11").labelled).toBe(true);
    expect(at("n0").labelled).toBe(false);
  });
});
