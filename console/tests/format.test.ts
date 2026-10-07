import { describe, expect, it } from "vitest";
import { age, ago, capped, compact, count, day, duration, left, middle, money, percent, shortId, span, time, truncate } from "@/lib/format";

describe("formatters", () => {
  it("says how long ago something was", () => {
    const now = Date.now();
    expect(ago(new Date(now - 30_000).toISOString())).toMatch(/^\d+s ago$/);
    expect(ago(new Date(now - 5 * 60_000).toISOString())).toBe("5m ago");
    expect(ago(new Date(now - 3 * 3600_000).toISOString())).toBe("3h ago");
    expect(ago(null)).toBe("never");
    expect(ago("not a date")).toBe("—");
  });

  it("pluralises without an s on the end of everything", () => {
    expect(count(1, "case")).toBe("1 case");
    expect(count(2, "case")).toBe("2 cases");
    expect(count(2, "finding", "findings")).toBe("2 findings");
  });

  it("shortens a count to k and M, never to 1000k", () => {
    expect(compact(999)).toBe("999");
    expect(compact(48_200)).toBe("48k");
    expect(compact(999_499)).toBe("999k");
    expect(compact(999_500)).toBe("1.0M");
    expect(compact(5_040_000)).toBe("5.0M");
  });

  it("formats money with cents, so nothing spent reads $0.00", () => {
    expect(money(12.5)).toBe("$12.50");
    expect(money(0)).toBe("$0.00");
    expect(money(0.004)).toBe("$0.00");
  });

  it("measures time in its largest unit, days included", () => {
    expect(span(45)).toBe("45s");
    expect(span(12 * 60)).toBe("12m");
    expect(span(3600 + 25 * 60)).toBe("1h25m");
    expect(span(3 * 3600)).toBe("3h");
    expect(span(274.6 * 3600)).toBe("11.4d");
    expect(span(2 * 86_400)).toBe("2d");
  });

  it("says ages and time left the way a row does", () => {
    const now = Date.parse("2026-10-03T12:00:00Z");
    const before = (s: number) => new Date(now - s * 1000).toISOString();
    expect(age(before(12 * 60), now)).toBe("12m");
    expect(age(before(3 * 3600 + 600), now)).toBe("3h");
    expect(age(before(3 * 86_400), now)).toBe("3d");
    expect(age(null, now)).toBe("never");
    expect(left(new Date(now + (3600 + 52 * 60) * 1000).toISOString(), now)).toBe("1h52");
    expect(left(new Date(now - 1000).toISOString(), now)).toBe("");
  });

  it("writes clock times and day headings", () => {
    const at = new Date(2026, 8, 25, 14, 2, 11).toISOString();
    expect(time(at)).toBe("14:02:11");
    expect(day(at)).toBe("Fri 25 Sep");
  });

  it("shortens ids and long values, and marks a capped count", () => {
    expect(shortId("CASE-172f787307524997fb73")).toBe("CASE-172f…");
    expect(shortId("F-edf08823eaed46b959b02028")).toBe("F-edf0…");
    expect(middle("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA…MPLE");
    expect(capped(200, 200)).toBe("200+");
    expect(capped(1707, 5000)).toBe("1,707");
  });

  it("formats the rest", () => {
    expect(percent(0.875)).toBe("88%");
    expect(duration(45)).toBe("45s");
    expect(duration(3 * 3600)).toBe("3.0h");
    expect(truncate("abcdef", 4)).toBe("abc…");
    expect(truncate("abc", 10)).toBe("abc");
  });
});
