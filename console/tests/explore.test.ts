import { describe, expect, it } from "vitest";
import { addTerm, exploreHref, splitTerms, term, word } from "@/lib/explore";

describe("a term going back into the box", () => {
  it("quotes a value with spaces and leaves a plain one alone", () => {
    expect(term("actor_user_name", "alice")).toBe("actor_user_name=alice");
    expect(term("message", "access denied")).toBe('message="access denied"');
    expect(term("status", "Success", "!=")).toBe("status!=Success");
  });

  it("keeps a quote in the value exact, as the kernel parses quotes", () => {
    expect(term("actor.user.name", "o'brien")).toBe(`actor.user.name="o'brien"`);
    expect(term("message", 'said "no"')).toBe(`message='said "no"'`);
    expect(term("message", `it's "fine" now`)).toBe("message~fine");
    expect(term("message", `it's "fine" now`, "!=")).toBe("message!~fine");
    expect(term("message", "")).toBe('message=""');
    expect(word("two words")).toBe('"two words"');
    expect(word("alice")).toBe("alice");
  });

  it("adds a term to the running query once", () => {
    expect(addTerm("status=Failure secret", "status=Failure")).toBe("status=Failure secret");
    expect(addTerm("status = Failure", "status=Failure")).toBe("status = Failure");
    expect(addTerm("secret", 'message="a b"')).toBe('secret message="a b"');
    expect(splitTerms(`actor.user.name="jane doe" status!=Success word`)).toEqual([
      'actor.user.name="jane doe"',
      "status!=Success",
      "word",
    ]);
  });

  it("links Explore over a window", () => {
    expect(exploreHref({ q: "status=Failure", since: "-1h" })).toBe("/explore?q=status%3DFailure&since=-1h");
    expect(exploreHref({})).toBe("/explore");
  });
});
