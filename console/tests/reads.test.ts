import { afterEach, describe, expect, it, vi } from "vitest";
import { ON_SOURCES } from "@/lib/reads";

vi.mock("@/lib/stream", async (original) => ({ ...(await original<typeof import("@/lib/stream")>()), streamState: () => "live" }));

describe("source.list while the stream is live", () => {
  afterEach(() => window.history.replaceState(null, "", "/"));

  it("is polled on Connections and Health, where it shows, and nowhere else", () => {
    for (const [path, every] of [
      ["/connections", 30_000],
      ["/connections/okta", 30_000],
      ["/health", 30_000],
      ["/cases", false],
      ["/connectionsx", false],
    ] as const) {
      window.history.replaceState(null, "", path);
      expect(ON_SOURCES.refetchInterval(), path).toBe(every);
    }
  });
});
