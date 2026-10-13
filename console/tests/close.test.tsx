import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useCloseCase } from "@/lib/queries";
import { dismiss, useToasts } from "@/lib/toast";

function closing(data: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ data, summary: "", citations: [] }), { headers: { "content-type": "application/json" } })),
  );
  const client = new QueryClient();
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return renderHook(() => ({ close: useCloseCase(), toasts: useToasts() }), { wrapper });
}

describe("closing a case as expected", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("names what shoc did that is still in force, and stays with a way to undo it", async () => {
    const view = closing({
      case_uid: "CASE-1",
      state: "closed",
      verdict: "benign_expected",
      rejected_actions: 0,
      memory_id: "mem-1",
      still_in_force: [{ action_uid: "ACT-1", type: "aws.disable_access_key", target: "AKIAEXAMPLE" }],
    });
    await act(() => view.result.current.close.mutateAsync({ case_uid: "CASE-1", disposition: "benign_expected", reason: "travel" }));
    const [shown] = view.result.current.toasts;
    expect(shown?.text).toBe("Closed as Expected · still in force: Disable AWS key AKIAEXAMPLE");
    expect(shown?.life).toBe(Infinity);
    expect(shown?.action?.to).toBe("/cases/CASE-1?tab=response");
    act(() => dismiss(shown!.id));
  });

  it("says only the close when nothing is left in force", async () => {
    const view = closing({ case_uid: "CASE-2", state: "closed", verdict: "benign_expected", rejected_actions: 0, still_in_force: [] });
    await act(() => view.result.current.close.mutateAsync({ case_uid: "CASE-2", disposition: "benign_expected", reason: "travel" }));
    const [shown] = view.result.current.toasts;
    expect(shown?.text).toBe("Closed as Expected");
    expect(shown?.action).toBeUndefined();
    act(() => dismiss(shown!.id));
  });
});
