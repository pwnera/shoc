import { afterEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import {
  useConfigureCredential,
  useConfigureLlm,
  useConfigureLookup,
  useConfigureSlack,
  useConfigureSso,
  useConnectSource,
  usePushKey,
} from "@/lib/queries";

const SAVES: [string, () => { mutateAsync: (input: never) => Promise<unknown> }, Record<string, unknown>][] = [
  ["credential.configure", useConfigureCredential, { provider: "okta", settings: {}, secret: { token: "test-secret" } }],
  ["slack.configure", useConfigureSlack, { bot_token: "test-secret", signing_secret: "test-secret" }],
  ["llm.configure", useConfigureLlm, { api_key: "test-secret" }],
  ["sso.configure", useConfigureSso, { client_secret: "test-secret" }],
  ["source.configure", useConnectSource, { source: "okta", settings: {}, secret: { token: "test-secret" } }],
  ["intel.configure", useConfigureLookup, { lookup: "virustotal", secret: { api_key: "test-secret" } }],
];

describe("a typed secret after Save", () => {
  afterEach(() => vi.unstubAllGlobals());

  it.each(SAVES)("leaves the mutation cache once %s's form closes", async (_name, hook, input) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ data: {}, summary: "", citations: [] }), { headers: { "content-type": "application/json" } })),
    );
    const client = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result, unmount } = renderHook(() => hook(), { wrapper });
    await act(() => result.current.mutateAsync(input as never));
    expect(JSON.stringify(client.getMutationCache().getAll().map((m) => m.state.variables))).toContain("test-secret");
    unmount();
    await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
  });

  it("drops a push key shoc made once nothing shows it", async () => {
    const made = { source: "webhook", push_key: "test-push-key", signature_header: "x-sig", timestamp_header: "x-ts" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ data: made, summary: "", citations: [] }), { headers: { "content-type": "application/json" } })),
    );
    const client = new QueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
    const { result, unmount } = renderHook(() => usePushKey(), { wrapper });
    await act(() => result.current.mutateAsync({ source: "webhook" }));
    expect(JSON.stringify(client.getMutationCache().getAll().map((m) => m.state.data))).toContain("test-push-key");
    unmount();
    await waitFor(() => expect(client.getMutationCache().getAll()).toHaveLength(0));
  });
});
