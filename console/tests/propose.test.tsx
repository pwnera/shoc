import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ProposeDialog } from "@/routes/case/ProposeDialog";
import type { CredentialList, PolicyView } from "@/types";

const credential = (provider: string) => ({
  name: provider,
  provider,
  accounts: [],
  settings: {},
  has_secret: true,
  missing: [],
  updated_at: "2026-10-01T00:00:00Z",
  sources: [],
});

const ACTIONS = ["aws.disable_access_key", "okta.suspend_user"];

function show({ dry, held, actions = ACTIONS }: { dry: boolean; held: string[]; actions?: string[] }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const policy: PolicyView = {
    defaults: { autonomy: "L2", dry_run: dry },
    actions: {},
    available_actions: actions,
    action_params: {},
  };
  const credentials: CredentialList = { configured: held.map(credential), needs: [], providers: {} };
  client.setQueryData(["policy.show"], { data: policy, summary: "", citations: [] });
  client.setQueryData(["credential.list"], credentials);
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <ProposeDialog caseUid="CASE-1" entities={{}} onDone={() => {}} onClose={() => {}} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const chips = () =>
  screen.getAllByRole("button", { hidden: true }).map((b) => b.textContent).filter((t) => /AWS|Okta/.test(t ?? ""));

describe("the propose dialog", () => {
  it("marks a platform with no credential and sorts it last", () => {
    show({ dry: false, held: ["okta"] });
    expect(chips()).toEqual(["Suspend Okta user", "Disable AWS key"]);
    expect(screen.getAllByText("no credential", { selector: ".sh-badge" })).toHaveLength(1);
  });

  it("says an action with no credential will fail, and links to connect one", () => {
    show({ dry: false, held: ["okta"] });
    fireEvent.click(screen.getByRole("button", { name: "Disable AWS key", hidden: true }));
    expect(screen.getAllByRole("link", { name: /will fail · connect AWS/, hidden: true })[0]).toHaveAttribute(
      "href",
      "/connections?vendor=aws&view=credential",
    );
  });

  it("promises no failure for a dry run, which needs no credential", () => {
    show({ dry: true, held: [] });
    fireEvent.click(screen.getByRole("button", { name: "Disable AWS key", hidden: true }));
    expect(screen.queryByRole("link", { name: /will fail/, hidden: true })).toBeNull();
  });

  it("promises no failure for a page, which the Manager sends without a credential", () => {
    show({ dry: false, held: [], actions: ["notify.page"] });
    expect(screen.queryByText("no credential", { selector: ".sh-badge" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Page on-call", hidden: true }));
    expect(screen.queryByRole("link", { name: /will fail/, hidden: true })).toBeNull();
  });
});
