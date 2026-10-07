import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import { Connections } from "@/routes/Connections";
import { products, responseState, sortProducts } from "@/routes/connections/products";
import type { ConfiguredSource, CredentialList } from "@/types";

const at = (hoursAgo: number) => new Date(Date.now() - hoursAgo * 3_600_000).toISOString();

const source = (name: string, over: Partial<ConfiguredSource> = {}): ConfiguredSource => ({
  source: name,
  enabled: true,
  settings: {},
  interval_seconds: 300,
  has_secret: true,
  last_run_at: at(0.1),
  last_ok_at: at(0.1),
  last_error: null,
  events_seen: 5,
  ...over,
});

const SOURCES = [
  source("okta", { response: [{ provider: "okta", credentials: [], missing: ["acme.okta.com"] }] }),
  source("aws_cloudtrail:prod", { response: [{ provider: "aws", credentials: ["aws:prod"], missing: [] }] }),
  source("aws_guardduty", { response: [{ provider: "aws", credentials: ["aws:prod"], missing: [] }] }),
];

const CREDENTIALS: CredentialList = {
  configured: [
    {
      name: "aws:prod",
      provider: "aws",
      accounts: ["111111111111"],
      settings: { regions: "eu-west-1" },
      has_secret: true,
      missing: [],
      updated_at: at(1),
      sources: ["aws_cloudtrail:prod", "aws_guardduty"],
    },
  ],
  needs: [
    { provider: "notify", sources: [], credentials: [], missing: [] },
    { provider: "okta", sources: ["okta"], credentials: [], missing: ["acme.okta.com"] },
    { provider: "aws", sources: ["aws_cloudtrail:prod", "aws_guardduty"], credentials: ["aws:prod"], missing: [] },
  ],
  providers: {
    aws: {
      settings: [],
      optional: ["regions"],
      secret: ["access_key_id", "secret_access_key"],
      alternative: [],
      grant: "iam:UpdateAccessKey",
      connectors: ["aws_cloudtrail", "aws_guardduty"],
      actions: ["aws.disable_access_key"],
    },
    okta: {
      settings: ["org_url"],
      optional: [],
      secret: ["api_token"],
      alternative: [],
      grant: "a super administrator's token",
      where: "Admin Console → Security → API → Tokens → Create token",
      connectors: ["okta"],
      actions: ["okta.revoke_sessions"],
    },
    notify: {
      settings: [],
      optional: [],
      secret: ["routing_key"],
      alternative: [],
      grant: "an Events v2 key",
      connectors: [],
      actions: ["notify.page"],
    },
  },
};

const DATA: Record<string, unknown> = {
  "source/list": { configured: SOURCES, available: ["okta", "aws_cloudtrail", "aws_guardduty"], push_only: [], also_push: [], mappings: [], needs: {}, onboarding: [] },
  "health/sources": { sources: [], ok: true },
  "credential/list": CREDENTIALS,
  "credential/configure": { provider: "okta", configured: ["aws:prod", "okta"], missing: [], verified: true, verify_detail: "signed in as admin@acme.example" },
  "policy/show": {
    defaults: { autonomy: "L2" },
    principals: {},
    actions: { "aws.disable_access_key": { autonomy: "L1", reversible: true } },
    guards: {},
    available_actions: ["aws.disable_access_key", "okta.revoke_sessions"],
    action_params: {},
  },
  "intel/list": {
    rows: [],
    count: 0,
    total: 0,
    feeds: [{ feed: "abuse_ch_urlhaus", enabled: true, last_ok_at: at(2), last_error: "HTTP 503", indicators: 7 }],
    lookups: [],
    presets: [],
  },
  "llm/show": { provider: "anthropic", model: "claude-x", model_cheap: "", base_url: "", key: "set", stored: [], spend_usd_per_day: 0, hunt_tokens_per_day: 0 },
  "slack/show": { channel: "", approvers: {}, has_bot_token: false, verifies_requests: false },
  "ops/alerts": { alerts: [], count: 0 },
  "own/list": { rows: [], count: 0 },
  "health/cost": { spend: { rows: [], usd_total: 0, usd_today: 0, tokens: 0, days: 30 }, volume: { events: 0, days: 30, by_product: [] } },
  "events/summarize": { rows: [] },
  "health/quality": { sources: [] },
  "rule/list": { rules: [], count: 0 },
};

let calls: { path: string; body: Record<string, unknown> }[] = [];

function Here() {
  const location = useLocation();
  return <p data-testid="here">{location.search}</p>;
}

function show(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Connections />
        <Here />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("products", () => {
  it("puts a product's sources and its credential in one row, and paging elsewhere", () => {
    const rows = products(SOURCES, CREDENTIALS);
    expect(rows.map((p) => p.key).sort()).toEqual(["aws", "okta"]);
    const aws = rows.find((p) => p.key === "aws")!;
    expect(aws.sources.map((s) => s.source)).toEqual(["aws_cloudtrail:prod", "aws_guardduty"]);
    expect(aws.credentials.map((c) => c.name)).toEqual(["aws:prod"]);
    expect(responseState(aws)).toBe("connected");
    expect(responseState(rows.find((p) => p.key === "okta")!)).toBe("not connected");
  });

  it("lists a product shoc cannot act on before one it can", () => {
    const sorted = sortProducts(products(SOURCES, CREDENTIALS), () => "delivering");
    expect(sorted.map((p) => p.key)).toEqual(["okta", "aws"]);
  });

  it("calls a credential the vendor refused refused, not connected, and ranks it with a failing feed", () => {
    const refused = { ...CREDENTIALS, configured: [{ ...CREDENTIALS.configured[0]!, checked_at: at(1), check_ok: false }] };
    const aws = products(SOURCES, refused).find((p) => p.key === "aws")!;
    expect(responseState(aws)).toBe("refused");
    expect(sortProducts(products(SOURCES, refused), () => "delivering").map((p) => p.key)).toEqual(["aws", "okta"]);
  });

});

describe("the Connections screen", () => {
  beforeEach(() => {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        const path = new URL(url, "http://x").pathname.replace(/^\/v1\//, "");
        calls.push({ path, body: JSON.parse(String(init?.body ?? "{}")) });
        return Promise.resolve(
          new Response(JSON.stringify({ data: DATA[path] ?? {}, summary: "", citations: [] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("shows each product's logs and response apart, the one shoc cannot act on first", async () => {
    show("/connections");
    await waitFor(() => expect(document.querySelectorAll("tbody tr[data-row-key]")).toHaveLength(2));
    expect(screen.getByRole("columnheader", { name: "Logs" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Response" })).toBeInTheDocument();
    const words = (row: Element) => [...row.querySelectorAll(".sh-status")].map((s) => s.textContent);
    const [okta, aws] = [...document.querySelectorAll("tbody tr[data-row-key]")];
    expect(okta).toHaveTextContent("Okta");
    expect(words(okta!)).toEqual(["delivering", "not connected"]);
    expect(aws).toHaveTextContent("AWS");
    expect(words(aws!)).toEqual(["delivering", "connected"]);
    // The strip counts products as the list does: three sources, two products.
    expect(screen.getByText("2 of 2")).toBeInTheDocument();
  });

  it("reviews a product's response apart from its collection: the acts, the credential, its last check", async () => {
    show("/connections?source=aws_guardduty&view=response");
    expect(await screen.findByText("Disable AWS key")).toBeInTheDocument();
    expect(screen.getByText("111111111111")).toBeInTheDocument();
    expect(screen.getByText("never")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Response", checked: true, hidden: true })).toBeInTheDocument();
    // The other side keeps the view: Review there is the logs' review.
    await userEvent.click(screen.getByRole("radio", { name: "Logs", hidden: true }));
    expect(screen.getByTestId("here").textContent).not.toContain("view=");
    expect(await screen.findByText("Last ok")).toBeInTheDocument();
  });

  it("onboards a credential with its own steps, grant and click path", async () => {
    show("/connections?vendor=okta&view=grant");
    expect(await screen.findByText("a super administrator's token")).toBeInTheDocument();
    expect(screen.getByText("stored")).toBeInTheDocument();
    expect(screen.getByText("Tokens")).toBeInTheDocument();
  });

  it("connects a product with the accounts its sources saw, and says what the read returned", async () => {
    show("/connections?vendor=okta&view=credential");
    await screen.findByText("a super administrator's token");
    await userEvent.click(screen.getByRole("button", { name: /acme\.okta\.com/, hidden: true }));
    await userEvent.type(screen.getByLabelText("org url"), "https://acme.okta.com");
    await userEvent.type(screen.getByLabelText("api token"), "00token");
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));
    // credential.configure is L2: Save asks first.
    expect(calls.some((c) => c.path === "credential/configure")).toBe(false);
    const confirm = within(document.querySelector(".sh-confirm") as HTMLElement);
    expect(confirm.getByText("Connect Okta")).toBeInTheDocument();
    expect(confirm.getByText("acts in: acme.okta.com")).toBeInTheDocument();
    await userEvent.click(confirm.getByRole("button", { name: "Connect", hidden: true }));
    await waitFor(() => expect(calls.some((c) => c.path === "credential/configure")).toBe(true));
    expect(calls.find((c) => c.path === "credential/configure")!.body).toEqual({
      provider: "okta",
      settings: { org_url: "https://acme.okta.com", accounts: ["acme.okta.com"] },
      secret: { api_token: "00token" },
      verify: true,
    });
    expect(await screen.findByText("signed in as admin@acme.example")).toBeInTheDocument();
    expect(screen.getByText("works")).toBeInTheDocument();
  });

  it("refuses another account under a name that is taken", async () => {
    show("/connections?vendor=aws&view=credential&credential=%2B");
    await screen.findByText("iam:UpdateAccessKey");
    await userEvent.type(screen.getByLabelText("label"), "prod");
    expect(await screen.findByText(/aws:prod is connected/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));
    expect(calls.some((c) => c.path === "credential/configure")).toBe(false);
  });

  it("lands on another account once it is saved, without calling its own name taken", async () => {
    show("/connections?vendor=aws&view=credential&credential=%2B");
    await screen.findByText("iam:UpdateAccessKey");
    await userEvent.type(screen.getByLabelText("label"), "staging");
    await userEvent.type(screen.getByLabelText("access key id"), "AKIDEXAMPLE");
    await userEvent.type(screen.getByLabelText("secret access key"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));
    await userEvent.click(within(document.querySelector(".sh-confirm") as HTMLElement).getByRole("button", { name: "Connect", hidden: true }));
    await waitFor(() => expect(screen.getByTestId("here").textContent).toContain("credential=aws%3Astaging"));
    expect(calls.find((c) => c.path === "credential/configure")!.body.provider).toBe("aws:staging");
    expect(screen.queryByText(/is connected/)).not.toBeInTheDocument();
  });

  it("keeps a stored secret when the credential saves without replacing it", async () => {
    show("/connections?vendor=aws&view=credential");
    expect(await screen.findByDisplayValue("stored ••••")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));
    await userEvent.click(within(document.querySelector(".sh-confirm") as HTMLElement).getByRole("button", { name: "Save", hidden: true }));
    await waitFor(() => expect(calls.some((c) => c.path === "credential/configure")).toBe(true));
    expect(calls.find((c) => c.path === "credential/configure")!.body).toEqual({
      provider: "aws:prod",
      settings: { regions: "eu-west-1", accounts: ["111111111111"] },
      secret: {},
      verify: true,
    });
  });

  it("lists the intel sources, failing first, and the services shoc runs on", async () => {
    show("/connections?tab=intel");
    const row = await screen.findByText("URLhaus");
    expect(row.closest("tr")).toHaveTextContent("failing");
    await userEvent.click(screen.getByRole("tab", { name: /Services/ }));
    expect(await screen.findByText("claude-x", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("Slack").closest("tr")).toHaveTextContent("not connected");
    expect(screen.getByText("PagerDuty").closest("tr")).toHaveTextContent("not connected");
  });

  it("opens PagerDuty with no key on its Settings, its view in the URL", async () => {
    show("/connections?tab=services&service=paging");
    expect(await screen.findByText("an Events v2 key")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Settings", checked: true, hidden: true })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: "Onboarding", hidden: true }));
    expect(screen.getByTestId("here").textContent).toContain("view=grant");
  });

  it("asks the L2 confirm before it changes the model, naming what changes", async () => {
    show("/connections?tab=services&service=model");
    const model = await screen.findByLabelText("model");
    await userEvent.clear(model);
    await userEvent.type(model, "claude-y");
    await userEvent.click(screen.getByRole("button", { name: "Save", hidden: true }));
    expect(calls.some((c) => c.path === "llm/configure")).toBe(false);
    const confirm = within(document.querySelector(".sh-confirm") as HTMLElement);
    expect(confirm.getByText("Model · Anthropic · claude-y")).toBeInTheDocument();
    await userEvent.click(confirm.getByRole("button", { name: "Save", hidden: true }));
    await waitFor(() => expect(calls.find((c) => c.path === "llm/configure")?.body).toEqual({ model: "claude-y" }));
  });

  it("refuses a Slack approver with an id and no name rather than dropping it", async () => {
    show("/connections?tab=services&service=slack");
    await userEvent.type(await screen.findByLabelText("approvers"), "U0123 Sam Lee, U0456");
    expect(screen.getByText("no name for U0456")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save", hidden: true })).toBeDisabled();
  });

  it("keeps Add intel source in the URL, so Back closes it", async () => {
    show("/connections?tab=intel");
    await userEvent.click(await screen.findByRole("button", { name: "Add intel source" }));
    expect(screen.getByTestId("here").textContent).toContain("add=intel");
    // The page's confirm popovers are dialogs too: find the one that opened.
    const dialogs = await screen.findAllByRole("dialog", { hidden: true });
    expect(dialogs.some((d) => d.querySelector("h2")?.textContent === "Add intel source")).toBe(true);
  });

  it("opens a credential's link on its product", async () => {
    show("/connections?credential=aws%3Aprod");
    expect(await screen.findByRole("dialog", { hidden: true })).toHaveTextContent("AWS");
  });
});
