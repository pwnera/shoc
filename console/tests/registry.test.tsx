import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Access } from "@/routes/Access";

function capability(name: string, autonomy: "L0" | "L2", summary: string, required: string[] = []) {
  return {
    name,
    summary,
    scope: `${name.split(".")[0]}:read`,
    autonomy,
    principals: autonomy === "L2" ? ["human"] : ["human", "agent"],
    audit: autonomy !== "L0",
    tags: ["read"],
    rest: { method: "POST", path: `/v1/${name.split(".").join("/")}` },
    mcp_tool: name.replace(".", "_"),
    cli: `shoc ${name.split(".").join(" ")}`,
    input_schema: {
      type: "object",
      properties: {
        limit: { type: "integer", description: "Maximum rows" },
        action_uid: { type: "string", description: "The action" },
      },
      required,
    },
    output_schema: {
      type: "object",
      properties: { data: { type: "object", properties: { rows: { type: "array", items: { type: "object" } } } } },
    },
  };
}

const DATA: Record<string, unknown> = {
  "capability/list": {
    capabilities: [
      capability("finding.list", "L0", "List findings"),
      capability("finding.get", "L0", "One finding and its events"),
      capability("action.approve", "L2", "Approve a proposed action", ["action_uid"]),
    ],
    count: 3,
    version: "0.1.0",
  },
  "token/list": {
    tokens: [
      {
        token_id: "tok_1",
        who: "jane",
        role: "admin",
        kind: "human",
        scopes: [],
        created_by: "cli",
        created_at: "2026-09-01T00:00:00Z",
        expires_at: null,
        revoked_at: null,
      },
    ],
  },
  "token/create": { token_id: "tok_2", token: "shoc_secret_shown_once", who: "ci-bot" },
  "user/list": {
    users: [
      {
        user_id: "usr_1",
        email: "jane@example.com",
        role: "admin",
        method: "password",
        locked: false,
        last_login_at: "2026-10-01T00:00:00Z",
        created_at: "2026-09-01T00:00:00Z",
        disabled_at: null,
      },
      {
        user_id: "usr_2",
        email: "bob@example.com",
        role: "reader",
        method: "sso",
        locked: false,
        last_login_at: null,
        created_at: "2026-09-02T00:00:00Z",
        disabled_at: null,
      },
    ],
  },
  "user/invite": {
    user_id: "usr_3",
    email: "ann@example.com",
    role: "operator",
    link: "https://shoc.example.com/welcome#link_shown_once",
    emailed: false,
    expires_at: "2026-10-12T00:00:00Z",
  },
  "sso/show": { configured: false, issuer: "", client_id: "", domains: [], key: "unset", redirect_uri: "", updated_by: "" },
  "health/audit": {
    chain_ok: true,
    rows_verified: 4210,
    detail: "",
    head: "4210:abc",
    recent: [
      { seq: 4210, ts: "2026-10-01T00:00:00Z", principal_kind: "human", principal_id: "jane", capability: "action.approve", error: null, hash: "abc" },
    ],
  },
};

const SSO_OFF = DATA["sso/show"];

let calls: string[] = [];
let bodies: Record<string, unknown> = {};

function show(path = "/access?tab=capabilities") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Access />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the Access screen", () => {
  beforeEach(() => {
    calls = [];
    bodies = {};
    DATA["sso/show"] = SSO_OFF;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input).replace(/^.*\/v1\//, "");
        calls.push(path);
        bodies[path] = JSON.parse(String(init?.body ?? "{}"));
        return new Response(JSON.stringify({ data: DATA[path] ?? {}, summary: "", citations: [] }), { status: 200 });
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("reads the chain, the human-only count and the rows verified in the strip", async () => {
    show();
    expect(await screen.findByText("Intact")).toBeInTheDocument();
    expect(await screen.findByText("4,210")).toBeInTheDocument();
    expect(screen.getByText("you", { selector: ".sh-strip__label" })).toBeInTheDocument();
  });

  it("leaves the chain's total to the strip: the Audit pager counts what it loaded", async () => {
    show("/access?tab=audit");
    expect(await screen.findByText("4,210")).toBeInTheDocument();
    expect(screen.getAllByText("4,210")).toHaveLength(1);
  });

  it("lists capabilities by area with the you badge on the L2 rows only", async () => {
    show();
    expect(await screen.findByText("finding.list")).toBeInTheDocument();
    expect(screen.getAllByText("finding", { selector: "[data-area]" })).toHaveLength(1);
    expect(screen.getAllByText("action", { selector: "[data-area]" })).toHaveLength(1);
    expect(document.querySelectorAll(".sh-table .sh-auto--l2")).toHaveLength(1);
    // The summary is the name's tip, not a column.
    expect(screen.getByText("List findings").closest("[role=tooltip]")).not.toBeNull();
  });

  it("filters on name, summary and tag", async () => {
    show();
    await userEvent.type(await screen.findByLabelText("Filter capabilities"), "approve");
    await waitFor(() => expect(screen.queryByText("finding.list")).not.toBeInTheDocument());
    expect(screen.getByText("action.approve")).toBeInTheDocument();
  });

  it("shows how to call one capability with its required fields as placeholders", async () => {
    show("/access?tab=capabilities&cap=action.approve");
    await screen.findByText("action.approve", { selector: ".sh-dialog__title span" });
    const dialog = within(document.querySelector("dialog.sh-dialog") as HTMLElement);
    expect(dialog.getByText("Approve a proposed action")).toBeInTheDocument();
    expect(dialog.getByText("action_uid")).toBeInTheDocument();
    await userEvent.click(dialog.getByRole("radio", { name: "Call", hidden: true }));
    expect(dialog.getByText("shoc action approve <action_uid>")).toBeInTheDocument();
    expect(dialog.getByText(/curl -X POST \S+\/v1\/action\/approve/)).toBeInTheDocument();
    expect(dialog.getByText(/"name": "action_approve"/)).toBeInTheDocument();
  });

  it("issues a token only after a confirm, and drops it from the page once stored", async () => {
    show("/access?tab=tokens");
    expect(await screen.findByText("jane")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /new token/i }));
    await userEvent.type(screen.getByLabelText("Who"), "ci-bot");
    await userEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));
    expect(calls).not.toContain("token/create");
    expect(screen.getByText("New operator token · ci-bot")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));
    expect(await screen.findByText("shoc_secret_shown_once")).toBeInTheDocument();
    expect(calls).toContain("token/create");
    await userEvent.click(screen.getByRole("button", { name: "I've stored it", hidden: true }));
    expect(screen.queryByText("shoc_secret_shown_once")).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain("shoc_secret_shown_once");
  });

  it("invites a person only after a confirm, and drops the link from the page once stored", async () => {
    show("/access");
    expect(await screen.findByText("jane@example.com")).toBeInTheDocument();
    expect(screen.getByText("invited")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Invite" }));
    const dialog = within(document.querySelector("dialog.sh-dialog") as HTMLElement);
    await userEvent.type(dialog.getByLabelText("Email"), "Ann@example.com");
    await userEvent.click(dialog.getByRole("radio", { name: "operator", hidden: true }));
    await userEvent.click(dialog.getByRole("button", { name: "Invite", hidden: true }));
    expect(calls).not.toContain("user/invite");
    expect(dialog.getByText("Invite ann@example.com · operator")).toBeInTheDocument();
    await userEvent.click(dialog.getByRole("button", { name: "Invite", hidden: true }));
    expect(await screen.findByText("https://shoc.example.com/welcome#link_shown_once")).toBeInTheDocument();
    expect(bodies["user/invite"]).toEqual({ email: "ann@example.com", role: "operator" });
    await userEvent.click(screen.getByRole("button", { name: "I've stored it", hidden: true }));
    expect(document.body.innerHTML).not.toContain("link_shown_once");
  });

  it("opens Invite from the URL, as the palette's ?do= and Back expect", async () => {
    show("/access?invite=1");
    const dialog = within((await screen.findByRole("dialog", { hidden: true })) as HTMLElement);
    expect(dialog.getByLabelText("Email")).toBeInTheDocument();
  });

  it("keeps Audit's caller filter off the registry", async () => {
    show("/access?tab=capabilities&principal=agent");
    // `principal` is Audit's: the registry filters on `caller`, so the human-only capability stays listed.
    expect(await screen.findByText("action.approve")).toBeInTheDocument();
  });

  it("drops People's filters when the tab changes", async () => {
    show("/access?pq=jane");
    expect(await screen.findByLabelText("Filter people")).toHaveValue("jane");
    await userEvent.click(screen.getByRole("tab", { name: /Tokens/ }));
    await userEvent.click(screen.getByRole("tab", { name: /People/ }));
    expect(await screen.findByLabelText("Filter people")).toHaveValue("");
  });

  it("says how each person signs in, from user.list's method", async () => {
    show("/access?person=usr_2");
    expect(await screen.findByText("jane@example.com")).toBeInTheDocument();
    expect(screen.getByText("password", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("SSO", { selector: "span" })).toBeInTheDocument();
    const dialog = within(document.querySelector("dialog.sh-dialog") as HTMLElement);
    expect(dialog.getByText("SSO")).toBeInTheDocument();
  });

  it("keeps the stored client secret when it is left blank, and shows the kernel's redirect URI", async () => {
    DATA["sso/show"] = {
      configured: true,
      issuer: "https://idp.example.com",
      client_id: "shoc",
      domains: ["example.com"],
      key: "set",
      redirect_uri: "https://shoc.example.com:8443/auth/sso/callback",
      updated_by: "jane@example.com",
    };
    show("/access");
    await userEvent.click(await screen.findByRole("button", { name: /^SSO/ }));
    await screen.findByText("https://shoc.example.com:8443/auth/sso/callback");
    const dialog = within(document.querySelector("dialog.sh-dialog") as HTMLElement);
    expect(dialog.getByText("https://shoc.example.com:8443/auth/sso/callback")).toBeInTheDocument();
    expect(dialog.getByLabelText("Client secret")).toHaveAttribute("placeholder", "stored ••••");
    await userEvent.click(dialog.getByRole("button", { name: "Save", hidden: true }));
    await userEvent.click(dialog.getByRole("button", { name: "Save", hidden: true }));
    await waitFor(() => expect(calls).toContain("sso/configure"));
    expect(bodies["sso/configure"]).toEqual({
      issuer: "https://idp.example.com",
      client_id: "shoc",
      client_secret: "",
      domains: ["example.com"],
    });
  });

  it("asks for SHOC_PUBLIC_URL rather than guessing the redirect URI", async () => {
    show("/access");
    await screen.findByText("jane@example.com");
    await userEvent.click(screen.getByRole("button", { name: "SSO" }));
    expect(await screen.findByText("Needs shoc's public address")).toBeInTheDocument();
    // The variable's name is the tip, for whoever deploys shoc.
    expect(screen.getByText("SHOC_PUBLIC_URL").closest("[role=tooltip]")).not.toBeNull();
    expect(document.body.innerHTML).not.toContain("/auth/sso/callback");
  });
});
