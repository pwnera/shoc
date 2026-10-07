import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation, useSearchParams } from "react-router-dom";
import { ActionDialog } from "@/components/ActionDialog";
import { Response as ResponseScreen } from "@/routes/Response";
import { Playbook } from "@/routes/Playbook";
import { useClaimed } from "@/lib/popup";
import type { Action, Case, Playbook as Book, Rule } from "@/types";

const at = (hoursAgo: number) => new Date(Date.now() - hoursAgo * 3_600_000).toISOString();

function action(uid: string, over: Partial<Action> = {}): Action {
  return {
    action_uid: uid,
    case_uid: "CASE-1",
    type: "aws.disable_access_key",
    target: "AKIAIOSFODNN7EXAMPLE",
    params: {},
    autonomy: "L1",
    state: "done",
    reversible: true,
    dry_run: true,
    rationale: "",
    requested_by: "IR Commander",
    approved_by: null,
    result: {},
    created_at: at(3),
    updated_at: at(3),
    ...over,
  };
}

const ACTIONS: Action[] = [
  action("A-planned"),
  action("A-live", { type: "cloudflare.block_ip", target: "203.0.113.55", dry_run: false, updated_at: at(2) }),
  action("A-proposed", { type: "okta.suspend_user", target: "user:deploy-ci", state: "proposed", autonomy: "L2" }),
  action("P-1", { type: "notify.page", target: "the whole page message", state: "rejected" }),
  action("P-2", { type: "notify.page", target: "the whole page message", state: "rejected" }),
];

const CASES: Partial<Case>[] = [{ case_uid: "CASE-1", title: "Leaked key on deploy-ci", severity: "critical" }];

const BOOKS: Book[] = [
  {
    id: "contain_leaked_cloud_key",
    title: "Contain a leaked cloud access key",
    description: "Disable the key first.",
    rules: ["aws_access_key_created", "hunt:aws_first_key_use"],
    questions: [{ id: "who", ask: "Who created the key?" }],
    benign_when: ["A CI rotation window"],
    steps: [
      { name: "disable the access key", action: "aws.disable_access_key", optional: false },
      { name: "suspend the user", action: "okta.suspend_user", optional: true },
    ],
    trigger: { verdict: ["malicious"], entity_kinds: ["key"], attack_any: [], min_confidence: 0.8, severity_at_least: "high" },
  },
  {
    id: "contain_public_repository",
    title: "Put a leaked repository back behind the wall",
    description: "",
    rules: [],
    questions: [],
    benign_when: [],
    steps: [{ name: "make the repository private", action: "github.make_repo_private", optional: false }],
    trigger: { verdict: ["malicious"], entity_kinds: [], attack_any: [], min_confidence: 0.7, severity_at_least: "high" },
  },
];

const RULES: Partial<Rule>[] = [
  { id: "aws_access_key_created", title: "New IAM access key created", severity: "high", logsource: { product: "aws" }, attack: [] },
];

const RUNS = [
  { run_uid: "RUN-1", case_uid: "CASE-1", playbook_id: "contain_leaked_cloud_key", state: "done", step_index: 2, dry_run: true, started_at: at(30), error: null },
  { run_uid: "RUN-2", case_uid: "CASE-1", playbook_id: "contain_public_repository", state: "failed", step_index: 0, dry_run: true, started_at: at(5), error: "boom" },
];

const POLICY = {
  defaults: { autonomy: "L2", dry_run: true, min_confidence: 0.8, severity_at_least: "high" },
  principals: { agent: "L1", human: "L2" },
  actions: {
    "aws.disable_access_key": { autonomy: "L1", reversible: true, min_confidence: 0.85, severity_at_least: "high" },
    "okta.suspend_user": { autonomy: "L2", reversible: true },
    "github.make_repo_private": { autonomy: "L2", reversible: true },
    "openai.delete_api_key": { autonomy: "L2", reversible: false },
  },
  guards: { protected_targets: ["user:*admin*"], require_citations: true, max_auto_actions_per_case: 3 },
  available_actions: [],
  action_params: { "aws.disable_access_key": { required: ["access_key_id"], summary: "", reversible: true } },
};

const DATA: Record<string, unknown> = {
  "action/list": { rows: ACTIONS, count: ACTIONS.length, waiting_for_approval: 1 },
  "policy/show": POLICY,
  "playbook/list": { playbooks: BOOKS, count: BOOKS.length, near_misses: [] },
  "playbook/runs": { runs: RUNS, count: RUNS.length },
  "rule/list": { rules: RULES, count: RULES.length },
  "health/rules": { rules: [], ok: true },
  "hunt/results": {
    runs: [],
    count: 0,
    metrics: {},
    readiness: [{ pack_id: "aws_first_key_use", state: "ready", title: "First use of a new key", reason: "", ready_at: null, sources: [], accounts: [] }],
  },
  "ops/alerts": { alerts: [], count: 0 },
  "case/list": { rows: CASES, count: CASES.length },
};

let calls: { path: string; body: Record<string, unknown> }[] = [];
let failing = new Set<string>();
/** Answers a test swaps in, and paths that never answer. */
let overrides: Record<string, unknown> = {};
let hanging = new Set<string>();

function envelope(data: unknown, status = 200) {
  return new Response(JSON.stringify(status === 200 ? { data, summary: "", citations: [] } : { detail: "store down" }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function Where() {
  const location = useLocation();
  return <p data-testid="where">{location.pathname + location.search}</p>;
}

/** The shell's `?action=` deep link, which the screen relies on unless it claims it. */
function ActionHost() {
  const [params, setParams] = useSearchParams();
  const claimed = useClaimed();
  const uid = claimed.includes("action") ? null : params.get("action");
  const location = useLocation();
  return (
    <>
      <p data-testid="here">{location.search}</p>
      {uid ? (
        <ActionDialog
          key={uid}
          uid={uid}
          onClose={() =>
            setParams((current) => {
              const out = new URLSearchParams(current);
              out.delete("action");
              return out;
            })
          }
        />
      ) : null}
    </>
  );
}

function show(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/response"
            element={
              <>
                <ResponseScreen />
                <ActionHost />
              </>
            }
          />
          <Route path="/response/playbooks/:playbookId" element={<Playbook />} />
          <Route path="*" element={<Where />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

describe("the Response screen", () => {
  beforeEach(() => {
    calls = [];
    failing = new Set();
    overrides = {};
    hanging = new Set();
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        const path = new URL(url, "http://x").pathname.replace(/^\/v1\//, "");
        calls.push({ path, body: JSON.parse(String(init?.body ?? "{}")) });
        if (hanging.has(path)) return new Promise<Response>(() => {});
        if (failing.has(path)) return Promise.resolve(envelope(null, 503));
        return Promise.resolve(envelope(overrides[path] ?? DATA[path] ?? {}));
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("opens on Activity: no proposals, no pages, and a dry run reads planned", async () => {
    show("/response");
    const feed = await screen.findByRole("list", { name: "Activity" });
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent("Activity2");
    // Each badge is drawn twice, at the row's end and under the label on a phone; CSS shows one.
    expect(within(feed).queryAllByText("planned")).not.toHaveLength(0);
    expect(within(feed).queryAllByText("done")).not.toHaveLength(0);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(within(feed).queryByText("Suspend Okta user")).not.toBeInTheDocument();
    expect(within(feed).queryByText("Page on-call")).not.toBeInTheDocument();
    expect(calls.find((c) => c.path === "action/list")?.body).toEqual({ limit: 500 });
    expect(calls.some((c) => c.path === "hunt/results")).toBe(false);
  });

  it("filters by state and by dry run", async () => {
    show("/response?state=done&run=dry");
    const feed = await screen.findByRole("list", { name: "Activity" });
    expect(within(feed).getByText("AKIAIOSFODNN7EXAMPLE")).toBeInTheDocument();
    expect(within(feed).queryByText("203.0.113.55")).not.toBeInTheDocument();
  });

  it("filters to live actions with run=live", async () => {
    show("/response?state=done&run=live");
    const feed = await screen.findByRole("list", { name: "Activity" });
    expect(within(feed).getByText("203.0.113.55")).toBeInTheDocument();
    expect(within(feed).queryByText("AKIAIOSFODNN7EXAMPLE")).not.toBeInTheDocument();
  });

  it("splits an expired action from a rejected one, and the Overview's older link lands on Expired", async () => {
    overrides["action/list"] = {
      rows: [
        action("A-expired", { state: "rejected", approved_by: "unattended", updated_at: at(2) }),
        action("A-rejected", { type: "cloudflare.block_ip", target: "203.0.113.9", state: "rejected", approved_by: "human:sam" }),
      ],
      count: 2,
      waiting_for_approval: 0,
    };
    show("/response?state=rejected&by=unattended");
    const feed = await screen.findByRole("list", { name: "Activity" });
    expect(within(feed).queryAllByText("expired")).not.toHaveLength(0);
    expect(within(feed).queryByText("rejected")).not.toBeInTheDocument();
  });

  it("puts the dry run and the guards in the strip", async () => {
    show("/response");
    expect(await screen.findByText("Dry run")).toBeInTheDocument();
    expect(screen.getByText("≥ 80%")).toBeInTheDocument();
    expect(screen.getByText("citations")).toBeInTheDocument();
    expect(screen.getByText("never acted on alone")).toBeInTheDocument();
  });

  it("never shows an empty feed or a zero when the log fails", async () => {
    failing.add("action/list");
    show("/response");
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(screen.queryByText("Nothing ran")).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Activity/ })).toHaveTextContent("Activity—");
  });

  it("groups pages by case and reads a refused page as not sent, never rejected", async () => {
    show("/response?tab=pages");
    const table = await screen.findByRole("grid", { name: "Pages" });
    await waitFor(() => expect(within(table).getByText("Leaked key on deploy-ci")).toBeInTheDocument());
    expect(within(table).getByText("not sent")).toBeInTheDocument();
    expect(within(table).getByText("×2")).toBeInTheDocument();
    expect(within(table).queryByText("rejected")).not.toBeInTheDocument();
    expect(within(table).queryByText("the whole page message")).not.toBeInTheDocument();
  });

  it("lists only playbooks whose newest run failed from Health's link", async () => {
    show("/response?tab=playbooks&run=failed");
    const table = await screen.findByRole("grid", { name: "Playbooks" });
    await waitFor(() => expect(within(table).getByText("Put a leaked repository back behind the wall")).toBeInTheDocument());
    expect(within(table).queryByText("Contain a leaked cloud access key")).not.toBeInTheDocument();
    expect(screen.getByText("last run failed")).toBeInTheDocument();
  });

  it("groups autonomy by platform and flags a one-way act", async () => {
    show("/response?tab=autonomy");
    expect(await screen.findByText("AWS · 1 auto")).toBeInTheDocument();
    expect(screen.getByText("GitHub · 1 you")).toBeInTheDocument();
    expect(screen.getAllByRole("img", { name: "one-way" })).toHaveLength(1);
  });

  it("filters Autonomy by product, as Playbooks and Connections name it", async () => {
    show("/response?tab=autonomy&product=github");
    expect(await screen.findByText("GitHub · 1 you")).toBeInTheDocument();
    expect(screen.queryByText("AWS · 1 auto")).not.toBeInTheDocument();
  });

  it("says no action matches in Activity, as Autonomy does", async () => {
    show("/response?q=nothing-like-this");
    expect(await screen.findByText("No action matches")).toBeInTheDocument();
  });

  it("opens an action's policy from Autonomy and steps through the list from it", async () => {
    show("/response?tab=autonomy&policy=aws.disable_access_key");
    const title = await screen.findByRole("heading", { name: "Disable AWS key", hidden: true });
    const dialog = title.closest("dialog")!;
    expect(within(dialog).getByText("1 / 4")).toBeInTheDocument();
    expect(within(dialog).getByText("↺ reversible")).toBeInTheDocument();
    expect(within(dialog).getByText("access key")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Copy aws.disable_access_key", hidden: true })).toBeInTheDocument();
    fireEvent.keyDown(dialog, { key: "ArrowDown" });
    expect(await screen.findByRole("heading", { name: "Make repo private", hidden: true })).toBeInTheDocument();
    expect(screen.getByTestId("here")).toHaveTextContent("policy=github.make_repo_private");
  });

  it("marks a playbook's newest run only when it needs a look", async () => {
    show("/response?tab=playbooks");
    const table = await screen.findByRole("grid", { name: "Playbooks" });
    const failed = (await within(table).findByText("Put a leaked repository back behind the wall")).closest("tr")!;
    await waitFor(() => expect(within(failed).getByRole("img", { name: "last run failed" })).toBeInTheDocument());
    const done = within(table).getByText("Contain a leaked cloud access key").closest("tr")!;
    expect(within(done).queryByRole("img", { name: /last run/ })).not.toBeInTheDocument();
    // Both have a step that waits for a person.
    expect(within(done).getByText("you")).toBeInTheDocument();
  });

  it("claims no 'you' on a playbook while the policy is pending", async () => {
    hanging.add("policy/show");
    show("/response?tab=playbooks");
    const table = await screen.findByRole("grid", { name: "Playbooks" });
    await within(table).findByText("Contain a leaked cloud access key");
    expect(within(table).queryByText("you")).not.toBeInTheDocument();
    expect(within(table).queryByRole("img", { name: "you" })).not.toBeInTheDocument();
  });

  it("claims no 'you' on a playbook when the policy fails", async () => {
    failing.add("policy/show");
    show("/response?tab=playbooks");
    expect(await screen.findByText("Can't tell")).toBeInTheDocument();
    const table = screen.getByRole("grid", { name: "Playbooks" });
    await within(table).findByText("Contain a leaked cloud access key");
    expect(within(table).queryByText("you")).not.toBeInTheDocument();
    expect(within(table).queryByRole("img", { name: "you" })).not.toBeInTheDocument();
  });

  it("reads a split page group by the state most of its pages are in", async () => {
    const held = (uid: string) => action(uid, { type: "notify.page", target: "message", state: "rejected", case_uid: "CASE-1" });
    overrides["action/list"] = {
      rows: [held("P-1"), held("P-2"), held("P-3"), action("P-4", { type: "notify.page", target: "message", dry_run: false })],
      count: 4,
      waiting_for_approval: 0,
    };
    show("/response?tab=pages");
    const table = await screen.findByRole("grid", { name: "Pages" });
    await waitFor(() => expect(within(table).getByText("not sent")).toBeInTheDocument());
    expect(within(table).queryByText("mixed")).not.toBeInTheDocument();
    expect(within(table).getByText("×4")).toBeInTheDocument();
    // The tab counts pages; one page of groups draws no footer.
    expect(screen.getByRole("tab", { name: /Pages/ })).toHaveTextContent("Pages4");
    expect(screen.queryByText(/of 1 group/)).not.toBeInTheDocument();
  });

  it("opens ActionDialog from ?action= and from a row; Undo asks first; Run now keeps the dry run", async () => {
    overrides["action/list"] = {
      rows: [...ACTIONS, action("A-approved", { type: "crowdstrike.isolate_host", target: "host:build-01", state: "approved", updated_at: at(1) })],
      count: ACTIONS.length + 1,
      waiting_for_approval: 1,
    };
    show("/response?action=A-approved");
    expect(await screen.findByRole("heading", { name: "Isolate CrowdStrike host", hidden: true })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Run now", hidden: true }));
    await waitFor(() =>
      expect(calls.find((c) => c.path === "action/run")?.body).toEqual({ action_uid: "A-approved", dry_run: true }),
    );

    fireEvent.click(screen.getByRole("button", { name: "Close", hidden: true }));
    const feed = await screen.findByRole("list", { name: "Activity" });
    await userEvent.click(within(feed).getByText("Block IP at Cloudflare"));
    expect(screen.getByTestId("here")).toHaveTextContent("action=A-live");
    const undo = await screen.findByRole("button", { name: "Undo", hidden: true });
    expect(undo).toHaveAttribute("aria-haspopup", "dialog");
    expect(screen.getByRole("dialog", { name: "Undo Block IP at Cloudflare", hidden: true })).toBeInTheDocument();
    fireEvent.click(undo);
    expect(calls.some((c) => c.path === "action/undo")).toBe(false);
  });

  it("holds rows that arrive while the reader is here behind a new pill", async () => {
    const client = show("/response");
    const feed = await screen.findByRole("list", { name: "Activity" });
    await within(feed).findByText("Disable AWS key");
    overrides["action/list"] = {
      rows: [...ACTIONS, action("A-new", { type: "github.make_repo_private", target: "acme/api", dry_run: false, updated_at: at(0.1) })],
      count: ACTIONS.length + 1,
      waiting_for_approval: 1,
    };
    await client.invalidateQueries({ queryKey: ["action.list"] });
    const pill = await screen.findByRole("button", { name: /1 new/ });
    expect(within(feed).queryByText("Make repo private")).not.toBeInTheDocument();
    await userEvent.click(pill);
    expect(await within(screen.getByRole("list", { name: "Activity" })).findByText("Make repo private")).toBeInTheDocument();
  });
});

describe("the playbook page", () => {
  beforeEach(() => {
    calls = [];
    failing = new Set();
    overrides = {};
    hanging = new Set();
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        const path = new URL(url, "http://x").pathname.replace(/^\/v1\//, "");
        calls.push({ path, body: JSON.parse(String(init?.body ?? "{}")) });
        if (hanging.has(path)) return new Promise<Response>(() => {});
        if (failing.has(path)) return Promise.resolve(envelope(null, 503));
        return Promise.resolve(envelope(overrides[path] ?? DATA[path] ?? {}));
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("draws the steps with their autonomy and the checklists as plain lists", async () => {
    show("/response/playbooks/contain_leaked_cloud_key");
    const steps = await screen.findByRole("list", { name: "Steps" });
    await waitFor(() => expect(within(steps).getByText("auto")).toBeInTheDocument());
    expect(within(steps).getByText("you")).toBeInTheDocument();
    // The severity floor is a badge, as the strip draws the trigger's.
    expect(within(steps).getByText("≥ 85%")).toBeInTheDocument();
    expect(within(steps).getByText("high")).toHaveClass("sh-badge");
    expect(screen.getByText("Who created the key?").closest("li")).not.toBeNull();
    expect(screen.queryByText("Disable the key first.")).not.toBeInTheDocument();
    expect(calls.some((c) => c.path === "playbook/get")).toBe(false);
  });

  it("opens a step's policy and steps to the next step with the arrow keys", async () => {
    show("/response/playbooks/contain_leaked_cloud_key?step=0");
    const title = await screen.findByRole("heading", { name: "Disable AWS key", hidden: true });
    const dialog = title.closest("dialog")!;
    expect(within(dialog).getByText("1 / 2")).toBeInTheDocument();
    fireEvent.keyDown(dialog, { key: "ArrowDown" });
    expect(await screen.findByRole("heading", { name: "Suspend Okta user", hidden: true })).toBeInTheDocument();
  });

  it("keeps the hunt packs under a failed rule list", async () => {
    failing.add("rule/list");
    show("/response/playbooks/contain_leaked_cloud_key");
    const rail = await screen.findByRole("complementary", { name: "Detections" });
    expect(await within(rail).findByRole("alert")).toBeInTheDocument();
    const table = within(rail).getByRole("grid", { name: "Detections" });
    expect(await within(table).findByText("First use of a new key")).toBeInTheDocument();
    expect(within(table).queryByText("aws_access_key_created")).not.toBeInTheDocument();
    expect(within(rail).queryByText(/of 1/)).not.toBeInTheDocument();
  });

  it("counts the live rules in the detections' header", async () => {
    overrides["health/rules"] = {
      rules: [{ rule_id: "aws_access_key_created", findings_7d: 2, noisy: false, error: null, silent_reason: "" }],
      ok: true,
    };
    show("/response/playbooks/contain_leaked_cloud_key");
    const rail = await screen.findByRole("complementary", { name: "Detections" });
    expect(await within(rail).findByText("1 live")).toBeInTheDocument();
  });

  it("sends a hunt detection to Hunts on its pack", async () => {
    show("/response/playbooks/contain_leaked_cloud_key");
    const table = await screen.findByRole("grid", { name: "Detections" });
    const row = await within(table).findByText("First use of a new key");
    await userEvent.click(row);
    expect(await screen.findByTestId("where")).toHaveTextContent("/hunts?pack=aws_first_key_use");
  });

  it("says when there is no such playbook", async () => {
    show("/response/playbooks/nope");
    expect(await screen.findByText("No playbook nope")).toBeInTheDocument();
  });
});
