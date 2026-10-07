import { beforeAll, describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { CloseDialog } from "@/routes/case/CloseDialog";
import { Discussion } from "@/routes/case/Discussion";
import { PagesTab } from "@/routes/case/PagesTab";
import { conceded, firstLine, pickedUp, proposalOf, roundsOf, visibleMessages } from "@/routes/case/messages";
import { nearMisses } from "@/routes/case/misses";
import { caseCites, caseMoments, firstContainment, gapsOf, verdictMessage, type Open } from "@/routes/case/moments";
import type { Action, Case, CaseRecord, OpenspaceMessage, TimelineEvent, TimelineResult } from "@/types";

const record: Case = {
  case_uid: "CASE-1",
  title: "5 findings for AKIAIOSFODNN7EXAMPLE",
  severity: "critical",
  state: "containment",
  verdict: "malicious",
  confidence: 0.82,
  entity_key: "AKIAIOSFODNN7EXAMPLE",
  summary: "",
  finding_uids: ["F-1", "F-2"],
  attack: ["T1078.004"],
  rounds: 7,
  tokens_used: 48_000,
  opened_at: "2026-09-25T13:09:45Z",
  updated_at: "2026-09-26T15:00:00Z",
  closed_at: null,
};

const event = (uid: string, time: string, extra: Partial<TimelineEvent> = {}): TimelineEvent => ({
  event_uid: uid,
  time,
  class_name: "API Activity",
  activity_name: null,
  severity_id: 1,
  status: "Success",
  actor_user_name: "deploy-ci",
  actor_session_uid: "AKIAIOSFODNN7EXAMPLE",
  src_endpoint_ip: "203.0.113.55",
  api_operation: "GetObject",
  api_service_name: "s3",
  cloud_account_uid: "123456789012",
  cloud_region: "us-east-1",
  resource_uid: null,
  metadata_product: "AWS CloudTrail",
  message: null,
  cited: false,
  ...extra,
});

const message = (id: number, extra: Partial<OpenspaceMessage>): OpenspaceMessage => ({
  msg_id: id,
  round: 1,
  agent: "Investigator",
  principal: "agent",
  kind: "observation",
  to_agent: "",
  body: "text",
  cited_event_uids: [],
  confidence: null,
  tokens: 0,
  model: null,
  created_at: `2026-09-25T14:0${id}:00Z`,
  repeats: 0,
  last_repeat_at: null,
  ...extra,
});

const action = (uid: string, extra: Partial<Action>): Action => ({
  action_uid: uid,
  case_uid: "CASE-1",
  type: "aws.disable_access_key",
  target: "AKIAIOSFODNN7EXAMPLE",
  params: {},
  autonomy: "L2",
  state: "done",
  reversible: true,
  dry_run: false,
  rationale: "",
  requested_by: "IR Commander",
  approved_by: null,
  result: {},
  created_at: "2026-09-26T14:00:00Z",
  ...extra,
});

describe("case moments", () => {
  it("collapses a run of one uncited call by one actor inside a minute, and keeps cited events apart", () => {
    const events = [
      event("e1", "2026-09-25T13:07:30Z", { api_operation: "StopLogging", cited: true }),
      event("e2", "2026-09-25T13:07:31Z"),
      event("e3", "2026-09-25T13:07:40Z"),
      event("e4", "2026-09-25T13:08:10Z"),
      event("e5", "2026-09-25T13:08:45Z"),
      event("e6", "2026-09-25T13:08:46Z", { cited: true }),
    ];
    const moments = caseMoments({ record, events, findings: [], openspace: [], actions: [] }).filter((m) => m.type === "event");
    expect(moments.map((m) => (m.type === "event" ? [m.event.event_uid, m.count] : null))).toEqual([
      ["e1", 1],
      ["e2", 3],
      ["e5", 1],
      ["e6", 1],
    ]);
  });

  it("leaves pages out, places actions when they ran, and opens and closes the case", () => {
    const actions = [
      action("a1", { executed_at: "2026-09-26T14:53:51Z" }),
      action("a2", { type: "notify.page", executed_at: "2026-09-26T14:40:00Z" }),
    ];
    const moments = caseMoments({ record: { ...record, closed_at: "2026-09-30T21:48:17Z" }, events: [], findings: [], openspace: [], actions });
    expect(moments.map((m) => m.key)).toEqual(["case:opened", "action:a1", "case:closed"]);
  });

  it("counts containment from the first action that ran, undone or not, never a page", () => {
    const actions = [
      action("late", { executed_at: "2026-09-27T19:30:27Z", state: "done" }),
      action("first", { executed_at: "2026-09-26T14:53:51Z", state: "rolled_back" }),
      action("page", { type: "notify.page", executed_at: "2026-09-26T14:40:32Z" }),
      action("proposed", { state: "proposed" }),
    ];
    expect(firstContainment(actions)?.action_uid).toBe("first");
  });

  it("numbers cited events by time, E1 the earliest, whoever cited them", () => {
    const events = [event("late", "2026-09-25T13:09:00Z", { cited: true }), event("early", "2026-09-25T13:07:00Z")];
    const cites = caseCites(events, [message(1, { cited_event_uids: ["early"] })]);
    expect(cites.of("early")).toBe(1);
    expect(cites.of("late")).toBe(2);
  });

  it("stands the verdict on the newest decision, else the newest hypothesis", () => {
    const open = [message(1, { kind: "hypothesis" }), message(2, { kind: "decision" }), message(3, { kind: "hypothesis" })];
    expect(verdictMessage(open)?.msg_id).toBe(2);
    expect(verdictMessage([message(1, { kind: "hypothesis" })])?.msg_id).toBe(1);
  });
});

describe("case gaps", () => {
  const data = (openspace: OpenspaceMessage[], total = openspace.length): CaseRecord => ({
    case: record,
    findings: [],
    openspace,
    openspace_total: total,
    entities: {},
  });
  const timeline = (events: TimelineEvent[], truncated = false): TimelineResult => ({
    case_uid: "CASE-1",
    events,
    count: events.length,
    truncated,
    limit: 500,
    window_start: "2026-09-25T12:00:00Z",
    window_end: "2026-09-25T14:00:00Z",
    products: [],
  });
  const everyone = ["Investigator", "Challenger", "IR Commander", "CTI", "Surveyor"].map((agent, i) => message(i, { agent }));

  it("lists cited events the store lost only when the timeline is whole", () => {
    const said = [...everyone, message(9, { cited_event_uids: ["kept", "gone"] })];
    expect(gapsOf(data(said), timeline([event("kept", "2026-09-25T13:00:00Z")]))).toEqual(["1 cited event no longer stored"]);
    expect(gapsOf(data(said), timeline([event("kept", "2026-09-25T13:00:00Z")], true))).toEqual(["first 500 events in the window"]);
  });

  it("says older messages are not shown, and which in-case roles never spoke", () => {
    expect(gapsOf(data([message(1, {})], 249))).toEqual([
      "older messages not shown",
      "Challenger, IR Commander, CTI, Surveyor never spoke",
    ]);
    expect(gapsOf(data(everyone))).toEqual([]);
  });
});

describe("discussion", () => {
  const thread = [
    message(1, { kind: "hypothesis" }),
    message(2, { kind: "challenge", agent: "Challenger", body: "[arguing benign, grounded in written_fact] A CI run [Looked up: events_query x6]" }),
    message(3, { kind: "inject", agent: "human:jane", principal: "human", body: "The key is ours" }),
    message(4, { kind: "proposal", agent: "IR Commander", body: '{"action": "aws.disable_access_key", "target": "AKIAIOSFODNN7EXAMPLE"}' }),
    message(5, { kind: "concede", agent: "Challenger" }),
    message(6, { kind: "decision", agent: "IR Commander" }),
  ];

  it("shows outcomes by default, adds the debate, and a person's message in every mode", () => {
    expect(visibleMessages(thread, "outcomes").map((m) => m.msg_id)).toEqual([3, 4, 6]);
    expect(visibleMessages(thread, "debate").map((m) => m.msg_id)).toEqual([1, 2, 3, 4, 5, 6]);
  });

  it("reads one line: a proposal as its action and target, prose without the kernel's asides", () => {
    expect(firstLine(thread[3]!)).toBe("Disable AWS key · AKIAIOSFODNN7EXAMPLE");
    expect(firstLine(message(7, { kind: "proposal", body: '{"action": "aws.disable_access_key", "target": "key:AKIAIOSFODNN7EXAMPLE"}' }))).toBe(
      "Disable AWS key · AKIAIOSFODNN7EXAMPLE",
    );
    expect(firstLine(thread[1]!)).toBe("A CI run");
    expect(proposalOf(thread[0]!)).toBeNull();
    // A decision's page condition reads in words, as the action dialog says it.
    expect(firstLine(message(8, { kind: "decision", body: "Contain the key. Paging a human (uncontainable_and_active)." }))).toBe(
      "Contain the key. Paging a human (can't contain, still active).",
    );
    expect(firstLine(message(9, { kind: "decision", body: "Paging a human (no condition named)." }))).toBe("Paging a human (no condition named).");
  });

  it("strikes a challenge its author later conceded, and marks a person's message the crew answered", () => {
    expect([...conceded(thread)]).toEqual([2]);
    expect(pickedUp(thread, thread[2]!)).toBe(true);
    expect(pickedUp(thread.slice(0, 3), thread[2]!)).toBe(false);
  });

  it("starts a run when the round drops, and files shoc's round-1 notes under the round they fall in", () => {
    const runs = [
      message(1, { round: 1, agent: "shoc" }),
      message(2, { round: 79, kind: "hypothesis" }),
      message(3, { round: 1, agent: "shoc" }),
      message(4, { round: 80, kind: "decision", agent: "IR Commander" }),
      message(5, { round: 1, kind: "inject", agent: "Ops", principal: "service" }),
      message(6, { round: 78, kind: "hypothesis" }),
      message(7, { round: 80, kind: "decision", agent: "IR Commander" }),
      message(8, { round: 1, kind: "request", agent: "Manager" }),
    ];
    const keys = runs.map((m) => roundsOf(runs).get(m.msg_id)!.key);
    expect(keys).toEqual(["0:1", "0:79", "0:79", "0:80", "0:80", "1:78", "1:80", "2:1"]);
  });

  beforeAll(() => {
    // jsdom scrolls nothing.
    Element.prototype.scrollTo ??= () => {};
  });

  const discussion = (openspace: OpenspaceMessage[]) =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient()}>
          <Discussion
            data={{ case: record, findings: [], openspace, openspace_total: openspace.length, entities: {} }}
            steer={false}
            onSteer={() => {}}
            open={{} as Open}
          />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  const passes = [
    message(1, { round: 5, kind: "decision", created_at: "2026-09-25T12:00:00Z" }),
    message(2, { round: 5, kind: "decision", created_at: "2026-09-26T12:00:00Z" }),
    message(3, { round: 2, kind: "decision", created_at: "2026-09-26T13:00:00Z" }),
    message(4, { round: 3, kind: "decision", created_at: "2026-09-26T14:00:00Z" }),
  ];

  it("names each pass once, on its day row, and keeps one divider for a round that crosses midnight", () => {
    const { container } = discussion(passes);
    const text = (sel: string) => [...container.querySelectorAll(sel)].map((el) => el.textContent?.replace(/\s+/g, " ").trim());
    expect(text(".sh-trace__round")).toEqual(["round 5", "round 2", "round 3"]);
    expect(text(".sh-tl__day").map((d) => d?.replace(/^.*?(· pass \d)?$/, "$1"))).toEqual(["· pass 1", "", "· pass 2"]);
    // The rail spells "R5", and its name starts with what shows, the pass after it for screen readers only.
    const rail = screen.getByRole("navigation", { name: "Rounds", hidden: true });
    const buttons = within(rail).getAllByRole("button", { hidden: true });
    expect(buttons.map((b) => b.textContent)).toEqual(["R5, pass 1", "R2, pass 2", "R3, pass 2"]);
    expect(buttons.some((b) => b.hasAttribute("aria-label"))).toBe(false);
  });

  it("draws no rail when every pass shows one round, which its divider already names", () => {
    discussion(passes.slice(0, 3));
    expect(screen.queryByRole("navigation", { name: "Rounds", hidden: true })).toBeNull();
  });
});

describe("run a playbook", () => {
  const miss = (id: string, misses: string[]) => ({ playbook_id: id, title: id, misses });

  it("says the confidence miss once when every playbook has it, and keeps a different bar on its row", () => {
    const near = nearMisses([
      miss("b", ["none of its rules fired on this case", "confidence is 0.08, it wants 0.80"]),
      miss("a", ["confidence is 0.08, it wants 0.80"]),
      miss("c", ["none of its rules fired on this case", "confidence is 0.08, it wants 0.75"]),
    ]);
    expect(near).toMatchObject({ has: 0.08, bar: 0.8, shared: [] });
    expect(near.misses.map((m) => [m.playbook_id, m.wants, m.own])).toEqual([
      ["a", 0.8, []],
      ["c", 0.75, ["none of its rules fired on this case"]],
      ["b", 0.8, ["none of its rules fired on this case"]],
    ]);
  });

  it("puts no chip on top when a playbook misses on something else only", () => {
    const near = nearMisses([miss("a", ["confidence is 0.08, it wants 0.80"]), miss("b", ["none of its rules fired on this case"])]);
    expect(near.bar).toBeNull();
    expect(near.misses[0]).toMatchObject({ playbook_id: "a", wants: 0.8, own: [] });
  });
});

describe("close dialog", () => {
  const wrap = (verdict: Case["verdict"]) =>
    render(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient()}>
          <CloseDialog record={{ ...record, verdict }} onClose={() => {}} />
        </QueryClientProvider>
      </MemoryRouter>,
    );

  it("presets the crew's verdict and offers Remember only for Expected and Rule was wrong", () => {
    wrap("malicious");
    expect(screen.getByRole("radio", { name: "Attack", hidden: true })).toHaveAttribute("aria-checked", "true");
    expect(screen.queryByRole("radiogroup", { name: "Remember", hidden: true })).toBeNull();
    fireEvent.click(screen.getByRole("radio", { name: "Expected", hidden: true }));
    const remember = screen.getByRole("radiogroup", { name: "Remember", hidden: true });
    expect(remember).toHaveTextContent("30d90d1y");
    expect(remember).not.toHaveTextContent(/don't|never|none/i);
    fireEvent.click(screen.getByRole("radio", { name: "Rule was wrong", hidden: true }));
    expect(screen.getByRole("radiogroup", { name: "Remember", hidden: true })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("radio", { name: "Suspicious", hidden: true }));
    expect(screen.queryByRole("radiogroup", { name: "Remember", hidden: true })).toBeNull();
  });

  it("guesses nothing when the crew handed the call to a person, and needs a reason", () => {
    wrap("needs_human");
    expect(screen.queryAllByRole("radio", { checked: true, hidden: true })).toHaveLength(0);
    // The Close that opens the confirm, not the dialog's own close.
    const submit = screen.getAllByRole("button", { name: "Close", hidden: true }).find((b) => b.getAttribute("aria-haspopup") === "dialog");
    expect(submit).toBeDisabled();
  });

  it("holds the focus on the choice when nothing is preset, so 1–4 pick at once", () => {
    wrap("needs_human");
    expect(document.activeElement).toHaveAttribute("role", "radio");
    fireEvent.keyDown(document.activeElement!, { key: "3" });
    const picked = screen.getByRole("radio", { name: "Expected", hidden: true });
    expect(picked).toHaveAttribute("aria-checked", "true");
    expect(document.activeElement).toBe(picked);
  });
});

describe("the case's pages", () => {
  const page = (uid: string, extra: Partial<Action>) =>
    action(uid, { type: "notify.page", target: "oncall", requested_by: "Manager", ...extra });
  const pages = (rows: Action[]) =>
    render(
      <MemoryRouter>
        <PagesTab rows={rows} loading={false} error={null} onRetry={() => {}} open={{ action: () => {} } as unknown as Open} />
      </MemoryRouter>,
    );

  it("folds a burst in one state into one row and words each state as a page's", () => {
    const { container } = pages([
      page("p1", { created_at: "2026-09-27T19:30:00Z" }),
      page("p2", { state: "rejected", created_at: "2026-09-27T15:00:00Z" }),
      page("p3", { state: "rejected", created_at: "2026-09-27T11:00:00Z" }),
      page("p4", { state: "rejected", created_at: "2026-09-27T07:00:00Z" }),
      page("p5", { state: "rolled_back", created_at: "2026-09-26T14:40:00Z" }),
      page("p6", { state: "rejected", created_at: "2026-09-26T14:00:00Z" }),
    ]);
    const rows = [...container.querySelectorAll<HTMLElement>('table[aria-label="Pages"] tbody tr')];
    expect(rows.map((r) => r.querySelector(".sh-status")?.textContent)).toEqual(["delivered", "not sent", "withdrawn", "not sent"]);
    expect(within(rows[1]!).getByText("×3")).toBeInTheDocument();
    expect(screen.queryByText("Page on-call")).not.toBeInTheDocument();
  });

  it("says nobody was paged, as Response does", () => {
    pages([]);
    expect(screen.getByText("Nobody was paged")).toBeInTheDocument();
  });
});
