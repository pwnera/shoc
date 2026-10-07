import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { platformOf } from "@/components/brands";
import { Clamped } from "@/components/ui/clamped";
import { HuntFlow } from "@/components/Workflows";
import { Dialog } from "@/components/ui/dialog";
import { Announcer, ErrorNote, Tabs } from "@/components/ui/misc";
import { Prose } from "@/components/ui/prose";
import { Strip } from "@/components/ui/strip";
import { Timeline } from "@/components/ui/timeline";
import { announce } from "@/lib/announce";
import { ApiError } from "@/lib/api";
import { copyText } from "@/lib/copy";
import { who } from "@/lib/crew";
import { chipWord } from "@/lib/filters";
import { clock, dayMonth, stamp } from "@/lib/format";
import { platformName, refusal } from "@/lib/labels";
import { usePaged } from "@/lib/paged";
import { useTab } from "@/lib/param";
import { actionTypes, ruleOf } from "@/lib/policy";
import { sinceDim, sinceTime, sinceWord } from "@/lib/since";
import { toastError, useToasts } from "@/lib/toast";
import type { PolicyView } from "@/types";

describe("copying over plain HTTP", () => {
  afterEach(() => vi.restoreAllMocks());

  it("falls back to a scratch field and execCommand, and leaves nothing behind", async () => {
    const exec = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", { value: exec, configurable: true });
    expect(await copyText("CASE-172f787307524997fb73")).toBe("copied");
    expect(exec).toHaveBeenCalledWith("copy");
    expect(document.querySelector("textarea")).toBeNull();
  });

  it("says nothing was copied when the browser refuses and no value is on screen", async () => {
    Object.defineProperty(document, "execCommand", { value: () => false, configurable: true });
    expect(await copyText("x")).toBe("");
  });
});

describe("a since from a link", () => {
  const now = Date.parse("2026-10-03T12:00:00Z");

  it("reads relative windows with or without a minus, and ISO times", () => {
    expect(sinceTime("7d", now)).toBe(now - 7 * 86_400_000);
    expect(sinceTime("-24h", now)).toBe(now - 86_400_000);
    expect(sinceTime("90m", now)).toBe(now - 90 * 60_000);
    expect(sinceTime("2026-10-01T08:00:00Z", now)).toBe(Date.parse("2026-10-01T08:00:00Z"));
    expect(sinceTime("soon", now)).toBeNaN();
  });

  it("names its chip and filters rows by it, without a menu entry", () => {
    expect(sinceWord("-7d")).toBe("7d");
    expect(sinceWord(new Date(2026, 8, 29, 14, 2).toISOString())).toBe("Tue 14:02");
    const dim = sinceDim<{ at: string }>((r) => r.at);
    expect(dim.options).toBeUndefined();
    expect(chipWord(dim, "-24h")).toBe("24h");
    expect(dim.test!({ at: new Date().toISOString() }, "24h")).toBe(true);
    expect(dim.test!({ at: "2020-01-01T00:00:00Z" }, "24h")).toBe(false);
  });
});

describe("times", () => {
  it("reads the 24-hour clock and spells the month as the day headings do", () => {
    const at = new Date(2026, 8, 27, 20, 28).toISOString();
    expect(clock(at)).toBe("20:28");
    expect(dayMonth(at)).toBe("27 Sep");
    expect(stamp(at)).toBe("27 Sep 20:28");
    expect(clock(null)).toBe("—");
  });
});

describe("the pager", () => {
  it("reads a capped list as its newest slice and jumps back to the first page", () => {
    const rows = Array.from({ length: 60 }, (_, i) => i);
    const { result } = renderHook(() => usePaged(rows, 25, { cap: 60, newest: true }), { wrapper: MemoryRouter });
    render(<>{result.current.pager}</>);
    // The newest slice says so in words, as Explore's footer does.
    expect(screen.getByText(/of newest 60/)).toBeInTheDocument();
    act(() => result.current.next());
    expect(result.current.at).toBe(1);
    act(() => result.current.first());
    expect(result.current.at).toBe(0);
  });

  it("takes its page from the host when given one", () => {
    const onPage = vi.fn();
    const { result } = renderHook(() => usePaged([1, 2, 3, 4], 2, { page: 1, onPage }), { wrapper: MemoryRouter });
    expect(result.current.page).toEqual([3, 4]);
    act(() => result.current.prev());
    expect(onPage).toHaveBeenCalledWith(0);
  });

  it("opens on the page it was turned to when Back brings the list again", () => {
    const rows = Array.from({ length: 30 }, (_, i) => i);
    // The browser router's entry index; a MemoryRouter starts on a POP, as Back does.
    window.history.replaceState({ idx: 4 }, "");
    const first = renderHook(() => usePaged(rows, 10), { wrapper: MemoryRouter });
    act(() => first.result.current.next());
    first.unmount();
    expect(renderHook(() => usePaged(rows, 10), { wrapper: MemoryRouter }).result.current.at).toBe(1);
    // Another list on the URL, and the same list in another history entry, keep their own page.
    expect(renderHook(() => usePaged(rows, 20), { wrapper: MemoryRouter }).result.current.at).toBe(0);
    window.history.replaceState({ idx: 5 }, "");
    expect(renderHook(() => usePaged(rows, 10), { wrapper: MemoryRouter }).result.current.at).toBe(0);
    window.history.replaceState(null, "");
  });
});

describe("words and rules", () => {
  it("draws the worker acting as an agent as shoc, not as an outside agent", () => {
    expect(who("agent:worker")).toMatchObject({ kind: "system", glyph: "mark" });
  });

  it("names an action's platform and stands a glyph in where there is no logo", () => {
    expect(platformName("entra.revoke_sessions")).toBe("Entra ID");
    expect(platformOf("aws.disable_access_key")).toMatchObject({ name: "AWS", logo: { label: "AWS" } });
    expect(platformOf("notify.page").logo).toBeNull();
    expect(platformOf("openai.delete_api_key")).toMatchObject({ name: "OpenAI", logo: { label: "ChatGPT" } });
  });

  it("fills an action's rule from the policy's defaults", () => {
    const policy: PolicyView = {
      defaults: { autonomy: "L2", min_confidence: 0.8 },
      actions: { "okta.revoke_sessions": { autonomy: "L1", severity_at_least: "high" } },
      available_actions: ["cloudflare.block_ip"],
      action_params: { "cloudflare.block_ip": { required: ["ip"], summary: "", reversible: false } },
    };
    expect(ruleOf(policy, "okta.revoke_sessions")).toMatchObject({ autonomy: "L1", min_confidence: 0.8, severity_at_least: "high", reversible: true });
    expect(ruleOf(policy, "cloudflare.block_ip")).toMatchObject({ autonomy: "L2", reversible: false, required: ["ip"], min_confidence: undefined });
    expect(actionTypes(policy)).toEqual(["cloudflare.block_ip", "okta.revoke_sessions"]);
  });

  it("says one failure once, whoever raises it second", () => {
    const { result } = renderHook(() => useToasts());
    const before = result.current.length;
    const error = new Error("refused");
    act(() => toastError(error, "Hunts failed"));
    act(() => toastError(error, "Hunts failed"));
    expect(result.current.length).toBe(before + 1);
    expect(result.current[0]!.text).toBe("Hunts failed: refused");
  });

  it("says what a role cannot do, in words, and a missing session as signed out", () => {
    expect(refusal("action.approve: caller lacks scope 'actions:approve'")).toBe("Your role can't approve actions");
    expect(refusal("playbook.merge: caller lacks scope 'playbooks:merge'")).toBe("Your role can't merge playbooks");
    expect(refusal("source.configure: caller lacks scope 'sources:write'")).toBe("Your role can't change sources");
    expect(refusal("finding.list: caller lacks scope 'findings:read'")).toBe("Not allowed to read findings");
    expect(refusal("action.approve: L2 capabilities require a human principal")).toBeUndefined();
    const { result } = renderHook(() => useToasts());
    act(() => toastError(new ApiError(403, "denied", "action.approve: caller lacks scope 'actions:approve'"), "Approve failed"));
    expect(result.current[0]!.text).toBe("Approve failed: Your role can't approve actions");
    act(() => toastError(new ApiError(401, "unauthenticated", "a bearer token is required"), "Approve failed"));
    expect(result.current[0]!.text).toBe("Approve failed: signed out");
    render(<ErrorNote error={new ApiError(403, "denied", "playbook.merge: caller lacks scope 'playbooks:merge'")} onRetry={() => {}} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Your role can't merge playbooks");
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });
});

describe("primitives", () => {
  const wrap = (ui: ReactNode, path = "/") => render(<MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>);

  it("shows a capped tab count as a count", () => {
    wrap(<Tabs value="all" onChange={() => {}} tabs={[{ value: "all", label: "All", count: "200+" }]} />);
    expect(screen.getByRole("tab")).toHaveTextContent("All200+");
  });

  it("keeps a timeline row's end slot outside its button", () => {
    wrap(
      <Timeline
        moments={[{ key: "m", at: "2026-10-03T12:00:00Z", dot: "cited", what: "GetObject", end: <button type="button">E1</button> }]}
        onOpen={() => {}}
      />,
    );
    const chip = screen.getByRole("button", { name: "E1" });
    expect(chip.closest(".sh-tl__row")).toBeNull();
    expect(chip.closest("li")).toBe(screen.getByRole("button", { name: /GetObject/ }).closest("li"));
  });

  it("says no state word while a stateless strip loads, and its facts wrap rather than take a tab stop", () => {
    wrap(<Strip stateless loading facts={[{ label: "events", value: 3 }]} />);
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.getByRole("group", { name: "Facts" })).not.toHaveAttribute("tabindex");
  });

  it("folds long text behind more, and gives text that fits no button", () => {
    const { unmount } = render(<Clamped text="Fits" />);
    expect(screen.queryByRole("button")).toBeNull();
    unmount();
    const tall = vi.spyOn(Element.prototype, "scrollHeight", "get").mockReturnValue(60);
    const box = vi.spyOn(Element.prototype, "clientHeight", "get").mockReturnValue(40);
    render(<Clamped text="Ransomware crews hit companies this size through their VPN" />);
    const more = screen.getByRole("button", { name: "more" });
    expect(more).toHaveAttribute("aria-expanded", "false");
    expect(document.getElementById(more.getAttribute("aria-controls")!)).toHaveTextContent(/^Ransomware crews/);
    fireEvent.click(more);
    expect(screen.getByRole("button", { name: "less" })).toHaveAttribute("aria-expanded", "true");
    tall.mockRestore();
    box.mockRestore();
  });

  it("closes a dialog on a backdrop click only when the press began on the backdrop", () => {
    const onClose = vi.fn();
    render(
      <Dialog title="Rule" onClose={onClose}>
        <textarea aria-label="YAML" />
      </Dialog>,
    );
    const dialog = document.querySelector("dialog")!;
    // A selection dragged out of the field ends on the backdrop.
    fireEvent.pointerDown(screen.getByRole("textbox", { hidden: true }));
    fireEvent.click(dialog);
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.pointerDown(dialog);
    fireEvent.click(dialog);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("speaks inside the open dialog on top, which leaves the page inert, and on the page when none is open", async () => {
    render(
      <>
        <Announcer />
        <Dialog title="Rule" onClose={() => {}}>
          body
        </Dialog>
      </>,
    );
    const [page, inside] = [...document.querySelectorAll('[role="status"]')];
    const said = async (text: string) => {
      announce(text);
      await act(() => new Promise((done) => requestAnimationFrame(done)));
    };
    // jsdom has no showModal.
    document.querySelector("dialog")!.setAttribute("open", "");
    await said("Copied");
    expect(inside).toHaveTextContent("Copied");
    expect(page).toBeEmptyDOMElement();
    document.querySelector("dialog")!.removeAttribute("open");
    await said("Saved");
    expect(page).toHaveTextContent("Saved");
    expect(inside).toBeEmptyDOMElement();
  });

  it("reads edition two's renamed tab ids as their successors", () => {
    const { result } = renderHook(() => useTab(["activity", "autonomy", "pages"] as const), {
      wrapper: ({ children }) => <MemoryRouter initialEntries={["/response?pane=history"]}>{children}</MemoryRouter>,
    });
    expect(result.current[0]).toBe("activity");
  });
});

describe("crew text set as prose", () => {
  it("chips entity keys and sets tool names in mono, and never makes HTML or a link", () => {
    const { container } = render(
      <MemoryRouter>
        <Prose
          text={'Unbridged to user:jane@example.com; identity_resolve finds no link. <a href="javascript:alert(1)">x</a> [y](https://evil.example)\n\n- **one**\n- `two`'}
        />
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "user jane@example.com" })).toBeTruthy();
    expect(container.querySelector("code")?.textContent).toBe("identity_resolve");
    expect(container.querySelectorAll("li")).toHaveLength(2);
    expect(container.querySelector("a")).toBeNull();
    expect(container.textContent).toContain('<a href="javascript:alert(1)">x</a>');
  });

  it("reads a tool call as a tool and its argument", () => {
    const { container } = render(
      <MemoryRouter>
        <Prose text="Effect half: google.get_user(jane@example.com) shows the state." />
      </MemoryRouter>,
    );
    expect(container.querySelector("code")?.textContent).toBe("google.get_user");
    expect(screen.getByRole("button", { name: "email jane@example.com" })).toBeTruthy();
  });

  it("breaks one long paragraph at its sentence ends, and leaves short ones and dotted names whole", () => {
    const long =
      "One credential stopped CloudTrail logging, minted a second access key and read 64 objects of a customer-data export inside two minutes, from an address with no prior use. " +
      "The documented benign explanations fail on the events: there is no CI baseline, no key rotation, and no decommissioning note on file for this account at all this quarter. " +
      "I could not check the created key because identity.resolve is not built.";
    const { container } = render(
      <MemoryRouter>
        <Prose text={long} />
        <Prose text="Newly exposed. Appears in two sources." />
      </MemoryRouter>,
    );
    const [first, second] = [...container.querySelectorAll(".sh-prose")].map((p) => [...p.querySelectorAll("p")].map((x) => x.textContent));
    expect(first).toHaveLength(3);
    expect(first![2]).toContain("identity.resolve is not built.");
    expect(second).toEqual(["Newly exposed. Appears in two sources."]);
  });

  it("chips an address before its port and an IPv6 address ending in ::, and a hash only as a whole word", () => {
    const md5 = "4bf92f3577b34da6a3ce929d0e0e4736";
    const { container } = render(
      <MemoryRouter>
        <Prose text={`Seen at 203.0.113.7:443, then 2001:db8::. Dropped ${md5}. trace_id=${md5} ${md5}-00f067aa0ba902b7`} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "ipv4 203.0.113.7" })).toBeTruthy();
    expect(container.textContent).toContain(":443,");
    expect(screen.getByRole("button", { name: "ipv6 2001:db8::" })).toBeTruthy();
    expect(screen.getAllByRole("button", { name: `md5 ${md5}` })).toHaveLength(1);
  });
});

describe("the front page's played cards", () => {
  afterEach(() => vi.useRealTimers());

  it("play once and hold their end, a heading under the section's, the body out of reach", () => {
    vi.useFakeTimers();
    render(<HuntFlow />);
    expect(screen.getByRole("heading", { level: 3 })).toHaveTextContent(/^Somebody signs in to Okta/);
    expect(document.querySelector(".sh-play")).toHaveAttribute("inert");
    expect(screen.getByRole("button", { name: "Skip" })).toBeInTheDocument();
    for (let i = 0; i < 4; i++) act(() => void vi.advanceTimersByTime(1400));
    act(() => void vi.advanceTimersByTime(60_000));
    expect(document.querySelector(".sh-play__run")).toHaveAttribute("data-shown", "4");
    fireEvent.click(screen.getByRole("button", { name: "Replay" }));
    expect(document.querySelector(".sh-play__run")).toBeNull();
    expect(screen.getByRole("button", { name: "Skip" })).toBeInTheDocument();
  });
});
