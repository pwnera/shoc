import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { parse } from "yaml";
import { MergeDialog } from "@/components/MergeDialog";
import { NARROWING_SECTIONS, RULE_SECTIONS, seeded, type Section } from "@/lib/merge";

const SECTIONS: Section[] = [
  { field: "pack", label: "Pack", template: "id: p1\ntitle: First policy change\n" },
  { field: "fixtures", label: "Fixtures", template: "source: okta\n" },
];

let reply: () => Response = () => new Response("{}");
let sent: Record<string, unknown>[] = [];
const ok = (data: unknown) => new Response(JSON.stringify({ data, summary: "", citations: [] }));

function show(props: Partial<Parameters<typeof MergeDialog>[0]> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <MergeDialog
          title="New pack"
          capability="hunt.merge"
          sections={SECTIONS}
          reasonExample="why"
          facts={(d) => [["pack", String(d.pack_id)]]}
          onClose={() => {}}
          {...props}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const button = (name: string) => screen.getByRole("button", { name, hidden: true });
const tab = (name: string) => screen.getByRole("tab", { name: new RegExp(name), hidden: true });
const editor = (name: string) => screen.getByLabelText(name) as HTMLTextAreaElement;
const check = () => fireEvent.submit(document.querySelector("form")!);

describe("the merge dialog", () => {
  beforeEach(() => {
    sessionStorage.clear();
    sent = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((_url: string, init?: RequestInit) => {
        sent.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>);
        return Promise.resolve(reply());
      }),
    );
  });
  afterEach(() => vi.unstubAllGlobals());

  it("opens Merge once Check passed on the input as it stands, and locks it again on an edit", async () => {
    reply = () => ok({ pack_id: "p1", checked: { readiness: "ready", tuples: 2, window: "1d" } });
    show();
    expect(button("Merge")).toBeDisabled();
    check();
    expect(await screen.findByText("Passes")).toBeInTheDocument();
    expect(sent[0]).toMatchObject({ dry_run: true, pack: { id: "p1" } });
    expect(button("Merge")).toBeEnabled();
    fireEvent.change(editor("Pack"), { target: { value: "id: p2\n" } });
    expect(button("Merge")).toBeDisabled();
    expect(screen.queryByText("Passes")).toBeNull();
  });

  it("lists each reason the gate gave whole, marks the tab one names, and dims them after an edit", async () => {
    reply = () =>
      new Response(
        JSON.stringify({
          error: {
            code: "gate_refused",
            message: "not merged: the id must be lower_snake_case; 3 to 80 characters; it did not return its surfaced fixture",
            reasons: ["the id must be lower_snake_case; 3 to 80 characters", "it did not return its surfaced fixture"],
          },
        }),
        { status: 422 },
      );
    show();
    check();
    expect(await screen.findByText("the id must be lower_snake_case; 3 to 80 characters")).toBeInTheDocument();
    expect(screen.getByText("it did not return its surfaced fixture")).toBeInTheDocument();
    expect(tab("Fixtures")).toHaveTextContent("!");
    expect(tab("Pack")).not.toHaveTextContent("!");
    expect(screen.queryByText("before your edit")).toBeNull();
    fireEvent.change(editor("Pack"), { target: { value: "id: p_2\n" } });
    expect(screen.getByText("before your edit")).toBeInTheDocument();
    expect(tab("Fixtures")).not.toHaveTextContent("!");
  });

  it("takes a refusal without its list as one reason", async () => {
    reply = () => new Response(JSON.stringify({ error: { code: "gate_refused", message: "not merged: a; b" } }), { status: 422 });
    show();
    check();
    expect(await screen.findByText("a; b")).toBeInTheDocument();
  });

  it("names the tab and marks the line that does not parse, and sends nothing", () => {
    show();
    fireEvent.click(tab("Fixtures"));
    fireEvent.change(editor("Fixtures"), { target: { value: "source: okta\nsource: aws\n" } });
    fireEvent.click(tab("Pack"));
    check();
    expect(tab("Fixtures")).toHaveAttribute("aria-selected", "true");
    expect(tab("Fixtures")).toHaveTextContent("!");
    expect(screen.getByText(/^Fixtures, line 2:/)).toBeInTheDocument();
    expect(document.querySelector("li.text-bad")?.textContent).toBe("2");
    expect(sent).toEqual([]);
  });

  it("waits for what the caller needs before it checks", () => {
    show({ missing: () => "Pick a playbook", head: (_doc, missing) => <span>{missing}</span> });
    expect(screen.queryByText("Pick a playbook")).toBeNull();
    check();
    expect(screen.getByText("Pick a playbook")).toBeInTheDocument();
    expect(sent).toEqual([]);
  });

  it("leaves the editor on Escape without closing, and keeps the draft for the next open", () => {
    const onClose = vi.fn();
    const first = show({ onClose });
    const area = editor("Pack");
    area.focus();
    fireEvent.change(area, { target: { value: "id: mine\n" } });
    fireEvent.keyDown(area, { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(button("Check"));
    first.unmount();
    show();
    expect(editor("Pack").value).toBe("id: mine\n");
    fireEvent.click(button("Start over"));
    expect(editor("Pack").value).toBe(SECTIONS[0]!.template);
  });

  it("indents every selected line on Tab and outdents them on Shift+Tab, keeping the selection", async () => {
    show();
    const area = editor("Pack");
    fireEvent.change(area, { target: { value: "a: 1\nb: 2\nc: 3" } });
    area.setSelectionRange(0, 9);
    fireEvent.keyDown(area, { key: "Tab" });
    await waitFor(() => expect(area.value).toBe("  a: 1\n  b: 2\nc: 3"));
    expect([area.selectionStart, area.selectionEnd]).toEqual([0, 13]);
    fireEvent.keyDown(area, { key: "Tab", shiftKey: true });
    await waitFor(() => expect(area.value).toBe("a: 1\nb: 2\nc: 3"));
    expect([area.selectionStart, area.selectionEnd]).toEqual([0, 9]);
    // No selection: two spaces at the caret.
    area.setSelectionRange(5, 5);
    fireEvent.keyDown(area, { key: "Tab" });
    await waitFor(() => expect(area.value).toBe("a: 1\n  b: 2\nc: 3"));
  });
});

describe("merge templates", () => {
  it("starts from what a backlog item says, and keeps the examples it does not", () => {
    const [rule, fixtures] = seeded(RULE_SECTIONS, "rule", { attack: ["T1105"], product: "okta", title: "A tool: fetched", id: "" });
    const doc = parse(rule!.template) as { id: unknown; title: string; attack: string[]; logsource: { product: string } };
    expect(doc.attack).toEqual(["T1105"]);
    expect(doc.logsource.product).toBe("okta");
    expect(doc.title).toBe("A tool: fetched");
    expect(doc.id).toBeNull();
    expect(fixtures).toBe(RULE_SECTIONS[1]);
    expect(seeded(NARROWING_SECTIONS, "hide_events", ["EVT-1", "EVT-2"])[1]!.template).toBe('["EVT-1","EVT-2"]\n');
    expect(seeded(NARROWING_SECTIONS, "hide_events", [])[1]).toBe(NARROWING_SECTIONS[1]);
  });
});
