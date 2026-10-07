import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Cites, EvidenceList } from "@/components/Citations";

function wrap(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("citations", () => {
  it("draws five E-chips, then +N, and tells the host what is pointed at", () => {
    const onPoint = vi.fn();
    wrap(<Cites uids={["a", "b", "c", "d", "e", "f", "g"]} onPoint={onPoint} highlight={["c"]} />);
    const chips = screen.getAllByRole("button");
    expect(chips.map((c) => c.textContent)).toEqual(["E1", "E2", "E3", "E4", "E5", "+2"]);
    expect(chips[2]).toHaveAttribute("data-hl");
    fireEvent.mouseEnter(chips[1]!);
    expect(onPoint).toHaveBeenLastCalledWith("b");
    fireEvent.mouseLeave(chips[1]!);
    expect(onPoint).toHaveBeenLastCalledWith(null);
  });

  it("numbers chips the way the page does, and says when nothing is cited", () => {
    wrap(<Cites uids={["x", "y"]} number={(uid) => (uid === "x" ? 4 : 7)} />);
    expect(screen.getAllByRole("button").map((c) => c.textContent)).toEqual(["E4", "E7"]);
  });

  it("marks an answer without evidence", () => {
    wrap(<Cites uids={[]} />);
    expect(screen.getByText("no evidence")).toBeInTheDocument();
  });

  it("opens a cited event on its fields, and fetches its raw record on demand", async () => {
    const event = {
      event_uid: "e1",
      time: "2026-10-01T10:00:00Z",
      api_operation: "CreateAccessKey",
      actor_user_name: "ci-deploy",
      src_endpoint_ip: "203.0.113.7",
      http_user_agent: "aws-cli/2.15",
      tenant_id: "default",
    };
    const raw = { eventName: "CreateAccessKey", sourceIPAddress: "203.0.113.7" };
    const withRaw = (init?: RequestInit) => String(init?.body).includes('"include_raw":true');
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) =>
        new Response(
          JSON.stringify({ data: { rows: [withRaw(init) ? { ...event, raw } : event], count: 1 }, summary: "", citations: [] }),
          { headers: { "content-type": "application/json" } },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);
    wrap(<EvidenceList uids={["e1"]} onClose={() => {}} />);

    fireEvent.click(await screen.findByText("CreateAccessKey"));
    // jsdom has no showModal, so the dialog's content counts as hidden.
    expect(screen.getByRole("button", { name: "Copy event id", hidden: true })).toHaveTextContent("e1");
    // Fields name a field as Explore's query does, leave out what the facts above say, and skip plumbing.
    expect(screen.getByText("http_request.user_agent")).toBeInTheDocument();
    expect(screen.queryByText("actor_user_name")).not.toBeInTheDocument();
    expect(screen.queryByText("tenant_id")).not.toBeInTheDocument();
    expect(screen.queryByText(/"sourceIPAddress"/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("radio", { name: "Raw", hidden: true }));
    expect(await screen.findByText(/"sourceIPAddress"/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => withRaw(init))).toBe(true);
    vi.unstubAllGlobals();
  });
});
