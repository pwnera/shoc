import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TokenGate } from "@/components/TokenGate";
import { browser } from "@/lib/signin";

const OTPAUTH = "otpauth://totp/shoc:ann%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=shoc";

let sent: { path: string; body: Record<string, unknown> }[] = [];

/** `/auth/link` opens the link; `accept` answers each `/auth/link/accept` in turn. */
function serve(open: [number, unknown], ...accept: [number, unknown][]) {
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      sent.push({ path, body: JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown> });
      const [status, answer] =
        path === "/auth/link" ? open : path === "/auth/link/accept" ? (accept.shift() ?? [500, {}]) : [404, {}];
      return new Response(JSON.stringify(answer), { status });
    }),
  );
}

function welcome(link = "lnk_abc") {
  window.history.replaceState(null, "", `/welcome#${link}`);
  return render(
    <TokenGate>
      <p>the console</p>
    </TokenGate>,
  );
}

async function fill(password: string, confirm: string, code: string) {
  await userEvent.type(screen.getByLabelText("New password"), password);
  await userEvent.type(screen.getByLabelText("Confirm password"), confirm);
  await userEvent.type(screen.getByLabelText("Code"), code);
  await userEvent.click(screen.getByRole("button", { name: "Continue" }));
}

describe("the welcome page", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    window.history.replaceState(null, "", "/");
  });

  it("opens the link from the fragment, clears it, and shows the new authenticator", async () => {
    serve([200, { email: "ann@example.com", enrol: true, otpauth: OTPAUTH }]);
    welcome();
    expect(await screen.findByText("ann@example.com")).toBeInTheDocument();
    expect(window.location.hash).toBe("");
    expect(sent).toEqual([{ path: "/auth/link", body: { link: "lnk_abc" } }]);
    expect(screen.getByRole("img", { name: "QR code for an authenticator app" }).getAttribute("src")).toMatch(/^data:image\/svg\+xml/);
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    expect(screen.queryByText("the console")).not.toBeInTheDocument();
  });

  it("asks again after a wrong code, then signs in and opens the console", async () => {
    const replace = vi.spyOn(browser, "replace").mockImplementation(() => {});
    serve(
      [200, { email: "ann@example.com", enrol: true, otpauth: OTPAUTH }],
      [401, { error: { code: "bad_code", message: "wrong code" } }],
      [200, {}],
    );
    welcome();
    await screen.findByText("ann@example.com");
    await fill("a long enough password", "a long enough password", "111111");
    expect(await screen.findByText("Wrong code")).toBeInTheDocument();
    expect(screen.getByLabelText("Code")).toHaveValue("");
    await userEvent.type(screen.getByLabelText("Code"), "222222");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await vi.waitFor(() => expect(replace).toHaveBeenCalledWith("/"));
    expect(sent.at(-1)).toEqual({
      path: "/auth/link/accept",
      body: { link: "lnk_abc", password: "a long enough password", code: "222222" },
    });
  });

  it("asks only for a password and a code when the link keeps the authenticator", async () => {
    serve([200, { email: "ann@example.com", enrol: false, otpauth: "" }]);
    welcome();
    await screen.findByText("ann@example.com");
    expect(screen.queryByRole("img", { name: "QR code for an authenticator app" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Code")).toBeInTheDocument();
  });

  it("refuses two different passwords without sending them", async () => {
    serve([200, { email: "ann@example.com", enrol: false, otpauth: "" }]);
    welcome();
    await screen.findByText("ann@example.com");
    await fill("a long enough password", "another long password", "123456");
    expect(screen.getByText("Passwords don't match")).toBeInTheDocument();
    expect(sent.some((s) => s.path === "/auth/link/accept")).toBe(false);
  });

  it("says when the link has expired, and its Log in opens the login page", async () => {
    serve([410, { error: { code: "link_expired", message: "expired" } }]);
    welcome();
    expect(await screen.findByText("This link has expired. Ask an admin for a new one.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Log in" })).toHaveAttribute("href", "/login");
  });

  it("keeps a good code when only the password is refused", async () => {
    serve(
      [200, { email: "ann@example.com", enrol: false, otpauth: "" }],
      [400, { error: { code: "bad_password", message: "password is too short" } }],
    );
    welcome();
    await screen.findByText("ann@example.com");
    await fill("short password", "short password", "123456");
    expect(await screen.findByText("password is too short")).toBeInTheDocument();
    expect(screen.getByLabelText("Code")).toHaveValue("123456");
  });

  it("opens the link again after a reload, from the tab's history rather than the address bar", async () => {
    serve([200, { email: "ann@example.com", enrol: false, otpauth: "" }]);
    const first = welcome();
    await screen.findByText("ann@example.com");
    expect(window.location.href).not.toContain("lnk_abc");
    first.unmount();
    render(
      <TokenGate>
        <p>the console</p>
      </TokenGate>,
    );
    expect(await screen.findByText("ann@example.com")).toBeInTheDocument();
    expect(sent.at(-1)).toEqual({ path: "/auth/link", body: { link: "lnk_abc" } });
  });

  it("says to open shoc at its public address when the kernel refuses this one", async () => {
    serve([403, { error: { code: "cross_site", message: "origin is not SHOC_PUBLIC_URL" } }]);
    welcome();
    expect(await screen.findByText("Open shoc at its public address")).toBeInTheDocument();
  });
});
