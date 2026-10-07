import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TokenGate } from "@/components/TokenGate";
import { clearSignedOut } from "@/lib/api";
import { browser, loginHere } from "@/lib/signin";

type Route = (body: Record<string, unknown>) => [number, unknown];
let routes: Record<string, Route> = {};
let sent: { path: string; body: Record<string, unknown> }[] = [];

function serve(next: Record<string, Route>) {
  routes = next;
  sent = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      sent.push({ path, body });
      const [status, answer] = routes[path]?.(body) ?? [404, { error: { code: "not_found", message: path } }];
      return new Response(JSON.stringify(answer), { status });
    }),
  );
}

const ME: [number, unknown] = [
  200,
  { data: { id: "jane@example.com", kind: "human", role: "admin", tenant: "default", email: "jane@example.com" }, summary: "", citations: [] },
];
const OUT: [number, unknown] = [401, { error: { code: "signed_out", message: "signed out" } }];

/** user.me refuses until a sign-in route answers. */
function signedOutUntil(start: unknown, extra: Record<string, Route> = {}) {
  let inside = false;
  const enter: Route = () => {
    inside = true;
    return [200, {}];
  };
  serve({
    "/v1/user/me": () => (inside ? ME : OUT),
    "/auth/start": () => [200, start],
    "/auth/login": enter,
    "/auth/token": enter,
    ...extra,
  });
}

const gate = () =>
  render(
    <TokenGate>
      <p>the console</p>
    </TokenGate>,
  );
const button = (name: string) => screen.getByRole("button", { name });
/** The login page, as the front page's Log in opens it. */
const logIn = async () => {
  window.history.replaceState(null, "", "/login");
  gate();
  expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent("Log in");
};

describe("the gate", () => {
  beforeEach(() => clearSignedOut());
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    window.history.replaceState(null, "", "/");
  });

  it("opens on the front page when user.me is refused, and its Log in goes to the login page", async () => {
    serve({ "/v1/user/me": () => OUT });
    gate();
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent("Your security team,run by agents.");
    expect(screen.queryByText("the console")).not.toBeInTheDocument();
    expect(screen.getByRole("img", { name: "Wazuh" })).toHaveAttribute("src", "/brands/wazuh.svg");
    expect(screen.getByRole("link", { name: "Log in" })).toHaveAttribute("href", "/login");
  });

  it("asks for the email first on the login page", async () => {
    serve({ "/v1/user/me": () => OUT });
    await logIn();
    expect(screen.getByLabelText("Email")).toHaveAttribute("type", "email");
    expect(button("Continue")).toBeDisabled();
    expect(screen.getByRole("link", { name: "shoc" })).toHaveAttribute("href", "/");
  });

  it("opens the login page at a signed-out screen's address, and signing in opens that screen", async () => {
    window.history.replaceState(null, "", "/cases/CASE-7f3a?tab=evidence");
    signedOutUntil({ method: "password" });
    gate();
    await userEvent.click(await screen.findByRole("button", { name: "Use a token" }));
    await userEvent.type(screen.getByLabelText("Token"), "shoc_admin_good");
    await userEvent.click(button("Open"));
    expect(await screen.findByText("the console")).toBeInTheDocument();
    expect(window.location.pathname + window.location.search).toBe("/cases/CASE-7f3a?tab=evidence");
  });

  it("gives /login way to the console's front screen once signed in", async () => {
    window.history.replaceState(null, "", "/login");
    serve({ "/v1/user/me": () => ME });
    gate();
    expect(await screen.findByText("the console")).toBeInTheDocument();
    expect(window.location.pathname).toBe("/");
  });

  it("draws a skeleton, not a blank page, while user.me is on its way", () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => new Promise<Response>(() => {})),
    );
    gate();
    expect(document.querySelector("[aria-busy=true]")).not.toBeNull();
    expect(screen.queryByText("the console")).not.toBeInTheDocument();
  });

  it("opens the console when user.me answers, sending no credential of its own", async () => {
    serve({ "/v1/user/me": () => ME });
    gate();
    expect(await screen.findByText("the console")).toBeInTheDocument();
    const init = vi.mocked(fetch).mock.calls[0]?.[1];
    expect((init?.headers as Record<string, string>).authorization).toBeUndefined();
  });

  it("opens the console when shoc cannot be reached, for its banner to say so", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))),
    );
    gate();
    expect(await screen.findByText("the console")).toBeInTheDocument();
  });

  it("asks for the email, the password, then the code, and sends the three together", async () => {
    signedOutUntil({ method: "password" });
    await logIn();
    await userEvent.type(screen.getByLabelText("Email"), "jane@example.com");
    await userEvent.click(button("Continue"));
    expect(sent.find((s) => s.path === "/auth/start")?.body).toEqual({ email: "jane@example.com", return_to: "/login" });
    await userEvent.type(await screen.findByLabelText("Password"), "correct horse battery");
    await userEvent.click(button("Continue"));
    // The password alone never goes out: a right one must not answer differently from a wrong one.
    expect(sent.some((s) => s.path === "/auth/login")).toBe(false);
    const code = await screen.findByLabelText("Code");
    expect(code).toHaveAttribute("autocomplete", "one-time-code");
    expect(code).toHaveAttribute("inputmode", "numeric");
    await userEvent.type(code, "123456");
    await userEvent.click(button("Continue"));
    expect(await screen.findByText("the console")).toBeInTheDocument();
    expect(window.location.pathname).toBe("/");
    expect(sent.find((s) => s.path === "/auth/login")?.body).toEqual({
      email: "jane@example.com",
      password: "correct horse battery",
      code: "123456",
    });
  });

  it("sends an SSO domain to the company's provider", async () => {
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => {});
    signedOutUntil({ method: "sso", url: "https://idp.example.com/authorize?state=s" });
    await logIn();
    await userEvent.type(screen.getByLabelText("Email"), "jane@example.com");
    await userEvent.click(button("Continue"));
    expect(assign).toHaveBeenCalledWith("https://idp.example.com/authorize?state=s");
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
  });

  it("says a refusal in one sentence and asks for the password again", async () => {
    signedOutUntil({ method: "password" }, { "/auth/login": () => [401, { error: { code: "bad_credentials", message: "no" } }] });
    await logIn();
    await userEvent.type(screen.getByLabelText("Email"), "jane@example.com");
    await userEvent.click(button("Continue"));
    await userEvent.type(await screen.findByLabelText("Password"), "wrong password!");
    await userEvent.click(button("Continue"));
    await userEvent.type(await screen.findByLabelText("Code"), "000000");
    await userEvent.click(button("Continue"));
    expect(await screen.findByText("Wrong email, password or code")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.queryByText("the console")).not.toBeInTheDocument();
  });

  it("turns a person's token into this browser's session", async () => {
    signedOutUntil({ method: "password" });
    await logIn();
    await userEvent.click(button("Use a token"));
    await userEvent.type(screen.getByLabelText("Token"), "shoc_admin_good");
    await userEvent.click(button("Open"));
    expect(await screen.findByText("the console")).toBeInTheDocument();
    expect(sent.find((s) => s.path === "/auth/token")?.body).toEqual({ token: "shoc_admin_good" });
  });

  it("opens the login page with the SSO callback's problem, and drops it from the address bar", async () => {
    window.history.replaceState(null, "", "/cases?signin=sso_domain");
    serve({ "/v1/user/me": () => OUT });
    gate();
    expect(await screen.findByText("This email can't sign in here")).toBeInTheDocument();
    expect(window.location.pathname + window.location.search).toBe("/cases");
  });

  it("keeps Continue off after a sign-in while the console loads, so the code goes out once", async () => {
    signedOutUntil({ method: "password" });
    const served = vi.mocked(fetch).getMockImplementation()!;
    // Signed in, user.me never answers: the login page stays up as it does while the gate probes.
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) =>
        String(input) === "/v1/user/me" && sent.some((s) => s.path === "/auth/login") ? new Promise<Response>(() => {}) : served(input, init),
      ),
    );
    await logIn();
    await userEvent.type(screen.getByLabelText("Email"), "jane@example.com");
    await userEvent.click(button("Continue"));
    await userEvent.type(await screen.findByLabelText("Password"), "correct horse battery");
    await userEvent.click(button("Continue"));
    await userEvent.type(await screen.findByLabelText("Code"), "123456");
    await userEvent.click(button("Continue"));
    await vi.waitFor(() => expect(sent.some((s) => s.path === "/auth/login")).toBe(true));
    expect(button("Continue")).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Code"), "{Enter}");
    expect(sent.filter((s) => s.path === "/auth/login")).toHaveLength(1);
  });

  it("says to open shoc at its public address when the kernel refuses this one", async () => {
    signedOutUntil({}, { "/auth/start": () => [403, { error: { code: "cross_site", message: "origin is not SHOC_PUBLIC_URL" } }] });
    await logIn();
    await userEvent.type(screen.getByLabelText("Email"), "jane@example.com");
    await userEvent.click(button("Continue"));
    expect(await screen.findByText("Open shoc at its public address")).toBeInTheDocument();
  });

  it("sends the signed-out banner's Log in to /login from the front screen, else to the screen's own address", () => {
    expect(loginHere()).toBe("/login");
    window.history.replaceState(null, "", "/cases/CASE-7f3a?tab=evidence");
    expect(loginHere()).toBe("/cases/CASE-7f3a?tab=evidence");
  });

  it("opens the login page rather than the front page when the SSO callback comes back to / with a problem", async () => {
    window.history.replaceState(null, "", "/?signin=sso_failed");
    serve({ "/v1/user/me": () => OUT });
    gate();
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent("Log in");
    expect(screen.getByText("Your provider's sign-in failed")).toBeInTheDocument();
  });
});
