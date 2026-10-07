import { describe, expect, it, beforeEach, vi, afterEach } from "vitest";
import { ApiError, auth, call, callData, clearSignedOut, explain, markSignedOut, recheck, useSignedOut } from "@/lib/api";
import { renderHook } from "@testing-library/react";

function respond(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
  );
}

/** A `fetch` stand-in whose calls keep their types. */
function mockFetch(handler: () => Promise<Response>) {
  const mock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => handler());
  vi.stubGlobal("fetch", mock);
  return mock;
}

function call_(mock: ReturnType<typeof mockFetch>, index: number) {
  const args = mock.mock.calls[index];
  if (!args) throw new Error(`fetch was not called ${index + 1} time(s)`);
  return { url: String(args[0]), init: args[1] ?? {} };
}

describe("the API client", () => {
  beforeEach(() => clearSignedOut());
  afterEach(() => vi.unstubAllGlobals());

  it("turns a capability name into its REST path", async () => {
    const fetchMock = mockFetch(() => respond({ data: {}, summary: "", citations: [] }));

    await call("case.set_state", { case_uid: "CASE-1", state: "closed" });

    const { url, init } = call_(fetchMock, 0);
    expect(url).toBe("/v1/case/set_state");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      case_uid: "CASE-1",
      state: "closed",
    });
  });

  it("sends no credential of its own: the session cookie goes with a same-origin call", async () => {
    const fetchMock = mockFetch(() => respond({ data: {}, summary: "", citations: [] }));
    await call("finding.list");
    const { init } = call_(fetchMock, 0);
    expect((init.headers as Record<string, string>).authorization).toBeUndefined();
    expect(init.credentials).toBeUndefined();
  });

  it("unwraps the envelope", async () => {
    mockFetch(() => respond({ data: { count: 3 }, summary: "3 findings", citations: ["e1"] }));
    await expect(callData<{ count: number }>("finding.list")).resolves.toEqual({ count: 3 });
  });

  it("turns an error body into an ApiError that knows it is about permission", async () => {
    mockFetch(() => respond({ error: { code: "denied", message: "caller lacks scope" } }, 403));
    const error = await call("action.approve", { action_uid: "x" }).catch((problem) => problem);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(403);
    expect(error.isAuth).toBe(true);
    expect(error.message).toBe("caller lacks scope");
  });

  it("does not pretend a non-JSON body is a result", async () => {
    mockFetch(() => Promise.resolve(new Response("<html>gateway</html>", { status: 502 })));
    await expect(call("finding.list")).rejects.toBeInstanceOf(ApiError);
  });

  it("raises the signed-out banner when the session ends, not for a missing scope, and stops calling", async () => {
    mockFetch(() => respond({ error: { code: "denied", message: "finding.list: caller lacks scope 'findings:read'" } }, 403));
    await call("finding.list").catch(() => {});
    expect(renderHook(() => useSignedOut()).result.current).toBe(false);
    mockFetch(() => respond({ error: { code: "signed_out", message: "signed out" } }, 401));
    const error = await call("finding.list").catch((e) => e);
    expect(explain(error)).toBe("Signed out");
    expect(renderHook(() => useSignedOut()).result.current).toBe(true);
    const fetchMock = mockFetch(() => respond({ data: {}, summary: "", citations: [] }));
    await expect(call("finding.list")).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rechecks user.me past the short-circuit, and lowers the banner only when it answers", async () => {
    markSignedOut();
    mockFetch(() => respond({ error: { code: "signed_out", message: "signed out" } }, 401));
    expect(await recheck()).toBe(false);
    expect(renderHook(() => useSignedOut()).result.current).toBe(true);
    const fetchMock = mockFetch(() => respond({ data: {}, summary: "", citations: [] }));
    expect(await recheck()).toBe(true);
    expect(call_(fetchMock, 0).url).toBe("/v1/user/me");
    expect(renderHook(() => useSignedOut()).result.current).toBe(false);
  });

  it("posts a sign-in route as JSON and keeps the route's own code, without the banner", async () => {
    const fetchMock = mockFetch(() => respond({ error: { code: "bad_credentials", message: "no" } }, 401));
    const error = (await auth("login", { email: "jane@example.com", password: "p", code: "123456" }).catch((e) => e)) as ApiError;
    const { url, init } = call_(fetchMock, 0);
    expect(url).toBe("/auth/login");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe("bad_credentials");
    expect(renderHook(() => useSignedOut()).result.current).toBe(false);
  });

  it("says when shoc cannot be reached", async () => {
    mockFetch(() => Promise.reject(new TypeError("Failed to fetch")));
    const error = await call("finding.list").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.isNetwork).toBe(true);
    expect(explain(error)).toMatch(/^Can't reach /);
  });

  it("counts a 401, or a call with no credential at all, as signed out", () => {
    expect(new ApiError(401, "signed_out", "signed out").isAuth).toBe(true);
    expect(new ApiError(401, "signed_out", "signed out").isSignedOut).toBe(true);
    expect(new ApiError(401, "unauthenticated", "no credential").isSignedOut).toBe(true);
    expect(new ApiError(403, "denied", "caller lacks scope 'findings:read'").isSignedOut).toBe(false);
  });

  it("carries every reason a gate refused", async () => {
    const reasons = ["fixture 'positive' does not match", "the id is taken; pick another"];
    mockFetch(() =>
      Promise.resolve(
        new Response(JSON.stringify({ error: { code: "gate_refused", message: "not merged", reasons } }), {
          status: 400,
        }),
      ),
    );
    const error = await call("detection.merge").catch((e) => e);
    expect(error.code).toBe("gate_refused");
    expect(error.reasons).toEqual(reasons);
  });
});
