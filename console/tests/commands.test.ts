import { describe, expect, it, vi } from "vitest";
import { act, render } from "@testing-library/react";
import { createElement } from "react";
import { MemoryRouter, Route, Routes, useLocation, useSearchParams } from "react-router-dom";
import {
  COMMANDS,
  GO_TO,
  ariaKeys,
  dispatch,
  handOff,
  keyLabel,
  keyOf,
  paletteLabel,
  runCommand,
  useCommand,
  useKeys,
  useListNav,
  useAsking,
  recordOf,
} from "@/lib/commands";
import { ROUTES } from "@/lib/nav";

/** A route pattern matches a path when every `:param` segment matches anything. */
function routed(path: string): boolean {
  const parts = path.split("/");
  return ROUTES.some((route) => {
    const want = route.split("/");
    return want.length === parts.length && want.every((w, i) => w.startsWith(":") || w === parts[i]);
  });
}

describe("the command table", () => {
  it("never gives two commands the same key in one scope", () => {
    const seen = new Map<string, string>();
    for (const c of COMMANDS)
      for (const key of [c.keys, c.alt].filter(Boolean)) {
        const slot = `${c.scope} ${key}`;
        expect(seen.get(slot), `${c.id} and ${seen.get(slot)} share ${slot}`).toBeUndefined();
        seen.set(slot, c.id);
      }
  });

  it("gives every page command a home, and every palette hand-off a home that routes", () => {
    for (const c of COMMANDS) {
      if (c.scope.startsWith("route:")) expect(c.home, c.id).toBeTruthy();
      if (c.palette) {
        expect(c.home, c.id).toBeTruthy();
        expect(routed(c.home!.split("?")[0]!), `${c.id} → ${c.home}`).toBe(true);
        expect(c.home).not.toContain(":");
      }
    }
  });

  it("has unique ids", () => {
    expect(new Set(COMMANDS.map((c) => c.id)).size).toBe(COMMANDS.length);
  });

  it("lists every screen and tab for Go to, each leading somewhere that routes", () => {
    expect(GO_TO.find((g) => g.label === "Response › Pages")?.to).toBe("/response?tab=pages");
    expect(GO_TO.find((g) => g.label === "Health › Crew")?.to).toBe("/health/crew");
    expect(GO_TO.find((g) => g.label === "Findings › Set aside")?.to).toBe("/findings?tab=aside");
    expect(GO_TO.find((g) => g.label === "Access › Tokens")?.to).toBe("/access?tab=tokens");
    for (const g of GO_TO) expect(routed(g.to.split("?")[0]!), g.to).toBe(true);
  });

  it("names palette commands by their home and hands them off with do", () => {
    const run = COMMANDS.find((c) => c.id === "detection.run-all")!;
    expect(paletteLabel(run)).toBe("Detection › Run every rule now");
    expect(handOff(run)).toBe("/detection?do=detection.run-all");
    expect(handOff(COMMANDS.find((c) => c.id === "access.new-token")!)).toBe("/access?tab=tokens&do=access.new-token");
    expect(handOff(COMMANDS.find((c) => c.id === "access.invite")!)).toBe("/access?do=access.invite");
  });
});

describe("keys as text", () => {
  it("spells a keydown as the table does", () => {
    const k = (key: string, mods: Partial<KeyboardEvent> = {}) =>
      keyOf({ key, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false, ...mods });
    expect(k("K", { metaKey: true })).toBe("mod+k");
    expect(k("k", { ctrlKey: true })).toBe("mod+k");
    expect(k("J", { metaKey: true, shiftKey: true })).toBe("mod+shift+j");
    expect(k("?", { shiftKey: true })).toBe("?");
    expect(k("ArrowRight", { shiftKey: true })).toBe("shift+arrowright");
    expect(k(" ")).toBe("space");
  });

  it("writes keys for tips and for aria-keyshortcuts", () => {
    expect(keyLabel("g c")).toBe("G C");
    expect(ariaKeys("mod+k")).toBe("Meta+K Control+K");
    expect(ariaKeys("g c")).toBe("G C");
    expect(ariaKeys("shift+arrowright")).toBe("Shift+Arrowright");
  });
});

function Bind({ id, run, enabled = true }: { id: string; run: () => void; enabled?: boolean }) {
  useCommand(id, run, enabled);
  return null;
}

function Keys() {
  useKeys();
  return null;
}

function Where() {
  const location = useLocation();
  return createElement("output", null, location.pathname + location.search);
}

describe("bound commands", () => {
  it("lets the page's key win over a global one and falls back to the palette for /", () => {
    const close = vi.fn();
    const palette = vi.fn();
    render(
      createElement(
        MemoryRouter,
        null,
        createElement(Bind, { id: "case.close", run: close }),
        createElement(Bind, { id: "shell.palette", run: palette }),
      ),
    );
    const event = new KeyboardEvent("keydown", { key: "c" });
    expect(dispatch("c", event, () => {})).toBe(true);
    expect(close).toHaveBeenCalledOnce();
    expect(runCommand("shell.filter")).toBe(true);
    expect(palette).toHaveBeenCalledOnce();
  });

  it("answers nothing for a key nobody bound", () => {
    expect(dispatch("?", new KeyboardEvent("keydown", { key: "?" }), vi.fn())).toBe(false);
  });

  it("follows a G chord, and ignores single keys typed into a field", async () => {
    const view = render(createElement(MemoryRouter, { initialEntries: ["/"] }, createElement(Keys), createElement(Where)));
    const press = (key: string, target: EventTarget = window) =>
      act(() => void target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true })));
    await press("g");
    await press("c");
    expect(view.container.querySelector("output")?.textContent).toBe("/cases");
    const input = document.createElement("input");
    document.body.append(input);
    await press("g", input);
    await press("f", input);
    expect(view.container.querySelector("output")?.textContent).toBe("/cases");
    input.remove();
  });

  it("runs a palette hand-off once and drops do from the URL", async () => {
    const run = vi.fn();
    const view = render(
      createElement(
        MemoryRouter,
        { initialEntries: ["/detection?tab=rules&do=detection.run-all"] },
        createElement(
          Routes,
          null,
          createElement(Route, {
            path: "/detection",
            element: createElement("div", null, createElement(Bind, { id: "detection.run-all", run }), createElement(Where)),
          }),
        ),
      ),
    );
    await act(async () => {});
    expect(run).toHaveBeenCalledOnce();
    expect(view.container.querySelector("output")?.textContent).toBe("/detection?tab=rules");
  });

  it("runs a hand-off whose handler writes the URL once, and leaves no do behind", async () => {
    const run = vi.fn();
    function Opens() {
      const [, setParams] = useSearchParams();
      useCommand("sources.add", () => {
        run();
        setParams((current) => {
          const out = new URLSearchParams(current);
          out.set("add", "1");
          return out;
        });
      });
      return null;
    }
    const view = render(
      createElement(
        MemoryRouter,
        { initialEntries: ["/connections?do=sources.add"] },
        createElement(Routes, null, createElement(Route, { path: "/connections", element: createElement("div", null, createElement(Opens), createElement(Where)) })),
      ),
    );
    await act(async () => {});
    await act(async () => {});
    expect(run).toHaveBeenCalledOnce();
    expect(view.container.querySelector("output")?.textContent).toBe("/connections?add=1");
  });

  it("drops a hand-off that arrives while its command cannot run, rather than running it later", async () => {
    const run = vi.fn();
    const tree = (enabled: boolean) =>
      createElement(
        MemoryRouter,
        { initialEntries: ["/connections?do=source.pull"] },
        createElement(Bind, { id: "source.pull", run, enabled }),
        createElement(Where),
      );
    const view = render(tree(false));
    await act(async () => {});
    expect(view.container.querySelector("output")?.textContent).toBe("/connections");
    view.rerender(tree(true));
    await act(async () => {});
    expect(run).not.toHaveBeenCalled();
  });

  it("asks before a hand-off that writes, and runs it only on the confirm", async () => {
    const run = vi.fn();
    let asked: ReturnType<typeof useAsking> = [null, () => {}];
    function Asking() {
      asked = useAsking();
      return null;
    }
    render(
      createElement(
        MemoryRouter,
        { initialEntries: ["/intel?ioc=x&do=indicator.sweep"] },
        createElement(Bind, { id: "indicator.sweep", run }),
        createElement(Asking),
      ),
    );
    await act(async () => {});
    expect(run).not.toHaveBeenCalled();
    expect(asked[0]?.command.id).toBe("indicator.sweep");
    act(() => {
      asked[0]!.run();
      asked[1]();
    });
    expect(run).toHaveBeenCalledOnce();
    expect(asked[0]).toBeNull();
  });
});

function List({ rows, onOpen }: { rows: string[]; onOpen: (r: string) => void }) {
  const nav = useListNav(rows, (r) => r, { onOpen });
  return createElement(
    "ul",
    null,
    rows.map((r) => createElement("li", { key: r, ...nav.rowProps(r) }, r)),
  );
}

describe("list keys", () => {
  it("moves the active row by id and opens it", async () => {
    const onOpen = vi.fn();
    const key = (k: string) => act(() => void dispatch(k, new KeyboardEvent("keydown", { key: k }), vi.fn()));
    const view = render(createElement(MemoryRouter, null, createElement(List, { rows: ["a", "b", "c"], onOpen })));
    await key("j");
    await key("j");
    expect(view.container.querySelector("[data-active]")?.textContent).toBe("b");
    // A refresh that puts a new row on top keeps "b" active.
    view.rerender(createElement(MemoryRouter, null, createElement(List, { rows: ["new", "a", "b", "c"], onOpen })));
    expect(view.container.querySelector("[data-active]")?.textContent).toBe("b");
    await key("enter");
    expect(onOpen).toHaveBeenCalledWith("b");
    await key("end");
    expect(view.container.querySelector("[data-active]")?.textContent).toBe("c");
  });

  it("knows which record a path is the page of", () => {
    expect(recordOf("/cases/CASE-1")).toEqual({ kind: "case", id: "CASE-1", to: "/cases/CASE-1" });
    expect(recordOf("/detection/rules/aws_root_login")?.kind).toBe("rule");
    expect(recordOf("/cases")).toBeNull();
  });
});
