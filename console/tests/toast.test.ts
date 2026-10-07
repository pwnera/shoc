import { describe, expect, it } from "vitest";
import { forgetUndo, lastUndoable, toast, undoUntil } from "@/lib/toast";

describe("Z", () => {
  it("skips an action already undone or past its undo window", () => {
    toast({ tone: "ok", text: "Disable AWS key ran", undo: "A-1" });
    toast({ tone: "ok", text: "Sign user out ran", undo: "B-2" });
    expect(lastUndoable()).toBe("B-2");
    forgetUndo("B-2");
    expect(lastUndoable()).toBe("A-1");
    undoUntil("A-1", new Date(Date.now() - 1_000).toISOString());
    expect(lastUndoable()).toBeUndefined();
  });
});
