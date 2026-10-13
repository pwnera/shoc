import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Seg } from "@/components/ui/seg";

const OPTIONS = ["new", "triage", "closed"];

describe("a segmented control", () => {
  it("picks with the arrow keys when it only changes a view", async () => {
    const onChange = vi.fn();
    render(<Seg label="Window" value="new" options={OPTIONS} onChange={onChange} />);
    screen.getByRole("radio", { name: "new" }).focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(onChange).toHaveBeenCalledWith("triage");
  });

  it("only moves with the arrow keys when it writes, and picks on Enter or Space", async () => {
    const onChange = vi.fn();
    render(<Seg label="Status" manual value="new" options={OPTIONS} onChange={onChange} />);
    screen.getByRole("radio", { name: "new" }).focus();
    await userEvent.keyboard("{ArrowRight}{ArrowRight}");
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByRole("radio", { name: "closed" })).toHaveFocus();
    await userEvent.keyboard("{ArrowLeft}");
    expect(screen.getByRole("radio", { name: "triage" })).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(onChange).toHaveBeenCalledWith("triage");
    await userEvent.keyboard("{ArrowLeft} ");
    expect(onChange).toHaveBeenLastCalledWith("new");
  });
});
