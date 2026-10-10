import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Table, type Column } from "@/components/ui/table";
import { useSort } from "@/lib/sort";

type Row = { id: string; name: string; n: number | null };
const ROWS: Row[] = [
  { id: "a", name: "item 9", n: 2 },
  { id: "b", name: "Item 1", n: null },
  { id: "c", name: "item 10", n: 30 },
];
const COLUMNS: Column<Row>[] = [
  { label: "Name", cell: (r) => <b>{r.name}</b> },
  { label: "Count", cell: (r) => `${r.n ?? "–"}`, sort: (r) => r.n },
  { label: "", menu: true, cell: () => "⋯" },
];

function List() {
  const sorted = useSort(ROWS, COLUMNS);
  return <Table label="List" columns={COLUMNS} rows={sorted.rows} rowKey={(r) => r.id} sort={sorted.sort} />;
}

const names = () => screen.getAllByRole("row").slice(1).map((tr) => tr.firstElementChild!.textContent);

describe("sorting a table from its heads", () => {
  it("sorts by the cell's text, ascending, descending, then back to the list's order", () => {
    render(<List />, { wrapper: MemoryRouter });
    const head = screen.getByRole("button", { name: "Name" });
    fireEvent.click(head);
    expect(names()).toEqual(["Item 1", "item 9", "item 10"]);
    expect(head.closest("th")).toHaveAttribute("aria-sort", "ascending");
    fireEvent.click(head);
    expect(names()).toEqual(["item 10", "item 9", "Item 1"]);
    fireEvent.click(head);
    expect(names()).toEqual(["item 9", "Item 1", "item 10"]);
    expect(head.closest("th")).not.toHaveAttribute("aria-sort");
  });

  it("sorts by the column's value with empty values last either way, and leaves a menu head alone", () => {
    render(<List />, { wrapper: MemoryRouter });
    const head = screen.getByRole("button", { name: "Count" });
    fireEvent.click(head);
    expect(names()).toEqual(["item 9", "item 10", "Item 1"]);
    fireEvent.click(head);
    expect(names()).toEqual(["item 10", "item 9", "Item 1"]);
    expect(screen.getAllByRole("button")).toHaveLength(2);
  });
});
