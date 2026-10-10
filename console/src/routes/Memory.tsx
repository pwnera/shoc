/**
 * Memory: what has the crew been told or learned about this company, and is
 * any of it wrong? Facts, Notes and Corrections partition what `memory.search`
 * returns (100 at most, its cap). The risk the question asks about, a
 * person's word that keeps silencing the crew, is the "told by people" filter,
 * which the strip counts and presses; beside it, when the newest was added.
 * A row is where it came from, what it is about (an entity as its chip, a
 * correction's rule by its title) and what it says; the memory dialog holds
 * the rest. Bare /memory is Facts, as every screen lands on its first tab; an
 * empty Facts points to the tab that has rows. Add a fact (`N`) opens a dialog.
 *
 * Capabilities: memory.search, memory.add_fact; rule.list names a correction's rule.
 */
import { useState } from "react";
import { Plus } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { Avatar } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Strip } from "@/components/ui/strip";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useCommand, useListNav, useTabKeys } from "@/lib/commands";
import { bare } from "@/lib/entity";
import { useFilters, type Dim } from "@/lib/filters";
import { age, stamp } from "@/lib/format";
import { staleSince } from "@/lib/loaded";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useTab } from "@/lib/param";
import { useFollow, usePopParam } from "@/lib/popup";
import { MEMORY_CAP, useMemory, useRules } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import { toast } from "@/lib/toast";
import type { Memory as Row } from "@/types";
import { AddFactDialog } from "./memory/AddFactDialog";
import { MemoryDialog, Subject } from "./memory/MemoryDialog";
import { aboutOf, bodyOf, ORIGINS, originOf, tabOf, TABS, type Tab } from "./memory/origin";

/** Subjects offered in the filter menu, busiest first. */
const SUBJECTS = 20;

const label = (tab: Tab) => tab.charAt(0).toUpperCase() + tab.slice(1);

export function Memory() {
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const memory = useMemory(params.get("q") ?? "");
  const all = memory.data?.rows ?? [];
  const inTab = (t: string) => all.filter((r) => tabOf(r.kind) === t);
  const [tab, setTab] = useTab(TABS);
  const rules = useRules();
  const titles = new Map((rules.data?.rules ?? []).map((r) => [r.id, r.title]));
  const ruleTitle = (id: string) => titles.get(id) ?? id;
  /** A subject in the filter menu, in the words its rows draw it with. */
  const words = (r: Row) => {
    const { rule, rest } = aboutOf(r);
    return rule ? `${ruleTitle(rule)} · ${bare(rest)}` : bare(rest);
  };
  // An empty tab points to the first that has rows, so a Facts with none never reads as "nothing remembered".
  const other = TABS.find((t) => t !== tab && inTab(t).length);
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));
  const [adding, setAdding] = useState(false);
  const [fresh, setFresh] = useState("");
  useCommand("memory.add", () => setAdding(true));

  const capped = all.length >= MEMORY_CAP;
  const subjects = [...all.reduce((m, r) => m.set(r.subject, (m.get(r.subject) ?? 0) + 1), new Map<string, number>())]
    .filter(([s]) => s)
    .sort((a, b) => b[1] - a[1])
    .slice(0, SUBJECTS);
  const dims: Dim<Row>[] = [
    {
      id: "by",
      label: "told by",
      options: [{ value: "human", label: "people", count: all.filter((r) => r.source === "human").length }],
      test: (r, v) => r.source === v,
    },
    {
      id: "subject",
      label: "about",
      options: subjects.map(([value, count]) => ({ value, label: words(all.find((r) => r.subject === value)!), count })),
      test: (r, v) => r.subject === v,
    },
  ];
  // The text goes to the kernel (`memory.search {query}`); the dimensions filter the loaded rows.
  const filters = useFilters(dims);

  const columns: Column<Row>[] = [
    {
      label: "Source",
      fit: true,
      sort: (r) => r.source,
      cell: (r) => <Avatar who={ORIGINS[originOf(r.source)].who} size={16} />,
    },
    {
      label: "Memory",
      sort: (r) => (r.subject ? `${words(r)} · ${bodyOf(r)}` : bodyOf(r)),
      cell: (r) => (
        <>
          {/* On a phone the subject gives up the row to the fact. */}
          {r.subject ? (
            <span className="text-fg-1">
              <span className="max-md:inline-block max-md:max-w-[12ch] max-md:truncate max-md:align-bottom">
                <Subject memory={r} ruleTitle={ruleTitle} mono />
              </span>{" "}
              ·{" "}
            </span>
          ) : null}
          <span className="text-fg-2">{bodyOf(r)}</span>
        </>
      ),
    },
    { label: "Added", fit: true, mono: true, hide: "md", sort: (r) => r.created_at, cell: (r) => age(r.created_at, now) },
  ];
  const sorted = useSort(inTab(tab).filter(filters.keep), columns);
  const rows = sorted.rows;
  // At the cap every slice is a lower bound: "of 37+".
  const paged = usePaged(rows, 25, capped ? { cap: rows.length } : {});
  const pop = usePopParam("memory");
  const open = (row: Row | undefined, replace = false) => pop(row && row.memory_id, replace);
  const nav = useListNav(paged.page, (r) => r.memory_id, {
    onOpen: (r) => open(r),
    copy: (r) => r.memory_id,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const at = rows.findIndex((r) => r.memory_id === params.get("memory"));
  useFollow(nav, at >= 0 ? rows[at]!.memory_id : "", { keys: rows.map((r) => r.memory_id), size: 25, go: paged.go });
  const loading = memory.isPending;
  const error = memory.isError && !memory.data ? memory.error : undefined;
  const told = all.filter((r) => r.source === "human").length;
  const newest = all.reduce((m, r) => (r.created_at > m ? r.created_at : m), "");


  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Memory"
        strip={
          // The table's error carries the one Retry.
          <Strip
            stateless
            loading={loading}
            error={error}
            asOf={staleSince(memory)}
            facts={[
              {
                label: "told by people",
                value: memory.data ? told : null,
                onClick: () => filters.set("by", filters.values.by === "human" ? "" : "human"),
                pressed: filters.values.by === "human",
              },
              {
                label: "last added",
                value: memory.data ? (newest ? age(newest, now) : "never") : null,
                tip: newest ? stamp(newest) : undefined,
              },
            ]}
          />
        }
      />
      <Tabs
        id="memory"
        label="Memory"
        value={tab}
        onChange={setTab}
        tabs={TABS.map((t) => ({
          value: t,
          label: label(t),
          count: memory.data ? inTab(t).length : null,
        }))}
      />
      <TabPanel id="memory" value={tab}>
        <Card>
          <FilterBar
            dims={dims}
            value={filters.values}
            onChange={filters.set}
            text={filters.text}
            onText={filters.setText}
            onClear={filters.clear}
            placeholder="Filter memory"
          >
            {/* A create control sits in its list's toolbar, as on every screen. */}
            <Tip label="Add fact" kbd="N">
              <Button size="sm" onClick={() => setAdding(true)} aria-keyshortcuts="N">
                <Plus aria-hidden />
                Add fact
              </Button>
            </Tip>
          </FilterBar>
          <Table
            columns={columns}
            rows={paged.page}
            sort={sorted.sort}
            onSort={paged.first}
            rowKey={(r) => r.memory_id}
            rowProps={nav.rowProps}
            isNew={(r) => r.memory_id === fresh}
            loading={loading}
            error={error}
            onRetry={() => void memory.refetch()}
            label={tab}
            empty={
              filters.active ? (
                <Empty kind="filtered" title="Nothing matches" onClear={filters.clear} />
              ) : (
                <Empty
                  kind="row"
                  title={all.length ? `No ${tab}` : "Nothing remembered"}
                  action={
                    other ? (
                      <button type="button" className="sh-link" onClick={() => setTab(other)}>
                        {label(other)} {inTab(other).length}
                      </button>
                    ) : undefined
                  }
                />
              )
            }
          />
          {paged.pager}
        </Card>
      </TabPanel>
      {at >= 0 ? (
        <MemoryDialog
          memory={rows[at]!}
          ruleTitle={ruleTitle}
          onClose={() => open(undefined, true)}
          step={{
            index: at,
            total: rows.length,
            onPrev: at > 0 ? () => open(rows[at - 1], true) : undefined,
            onNext: at < rows.length - 1 ? () => open(rows[at + 1], true) : undefined,
          }}
        />
      ) : null}
      {adding ? (
        <AddFactDialog
          onClose={() => setAdding(false)}
          onAdded={(id) => {
            setAdding(false);
            setFresh(id);
            toast({ tone: "ok", text: "Fact added" });
            // The new fact lands in Facts, unfiltered, where it flashes.
            setParams((current) => {
              const out = new URLSearchParams(current);
              for (const key of ["tab", "pane", "q", "by", "subject"]) out.delete(key);
              return out;
            });
          }}
        />
      ) : null}
    </div>
  );
}
