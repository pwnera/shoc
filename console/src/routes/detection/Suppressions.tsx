/**
 * What is muted and for how long: who muted it (a crew role or a person), the
 * rule or hunt pack, the entity (or the whole rule), and the elapsed share of
 * its life. A warn mark flags a row that mutes the same rule for the same
 * entity as another, once a `user:` prefix is set aside. A row opens the
 * suppression dialog (`?suppression=`), which steps through the list. The
 * text (`?mq=`) matches the title, rule id, entity, author and reason; chips
 * narrow to rules or hunts and to the crew or a person. A
 * name waits as a skeleton for the list that titles it; an id with no title
 * shows as the faint id, never as a made-up title.
 *
 * Capabilities used: suppression.list, rule.list and hunt.results (titles).
 */
import type { ReactNode } from "react";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Entity } from "@/components/ui/entity";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { Mark } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { who } from "@/lib/crew";
import { useFilters, type Dim } from "@/lib/filters";
import { principalWord } from "@/lib/labels";
import { usePaged } from "@/lib/paged";
import { useSuppressions } from "@/lib/queries";
import type { Suppression } from "@/types";
import { Left, LeftShort } from "./parts";
import { SuppressionDialog } from "./SuppressionDialog";
import { isHunt, packOf, sameEntity, useTitles } from "./state";
import { useStepper, useUrlPick } from "./stepper";

const SIZE = 25;
const dupKey = (row: Suppression) => `${row.rule_id}\u0000${sameEntity(row.entity)}`;

export function Suppressions() {
  const query = useSuppressions();
  const titles = useTitles();
  const faint = (id: string) => <span className="sh-mono text-fg-4">{isHunt(id) ? packOf(id) : id}</span>;
  const nameOf = (id: string): ReactNode => {
    const { title, pending } = titles(id);
    return title ?? (pending ? <Skel kind="text" /> : faint(id));
  };
  const pick = useUrlPick("suppression");
  // What comes back first, first.
  const all = [...(query.data?.suppressions ?? [])].sort((a, b) => a.expires_at.localeCompare(b.expires_at));
  const human = (r: Suppression) => who(r.created_by).kind === "human";
  const count = (test: (r: Suppression) => boolean) => all.filter(test).length;
  const dims: Dim<Suppression>[] = [
    {
      id: "muted",
      label: "muted",
      options: [
        { value: "rule", label: "a rule", count: count((r) => !isHunt(r.rule_id)) },
        { value: "hunt", label: "a hunt", count: count((r) => isHunt(r.rule_id)) },
      ],
      test: (r, v) => isHunt(r.rule_id) === (v === "hunt"),
    },
    {
      id: "by",
      label: "by",
      options: [
        { value: "crew", label: principalWord("agent"), count: count((r) => !human(r)) },
        { value: "person", label: principalWord("human"), count: count(human) },
      ],
      test: (r, v) => human(r) === (v === "person"),
    },
  ];
  const filters = useFilters(dims, {
    text: "mq",
    match: (r, text) =>
      [titles(r.rule_id).title ?? "", r.rule_id, r.entity, who(r.created_by).name, r.reason]
        .join(" ")
        .toLowerCase()
        .includes(text),
  });
  const rows = all.filter(filters.keep);
  // Duplicates are counted over the whole list, so a filter never hides why a row is marked.
  const seen = new Map<string, number>();
  for (const row of all) seen.set(dupKey(row), (seen.get(dupKey(row)) ?? 0) + 1);

  const paged = usePaged(rows, SIZE);
  const nav = useListNav(paged.page, (r) => r.suppression_uid, {
    onOpen: (r) => pick[1](r.suppression_uid, true),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const stepper = useStepper(rows, (r) => r.suppression_uid, pick, { ...paged, size: SIZE, setActive: nav.setActive });

  const columns: Column<Suppression>[] = [
    {
      label: "",
      width: 44,
      truncate: false,
      cell: (r) => (
        <span className="inline-flex items-center gap-2">
          <Avatar who={r.created_by} size={20} />
          {(seen.get(dupKey(r)) ?? 0) > 1 ? (
            <Tip label="Another row mutes the same rule for the same entity">
              <Mark tone="warn" label="duplicate" />
            </Tip>
          ) : null}
        </span>
      ),
    },
    {
      label: "",
      truncate: false,
      cell: (r) => (
        <span className="flex min-w-0 items-center gap-2">
          {isHunt(r.rule_id) ? <Badge tone="faint">hunt</Badge> : null}
          <span className="min-w-0 truncate font-medium text-fg-1">{nameOf(r.rule_id)}</span>
          {r.entity ? (
            <Entity value={r.entity} className="max-w-[45%]" />
          ) : (
            <span className="sh-mono shrink-0">whole rule</span>
          )}
          {/* The countdown column drops under 1024px; the time left stays as a word. */}
          <span className="sh-mono ml-auto shrink-0 pl-1 min-[1024px]:hidden">
            <LeftShort row={r} />
          </span>
        </span>
      ),
    },
    { label: "", width: 152, align: "right", truncate: false, hide: "md", cell: (r) => <Left row={r} /> },
  ];

  return (
    <section className="sh-card" aria-label="Muted">
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter muted"
      />
      <Table
        label="Muted"
        columns={columns}
        rows={paged.page}
        rowKey={(r) => r.suppression_uid}
        rowProps={nav.rowProps}
        loading={query.isPending}
        // A failed refresh keeps the rows it had.
        error={query.data ? undefined : query.error}
        onRetry={() => void query.refetch()}
        empty={
          filters.active ? (
            <Empty kind="filtered" title="Nothing muted matches" onClear={filters.clear} />
          ) : (
            "Nothing is muted"
          )
        }
      />
      {paged.pager}
      {stepper.row ? (
        <SuppressionDialog
          row={stepper.row}
          title={titles(stepper.row.rule_id).title ?? (isHunt(stepper.row.rule_id) ? packOf(stepper.row.rule_id) : stepper.row.rule_id)}
          onClose={stepper.close}
          step={stepper.step}
        />
      ) : null}
    </section>
  );
}
