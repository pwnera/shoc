/**
 * What the crew proposes to change in detection, partitioned: Open (needs a
 * decision), Source gaps (needs data shoc does not ingest, grouped by the
 * product to connect), Accepted, Closed. The slice and a rule filter live in
 * the URL (`?show=`, `?rule=`), with the kind and the text (`?cq=`: title,
 * rule id, reason). The Detection Engineer works the open items on
 * demand, behind a confirm (W or the palette opens it); a row opens the
 * backlog dialog (`?item=`, so a link elsewhere can open one), which steps
 * through the slice. A closed row says how the item ended.
 *
 * Capabilities used: detection.backlog (open, accepted, done, rejected),
 * detection.work, rule.list and hunt.results (rule titles).
 */
import { useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowUpCircle, BellOff, Bug, LayoutGrid, TrendingDown, type LucideIcon } from "lucide-react";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button, CrewMark } from "@/components/ui/button";
import { FilterBar } from "@/components/ui/filterbar";
import { productName } from "@/components/brands";
import { Empty, ErrorNote, Spinner } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { keyLabel, useCommand, useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { age } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useParam } from "@/lib/param";
import { useDetectionBacklog, useWorkBacklog } from "@/lib/queries";
import type { BacklogItem } from "@/types";
import { BacklogDialog } from "./BacklogDialog";
import { ItemTitle, Priority } from "./parts";
import { decisionOf, revertOf, SEGMENTS, segmentOf, useTitles, type Segment } from "./state";
import { useStepper, useUrlPick } from "./stepper";

const CAP = 200;
const SIZE = 25;

const KIND: Record<BacklogItem["kind"], { icon: LucideIcon; word: string }> = {
  defect: { icon: Bug, word: "defect" },
  suppression: { icon: BellOff, word: "mute" },
  promote: { icon: ArrowUpCircle, word: "promote a hunt" },
  coverage: { icon: LayoutGrid, word: "coverage" },
  decay: { icon: TrendingDown, word: "decay" },
};

function Glyphs({ item }: { item: BacklogItem }) {
  const kind = KIND[item.kind] ?? { icon: LayoutGrid, word: item.kind };
  const Icon = kind.icon;
  return (
    <span className="inline-flex items-center gap-2 align-middle">
      <Tip label={kind.word}>
        <Icon className="h-3.5 w-3.5 text-fg-3" role="img" aria-label={kind.word} />
      </Tip>
      {item.decided_by ? <Avatar who={item.decided_by} size={16} /> : null}
    </span>
  );
}

const byDecided = (a: BacklogItem, b: BacklogItem) =>
  (b.decided_at ?? b.created_at).localeCompare(a.decided_at ?? a.created_at);

export function Changes() {
  const [params] = useSearchParams();
  const [show, setShow] = useParam<Segment>("show", "open");
  const pick = useUrlPick("item");
  const open = useDetectionBacklog("open");
  const accepted = useDetectionBacklog("accepted");
  const done = useDetectionBacklog("done");
  const rejected = useDetectionBacklog("rejected");
  const work = useWorkBacklog();
  const now = useNow();
  const titles = useTitles();

  const slices: Record<Segment, { queries: (typeof open)[]; items: BacklogItem[] }> = {
    open: { queries: [open], items: (open.data?.items ?? []).filter((i) => segmentOf(i) === "open") },
    gaps: { queries: [open], items: (open.data?.items ?? []).filter((i) => segmentOf(i) === "gaps") },
    accepted: { queries: [accepted], items: accepted.data?.items ?? [] },
    closed: {
      queries: [done, rejected],
      items: [...(done.data?.items ?? []), ...(rejected.data?.items ?? [])].sort(byDecided),
    },
  };
  // A link to one item (`?item=` without `?show=`) lands on the slice that holds it.
  const target = pick[0]
    ? [open, accepted, done, rejected].flatMap((q) => q.data?.items ?? []).find((i) => i.item_uid === pick[0])
    : undefined;
  const linked = !params.has("show") && target ? segmentOf(target) : null;
  useEffect(() => {
    if (linked && linked !== "open") setShow(linked);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linked]);
  const segment = linked ?? (SEGMENTS.some((s) => s.value === show) ? show : "open");
  const slice = slices[segment];
  const dims: Dim<BacklogItem>[] = [
    // Set by the rule page's link only.
    { id: "rule", label: "rule", word: (id) => titles(id).title ?? id, test: (i, v) => i.rule_id === v },
    {
      id: "kind",
      label: "kind",
      options: (Object.keys(KIND) as BacklogItem["kind"][])
        .map((k) => ({ value: k, label: KIND[k].word, count: slice.items.filter((i) => i.kind === k).length }))
        .filter((o) => o.count),
      test: (i, v) => i.kind === v,
    },
  ];
  // Its own text parameter: Rules, a tab away, keeps `q`.
  const filters = useFilters(dims, {
    text: "cq",
    match: (i, text) => `${i.title} ${i.rule_id} ${i.reason}`.toLowerCase().includes(text),
  });
  const items = slice.items.filter(filters.keep);
  // A failed refresh keeps the rows it had: only a load with nothing cached is an error.
  const failed = slice.queries.find((q) => q.isError && !q.data);
  const pending = slice.queries.some((q) => q.isPending);
  const atCap = slice.queries.some((q) => (q.data?.items.length ?? 0) >= CAP);

  // Source gaps group under the product they wait for, so one Connect closes a group.
  const groups = new Map<string, BacklogItem[]>();
  if (segment === "gaps")
    for (const item of items) {
      const product = item.evidence?.waiting_for?.[0] ?? "";
      groups.set(product, [...(groups.get(product) ?? []), item]);
    }
  const ordered = segment === "gaps" ? [...groups.values()].flat() : items;

  const paged = usePaged(ordered, SIZE, { cap: atCap ? CAP : undefined });
  const listed = segment === "gaps" ? ordered : paged.page;
  const nav = useListNav(listed, (i) => i.item_uid, {
    onOpen: (i) => pick[1](i.item_uid, true),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // Source gaps scroll in one box rather than page.
  const stepper = useStepper(ordered, (i) => i.item_uid, pick, {
    ...paged,
    ...(segment === "gaps" ? { start: 0, size: Infinity } : { size: SIZE }),
    setActive: nav.setActive,
  });
  const current = stepper.row ?? target;
  // W and the palette (`?do=detection.work`) open the confirm; only its Enter spends crew tokens.
  const [asking, setAsking] = useState(false);
  useCommand("detection.work", () => setAsking(true));

  const columns: Column<BacklogItem>[] = [
    { label: "", width: 44, truncate: false, cell: (i) => <Glyphs item={i} /> },
    { label: "", fit: true, cell: (i) => <Priority value={i.priority} /> },
    { label: "", strong: true, cell: (i) => <ItemTitle item={i} rule={i.rule_id ? titles(i.rule_id).title : undefined} /> },
    // Closed, how each ended; the dialog says why.
    ...(segment === "closed"
      ? [
          {
            label: "",
            fit: true,
            cell: (i: BacklogItem) => <Badge tone="faint">{revertOf(i) ? "reverted" : (decisionOf(i)?.word ?? i.state)}</Badge>,
          },
        ]
      : []),
    { label: "", width: 72, align: "right", mono: true, cell: (i) => age(i.created_at, now) },
  ];
  const count = (s: Segment) =>
    slices[s].queries.some((q) => !q.data) ? undefined : slices[s].items.filter(filters.keep).length;

  const empty: Record<Segment, ReactNode> = {
    open: "No open changes",
    gaps: "No source gaps",
    accepted: "Nothing accepted",
    closed: "Nothing closed",
  };
  const table = (rows: BacklogItem[]) => (
    <Table
      label="Changes"
      columns={columns}
      rows={rows}
      rowKey={(i) => i.item_uid}
      rowProps={nav.rowProps}
      loading={pending}
      error={failed?.error}
      onRetry={() => void failed?.refetch()}
      empty={filters.active ? <Empty kind="filtered" title="No change matches" onClear={filters.clear} /> : empty[segment]}
    />
  );

  return (
    <section className="sh-card" aria-label="Changes">
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter changes"
        lead={
          <Seg
            label="Changes"
            value={segment}
            onChange={setShow}
            options={SEGMENTS.map((s) => ({ value: s.value, label: s.label, count: count(s.value) }))}
          />
        }
      >
        <Popover
          label="Let the Detection Engineer work"
          align="end"
          open={asking}
          onOpenChange={setAsking}
          trigger={(props) => (
            <Tip label="Works the top five open items" kbd={keyLabel("w")}>
              <Button {...props} variant="crew" size="sm" disabled={work.isPending} aria-keyshortcuts="W">
                {work.isPending ? <Spinner /> : <CrewMark />}
                Let the Detection Engineer work
              </Button>
            </Tip>
          )}
        >
          <Confirm
            what="Work the top 5 open items"
            go="Work"
            onConfirm={() => {
              setAsking(false);
              if (!work.isPending) work.mutate(5);
            }}
            onCancel={() => setAsking(false)}
          />
        </Popover>
      </FilterBar>
      {work.error ? <ErrorNote error={work.error} inline /> : null}

      {segment === "gaps" && !pending && !failed && items.length ? (
        <div className="max-h-[480px] overflow-y-auto">
          {[...groups].map(([product, members]) => (
            <div key={product}>
              <div className="flex h-8 items-center gap-2 border-b border-line-1 bg-bg-2 px-3">
                <span className="sh-label">{product ? productName(product) : "unknown source"}</span>
                <span className="sh-mono">{members.length}</span>
                {product ? (
                  <Link className="sh-link ml-auto text-xs" to={`/connections?add=${encodeURIComponent(product)}`}>
                    Connect
                  </Link>
                ) : null}
              </div>
              {table(members)}
            </div>
          ))}
        </div>
      ) : (
        <>
          {table(listed)}
          {paged.pager}
        </>
      )}

      {current ? <BacklogDialog item={current} onClose={stepper.close} step={stepper.step} /> : null}
    </section>
  );
}
