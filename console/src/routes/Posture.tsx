/**
 * Posture: what does the company have that is reachable from outside or
 * privileged, and how is it connected? The strip says when the Surveyor last
 * looked, over what window, and whether it read only the newest events; the
 * quadrant counts exposed × privileged from the same rows the list shows, and
 * a cell filters the list. Seen lists what acted in the window; Listed only what a source's
 * own API lists that did nothing. Every row opens EntityDialog, home of an
 * entity's exposure, identity and neighbours.
 *
 * Capabilities: posture.get (a read; Re-survey, behind a confirm, sends
 * refresh), surface.list, snapshot.list, graph.refresh (⋯ opens the Rebuild
 * the graph confirm).
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { MoreHorizontal, RefreshCw } from "lucide-react";
import { EntityDialog } from "@/components/EntityDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Entity } from "@/components/ui/entity";
import { FilterBar } from "@/components/ui/filterbar";
import { ProductLogo } from "@/components/ui/logo";
import { Empty, Spinner, TabPanel, Tabs } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Confirm, Popover } from "@/components/ui/pop";
import { Strip } from "@/components/ui/strip";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";
import { useCommand, useListNav, useTabKeys } from "@/lib/commands";
import { parseEntity } from "@/lib/entity";
import { useFilters, type Dim } from "@/lib/filters";
import { age, num, stamp } from "@/lib/format";
import { loadError } from "@/lib/loaded";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useTab } from "@/lib/param";
import { focusRow, useClaim, useFollow, usePopParam } from "@/lib/popup";
import { usePosture, useRefreshGraph, useResurvey, useSnapshots, useSurface } from "@/lib/queries";
import { toastError } from "@/lib/toast";
import type { Exposure, SnapshotRow } from "@/types";
import { byRisk, CELLS, cellOf, FLAGS, flagOf, listedOnly, snapshotKey } from "./posture/cells";
import { Quadrant } from "./posture/Quadrant";

const TABS = ["seen", "listed"] as const;
/** `surface.list` caps at 500, `snapshot.list` at 1,000. */
const SEEN_CAP = 500;

/**
 * Whole, cut from the end only when the cell runs out: a 20-character key or a
 * 12-digit account fits a phone row. Under 1024px a value past 28 characters
 * (an ARN, a hash) keeps its head and tail instead.
 */
function Whole({ value }: { value: string }) {
  if ((parseEntity(value)?.value ?? value).length <= 28) return <Entity value={value} full />;
  return (
    <>
      <Entity value={value} full className="max-lg:hidden" />
      <Entity value={value} className="lg:hidden" />
    </>
  );
}

/** Opens EntityDialog over the screen (`?entity=`). */
const useOpenEntity = () => usePopParam("entity", ["view"]);

/**
 * The list's own EntityDialog, which steps through its rows with J and K and
 * turns its page; while mounted the shell's copy stays shut.
 */
function EntityStep({
  keys,
  nav,
  go,
}: {
  keys: string[];
  nav: { setActive: (key: string) => void };
  go: (index: number) => void;
}) {
  useClaim("entity");
  const [params, setParams] = useSearchParams();
  const pop = useOpenEntity();
  const picked = params.get("entity") ?? "";
  const at = keys.indexOf(picked);
  useFollow(nav, picked, { keys, size: 25, go });
  if (!picked) return null;
  return (
    <EntityDialog
      entity={picked}
      view={params.get("view") ?? undefined}
      onView={(view) =>
        setParams(
          (current) => {
            const out = new URLSearchParams(current);
            out.set("view", view);
            return out;
          },
          { replace: true },
        )
      }
      onClose={() => {
        pop(null);
        focusRow(picked);
      }}
      step={
        at >= 0
          ? {
              index: at,
              total: keys.length,
              onPrev: at > 0 ? () => pop(keys[at - 1], true) : undefined,
              onNext: at < keys.length - 1 ? () => pop(keys[at + 1], true) : undefined,
            }
          : undefined
      }
    />
  );
}

function Seen({ rows, loading, error, onRetry }: { rows: Exposure[]; loading: boolean; error: unknown; onRetry: () => void }) {
  const now = useNow();
  const openEntity = useOpenEntity();
  const kinds = [...new Set(rows.map((e) => e.kind))].sort();
  const dims: Dim<Exposure>[] = [
    {
      id: "cell",
      label: "flags",
      options: CELLS.map((c) => ({ value: c.id, label: c.label, count: rows.filter((e) => cellOf(e) === c.id).length })),
      test: (e, v) => cellOf(e) === v,
    },
    { id: "stale", label: "stale", options: [{ value: "yes", label: "stale", count: rows.filter((e) => e.stale).length }], test: (e) => e.stale },
    {
      id: "kind",
      label: "kind",
      options: kinds.map((k) => ({ value: k, count: rows.filter((e) => e.kind === k).length })),
      test: (e, v) => e.kind === v,
    },
  ];
  const filters = useFilters(dims, { match: (e, text) => e.entity.toLowerCase().includes(text) });
  const shown = rows.filter(filters.keep);
  const paged = usePaged(shown, 25, { newest: rows.length >= SEEN_CAP });
  const nav = useListNav(paged.page, (e) => e.entity, {
    onOpen: (e) => openEntity(e.entity),
    copy: (e) => e.entity,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const columns: Column<Exposure>[] = [
    {
      label: "",
      fit: true,
      cell: (e) => {
        const flag = flagOf(e, filters.values);
        if (!flag) return null;
        const look = FLAGS[flag];
        return (
          // The human outline has no fill, as the tones have none.
          <Badge tone={look.tone} className={cn(look.className, look.className && "bg-transparent")}>
            <span className="md:hidden" aria-hidden>
              {look.short}
            </span>
            <span className="max-md:sr-only">{look.word}</span>
          </Badge>
        );
      },
    },
    { label: "", truncate: false, cell: (e) => <Whole value={e.entity} /> },
    { label: "", fit: true, mono: true, hide: "md", cell: (e) => age(e.last_seen, now) },
  ];
  return (
    <>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter entities"
      />
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(e) => e.entity}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Seen"
        empty={
          filters.active ? (
            <Empty kind="filtered" title="Nothing matches" onClear={filters.clear} />
          ) : (
            <Empty kind="row" title="Nothing seen in the window" />
          )
        }
      />
      {paged.pager}
      <EntityStep keys={shown.map((e) => e.entity)} nav={nav} go={paged.go} />
    </>
  );
}

function Listed({
  rows,
  listedAny,
  seenCapped,
  loading,
  error,
  onRetry,
}: {
  rows: SnapshotRow[];
  /** Whether `snapshot.list` returned any row; with none, nothing was listed to compare. */
  listedAny: boolean;
  seenCapped: boolean;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const now = useNow();
  const openEntity = useOpenEntity();
  const paged = usePaged(rows);
  const nav = useListNav(paged.page, snapshotKey, {
    onOpen: (row) => openEntity(snapshotKey(row)),
    copy: snapshotKey,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const columns: Column<SnapshotRow>[] = [
    {
      label: "",
      fit: true,
      cell: (row) => <ProductLogo product={row.source} named />,
    },
    { label: "", truncate: false, cell: (row) => <Whole value={snapshotKey(row)} /> },
    {
      label: "",
      fit: true,
      hide: "md",
      cell: (row) => (
        <Tip label={row.last_active ? `last active ${stamp(row.last_active)}` : "never active"} mono>
          <span className="sh-mono">{age(row.taken_at, now)}</span>
        </Tip>
      ),
    },
  ];
  if (seenCapped) return <Empty kind="row" title={`Seen list capped at ${num(SEEN_CAP)}`} />;
  return (
    <>
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={snapshotKey}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Listed only"
        empty={listedAny ? "Every listed entity acted in the window" : "No source lists its accounts"}
      />
      {paged.pager}
      <EntityStep keys={rows.map(snapshotKey)} nav={nav} go={paged.go} />
    </>
  );
}

export function Posture() {
  const now = useNow();
  const [tab, setTab] = useTab(TABS);
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));
  const [params, setParams] = useSearchParams();
  const posture = usePosture();
  const surface = useSurface({ exposedOnly: false, limit: SEEN_CAP });
  const snapshots = useSnapshots({ limit: 1000 });
  const resurvey = useResurvey();
  const rebuild = useRefreshGraph();
  const [asking, setAsking] = useState(false);
  const [resurveying, setResurveying] = useState(false);

  const survey = posture.data?.data;
  const days = survey?.window_days ?? 30;
  const again = () => {
    if (!resurvey.isPending) resurvey.mutate(days, { onError: (error) => toastError(error, "Survey failed") });
  };
  // The palette hands Re-survey and Rebuild to their confirms, which run them.
  useCommand("posture.resurvey", () => setResurveying(true));
  useCommand("posture.rebuild", () => setAsking(true));

  const seen = [...(surface.data?.entities ?? [])].sort(byRisk);
  const seenCapped = seen.length >= SEEN_CAP;
  const listed = surface.data && snapshots.data ? listedOnly(snapshots.data.rows, seen) : [];
  const pick = (cell: string) =>
    setParams((current) => {
      const out = new URLSearchParams(current);
      if (out.get("cell") === cell) out.delete("cell");
      else out.set("cell", cell);
      out.delete("tab");
      return out;
    });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Posture"
        strip={
          <Strip
            stateless
            loading={posture.isPending}
            error={loadError(posture)}
            onRetry={() => void posture.refetch()}
            facts={[
              {
                label: "surveyed",
                value: survey ? (survey.taken_at ? age(survey.taken_at, now) : "never") : null,
                tip: survey?.taken_at ? stamp(survey.taken_at) : undefined,
              },
              { label: "window", value: survey ? `${survey.window_days}d` : null },
              // The exposed × privileged count is the quadrant's cell, which filters the list.
              ...(survey?.truncated && survey.limit
                ? [{ label: "newest events", value: num(survey.limit), tone: "warn" as const, tip: "The survey read only these; the window held more" }]
                : []),
            ]}
          />
        }
        aside={
          <>
            <Popover
              label="Re-survey"
              align="end"
              open={resurveying}
              onOpenChange={setResurveying}
              trigger={(props) => (
                <Button {...props} disabled={resurvey.isPending}>
                  {resurvey.isPending ? <Spinner /> : <RefreshCw aria-hidden />}
                  Re-survey
                </Button>
              )}
            >
              <Confirm
                what={`Re-survey · ${days} days of events`}
                go="Re-survey"
                onConfirm={() => {
                  setResurveying(false);
                  again();
                }}
                onCancel={() => setResurveying(false)}
              />
            </Popover>
            {/* A menu of one item: the ⋯ opens its confirm itself. */}
            <Popover
              label="Rebuild the graph"
              align="end"
              open={asking}
              onOpenChange={setAsking}
              trigger={(props) => (
                <Button {...props} variant="ghost" size="icon" aria-label="Rebuild the graph">
                  <MoreHorizontal aria-hidden />
                </Button>
              )}
            >
              <Confirm
                what={`Rebuild the graph · ${days} days of events`}
                go="Rebuild"
                onConfirm={() => rebuild.mutateAsync(days).then(() => setAsking(false))}
                onCancel={() => setAsking(false)}
              />
            </Popover>
          </>
        }
      />
      <div className="flex flex-col gap-1">
        <Quadrant rows={seen} loading={surface.isPending} unknown={Boolean(loadError(surface))} value={params.get("cell") ?? ""} onPick={pick} />
        {seenCapped ? <span className="sh-micro">of newest {num(SEEN_CAP)}</span> : null}
      </div>
      <Tabs
        id="posture"
        label="Posture"
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "seen", label: "Seen", count: surface.data ? seen.length : null },
          {
            value: "listed",
            label: "Listed only",
            count: surface.data && snapshots.data && !seenCapped ? listed.length : null,
          },
        ]}
      />
      <TabPanel id="posture" value={tab}>
        <Card>
          {tab === "seen" ? (
            <Seen rows={seen} loading={surface.isPending} error={loadError(surface)} onRetry={() => void surface.refetch()} />
          ) : (
            <Listed
              rows={listed}
              listedAny={Boolean(snapshots.data?.rows.length)}
              seenCapped={seenCapped}
              loading={surface.isPending || snapshots.isPending}
              error={loadError(surface) ?? loadError(snapshots)}
              onRetry={() => {
                void surface.refetch();
                void snapshots.refetch();
              }}
            />
          )}
        </Card>
      </TabPanel>
    </div>
  );
}
