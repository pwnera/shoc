/**
 * Connections › Intel: every intel source shoc reaches out to, one row each:
 * indicator feeds, report sources and the lookups set up with an account,
 * failing first. A row opens its dialog (`?feed=` or `?lookup=`), which J and
 * K step through the list; Add intel source (`?add=intel`) offers the named
 * report sources, any feed by URL and the lookups that need a key, and Refresh
 * feeds pulls every enabled feed behind a confirm (palette and
 * `?do=intel.refresh` stop at the confirm). What the feeds carry is Intel's.
 *
 * Capabilities used: intel.list (feeds, presets, lookups), intel.refresh, and
 * the dialogs' intel.configure.
 */
import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Plus, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CardToolbar } from "@/components/ui/card";
import { Empty, Spinner } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { Status, type StatusTone } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { command, useCommand, useListNav } from "@/lib/commands";
import { age, num } from "@/lib/format";
import { feedState, lookupState } from "@/lib/labels";
import { loadError } from "@/lib/loaded";
import { useNow } from "@/lib/now";
import { closeParams, useFollow } from "@/lib/popup";
import { useIndicators, useRefreshIntel } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import { toastError } from "@/lib/toast";
import { feedName, isReportSource } from "../intel/feeds";
import { AddSourceDialog } from "./AddSourceDialog";
import { FeedDialog } from "./FeedDialog";
import { LookupDialog } from "./LookupDialog";

const REFRESH = command("intel.refresh")?.label ?? "Pull feeds";

type Row = { param: "feed" | "lookup"; id: string; kind: string; word: string; tone: StatusTone; when: string; at: string | null };

/* Failing first, then the ones that need a look. */
const RANK: Partial<Record<StatusTone, number>> = { bad: 0, warn: 1 };

export function IntelSources() {
  const now = useNow();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  // The sources ride on intel.list; one indicator row is all this tab needs of the rest.
  const list = useIndicators("", "", 1);
  const refresh = useRefreshIntel();
  const [asking, setAsking] = useState(false);
  const adding = params.get("add") === "intel";
  useCommand("intel.refresh", () => setAsking(true));

  const feeds = list.data?.feeds ?? [];
  const lookups = list.data?.lookups ?? [];
  const listed: Row[] = [
    ...feeds.map((f): Row => {
      const s = feedState(f);
      return { param: "feed", id: f.feed, kind: isReportSource(f) ? "reports" : "indicators", word: s.word, tone: s.tone, when: age(f.last_ok_at, now), at: f.last_ok_at };
    }),
    ...lookups
      .filter((l) => l.configured)
      .map((l): Row => {
        const s = lookupState(l, now);
        return { param: "lookup", id: l.source, kind: "lookup", word: s.word, tone: s.tone, when: `${num(l.calls_today)}/${num(l.per_day)}`, at: null };
      }),
  ].sort((a, b) => (RANK[a.tone] ?? 2) - (RANK[b.tone] ?? 2) || feedName(a.id).localeCompare(feedName(b.id)));
  const columns: Column<Row>[] = [
    {
      label: "State",
      fit: true,
      sort: (r) => RANK[r.tone] ?? 2,
      cell: (r) => (
        <Status tone={r.tone} badge>
          {r.word}
        </Status>
      ),
    },
    { label: "Name", strong: true, cell: (r) => feedName(r.id) },
    { label: "Kind", width: 96, hide: "md", mono: true, cell: (r) => r.kind },
    { label: "Last", width: 96, align: "right", mono: true, sort: (r) => r.at, cell: (r) => r.when },
  ];
  const sorted = useSort(listed, columns);
  const rows = sorted.rows;
  /** Open a row's dialog, or step to it in place (J and K, or Set up from Add intel source); the other kind's goes. */
  const open = (row: Pick<Row, "param" | "id">, push = true) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        out.delete("feed");
        out.delete("lookup");
        out.delete("add");
        out.set(row.param, row.id);
        return out;
      },
      { replace: !push },
    );
  const nav = useListNav(rows, (r) => `${r.param}:${r.id}`, { onOpen: (r) => open(r) });
  const feed = feeds.find((f) => f.feed === params.get("feed"));
  const lookup = lookups.find((l) => l.source === params.get("lookup"));
  const at = rows.findIndex((r) => (r.param === "feed" ? feed?.feed : lookup?.source) === r.id);
  useFollow(nav, at >= 0 ? `${rows[at]!.param}:${rows[at]!.id}` : "");
  // A lookup being set up is not a row yet, so it has no place to step from.
  const step =
    at >= 0
      ? {
          index: at,
          total: rows.length,
          onPrev: at > 0 ? () => open(rows[at - 1]!, false) : undefined,
          onNext: at < rows.length - 1 ? () => open(rows[at + 1]!, false) : undefined,
        }
      : undefined;

  return (
    <>
      <CardToolbar className="justify-end gap-2">
        <Popover
          label={REFRESH}
          align="end"
          open={asking}
          onOpenChange={setAsking}
          trigger={(props) => (
            <Button {...props} size="sm" variant="ghost" disabled={refresh.isPending}>
              {refresh.isPending ? <Spinner /> : <RefreshCw aria-hidden />}
              {REFRESH}
            </Button>
          )}
        >
          <Confirm
            what={`Pull every enabled feed${feeds.length ? ` · ${feeds.filter((f) => f.enabled).length}` : ""}`}
            go="Pull"
            onConfirm={() => {
              setAsking(false);
              refresh.mutate(undefined, { onError: (error) => toastError(error, "Refresh failed") });
            }}
            onCancel={() => setAsking(false)}
          />
        </Popover>
        <Button
          size="sm"
          onClick={() =>
            setParams((current) => {
              const out = new URLSearchParams(current);
              out.set("add", "intel");
              return out;
            })
          }
        >
          <Plus aria-hidden />
          Add intel source
        </Button>
      </CardToolbar>
      <Table
        label="Intel sources"
        columns={columns}
        rows={rows}
        sort={sorted.sort}
        rowKey={(r) => `${r.param}:${r.id}`}
        rowProps={nav.rowProps}
        loading={list.isPending}
        error={loadError(list)}
        onRetry={() => void list.refetch()}
        empty={<Empty kind="row" title="No intel source" />}
      />
      {feed ? <FeedDialog key={feed.feed} feed={feed} step={step} onClose={() => closeParams(["feed"], navigate)} /> : null}
      {lookup ? (
        <LookupDialog key={lookup.source} lookup={lookup} step={step} onClose={() => closeParams(["lookup"], navigate)} />
      ) : null}
      {adding ? (
        <AddSourceDialog
          presets={(list.data?.presets ?? []).filter((p) => !p.configured)}
          lookups={lookups.filter((l) => !l.configured)}
          onLookup={(source) => open({ param: "lookup", id: source }, false)}
          onClose={() => closeParams(["add"], navigate)}
        />
      ) : null}
    </>
  );
}
