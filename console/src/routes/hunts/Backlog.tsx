/**
 * Hunts › Backlog: hypotheses worth testing that no pack answers yet, Open or
 * Closed. A row is a dashed mark when no pack answers it, its priority, the
 * title, how it ended once closed, and when it was raised. A row opens the item
 * dialog (`?item=`): its story (raised, from which report or pack; worked by the
 * Hunter; decided, by whom, with the pack, run or source it points to), the
 * hypothesis (what the report saw the attacker do, the shape to look for, what
 * looks the same, what would confirm it, why it matters), the logs that would
 * show it and whether we receive them, the rules, packs and cases on its
 * techniques (`detection/context.tsx`), the techniques it tests by name, and
 * the reason it ended in its author's words. Run when a pack answers it, Merge
 * (M, a pack written as YAML, started from the item) while it is open and none
 * does, and Reject, Done and Reopen (R, D, O) as on a detection item: ending
 * one asks why. Hypotheses come from Intel's reports and the crew. The text
 * (`?hq=`) matches the title, hypothesis and pack; a chip keeps the items a pack
 * answers or the ones none does.
 *
 * Capabilities used: hunt.pack, hunt.merge, hunt.decide, intel.reports (report
 * titles); the rows are Hunts' `hunt.backlog` and `hunt.results`.
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Check, GitMerge, Gavel, Inbox, RotateCcw, Wrench, X } from "lucide-react";
import { productName } from "@/components/brands";
import { PackEditor } from "@/components/Editors";
import { Badge } from "@/components/ui/badge";
import { Button, CrewMark } from "@/components/ui/button";
import { Clamped } from "@/components/ui/clamped";
import { Status } from "@/components/ui/status";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Quote } from "@/components/ui/field";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, ErrorNote, Spinner } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useFilters, type Dim } from "@/lib/filters";
import { keyLabel, useCommand, useListNav } from "@/lib/commands";
import { who } from "@/lib/crew";
import { age, num, shortId } from "@/lib/format";
import { INTAKES, OUTCOMES, principalWord } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useParam } from "@/lib/param";
import { useFollow } from "@/lib/popup";
import { useDecideHunt, useIntelReports, useRunPack } from "@/lib/queries";
import type { HuntBacklogItem } from "@/types";
import { Story } from "@/routes/detection/BacklogDialog";
import { contextRows, saidIn, techniqueChips } from "@/routes/detection/context";
import { LinkChip } from "@/routes/detection/parts";
import { useDecision, type Ending } from "@/routes/detection/state";
import type { Step } from "@/routes/detection/story";
import { RunTrace } from "./HuntRunDialog";

/** `hunt_backlog.trigger` words; the shared map lacks `source` and `human`. A principal (`human:jane`) is who raised it. */
const TRIGGERS: Record<string, string> = { ...INTAKES, source: OUTCOMES.gap.word, human: principalWord("human") };
const triggerWord = (trigger: string) => TRIGGERS[trigger] ?? (trigger.includes(":") ? who(trigger).name : trigger);

const HUNTER = "Hunter";

/** How an item ended, in `evidence.decision` words; a packed item has none, its pack says it. */
const DECISIONS: Record<string, string> = {
  covered: "covered",
  not_worth: "not worth a pack",
  source_gap: "source gap",
  stuck: "stuck",
  reverted: "reverted",
  tested: "tested",
  superseded: "superseded",
};

/**
 * Why the item stands where it does, and who said so. Open: why the Hunter put
 * it off, if it did. A pack's first run closes the item, which is shoc's hand.
 */
function decisionOf(item: HuntBacklogItem): { word: string; because: string; by: string | null } | null {
  const e = item.evidence ?? {};
  if (item.state === "open") {
    if (e.later) return { word: "later", because: e.later, by: HUNTER };
    return e.reopened ? { word: "reopened", because: e.reopened, by: item.decided_by ?? null } : null;
  }
  const raw = e.decision ?? "";
  if (!raw) return { word: item.state, because: "", by: item.decided_by ?? null };
  return {
    word: DECISIONS[raw] ?? raw.replace(/_/g, " "),
    because: e.because ?? "",
    by: raw === "tested" ? "shoc" : (item.decided_by ?? HUNTER),
  };
}

const tokens = (n: number) => (n >= 1000 ? `${num(Math.round(n / 1000))}k tok` : `${n} tok`);

/** The Hunter files a pack it could not run as "<pack_id> could not run". */
const GAP = /^(\S+) could not run$/;

/** The item's title; a pack it could not run is the pack's own title, and its row says "couldn't look" as Runs does. */
const titleOf = (item: HuntBacklogItem, titles: Map<string, string>) => {
  const gap = GAP.exec(item.title)?.[1];
  return gap ? (titles.get(gap) ?? gap) : item.title;
};
const isGap = (item: HuntBacklogItem) => GAP.test(item.title);

const NoPack = () => (
  <span
    className="inline-block h-2.5 w-2.5 shrink-0 rounded-[2px] border border-dashed border-fg-4"
    role="img"
    aria-label="no pack answers it"
  />
);

/** Raised (by whom, from which report or pack), worked by the Hunter, decided (by whom, with what it points to). */
function story(
  item: HuntBacklogItem,
  reportTitle: (uid: string) => string | undefined,
  titles: Map<string, string>,
  packHref: (id: string) => string,
): Step[] {
  const e = item.evidence ?? {};
  const report = e.report_uid ?? "";
  const gap = GAP.exec(item.title)?.[1];
  const pack = (id: string, label = "Pack") => (
    <LinkChip key={`${label}:${id}`} to={packHref(id)} label={label} value={titles.get(id) ?? id} />
  );
  const steps: Step[] = [
    {
      key: "raised",
      glyph: Inbox,
      who: item.trigger.includes(":") ? item.trigger : null,
      badge: <Badge tone="faint">{triggerWord(item.trigger)}</Badge>,
      text: "raised",
      chips:
        report || gap ? (
          <>
            {report ? (
              <Tip label={report} mono>
                <span className="inline-flex min-w-0">
                  <LinkChip
                    to={`/intel?tab=reports&report=${encodeURIComponent(report)}`}
                    label="Report"
                    value={reportTitle(report) ?? e.source ?? shortId(report)}
                  />
                </span>
              </Tip>
            ) : null}
            {gap && titles.has(gap) ? pack(gap) : null}
          </>
        ) : undefined,
      time: item.created_at,
    },
  ];
  if (e.worked_at) {
    const tries = Number(e.tries ?? 0);
    const spent = Number(e.tokens_today ?? 0);
    steps.push({
      key: "worked",
      glyph: Wrench,
      who: HUNTER,
      badge: <Badge tone="faint">worked</Badge>,
      meta: [tries > 1 ? `${tries} tries` : "", spent ? tokens(spent) : ""].filter(Boolean).join(" · "),
      time: e.worked_at,
    });
  }
  const decision = decisionOf(item);
  if (decision && item.state !== "open") {
    const answered = item.pack_id || e.covered_by || "";
    steps.push({
      key: "decided",
      glyph: item.pack_id ? GitMerge : Gavel,
      who: decision.by,
      badge: <Badge>{decision.word}</Badge>,
      chips: (
        <>
          {answered ? pack(answered, e.covered_by && !item.pack_id ? "Covered by" : "Pack") : null}
          {e.run_uid ? (
            <LinkChip to={`/hunts?run=${encodeURIComponent(e.run_uid)}`} label="Run" value={shortId(e.run_uid)} />
          ) : null}
          {/* With a context, its "connect" row names what to connect. */}
          {(item.context ? [] : (e.waiting_for ?? [])).map((product) => (
            <LinkChip
              key={product}
              to={`/connections?add=${encodeURIComponent(product)}`}
              label="Connect"
              value={productName(product)}
            />
          ))}
        </>
      ),
      time: item.decided_at ?? null,
    });
  }
  return steps;
}

const ASK: Record<Ending, { what: string; go: string }> = {
  rejected: { what: "Reject", go: "Reject" },
  done: { what: "Done without a new pack", go: "Done" },
};

function ItemDialog({
  item,
  titles,
  onClose,
  step,
}: {
  item: HuntBacklogItem;
  titles: Map<string, string>;
  onClose: () => void;
  step: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const run = useRunPack();
  const reports = useIntelReports();
  // The newest 100 name most reports; the item's own context names the rest it cites.
  const reportTitle = (uid: string) =>
    reports.data?.rows.find((r) => r.report_uid === uid)?.title ??
    item.context?.reports.find((r) => r.report_uid === uid)?.title;
  const [merging, setMerging] = useState(false);
  const decide = useDecideHunt();
  const { ending, reject, done, settle, ask, reopen, stop } = useDecision(item, decide, onClose);
  const mine = run.variables === item.pack_id;
  const e = item.evidence ?? {};
  const decision = decisionOf(item);
  const live = item.state === "open";
  const mergeable = live && !item.pack_id;
  const [params] = useSearchParams();
  // The pack's dialog replaces this one on the same tab; Back returns here.
  const packHref = (id: string) => {
    const out = new URLSearchParams(params);
    out.delete("item");
    out.set("pack", id);
    return `?${out.toString()}`;
  };
  // An item once said only which report suggested it; the Report chip says that now.
  const whyNow = item.why_now.startsWith("suggested by '") ? "" : item.why_now;
  // The editor over this dialog takes the keys while it is open.
  useCommand("backlog.done", () => ask("done"), live && !merging);
  useCommand("backlog.reject", () => ask("rejected"), live && !merging);
  useCommand("backlog.reopen", reopen, !live && !merging);
  useCommand("backlog.merge", () => setMerging(true), mergeable && !merging);
  const key = (id: string) => keyLabel(id);
  return (
    <Dialog
      title={titleOf(item, titles)}
      id={item.item_uid}
      onClose={onClose}
      step={step}
      head={
        <>
          <Badge>P{item.priority}</Badge>
          {!live ? <Badge tone="idle">{decision?.word ?? item.state}</Badge> : null}
        </>
      }
      footer={
        <>
          {item.pack_id ? (
            <Button variant="crew" className="mr-auto" disabled={run.isPending} onClick={() => run.mutate(item.pack_id)}>
              {run.isPending && mine ? <Spinner /> : <CrewMark />}
              Run {titles.get(item.pack_id) ?? item.pack_id}
            </Button>
          ) : null}
          {live ? (
            <>
              {mergeable ? (
                <Tip label="Merge a pack" kbd={key("m")}>
                  <Button variant="ghost" onClick={() => setMerging(true)} aria-keyshortcuts="M">
                    <GitMerge aria-hidden />
                    Merge
                  </Button>
                </Tip>
              ) : null}
              <Tip label="Reject" kbd={key("r")}>
                <Button
                  ref={reject}
                  variant="ghost"
                  disabled={decide.isPending}
                  onClick={() => ask("rejected")}
                  aria-keyshortcuts="R"
                >
                  <X aria-hidden />
                  Reject
                </Button>
              </Tip>
              <Tip label="Handled without a new pack" kbd={key("d")}>
                <Button
                  ref={done}
                  variant="primary"
                  disabled={decide.isPending}
                  onClick={() => ask("done")}
                  aria-keyshortcuts="D"
                >
                  <Check aria-hidden />
                  Done
                </Button>
              </Tip>
            </>
          ) : (
            <Tip label="Reopen" kbd={key("o")}>
              <Button variant="ghost" disabled={decide.isPending} onClick={reopen} aria-keyshortcuts="O">
                <RotateCcw aria-hidden />
                Reopen
              </Button>
            </Tip>
          )}
        </>
      }
    >
      <Story steps={story(item, reportTitle, titles, packHref)} />
      <Fields
        rows={[
          ["hypothesis", item.hypothesis.trim() !== item.title.trim() ? item.hypothesis : null],
          ["in the report", e.procedure || saidIn(item.context, e.report_uid)],
          ["look for", e.logic],
          ["looks the same", e.false_positives],
          ["would confirm", item.would_confirm],
          // Without a context the item's own words say it; with one, its rows do.
          ["why it matters", !item.context && whyNow ? <Clamped text={whyNow} /> : null],
          ...contextRows(item.context, { reportUid: e.report_uid, said: false, relevance: whyNow || true }),
          ["data", item.context?.seen_in.length ? null : item.data_needed],
          ["att&ck", techniqueChips(item.attack, item.context)],
        ]}
      />
      {decision?.because ? (
        <Quote by={decision.by} label={decision.word === "later" || decision.word === "reopened" ? decision.word : "because"}>
          {decision.because}
        </Quote>
      ) : null}
      {ending ? (
        <Confirm
          key={`${item.item_uid}:${ending}`}
          inline
          danger={ending === "rejected"}
          what={ASK[ending].what}
          go={ASK[ending].go}
          note={{ required: true, label: "Reason", placeholder: "Why" }}
          onCancel={stop}
          onConfirm={(reason) => settle(ending, reason)}
        />
      ) : null}
      {decide.error && decide.variables?.item_uid === item.item_uid && !ending ? (
        <ErrorNote error={decide.error} inline />
      ) : null}
      {mine && run.data ? <RunTrace run={run.data.data} /> : null}
      {mine && run.error ? <ErrorNote error={run.error} inline /> : null}
      {merging ? (
        <PackEditor
          key={item.item_uid}
          itemUid={item.item_uid}
          seed={{ title: item.title, hypothesis: item.hypothesis, attack: item.attack }}
          onClose={() => setMerging(false)}
        />
      ) : null}
    </Dialog>
  );
}

export function Backlog({
  items,
  loading,
  error,
  onRetry,
  titles,
}: {
  items: HuntBacklogItem[];
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  /** Pack titles by id, every pack this tenant has. */
  titles: Map<string, string>;
}) {
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const [which, setWhich] = useParam<"open" | "closed">("backlog", "open");
  const shown = items.filter((i) => (which === "open") === (i.state === "open"));
  const dims: Dim<HuntBacklogItem>[] = [
    {
      id: "answered",
      label: "pack",
      options: [
        { value: "yes", label: "answers it", count: shown.filter((i) => i.pack_id).length },
        { value: "no", label: "none yet", count: shown.filter((i) => !i.pack_id).length },
      ],
      test: (i, v) => Boolean(i.pack_id) === (v === "yes"),
    },
  ];
  // Its own text parameter: Runs, a tab away, keeps `q`.
  const filters = useFilters(dims, {
    text: "hq",
    match: (i, text) => `${titleOf(i, titles)} ${i.hypothesis} ${i.pack_id}`.toLowerCase().includes(text),
  });
  const rows = shown
    .filter(filters.keep)
    .sort((a, b) => a.priority - b.priority || b.created_at.localeCompare(a.created_at));
  const count = (open: boolean) =>
    loading || error ? undefined : items.filter((i) => (i.state === "open") === open && filters.keep(i)).length;
  const paged = usePaged(rows, 25);
  const open = (item: HuntBacklogItem | undefined, replace = false) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        if (item) out.set("item", item.item_uid);
        else out.delete("item");
        return out;
      },
      { replace },
    );
  const nav = useListNav(paged.page, (i) => i.item_uid, {
    onOpen: (i) => open(i),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const item = items.find((i) => i.item_uid === params.get("item"));
  const at = item ? rows.indexOf(item) : -1;
  useFollow(nav, at >= 0 ? item!.item_uid : "", { keys: rows.map((i) => i.item_uid), size: 25, go: paged.go });

  const columns: Column<HuntBacklogItem>[] = [
    {
      label: "",
      fit: true,
      cell: (i) => (
        <span className="flex items-center gap-2">
          {i.pack_id ? <span className="h-2.5 w-2.5 shrink-0" aria-hidden /> : <NoPack />}
          <Badge>P{i.priority}</Badge>
        </span>
      ),
    },
    {
      label: "",
      strong: true,
      cell: (i) =>
        isGap(i) ? (
          <span className="inline-flex min-w-0 items-center gap-2">
            <span className="truncate">{titleOf(i, titles)}</span>
            <Status tone={OUTCOMES.gap.tone} badge>
              {OUTCOMES.gap.word}
            </Status>
          </span>
        ) : (
          titleOf(i, titles)
        ),
    },
    // Closed, how each ended; the dialog says why.
    ...(which === "closed"
      ? [{ label: "", fit: true, cell: (i: HuntBacklogItem) => <Badge tone="faint">{decisionOf(i)?.word ?? i.state}</Badge> }]
      : []),
    { label: "", fit: true, mono: true, hide: "md", cell: (i) => age(i.created_at, now) },
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
        placeholder="Filter hypotheses"
        lead={
          <Seg
            label="Backlog"
            value={which}
            onChange={setWhich}
            options={[
              { value: "open", label: "Open", count: count(true) },
              { value: "closed", label: "Closed", count: count(false) },
            ]}
          />
        }
      />
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(i) => i.item_uid}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Backlog"
        empty={
          filters.active ? (
            <Empty kind="filtered" title="No hypothesis matches" onClear={filters.clear} />
          ) : which === "open" ? (
            "No open hypotheses"
          ) : (
            "Nothing closed"
          )
        }
      />
      {paged.pager}
      {item ? (
        <ItemDialog
          item={item}
          titles={titles}
          onClose={() => open(undefined, true)}
          step={{
            index: Math.max(0, at),
            total: at >= 0 ? rows.length : 1,
            onPrev: at > 0 ? () => open(rows[at - 1], true) : undefined,
            onNext: at >= 0 && at < rows.length - 1 ? () => open(rows[at + 1], true) : undefined,
          }}
        />
      ) : null}
    </>
  );
}
