/**
 * Response › Activity: every action that ran or was tried, newest first, by
 * day. Proposals are decisions (the Overview inbox) and pages have their own
 * tab, so neither shows here. State and dry run are filters, like the rest. Rows
 * that arrive while the reader is here wait behind a "new" pill, so the feed
 * never moves under them. A row opens ActionDialog (`?action=`), the home of
 * Undo and Run now, which steps through the feed with J and K.
 *
 * Capabilities used: action.list (the shared log), ops.alerts (stuck actions),
 * case.list (the case chip's title).
 */
import { useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { ActionDialog } from "@/components/ActionDialog";
import { Card } from "@/components/ui/card";
import { Entity } from "@/components/ui/entity";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty, ErrorNote, NewPill } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { Status } from "@/components/ui/status";
import { Timeline, type Moment } from "@/components/ui/timeline";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { useFilters, type Dim } from "@/lib/filters";
import { shortId } from "@/lib/format";
import { actionLabel, actionState, principalWord } from "@/lib/labels";
import { usePaged } from "@/lib/paged";
import { focusRow, useClaim, useFollow, usePopParam } from "@/lib/popup";
import { ACTION_CAP, useActionLog, useAlerts, useCaseLog } from "@/lib/queries";
import { sinceDim } from "@/lib/since";
import type { Action } from "@/types";
import { PlatformMark } from "./marks";
import { changedAt, deciderOf, isActivity, SEGMENTS } from "./policy";

/* Nobody in time is the Expired segment's slice, so it is no "by" of its own. */
const BY = [
  { value: "crew", label: principalWord("agent") },
  { value: "human", label: principalWord("human") },
] as const;

const RUN = [
  { value: "dry", label: "dry run" },
  { value: "live", label: "live" },
] as const;

const newestFirst = (a: Action, b: Action) => Date.parse(changedAt(b)) - Date.parse(changedAt(a));

export function Activity() {
  const log = useActionLog();
  const alerts = useAlerts();
  const cases = useCaseLog();
  const [params, setParams] = useSearchParams();
  // The feed opens its own ActionDialog, so it can step through the rows; the shell's copy stays shut.
  useClaim("action");
  const pop = usePopParam("action", ["do"]);
  // The Overview's older link for expired actions (`state=rejected&by=unattended`) lands on Expired.
  const legacy = params.get("state") === "rejected" && params.get("by") === "unattended";
  const all = (log.data?.rows ?? []).filter(isActivity).sort(newestFirst);
  const caseUid = params.get("case");
  const caseTitle = caseUid ? cases.data?.rows.find((c) => c.case_uid === caseUid)?.title : undefined;

  const dims: Dim<Action>[] = [
    {
      id: "state",
      label: "state",
      options: SEGMENTS.map((s) => ({ value: s.id, label: s.label, count: all.filter(s.test).length })),
      test: (a, v) => !!SEGMENTS.find((s) => s.id === (legacy && v === "rejected" ? "expired" : v))?.test(a),
    },
    {
      id: "by",
      label: "by",
      options: BY.map((o) => ({ ...o, count: all.filter((a) => deciderOf(a) === o.value).length })),
      // The older link's by=unattended is not offered, but still matches what Expired holds.
      test: (a, v) => deciderOf(a) === (v === "unattended" ? null : v),
    },
    {
      id: "run",
      label: "run",
      options: RUN.map((o) => ({ ...o, count: all.filter((a) => a.dry_run === (o.value === "dry")).length })),
      test: (a, v) => a.dry_run === (v === "dry"),
    },
    sinceDim<Action>(changedAt),
    {
      id: "case",
      label: "case",
      options: caseUid ? [{ value: caseUid, label: caseTitle ?? shortId(caseUid) }] : [],
      test: (a, v) => a.case_uid === v,
    },
  ];
  const filters = useFilters(dims, {
    match: (a, text) => `${actionLabel(a.type)} ${a.type} ${a.target}`.toLowerCase().includes(text),
  });

  // Rows seen at the first answer are the reader's; later ones wait for the pill.
  const [known, setKnown] = useState<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [reveal, setReveal] = useState(0);
  if (log.data && known === null) setKnown(new Set(all.map((a) => a.action_uid)));
  const seen = (a: Action) => !known || known.has(a.action_uid);

  const kept = all.filter(filters.keep);
  const shown = kept.filter(seen);
  const held = kept.filter((a) => !seen(a));
  const stuck = new Set((alerts.data?.alerts ?? []).filter((a) => a.kind === "action.stuck").map((a) => a.subject));

  const showHeld = () => {
    const arrived = all.filter((a) => !seen(a)).map((a) => a.action_uid);
    setKnown(new Set([...(known ?? []), ...arrived]));
    setFresh(new Set(arrived));
    setReveal((n) => n + 1);
  };

  let body: ReactNode;
  if (log.isError && !log.data) body = <ErrorNote error={log.error} onRetry={() => void log.refetch()} />;
  else if (log.isPending) body = <FeedSkeleton />;
  else
    body = (
      <Feed
        key={reveal}
        rows={shown}
        stuck={stuck}
        fresh={fresh}
        capped={(log.data?.rows.length ?? 0) >= ACTION_CAP}
        empty={
          filters.active ? (
            <Empty
              kind="filtered"
              title="No action matches"
              // One URL write: two in one tick would each start from the same URL.
              onClear={() =>
                setParams(
                  (current) => {
                    const out = new URLSearchParams(current);
                    for (const key of ["q", ...dims.map((d) => d.id)]) out.delete(key);
                    return out;
                  },
                  { replace: true },
                )
              }
            />
          ) : (
            <Empty title="Nothing ran" />
          )
        }
      />
    );

  return (
    <Card>
      <FilterBar
        dims={dims}
        value={filters.values}
        onChange={filters.set}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter actions"
      />
      {/* No height of its own: the pill floats over the first rows, so the feed never drops under the reader. */}
      <div className="sticky top-[calc(var(--topbar-h)+var(--space-2))] z-[var(--z-sticky)] flex h-0 justify-center">
        <NewPill count={held.length} onClick={showHeld} />
      </div>
      {body}
      {/* Until the feed is in, a linked action opens on its own. */}
      {!log.data && params.get("action") ? <ActionDialog uid={params.get("action")!} onClose={() => pop(null)} /> : null}
    </Card>
  );
}

function FeedSkeleton() {
  return (
    <div className="flex flex-col gap-3 p-3" aria-busy="true">
      <span role="status" className="sr-only">
        loading
      </span>
      {[58, 44, 66, 52, 40, 61].map((w, i) => (
        <Skel key={i} kind="row" width={`${w}%`} />
      ))}
    </div>
  );
}

/** One page of the feed; remounted when held rows are let in, so it starts again at the top. */
function Feed({
  rows,
  stuck,
  fresh,
  capped,
  empty,
}: {
  rows: Action[];
  stuck: Set<string>;
  fresh: Set<string>;
  capped: boolean;
  empty: ReactNode;
}) {
  const [params] = useSearchParams();
  const picked = params.get("action") ?? "";
  const pop = usePopParam("action", ["do"]);
  const keys = rows.map((a) => a.action_uid);
  const at = keys.indexOf(picked);
  const { page, pager, prev, next, go } = usePaged(rows, 25, { cap: capped ? rows.length : undefined });
  const nav = useListNav(page, (a) => a.action_uid, { onOpen: (a) => pop(a.action_uid), onPrevPage: prev, onNextPage: next });
  useFollow(nav, picked, { keys, size: 25, go });
  const dialog = picked ? (
    <ActionDialog
      uid={picked}
      action={rows[at]}
      undo={params.get("do") === "undo"}
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
  ) : null;
  if (!rows.length)
    return (
      <>
        {empty}
        {dialog}
      </>
    );

  const byKey = new Map(page.map((a) => [a.action_uid, a]));
  const moments = page.map((a): Moment => {
    const state = actionState(a);
    const badge = (
      <Status tone={state.tone} badge>
        {state.word}
      </Status>
    );
    return {
      key: a.action_uid,
      at: changedAt(a),
      dot: "event",
      who: a.requested_by,
      what: <What action={a} badge={badge} />,
      end: (
        <>
          {stuck.has(a.action_uid) ? (
            <Tip label="Stuck">
              <AlertTriangle className="h-3.5 w-3.5 text-warn" role="img" aria-label="stuck" />
            </Tip>
          ) : null}
          <span className="hidden md:contents">{badge}</span>
        </>
      ),
      active: nav.activeKey === a.action_uid,
      isNew: fresh.has(a.action_uid),
    };
  });

  return (
    <>
      <div className="px-2 py-1">
        <Timeline variant="feed" moments={moments} rowProps={(m) => nav.rowProps(byKey.get(m.key)!)} label="Activity" />
      </div>
      {pager}
      {dialog}
    </>
  );
}

/**
 * Platform logo, the action's label and its target after it. Under 768px the
 * target and the state badge take a second line, so the label keeps the row.
 */
function What({ action, badge }: { action: Action; badge: ReactNode }) {
  return (
    <span className="flex min-w-0 max-w-full items-center gap-2 py-1 md:py-0">
      <PlatformMark id={action.type} />
      <span className="flex min-w-0 flex-1 flex-col md:flex-row md:items-center md:gap-2">
        <span className="min-w-0 truncate text-fg-1 md:shrink-0">{actionLabel(action.type)}</span>
        <span className="flex min-w-0 items-center gap-2">
          {action.target ? (
            <>
              <span className="hidden text-fg-4 md:inline" aria-hidden>
                ·
              </span>
              <Entity value={action.target} className="min-w-0" />
            </>
          ) : null}
          <span className="ml-auto flex shrink-0 md:hidden">{badge}</span>
        </span>
      </span>
    </span>
  );
}
