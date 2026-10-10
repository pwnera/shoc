/**
 * One hunt pack, the target of every `hunt:` link (`?pack=<id>`): its
 * hypothesis, its logic (the detection as YAML, what counts as new, the
 * window and cadence, the pivots, the triage question and what to check
 * first), readiness with the sources it reads (or the one to connect),
 * the accounts it covers, where it was taken from, its id, and its runs in
 * the window, each opening the run dialog. Run now (`R`, `hunt.pack`) shows when
 * the pack is ready; its answer appears here as the same trace. Revert
 * (`hunt.revert`) takes back a pack merged here behind a confirm that asks why;
 * the list does not say which packs were merged, so a shipped one shows the
 * kernel's refusal there.
 */
import { useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Undo2 } from "lucide-react";
import { Provenance } from "@/components/Provenance";
import { Button, CrewMark } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Copy, Quote } from "@/components/ui/field";
import { Chip } from "@/components/ui/filterbar";
import { productName } from "@/components/brands";
import { Empty, ErrorNote, Spinner } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { Status } from "@/components/ui/status";
import { Tactics } from "@/components/ui/tactics";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useCommand, useListNav } from "@/lib/commands";
import { age } from "@/lib/format";
import { OUTCOMES } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { useRevertPack, useRunPack } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import { sourceName } from "@/lib/sources";
import { toast } from "@/lib/toast";
import type { HuntLogic, HuntReadiness, HuntRun } from "@/types";
import { Yaml } from "../rule/Workbench";
import { HuntRunDialog, RunTrace } from "./HuntRunDialog";
import { Readiness } from "./Packs";

type Step = { index: number; total: number; onPrev?: () => void; onNext?: () => void };

function PackRuns({ runs: given, title }: { runs: HuntRun[]; title: string }) {
  const now = useNow();
  const [open, setOpen] = useState<number | null>(null);
  const columns: Column<HuntRun>[] = [
    {
      label: "Outcome",
      fit: true,
      sort: (r) => Object.keys(OUTCOMES).indexOf(r.outcome),
      cell: (r) => {
        const o = OUTCOMES[r.outcome] ?? { word: r.outcome, tone: "idle" as const };
        return <Status tone={o.tone}>{o.word}</Status>;
      },
    },
    {
      label: "Rows",
      sort: (r) => r.rows_returned,
      cell: (r) => (r.finding_uid ? "raised a finding" : `${r.rows_returned.toLocaleString()} rows`),
    },
    { label: "Ran", fit: true, mono: true, sort: (r) => r.ran_at, cell: (r) => age(r.ran_at, now) },
  ];
  const sorted = useSort(given, columns);
  const runs = sorted.rows;
  const nav = useListNav(runs, (r) => r.run_uid, { onOpen: (r) => setOpen(runs.indexOf(r)) });
  const run = open !== null ? runs[open] : undefined;
  return (
    <>
      <Table
        columns={columns}
        rows={runs}
        sort={sorted.sort}
        rowKey={(r) => r.run_uid}
        rowProps={nav.rowProps}
        bounded={200}
        label="Runs"
      />
      {run && open !== null ? (
        <HuntRunDialog
          run={run}
          title={title}
          onClose={() => setOpen(null)}
          step={{
            index: open,
            total: runs.length,
            onPrev: open > 0 ? () => setOpen(open - 1) : undefined,
            onNext: open < runs.length - 1 ? () => setOpen(open + 1) : undefined,
          }}
        />
      ) : null}
    </>
  );
}

const mono = (value: string): ReactNode => (value ? <span className="sh-mono sh-mono--strong">{value}</span> : null);

/** What counts as new: a tuple first seen in the lookback, or a grouping few (or many) share. */
function baseline(logic: HuntLogic): string {
  if (logic.first_seen.length) return `first ${logic.first_seen.join(" + ")} in ${logic.lookback}`;
  const rare = logic.rare;
  if (!rare) return "";
  const band = rare.seen_by_at_least
    ? `at least ${rare.seen_by_at_least}`
    : `fewer than ${rare.seen_by_fewer_than}`;
  return `${rare.by.join(" + ")} seen by ${band} ${rare.among} in ${logic.lookback}`;
}

/** The pack's logic, as a rule's page shows a rule's: the detection, then the facts that shape it. */
function Logic({ logic }: { logic: HuntLogic }) {
  return (
    <section className="flex flex-col gap-2" aria-label="Logic">
      <span className="sh-label">logic</span>
      <Yaml value={logic.detection} />
      <Fields
        ruled
        rows={[
          ["new when", mono(baseline(logic))],
          ["looks at", mono(`the last ${logic.window}, every ${logic.cadence_days === 1 ? "day" : `${logic.cadence_days} days`}`)],
          [
            "pivots on",
            logic.pivot.length ? (
              <span className="flex flex-wrap gap-1">
                {logic.pivot.map((f) => (
                  <Chip key={f} value={f} />
                ))}
              </span>
            ) : null,
          ],
          ["triage", logic.triage ? <Quote>{logic.triage}</Quote> : null],
          [
            "checks first",
            logic.follow_up.length ? (
              <ul className="m-0 flex list-disc flex-col gap-1 pl-4">
                {logic.follow_up.map((q) => (
                  <li key={q}>{q}</li>
                ))}
              </ul>
            ) : null,
          ],
          [
            "sensitive",
            logic.sensitive ? (
              <Tip label="A second inconclusive on the same values raises a finding">
                <span>yes</span>
              </Tip>
            ) : null,
          ],
        ]}
      />
    </section>
  );
}

function Body({ pack, runs, days }: { pack: HuntReadiness; runs: HuntRun[]; days: string }) {
  const now = useNow();
  const title = pack.title ?? pack.pack_id;
  const needs: ReactNode =
    pack.state === "not_applicable" ? (
      pack.product ? (
        <Link to={`/connections?add=${encodeURIComponent(pack.product)}`} className="sh-chip sh-chip--dashed">
          connect {productName(pack.product)}
        </Link>
      ) : null
    ) : pack.sources.length ? (
      <span className="flex flex-wrap gap-1">
        {pack.sources.map((source) => (
          <Link key={source} to={`/connections?source=${encodeURIComponent(source)}`} className="sh-chip">
            <span className="sh-chip__value">{sourceName(source)}</span>
          </Link>
        ))}
      </span>
    ) : null;
  return (
    <>
      {pack.hypothesis ? <Quote>{pack.hypothesis}</Quote> : null}
      {pack.logic ? <Logic logic={pack.logic} /> : null}
      <Fields
        rows={[
          ["ready", <Readiness row={pack} now={now} />],
          ["reads", needs],
          [
            "accounts",
            pack.accounts.length ? (
              <span className="flex flex-wrap gap-1">
                {pack.accounts.map((account) => (
                  <Chip key={account} value={account} />
                ))}
              </span>
            ) : null,
          ],
          ["att&ck", pack.attack?.length ? (
              // Fourteen fixed cells: on a phone they scroll inside the row, never the sheet.
              <span className="block max-w-full overflow-x-auto">
                <Tactics techniques={pack.attack} />
              </span>
            ) : null],
          ["from", pack.cites?.length ? <Provenance sources={pack.cites} /> : null],
          ["id", <Copy value={pack.pack_id} label="Copy pack id" />],
        ]}
      />
      <section className="flex flex-col gap-1">
        <span className="sh-label">runs · {days}d</span>
        {runs.length ? <PackRuns runs={runs} title={title} /> : <Empty kind="row" title={`No run in ${days} days`} />}
      </section>
    </>
  );
}

export function PackDialog({
  packId,
  pack,
  runs,
  days,
  pending,
  error,
  onRetry,
  onClose,
  step,
}: {
  packId: string;
  pack: HuntReadiness | undefined;
  runs: HuntRun[];
  days: string;
  pending: boolean;
  error: unknown;
  onRetry: () => void;
  onClose: () => void;
  step?: Step;
}) {
  const run = useRunPack();
  const ready = pack?.state === "ready";
  // Stepping to another pack keeps the mutation; its answer and error belong to the pack that ran.
  const mine = run.variables === packId;
  const busy = run.isPending && mine;
  const go = () => {
    if (!ready || run.isPending) return;
    run.mutate(packId);
  };
  useCommand("pack.run", go, ready);
  const answer = mine ? run.data?.data : undefined;
  const title = pack?.title ?? packId;
  // Keyed by the pack: J and K swap the pack under one open dialog.
  const revert = useRevertPack();
  const revertButton = useRef<HTMLButtonElement>(null);
  const [revertFor, setRevertFor] = useState<string | null>(null);
  const reverting = revertFor === packId;
  const stopReverting = () => {
    setRevertFor(null);
    requestAnimationFrame(() => revertButton.current?.focus());
  };

  return (
    <Dialog
      title={title}
      onClose={onClose}
      step={step}
      size="wide"
      footer={
        pack ? (
          <>
            {!reverting ? (
              <Button ref={revertButton} variant="danger" className="mr-auto" onClick={() => setRevertFor(packId)}>
                <Undo2 aria-hidden />
                Revert
              </Button>
            ) : null}
            {ready ? (
              <Tip label="Run now" kbd="R">
                <Button variant="crew" onClick={go} disabled={run.isPending} aria-keyshortcuts="R">
                  {busy ? <Spinner /> : <CrewMark />}
                  {busy ? "Hunting…" : "Run now"}
                </Button>
              </Tip>
            ) : null}
          </>
        ) : undefined
      }
    >
      {error ? (
        <ErrorNote error={error} onRetry={onRetry} />
      ) : pending ? (
        <div className="flex flex-col gap-2" aria-busy="true">
          <Skel kind="block" />
          <Skel kind="row" width="60%" />
        </div>
      ) : !pack ? (
        <Empty kind="page" title="No such pack" />
      ) : (
        <>
          {reverting ? (
            <Confirm
              inline
              danger
              what={`Revert ${title}`}
              go="Revert"
              note={{ required: true, label: "Reason", placeholder: "Why it goes" }}
              onCancel={stopReverting}
              onConfirm={(reason) =>
                revert.mutateAsync({ pack_id: packId, reason }).then(() => {
                  toast({ tone: "ok", text: `Reverted · ${title}` });
                  onClose();
                })
              }
            />
          ) : null}
          {answer ? (
            <section className="flex flex-col gap-1">
              <span className="sh-label">this run · now</span>
              <RunTrace run={answer} />
            </section>
          ) : null}
          {mine && run.error ? <ErrorNote error={run.error} inline /> : null}
          <Body pack={pack} runs={runs} days={days} />
        </>
      )}
    </Dialog>
  );
}
