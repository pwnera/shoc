/**
 * One hunt run as a trace on one rail: why the Hunter chose it, the query it
 * ran, what came back, what it ruled out and could not see, its outcome with
 * the Hunter's triage, and the finding it raised or the error it hit. No
 * prose block: the Hunter's own words are quoted where they are the record.
 * The pack dialog draws a fresh `hunt.pack` answer with the same trace.
 */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Ban, EyeOff, Flag, Lightbulb, Radar, Rows3, Terminal, type LucideIcon } from "lucide-react";
import { Chip } from "@/components/ui/filterbar";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Copy, Quote } from "@/components/ui/field";
import { Status } from "@/components/ui/status";
import { dayMonth, span, stamp } from "@/lib/format";
import { OUTCOMES } from "@/lib/labels";
import type { HuntOutcome, HuntRun } from "@/types";
import { fromRun } from "./runs";

/** What both a stored run and a fresh `hunt.pack` answer can say. */
export type TraceRun = {
  chosen_because?: string;
  query?: string;
  query_params?: Record<string, unknown>;
  rows: number;
  ran_at?: string;
  ingested_from?: string | null;
  ingested_to?: string | null;
  duration_ms?: number;
  ruled_out: string[];
  unseen: string[];
  outcome: HuntOutcome;
  triage: string;
  finding_uid: string;
  error: string;
};

function Step({ icon: Icon, label, meta, children }: { icon: LucideIcon; label: string; meta?: ReactNode; children: ReactNode }) {
  return (
    <li className="sh-trace__item">
      <div className="sh-trace__row cursor-default hover:bg-transparent">
        {/* The dialog's ground, hovered or not: these rows open nothing, so the node never lights. */}
        <span className="sh-trace__node bg-[var(--bg-float)]" aria-hidden>
          <Icon className="h-3.5 w-3.5" />
        </span>
        <div className="flex min-w-0 flex-col gap-2">
          <span className="sh-label">{label}</span>
          {children}
        </div>
        {meta ? <span className="sh-trace__meta">{meta}</span> : null}
      </div>
    </li>
  );
}

/** The tenant is every query's; the data window is the rows step's. */
const SKIP = new Set(["tenant_id", "ingested_from", "ingested_to"]);
/** A timestamp as Postgres writes one, "2026-10-03 22:11:44.838968+00:00". */
const WHEN = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/;

const param = (value: unknown) => (
  <span className="sh-mono sh-mono--strong">
    {typeof value !== "string" ? JSON.stringify(value) : WHEN.test(value) ? stamp(value.replace(" ", "T")) : value}
  </span>
);

/* The Hunter's schedule writes reason codes, not words it said (`shoc/agents/hunter.py` `_choose`). */
const DUE = /^due: last run (\d{4}-\d{2}-\d{2})$/;
const CHOSEN: Record<string, ReactNode> = { "never run here": <span className="sh-mono">due · never ran</span> };

export function RunTrace({ run }: { run: TraceRun }) {
  const outcome = OUTCOMES[run.outcome] ?? { word: run.outcome, tone: "idle" as const };
  const params = Object.entries(run.query_params ?? {}).filter(([key]) => !SKIP.has(key));
  return (
    <ol className="sh-trace" aria-label="Run">
      {run.chosen_because ? (
        <Step icon={Lightbulb} label="why it ran">
          {CHOSEN[run.chosen_because] ?? (DUE.test(run.chosen_because) ? (
            <span className="sh-mono">due · last ran {dayMonth(DUE.exec(run.chosen_because)![1])}</span>
          ) : (
            <Quote by="Hunter" crew>
              {run.chosen_because}
            </Quote>
          ))}
        </Step>
      ) : null}
      {run.query ? (
        <Step icon={Terminal} label="query">
          <Copy value={run.query} block label="Copy query" />
          {params.length ? <Fields rows={params.map(([key, value]): [string, ReactNode] => [key, param(value)])} /> : null}
        </Step>
      ) : null}
      <Step
        icon={Rows3}
        label="rows"
        meta={
          run.duration_ms === undefined ? undefined : run.duration_ms < 1000 ? `${run.duration_ms}ms` : span(run.duration_ms / 1000)
        }
      >
        <Fields
          rows={[
            ["returned", <span className="sh-mono sh-mono--strong">{run.rows.toLocaleString()}</span>],
            ["ran", run.ran_at ? <span className="sh-mono">{stamp(run.ran_at)}</span> : null],
            [
              "data",
              run.ingested_from || run.ingested_to ? (
                <span className="sh-mono">
                  {stamp(run.ingested_from)} → {stamp(run.ingested_to)}
                </span>
              ) : null,
            ],
          ]}
        />
      </Step>
      {run.ruled_out.length ? (
        <Step icon={Ban} label="ruled out">
          <span className="flex flex-wrap gap-1">
            {run.ruled_out.map((value) => (
              <Chip key={value} value={value} struck />
            ))}
          </span>
        </Step>
      ) : null}
      {run.unseen.length ? (
        <Step icon={EyeOff} label="not looked at">
          <span className="flex flex-wrap gap-1">
            {run.unseen.map((value) => (
              <Chip key={value} value={value} dashed />
            ))}
          </span>
        </Step>
      ) : null}
      <Step icon={Flag} label="outcome">
        <span>
          <Status tone={outcome.tone} badge>
            {outcome.word}
          </Status>
        </span>
        {run.triage ? (
          <Quote by="Hunter" crew>
            {run.triage}
          </Quote>
        ) : null}
      </Step>
      {run.finding_uid ? (
        <Step icon={Radar} label="finding">
          <Link to={`/findings/${run.finding_uid}`} className="sh-link self-start font-mono text-xs">
            {run.finding_uid}
          </Link>
        </Step>
      ) : run.error ? (
        <Step icon={AlertTriangle} label="error">
          <p className="sh-mono m-0 text-bad">{run.error}</p>
        </Step>
      ) : null}
    </ol>
  );
}

export function HuntRunDialog({
  run,
  title,
  onClose,
  step,
}: {
  run: HuntRun;
  title: string;
  onClose: () => void;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  return (
    // No id in the header: a run_uid tells the reader nothing, and on a phone it crowds out the title.
    <Dialog title={title} onClose={onClose} step={step} size="wide">
      <RunTrace run={fromRun(run)} />
    </Dialog>
  );
}
