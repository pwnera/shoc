/**
 * A weekly or board report, built once on demand and shown as a print view:
 * the period, KPI tiles in the words the screens use, the rules that fired
 * most (by title, each opening its page) and source quality, and for the
 * board the posture. Print renders the report alone on A4; Download keeps
 * the JSON; Send now posts it to Slack after a confirm (an admin token; a
 * refusal shows inline).
 *
 * Capabilities used: report.get (by the Export menu, never on load),
 * report.send, rule.list (titles).
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Download, Printer } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Stat, Stats } from "@/components/ui/card";
import { BarList } from "@/components/ui/charts";
import { Dialog } from "@/components/ui/dialog";
import { Label } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { QueryState } from "@/components/ui/state";
import { day, num, percent } from "@/lib/format";
import { DISPOSITIONS, findingStatus, verdictLabel } from "@/lib/labels";
import { useRules, useSendReport } from "@/lib/queries";
import type { ReportBody, ReportEnvelope } from "@/types";
import { KIND_LABEL, type Kind } from "./kinds";

/** A count from the body: some fields arrive as the list itself (held notices, merges), though typed as a number. */
const count = (value: unknown): number | undefined =>
  Array.isArray(value) ? value.length : typeof value === "number" ? value : undefined;
const sum = (values: number[]) => values.reduce((total, n) => total + n, 0);
const cap = (word: string) => word.charAt(0).toUpperCase() + word.slice(1);

/** The KPI tiles, one row per part of the report, so each row fills and a label stays on one line. */
function Tiles({ body, kind }: { body: ReportBody; kind: Kind }) {
  const groups: { label: string; tiles: [string, number | undefined][] }[] = [
    {
      label: "cases",
      tiles: [
        ["Total", count(body.cases?.total)],
        [DISPOSITIONS.malicious, count(body.cases?.malicious)],
        [cap(verdictLabel("unknown").word), count(body.cases?.needs_human)],
        ["Still open", count(body.cases?.open)],
      ],
    },
    {
      label: "findings",
      tiles: [
        ["Total", count(body.findings?.total)],
        ["Serious", count(body.findings?.serious)],
        [cap(findingStatus("suppressed")), count(body.findings?.suppressed)],
        [findingStatus("self"), count(body.findings?.own)],
      ],
    },
    {
      label: "actions",
      tiles: [
        ["Total", body.actions ? sum(body.actions.rows.map((r) => r.n)) : undefined],
        ["Waited on you", count(body.actions?.waiting_for_approval)],
        ["Held, no page", count(body.held)],
      ],
    },
    {
      label: "hunting",
      tiles: [
        ["Hunts", body.hunting?.metrics ? sum(Object.values(body.hunting.metrics.by_outcome ?? {})) : undefined],
        ["Rules proposed", count(body.hunting?.metrics?.detections_proposed)],
      ],
    },
    {
      label: "detection",
      tiles: [
        ["Changes open", count(body.detection?.backlog_open)],
        ["Muted", count(body.detection?.suppressions_active)],
        ["Rules merged", count(body.detection?.merges)],
      ],
    },
    ...(kind === "exec"
      ? [
          {
            label: "posture",
            tiles: [
              ["Exposed", count(body.posture?.exposed_entities)],
              ["Watched", count(body.posture?.entities_watched)],
              ["Indicators", count(body.posture?.indicators_known)],
            ] as [string, number | undefined][],
          },
        ]
      : []),
  ];
  return (
    <>
      {groups.map((group) => {
        const tiles = group.tiles.filter(([, value]) => value !== undefined);
        return tiles.length ? (
          <section key={group.label} className="flex flex-col gap-2" aria-label={group.label}>
            <Label>{group.label}</Label>
            <Stats>
              {tiles.map(([label, value]) => (
                <Stat key={label} label={label} value={num(value!)} />
              ))}
            </Stats>
          </section>
        ) : null;
      })}
    </>
  );
}

export function ExportDialog({
  kind,
  query,
  onRetry,
  onClose,
}: {
  kind: Kind;
  /** The export mutation: pending while the report builds. */
  query: { data?: ReportEnvelope; error: unknown; isPending: boolean; isError: boolean };
  onRetry: () => void;
  onClose: () => void;
}) {
  const send = useSendReport();
  const rules = useRules();
  const navigate = useNavigate();
  const [asking, setAsking] = useState(false);
  const report = query.data;
  const titled = new Map((rules.data?.rules ?? []).map((r) => [r.id, r.title]));
  const top = (report?.body.top_rules ?? []).map((r) => ({
    key: r.rule_id,
    label: titled.get(r.rule_id) ?? r.rule_id,
    value: r.n,
  }));

  const download = () => {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `shoc-${kind}-${report.period_end.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Dialog
      size="wide"
      title={KIND_LABEL[kind]}
      head={report ? <span className="sh-mono text-fg-4">{`${day(report.period_start)} → ${day(report.period_end)}`}</span> : null}
      onClose={onClose}
      footer={
        asking ? null : (
          <>
            <Button variant="ghost" disabled={!report} onClick={() => setAsking(true)}>
              Send now
            </Button>
            <Button disabled={!report} onClick={download}>
              <Download aria-hidden />
              Download JSON
            </Button>
            <Button variant="primary" disabled={!report} onClick={() => window.print()}>
              <Printer aria-hidden />
              Print
            </Button>
          </>
        )
      }
    >
      <QueryState
        queries={{ isPending: query.isPending, isError: query.isError, error: query.error, refetch: onRetry }}
      >
        {() => {
          const body = report!.body;
          return (
            <div className="sh-print flex flex-col gap-4">
              <h3 className="m-0 hidden text-fg-1 print:block">
                {KIND_LABEL[kind]} · {day(report!.period_start)} → {day(report!.period_end)}
              </h3>
              <Tiles body={body} kind={kind} />
              {kind === "exec" && body.posture?.weakest_source ? (
                <div className="flex items-baseline gap-2">
                  <Label>weakest source</Label>
                  <span className="text-fg-1">{body.posture.weakest_source}</span>
                </div>
              ) : null}
              {top.length ? (
                <div className="flex flex-col gap-2">
                  <Label>rules that fired most</Label>
                  <BarList
                    label="Rules that fired most"
                    rows={top}
                    onPick={(label) => {
                      const id = top.find((r) => r.label === label)?.key;
                      if (id) navigate(`/detection/rules/${encodeURIComponent(id)}`);
                    }}
                  />
                </div>
              ) : null}
              {body.quality?.sources.length ? (
                <div className="flex flex-col gap-2">
                  <Label>source quality</Label>
                  <BarList
                    label="Source quality"
                    rows={body.quality.sources.map((s) => ({ label: s.product, value: s.score }))}
                    format={percent}
                  />
                </div>
              ) : null}
            </div>
          );
        }}
      </QueryState>
      {asking ? (
        <Confirm
          inline
          what={`Send the ${KIND_LABEL[kind].toLowerCase()} to Slack`}
          go="Send"
          onConfirm={() => send.mutateAsync(kind).then(() => setAsking(false))}
          onCancel={() => setAsking(false)}
        />
      ) : null}
    </Dialog>
  );
}
