/**
 * One threat report the CTI role read (`?report=<uid>`): a graph from the
 * report to the actors, malware and campaigns it names and the techniques it
 * describes (each linked to ATT&CK), how many indicators it stored, the
 * source, and its suggested hunts as rows with "→ Backlog" (`hunt.propose`,
 * its one home). Withdraw (`intel.remove {report_uid}`) takes back every
 * indicator it stored, after a confirm; the report then reads withdrawn. Its summary and relevance prose are
 * not drawn: the fields say what they say.
 */
import { useState } from "react";
import { Undo2 } from "lucide-react";
import { Badge, ConfidenceBar } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Chip } from "@/components/ui/filterbar";
import { Graph } from "@/components/ui/graph";
import { ProseLine } from "@/components/ui/prose";
import { ErrorNote, Spinner } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { attackUrl } from "@/lib/attack";
import { count, stamp } from "@/lib/format";
import { useHuntBacklog, useProposeHunt, useRemoveIntel } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { IntelReport } from "@/types";

type Node = { id: string; kind: string; label: string; lane: string; what: string };
type Link = { src: string; dst: string };

const LANES = ["who", "report", "how"];
const PER_LANE = 6;
const LANE_LABEL: Record<string, string> = { who: "ACTORS · MALWARE", report: "REPORT", how: "TECHNIQUES" };

/** The report in the middle, who it names on the left, the techniques on the right. */
function graphOf(report: IntelReport): { nodes: Node[]; edges: Link[] } {
  const named = (list: string[], kind: string, what: string): Node[] =>
    list.map((label) => ({ id: `${what}:${label}`, kind, label, lane: "who", what }));
  const nodes: Node[] = [
    { id: "report", kind: "report", label: report.source_host || "report", lane: "report", what: "report" },
    ...named(report.actors, "user", "actor"),
    ...named(report.malware, "malware", "malware"),
    ...named(report.campaigns, "campaign", "campaign"),
    ...report.techniques.map((t) => ({ id: `technique:${t}`, kind: "technique", label: t, lane: "how", what: "technique" })),
  ];
  return { nodes, edges: nodes.slice(1).map((n) => ({ src: "report", dst: n.id })) };
}

function Hunts({ report }: { report: IntelReport }) {
  const propose = useProposeHunt();
  // A suggestion already on the backlog (any state) reads "proposed", so reopening never offers it twice.
  // The crew files a suggestion with its title cut short and the whole text as the hypothesis.
  const backlog = useHuntBacklog("");
  const listed = new Set((backlog.data?.items ?? []).flatMap((item) => [item.title, item.hypothesis]));
  return (
    <>
      <ul className="m-0 flex list-none flex-col p-0" aria-label="Suggested hunts">
        {report.hunts.map((hunt) => {
          const busy = propose.isPending && propose.variables?.title === hunt;
          return (
            <li key={hunt} className="flex min-h-8 items-center gap-2 border-b border-line-1 py-1 last:border-0">
              <span className="min-w-0 flex-1 text-fg-2">
                <ProseLine text={hunt} />
              </span>
              {/* One trailing slot; the ghost button's text, not its padding, meets the badge's edge. */}
              <span className="flex w-24 shrink-0 justify-end">
                {listed.has(hunt) || listed.has(hunt.trim().slice(0, 300)) ? (
                  <Badge tone="idle">proposed</Badge>
                ) : (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="-mr-2"
                    disabled={propose.isPending || backlog.isPending}
                    onClick={() =>
                      propose.mutate({ title: hunt, hypothesis: hunt, why_now: `report ${report.title}`, attack: report.techniques })
                    }
                  >
                    {busy ? <Spinner /> : null}→ Backlog
                  </Button>
                )}
              </span>
            </li>
          );
        })}
      </ul>
      {propose.error ? <ErrorNote error={propose.error} inline /> : null}
    </>
  );
}

export function ReportDialog({
  report,
  withdrawn,
  onWithdrawn,
  onClose,
  step,
}: {
  report: IntelReport;
  /** Withdrawn in this session: the kernel's `stored_count` still counts what it took back. */
  withdrawn?: boolean;
  onWithdrawn?: (reportUid: string) => void;
  onClose: () => void;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const remove = useRemoveIntel();
  const [asking, setAsking] = useState(false);
  const [more, setMore] = useState<string[]>([]);
  const { nodes, edges } = graphOf(report);
  // Only the lanes the report fills; a label sits under its node, so rows keep 44px apart.
  const lanes = LANES.filter((lane) => nodes.some((n) => n.lane === lane));
  const tallest = Math.max(1, ...lanes.map((lane) => nodes.filter((n) => n.lane === lane).length));

  return (
    <Dialog
      title={report.title}
      onClose={onClose}
      step={step}
      footer={
        report.stored_count && !withdrawn ? (
          <Popover
            open={asking}
            onOpenChange={setAsking}
            label="Withdraw"
            align="end"
            trigger={(props) => (
              <Button {...props} variant="ghost">
                <Undo2 aria-hidden />
                Withdraw
              </Button>
            )}
          >
            <Confirm
              what={`Withdraw ${count(report.stored_count, "indicator")} · ${report.source_host}`}
              go="Withdraw"
              danger
              onConfirm={() =>
                remove.mutateAsync({ report_uid: report.report_uid }).then((envelope) => {
                  toast({ tone: "ok", text: `${count(envelope.data.removed, "indicator")} withdrawn` });
                  setAsking(false);
                  onWithdrawn?.(report.report_uid);
                })
              }
              onCancel={() => setAsking(false)}
            />
          </Popover>
        ) : undefined
      }
    >
      {nodes.length > 1 ? (
        <Graph
          nodes={nodes}
          edges={edges}
          layout="layered"
          lanes={lanes}
          laneOf={(n) => n.lane}
          laneLabel={(lane) => LANE_LABEL[lane] ?? lane}
          focus="report"
          perLane={PER_LANE}
          height={56 + Math.min(tallest, PER_LANE + 1) * 44}
          name={(n) => `${n.what} ${n.label}`}
          onMore={setMore}
          onOpen={(n) => {
            if (n.kind === "technique") window.open(attackUrl(n.label), "_blank", "noopener");
          }}
          label="Report"
        />
      ) : null}
      {more.length ? (
        <span className="flex flex-wrap gap-1" aria-label="More">
          {nodes
            .filter((n) => more.includes(n.id))
            .map((n) =>
              n.kind === "technique" ? (
                <a key={n.id} className="sh-chip" href={attackUrl(n.label)} target="_blank" rel="noreferrer noopener">
                  <span className="sh-chip__value">{n.label}</span>
                </a>
              ) : (
                <Chip key={n.id} label={n.what} value={n.label} />
              ),
            )}
        </span>
      ) : null}
      <Fields
        rows={[
          [
            "source",
            report.url ? (
              <a className="sh-link truncate font-mono text-xs" href={report.url} target="_blank" rel="noreferrer noopener">
                {report.url}
              </a>
            ) : null,
          ],
          [
            "stored",
            withdrawn ? (
              <Badge tone="idle">withdrawn</Badge>
            ) : report.stored_count ? (
              <Chip value={`+${report.stored_count.toLocaleString()} indicators`} />
            ) : null,
          ],
          ["confidence", <ConfidenceBar value={report.confidence} />],
          ["read", <span className="sh-mono">{stamp(report.digested_at)}</span>],
        ]}
      />
      {report.hunts.length ? (
        <section className="flex flex-col gap-1">
          <span className="sh-label">suggested hunts</span>
          <Hunts report={report} />
        </section>
      ) : null}
    </Dialog>
  );
}
