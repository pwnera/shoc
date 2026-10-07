/**
 * Measurement: how fast and how accurate is shoc, per incident type, over
 * time? One window (`?days=`, 7, 30 or 90) applies to everything on the page:
 * the strip (cases, the share handled without a person, time to resolve,
 * the share the rule was wrong, spend per case), named as the table and the
 * verdicts name them, time per phase by incident type on one shared
 * log axis, and the verdict mix. Reports are an export: the Export menu builds
 * one on demand; nothing builds a report on load.
 *
 * Capabilities used: metrics.get, case.list (who closed the cases), ops.alerts
 * (a model without a price), and on Export report.get and report.send.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Meter, Share, type MeterTone } from "@/components/ui/meter";
import { Empty } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Menu } from "@/components/ui/pop";
import { Seg } from "@/components/ui/seg";
import { QueryState } from "@/components/ui/state";
import { Mark } from "@/components/ui/status";
import { Strip, type StripFact } from "@/components/ui/strip";
import { money, num, percent, span } from "@/lib/format";
import { foldVerdict, verdictLabel } from "@/lib/labels";
import { useParam } from "@/lib/param";
import { CASE_CAP, useAlerts, useCaseLog, useMetrics, useReportExport } from "@/lib/queries";
import { ExportDialog } from "./measurement/ExportDialog";
import { KIND_LABEL, type Kind } from "./measurement/kinds";
import { Times, type TypeRow } from "./measurement/Times";

const WINDOWS = ["7", "30", "90"] as const;
type Days = (typeof WINDOWS)[number];
const DAY = 86_400_000;

/* Verdicts in one order on every load, worst first; undecided (the crew handed over, nobody decided) closes the bar. */
const VERDICTS = ["malicious", "suspicious", "benign_expected", "false_positive", "unknown"];
/** Neutral tones that differ by shape as well as step, so no two neighbours read alike in either theme. */
const VERDICT_TONE: Record<string, MeterTone> = {
  malicious: "seq-4",
  suspicious: "seq-2",
  benign_expected: "muted",
  false_positive: "idle-hatched",
  unknown: "idle-dashed",
};
const rank = (verdict: string) => (VERDICTS.includes(verdict) ? VERDICTS.indexOf(verdict) : VERDICTS.length);

export function Measurement() {
  const navigate = useNavigate();
  const [days, setDays] = useParam<Days>("days", "30");
  const windowDays = (WINDOWS as readonly string[]).includes(days) ? Number(days) : 30;
  const metrics = useMetrics(windowDays);
  const cases = useCaseLog();
  const alerts = useAlerts();
  const exporter = useReportExport();
  const [exporting, setExporting] = useState<Kind | null>(null);
  // Cases reads a relative since, so the link stays the same from one render to the next.
  const closedLink = (extra = "") => `/cases?tab=closed&since=${windowDays}d${extra}`;

  const m = metrics.data?.data;
  // Only a first load that failed is an error: a failed refresh keeps the last answer, as of its time.
  const failed = metrics.isLoadingError ? metrics.error : undefined;
  const stale = [metrics, cases].filter((q) => q.isRefetchError);
  const asOf = stale.length ? new Date(Math.min(...stale.map((q) => q.dataUpdatedAt))).toISOString() : null;
  const types: TypeRow[] = Object.entries(m?.by_incident_type ?? {})
    .map(([type, row]) => ({ type, ...row }))
    .sort((a, b) => b.cases - a.cases);
  const total = types.reduce((sum, t) => sum + t.cases, 0);
  const timed = types.filter((t) => t.mttr_minutes !== null);
  const weighted = timed.reduce((sum, t) => sum + t.cases, 0);
  const mttr = weighted ? timed.reduce((sum, t) => sum + (t.mttr_minutes ?? 0) * t.cases, 0) / weighted : null;

  // Handled without you: closed in the window by the crew or the system, over every case closed in it.
  const from = Date.now() - windowDays * DAY;
  const closed = (cases.data?.rows ?? []).filter((c) => c.state === "closed" && c.closed_at && Date.parse(c.closed_at) >= from);
  // Older rows do not say who closed them; they count for neither side.
  const known = closed.filter((c) => c.closed_by);
  const alone = known.filter((c) => c.closed_by === "crew" || c.closed_by === "system").length;
  // Under three known closers a share says nothing: "—".
  const share = known.length >= 3 ? alone / known.length : null;
  const capped = (cases.data?.rows.length ?? 0) >= CASE_CAP;
  // A model shoc has no price for is counted at $0, so a cost per case would read as free.
  const unpriced = (alerts.data?.alerts ?? []).filter((a) => a.kind === "cost.unpriced");

  const facts: StripFact[] = [
    // metrics.get counts every case opened in the window, open or closed.
    { label: "cases", value: m ? total : null, to: `/cases?since=${windowDays}d` },
    {
      key: "alone",
      label: "handled without you",
      value: cases.isLoadingError ? null : share === null ? (cases.isPending ? undefined : "—") : (
        <span className="inline-flex items-center gap-2">
          <Meter value={share} showValue={false} width={40} label="Handled without you" />
          {percent(share)}
          <span className="text-fg-4">of {num(known.length)}</span>
        </span>
      ),
      tip: capped ? "Closed cases whose closer is known, of the last 200" : "Closed cases whose closer is known",
    },
    { label: "to resolve", value: mttr === null ? null : span(mttr * 60) },
    {
      label: verdictLabel("false_positive").word,
      value: m?.false_positive_rate === null || m?.false_positive_rate === undefined ? null : percent(m.false_positive_rate),
      to: closedLink("&verdict=false_positive"),
    },
    {
      label: "cost per case",
      value: m && total && alerts.data && !unpriced.length ? money(m.spend_usd / total) : null,
      tip: unpriced.length ? `no price: ${unpriced.map((a) => a.subject).join(", ")}` : undefined,
    },
  ];

  // "benign" reads "expected" too, so it joins that segment; a closed "needs you" is undecided. Cases filters both alike.
  const verdicts: Record<string, number> = {};
  for (const [v, n] of Object.entries(m?.dispositions ?? {})) {
    const key = v === "benign" ? "benign_expected" : foldVerdict(v);
    verdicts[key] = (verdicts[key] ?? 0) + n;
  }
  const dispositions = Object.entries(verdicts)
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => rank(a) - rank(b));

  const run = (kind: Kind) => {
    setExporting(kind);
    exporter.mutate(kind);
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Measurement"
        aside={
          <Menu
            label="Export"
            items={(Object.keys(KIND_LABEL) as Kind[]).map((kind) => ({ label: KIND_LABEL[kind], onSelect: () => run(kind) }))}
            trigger={(props) => (
              <Button {...props}>
                Export
                <ChevronDown aria-hidden />
              </Button>
            )}
          />
        }
        strip={
          <Strip
            facts={facts}
            loading={metrics.isPending}
            error={failed}
            onRetry={() => void metrics.refetch()}
            asOf={asOf}
            aside={
              <Seg
                label="Window"
                value={days}
                onChange={setDays}
                options={WINDOWS.map((d) => ({ value: d, label: `${d}d` }))}
              />
            }
          />
        }
      />

      <Card>
        <CardHeader title="Time by incident type" />
        <Times
          types={types}
          loading={metrics.isPending}
          error={failed}
          onRetry={() => void metrics.refetch()}
          empty={`No closed cases in ${windowDays} days`}
          closedLink={closedLink()}
        />
      </Card>

      <Card>
        <CardHeader title="Verdicts" />
        <CardBody>
          <QueryState
            queries={{ isPending: metrics.isPending, isError: metrics.isLoadingError, error: metrics.error, refetch: metrics.refetch }}
            isEmpty={!dispositions.length}
            empty={<Empty title={`No verdicts in ${windowDays} days`} />}
          >
            {() => (
              <div className="flex flex-col gap-2">
                <Share
                  label="Verdicts"
                  segments={dispositions.map(([v, n]) => ({
                    key: v,
                    label: verdictLabel(v).word,
                    value: n,
                    tone: VERDICT_TONE[v] ?? "muted",
                    onClick: () => navigate(closedLink(`&verdict=${encodeURIComponent(v)}`)),
                  }))}
                />
                {/* The counts sit under their segments; the legend only names them. */}
                <ul className="m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0">
                  {dispositions.map(([v]) => (
                    <li key={v} className="inline-flex items-center gap-1.5 text-fg-3">
                      <Mark tone={VERDICT_TONE[v] ?? "muted"} />
                      <span aria-hidden className="text-fg-2">
                        {verdictLabel(v).glyph}
                      </span>
                      {verdictLabel(v).word}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </QueryState>
        </CardBody>
      </Card>

      {exporting ? (
        <ExportDialog
          kind={exporting}
          query={exporter}
          onRetry={() => exporter.mutate(exporting)}
          onClose={() => {
            setExporting(null);
            exporter.reset();
          }}
        />
      ) : null}
    </div>
  );
}
