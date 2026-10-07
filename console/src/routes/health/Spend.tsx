/**
 * Health › Spend: today's model spend against the daily budget, 30 days of
 * spend per day stacked by model, the tokens behind it, the hunters' daily
 * token budget and what CTI may read in a day (RFC 0029); Intel draws today's
 * reads against it. "$0.00" is drawn in the default ink, never as good news: a
 * "no model" badge says when nothing is configured, and "no price" (the word
 * Problems uses) when Ops reports a model shoc has no price for. While every
 * day reads $0 the bars count tokens instead, so the chart still says when the
 * crew worked.
 *
 * Capabilities used: health.cost, llm.show, ops.alerts.
 */
import { Badge } from "@/components/ui/badge";
import { CardBody } from "@/components/ui/card";
import { Fields } from "@/components/ui/dialog";
import { Meter } from "@/components/ui/meter";
import { Label } from "@/components/ui/misc";
import { QueryState } from "@/components/ui/state";
import { TimeBar } from "@/components/ui/timebar";
import { count, money, num } from "@/lib/format";
import { useAlerts, useCost, useLlm } from "@/lib/queries";
import { spendBuckets } from "./model";

export function Spend() {
  const cost = useCost(30);
  const llm = useLlm();
  const alerts = useAlerts();
  return (
    <CardBody className="flex flex-col gap-4">
      {/* Alerts too: without them "$0.00" could not say whether a model goes unpriced. A failed refresh keeps what shows. */}
      <QueryState
        queries={[cost, llm, alerts].map((q) => ({ isPending: q.isPending, isError: q.isLoadingError, error: q.error, refetch: q.refetch }))}
      >
        {() => {
          const spend = cost.data!.spend;
          const config = llm.data!;
          const budget = config.spend_usd_per_day;
          const unpriced = (alerts.data?.alerts ?? []).filter((a) => a.kind === "cost.unpriced");
          const byTokens = spend.usd_total === 0 && spend.tokens > 0;
          const buckets = spendBuckets(spend.rows, spend.days, Date.now(), byTokens ? "tokens" : "usd");
          const over = budget > 0 && spend.usd_today > budget;
          return (
            <>
              <Fields
                ruled
                rows={[
                  [
                    "Today",
                    <span className="flex flex-wrap items-center gap-2">
                      {budget > 0 ? (
                        <Meter
                          value={spend.usd_today}
                          max={Math.max(budget, spend.usd_today)}
                          tone={over ? "bad" : "neutral"}
                          marks={[{ at: budget, label: "budget" }]}
                          label="Spend today against the daily budget"
                          width={160}
                          format={(v) => `${money(v)} of ${money(budget)}`}
                        />
                      ) : (
                        <span className="sh-mono sh-mono--strong">{money(spend.usd_today)}</span>
                      )}
                      {budget > 0 ? null : <Badge tone="idle">no budget</Badge>}
                      {config.model ? null : <Badge tone="idle">no model</Badge>}
                      {unpriced.length ? (
                        <Badge tone="warn" title={unpriced.map((a) => a.subject).join(", ")}>
                          no price
                        </Badge>
                      ) : null}
                    </span>,
                  ],
                  [`${spend.days} days`, <span className="sh-mono sh-mono--strong">{money(spend.usd_total)}</span>],
                  ["Tokens", <span className="sh-mono">{num(spend.tokens)}</span>],
                  ["Hunt budget", <span className="sh-mono">{num(config.hunt_tokens_per_day)} tokens a day</span>],
                  [
                    "Intel budget",
                    config.intel_reports_per_day && config.intel_tokens_per_day ? (
                      <span className="sh-mono">
                        {count(config.intel_reports_per_day, "report")} · {num(config.intel_tokens_per_day)} tokens a day
                      </span>
                    ) : null,
                  ],
                ]}
              />
              <div className="flex flex-col gap-2">
                <Label>{byTokens ? "tokens per day" : "spend per day"}</Label>
                <TimeBar
                  variant="bars"
                  from={buckets[0]!.from}
                  to={buckets[buckets.length - 1]!.to}
                  bars={buckets}
                  label={byTokens ? "Tokens per day by model" : "Spend per day by model"}
                />
              </div>
            </>
          );
        }}
      </QueryState>
    </CardBody>
  );
}
