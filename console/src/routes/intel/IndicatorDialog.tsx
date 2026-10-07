/**
 * One indicator: its fields, its description quoted as feed or report text, and
 * three acts. Sweep 90 days (`S`, `hunt.run`) searches our events for the
 * value and shows what matched here; Look up (`L`) opens EntityDialog on its
 * Intel view, the one home of `intel.lookup`; Remove (`X`, `intel.remove`)
 * withdraws this one value after a confirm. Steps through the list with J/K.
 */
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Search, Trash2 } from "lucide-react";
import { EventTable } from "@/components/EventTable";
import { Badge, ConfidenceBar, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Quote } from "@/components/ui/field";
import { Chip } from "@/components/ui/filterbar";
import { ErrorNote, Spinner } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { Tip } from "@/components/ui/tip";
import { useCommand } from "@/lib/commands";
import { parseEntity, exploreQuery } from "@/lib/entity";
import { exploreHref, word } from "@/lib/explore";
import { count, stamp } from "@/lib/format";
import { useRemoveIntel, useRunHunt } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { EventRow, Indicator } from "@/types";
import { defang, entityKey, feedName } from "./feeds";

type Sweep = ReturnType<typeof useRunHunt>;

/** A 90-day sweep's answer: how many events matched, the findings it raised, the events, and Explore over the same window. */
export function Swept({ sweep, value }: { sweep: Sweep; value: string }) {
  if (sweep.isPending)
    return (
      <p className="sh-mono m-0 flex items-center gap-2">
        <Spinner /> sweeping 90 days
      </p>
    );
  if (sweep.error) return <ErrorNote error={sweep.error} inline />;
  const answer = sweep.data?.data;
  if (!answer) return null;
  const entity = parseEntity(value);
  return (
    <section className="flex flex-col gap-2" aria-label="Sweep">
      <div className="flex flex-wrap items-center gap-2">
        <span className="sh-label">90 days</span>
        <span className="sh-mono sh-mono--strong">{count(answer.matches, "event")}</span>
        {answer.findings.map((uid) => (
          <Link key={uid} to={`/findings/${uid}`} className="sh-chip">
            <span className="sh-chip__value">{uid}</span>
          </Link>
        ))}
        <Link
          className="sh-link ml-auto text-xs"
          to={exploreHref({ q: entity ? exploreQuery(entity) : word(value), since: "-90d" })}
        >
          Open in Explore
        </Link>
      </div>
      {answer.matches ? <EventTable rows={answer.events as EventRow[]} bounded={320} label="Matched events" /> : null}
    </section>
  );
}

export function IndicatorDialog({
  indicator,
  onClose,
  step,
}: {
  indicator: Indicator;
  onClose: () => void;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const [params, setParams] = useSearchParams();
  const sweep = useRunHunt();
  const remove = useRemoveIntel();
  const [asking, setAsking] = useState(false);
  // EntityDialog opened over this one takes the keys.
  const keys = !params.get("entity");
  const key = entityKey(indicator.value);
  const mine = sweep.variables?.value === indicator.value;

  const run = () => {
    if (!sweep.isPending) sweep.mutate({ value: indicator.value, days: 90 });
  };
  const lookUp = () => {
    if (!key) return;
    setParams((current) => {
      const out = new URLSearchParams(current);
      out.set("entity", key);
      out.set("view", "intel");
      return out;
    });
  };
  useCommand("indicator.sweep", run, keys);
  useCommand("indicator.lookup", lookUp, keys && Boolean(key));
  useCommand("indicator.remove", () => setAsking(true), keys);

  // A feed's text is the feed's; a value someone added by hand carries their words.
  const typed = indicator.source.startsWith("manual:");
  const polled = !typed && !indicator.source.startsWith("report:");
  const shown = defang(indicator.type, indicator.value);
  return (
    <Dialog
      title={shown}
      onClose={onClose}
      step={step}
      head={<Badge>{indicator.type}</Badge>}
      footer={
        <>
          <Popover
            open={asking}
            onOpenChange={setAsking}
            label={`Remove ${shown}`}
            trigger={(props) => (
              <Tip label="Remove" kbd="X">
                <Button {...props} variant="ghost" aria-keyshortcuts="X" className="mr-auto">
                  <Trash2 aria-hidden />
                  Remove
                </Button>
              </Tip>
            )}
          >
            <Confirm
              what={`Remove ${indicator.type} · ${shown}`}
              facts={polled ? <Badge tone="warn">its feed brings it back</Badge> : undefined}
              go="Remove"
              danger
              onConfirm={() =>
                remove.mutateAsync({ values: [indicator.value] }).then((envelope) => {
                  toast({ tone: "ok", text: `${count(envelope.data.removed, "indicator")} removed` });
                  setAsking(false);
                  onClose();
                })
              }
              onCancel={() => setAsking(false)}
            />
          </Popover>
          {key ? (
            <Tip label="Look up" kbd="L">
              <Button variant="ghost" onClick={lookUp} aria-keyshortcuts="L">
                Look up
              </Button>
            </Tip>
          ) : null}
          <Tip label="Sweep 90 days" kbd="S">
            <Button onClick={run} disabled={sweep.isPending} aria-keyshortcuts="S">
              {sweep.isPending && mine ? <Spinner /> : <Search aria-hidden />}
              Sweep 90 days
            </Button>
          </Tip>
        </>
      }
    >
      <Fields
        rows={[
          ["severity", <SeverityBadge severity={indicator.severity} />],
          ["confidence", <ConfidenceBar value={indicator.confidence} plain />],
          ["source", <span className="sh-mono sh-mono--strong">{feedName(indicator.source)}</span>],
          [
            "tags",
            indicator.tags.length ? (
              <span className="flex flex-wrap gap-1">
                {indicator.tags.map((tag) => (
                  <Chip key={tag} value={tag} />
                ))}
              </span>
            ) : null,
          ],
          ["last seen", <span className="sh-mono">{stamp(indicator.last_seen)}</span>],
        ]}
      />
      {indicator.description ? (
        typed ? (
          <Quote by={`human:${indicator.source.replace(/^manual:(human:)?/, "")}`}>{indicator.description}</Quote>
        ) : (
          // Quote's type names log and feed only; "report" reads "from a report" until it lists it.
          <Quote untrusted={(indicator.source.startsWith("report:") ? "report" : "feed") as "feed"}>{indicator.description}</Quote>
        )
      ) : null}
      {mine ? <Swept sweep={sweep} value={indicator.value} /> : null}
    </Dialog>
  );
}
