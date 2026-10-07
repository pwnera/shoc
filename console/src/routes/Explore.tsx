/**
 * Explore: what exactly happened in the events, who did what, from where and
 * when. One query box over the OCSF store; the URL is the query, so Back steps
 * through queries and any link runs one. The strip counts the whole match, the
 * histogram draws it over the window (brush to zoom), the field rail breaks it
 * down by the pinned fields, and the results page through the loaded rows.
 *
 * Capabilities used: events.query (the rows; the NDJSON download asks again
 * with the original records), events.summarize (the histogram and total, the
 * failures over it, and each pinned field's top values).
 */
import { useRef, useState } from "react";
import { EventDialog } from "@/components/EventDialog";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Skel } from "@/components/ui/state";
import { Strip } from "@/components/ui/strip";
import { ApiError } from "@/lib/api";
import { useCommand, useListNav } from "@/lib/commands";
import { addTerm, PINNED, term } from "@/lib/explore";
import { num } from "@/lib/format";
import { useNow } from "@/lib/now";
import { useEventSearch, useEventSummary, useFieldTops } from "@/lib/queries";
import type { EventRow } from "@/types";
import { FieldRail } from "./explore/FieldRail";
import { Footer } from "./explore/Footer";
import { Histogram } from "./explore/Histogram";
import { QueryBar, type QueryBarHandle } from "./explore/QueryBar";
import { Results } from "./explore/Results";
import { kernelSince, relativeMs, remember, savedPins, savePins, useExploreQuery, windowOf, type Query } from "./explore/query";
import { TimeControl } from "./explore/TimeControl";

const PAGE = 50;
const FIRST = 100;
const WEEK = 7 * 86_400_000;

export function Explore() {
  const url = useExploreQuery();
  const { q, since, until, page, event } = url;
  const now = useNow();
  const bar = useRef<QueryBarHandle>(null);
  const time = useRef<HTMLSpanElement>(null);
  const [adding, setAdding] = useState(false);
  const [pins, setPins] = useState(() => savedPins(PINNED));

  // "Load more" grows this query's page; a new query starts at the first hundred.
  const key = `${q}|${since}|${until}`;
  const [more, setMore] = useState({ key, limit: FIRST });
  const limit = more.key === key ? more.limit : FIRST;

  const asked = { q, since: kernelSince(since), ...(until ? { until } : {}) };
  const search = useEventSearch({ ...asked, limit });
  const summary = useEventSummary({ ...asked, by: "time" });
  const failures = useEventSummary({ ...asked, by: "time", status: "Failure" });
  const tops = useFieldTops(asked, pins);

  const rows = search.data?.rows ?? [];
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const at = Math.min(page, pages);
  const shown = rows.slice((at - 1) * PAGE, at * PAGE);
  const pageOf = (index: number) => Math.floor(index / PAGE) + 1;

  const run = (next: Partial<Query>) => {
    remember(next.q ?? q);
    url.run(next);
  };
  const pivot = (field: string, value: string, op: "=" | "!=") => run({ q: addTerm(q, term(field, value, op)) });
  const openAt = (index: number) => {
    const row = rows[index];
    if (!row) return;
    nav.setActive(String(row.event_uid));
    url.openEvent(String(row.event_uid), pageOf(index));
  };
  const nav = useListNav(shown, (r) => String(r.event_uid), {
    onOpen: (r) => openAt(rows.indexOf(r)),
    copy: (r) => String(r.event_uid),
    onPrevPage: () => at > 1 && url.setPage(at - 1),
    onNextPage: () => at < pages && url.setPage(at + 1),
  });

  useCommand("explore.run", () => bar.current?.run());
  useCommand("shell.filter", () => bar.current?.focus());
  useCommand("explore.time", () =>
    time.current?.querySelector<HTMLElement>('[aria-checked="true"], [data-range]')?.focus(),
  );
  useCommand("explore.add-field", () => setAdding(true));

  const range = windowOf(since, until, Math.max(now, Date.now()));
  const short = range.to - range.from < WEEK;
  const values = Object.fromEntries(pins.map((f, i) => [f, (tops[i]?.data?.rows ?? []).map((r) => String(r.key))]));
  const index = event ? rows.findIndex((r) => String(r.event_uid) === event) : -1;
  // The last query's total is not this one's: until the new count lands, it is unknown.
  const total = summary.isPlaceholderData ? undefined : summary.data?.total;
  const counting = (summary.isPending || summary.isPlaceholderData) && !summary.isError && !search.isError;
  // A query the kernel refused (a 4xx) fails the same way again; only a store error is worth a retry.
  const refused = search.error instanceof ApiError && search.error.status >= 400 && search.error.status < 500;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Explore"
        strip={
          <>
            <Strip
              // Not `loading`, which adds a "…" word and pushes the fact aside on every run: the
              // value alone waits, as wide as the last count.
              facts={[
                {
                  key: "matched",
                  label: "matched",
                  value: counting ? (
                    <Skel kind="fact" width={summary.data ? `${num(summary.data.total).length}ch` : undefined} />
                  ) : (
                    total
                  ),
                },
              ]}
              // A query the kernel refused says so once, under the box; the strip only reads "—".
              error={summary.isError && !summary.data && !search.isError ? summary.error : undefined}
              onRetry={() => void summary.refetch()}
              aside={<TimeControl ref={time} since={since} until={until} onPick={(s, u) => run({ since: s, until: u })} />}
            />
            {/* Full width under the strip, as on Findings and Hunts. */}
            {search.isError ? null : (
              <Histogram
                // A new window draws afresh: a brush belongs to the window it was drawn on.
                key={`${since}|${until}`}
                all={summary.data}
                failed={failures.data}
                range={range}
                pending={summary.isPending}
                onZoom={(from, to) => run({ since: new Date(from).toISOString(), until: new Date(to).toISOString() })}
              />
            )}
          </>
        }
      />
      <QueryBar ref={bar} q={q} onRun={(next) => run({ q: next })} values={values} />
      {search.isError ? (
        <ErrorNote error={search.error} onRetry={refused ? undefined : () => void search.refetch()} />
      ) : (
        <>
          <div className="sh-layout--rail">
            <div className="min-w-0 max-lg:order-last">
              <FieldRail
                pins={pins}
                tops={tops}
                total={total}
                onPivot={pivot}
                onPin={(field) => {
                  const next = [...pins, field];
                  setPins(next);
                  savePins(next);
                }}
                onUnpin={(field) => {
                  const next = pins.filter((f) => f !== field);
                  setPins(next);
                  savePins(next);
                }}
                adding={adding}
                onAdding={setAdding}
              />
            </div>
            <Card className={search.isPlaceholderData ? "opacity-60" : undefined} aria-busy={search.isFetching || undefined}>
              <Results
                rows={shown}
                rowProps={nav.rowProps}
                loading={search.isPending}
                onRetry={() => void search.refetch()}
                empty={
                  <Empty
                    kind="row"
                    title="No events match"
                    action={
                      short && relativeMs(since) !== null ? (
                        <Button size="sm" onClick={() => run({ since: "7d", until: "" })}>
                          Try 7d
                        </Button>
                      ) : undefined
                    }
                  />
                }
              />
              {rows.length ? (
                <Footer
                  rows={rows}
                  start={(at - 1) * PAGE}
                  shown={shown.length}
                  pages={pages}
                  page={at}
                  onPage={url.setPage}
                  limit={limit}
                  matched={total}
                  truncated={Boolean(search.data?.truncated)}
                  onMore={() => setMore({ key, limit: Math.min(1000, limit + 400) })}
                  sql={search.data?.sql}
                />
              ) : null}
            </Card>
          </div>
        </>
      )}
      {event ? (
        <EventDialog
          key={index >= 0 ? "listed" : event}
          {...(index >= 0 ? { event: rows[index] as EventRow } : { uid: event })}
          onClose={() => url.openEvent("")}
          step={
            index >= 0
              ? {
                  index,
                  total: rows.length,
                  onPrev: index > 0 ? () => openAt(index - 1) : undefined,
                  onNext: index < rows.length - 1 ? () => openAt(index + 1) : undefined,
                }
              : undefined
          }
        />
      ) : null}
    </div>
  );
}
