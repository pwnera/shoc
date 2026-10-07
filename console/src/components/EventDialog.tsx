/**
 * One event, the home of every field it has: the operation, its outcome and
 * time, the key facts with pivots into Explore (+ and − over the event's hour,
 * or into the running query when already on Explore), then the rest of the
 * stored row under the OCSF paths Explore takes (Fields), or the record as the
 * vendor sent it (Raw). Fields leaves out what the head and the facts already
 * say and the kernel's own plumbing; Raw keeps everything. Opened from a row, a
 * citation, a toast or `?event=<uid>`; a row without its original record
 * fetches it on open.
 *
 * Capabilities used: events.query (by event_uid, with the raw record).
 */
import { useMemo, useState, type ReactNode } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { age, stamp } from "@/lib/format";
import { addTerm, around, exploreHref, fieldPath, fieldWord, term } from "@/lib/explore";
import { useNow } from "@/lib/now";
import { useEvents } from "@/lib/queries";
import type { EventRow } from "@/types";
import { Dialog, Fields, Json, type Pivot } from "./ui/dialog";
import { Copy, CopyButton } from "./ui/field";
import { ProductLogo } from "./ui/logo";
import { Empty, ErrorNote, Input, Switch } from "./ui/misc";
import { Seg } from "./ui/seg";
import { Skel } from "./ui/state";
import { Status } from "./ui/status";

type View = "fields" | "raw";
const VIEW = "shoc.event.view";

/** The facts worth a pivot: label, stored column, query field; the label is the path's one word. */
const FACTS: [string, keyof EventRow & string, string][] = (
  [
    ["actor_user_name", "actor.user.name"],
    ["src_endpoint_ip", "src_endpoint.ip"],
    ["api_operation", "api.operation"],
    ["resource_uid", "resource.uid"],
    ["cloud_account_uid", "cloud.account.uid"],
    ["cloud_region", "cloud.region"],
  ] as const
).map(([column, path]) => [fieldWord(path), column, path]);

const EMPTY = new Set(["", "-", "null", "none", "unknown", "n/a"]);

/** Storage the reader never needs here: the tenant, numeric class ids, the schema version, observables, the ingest stamp. */
const PLUMBING = new Set([
  "tenant_id",
  "ingested_at",
  "class_uid",
  "category_uid",
  "type_uid",
  "activity_id",
  "severity_id",
  "metadata_version",
  "metadata_profiles",
  "observables",
]);

/** Already above the list: the id chip, the head's status and time, the facts. */
const SHOWN = new Set(["event_uid", "status", "time", ...FACTS.map(([, column]) => column)]);

/** The rest of the stored row as OCSF paths: no raw record, no empty or placeholder values, `unmapped` unfolded. */
function flatten(row: EventRow): [string, string][] {
  const out: [string, string][] = [];
  const walk = (prefix: string, value: unknown) => {
    if (value === null || value === undefined) return;
    if (typeof value === "object" && !Array.isArray(value)) {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) walk(prefix ? `${prefix}.${k}` : k, v);
      return;
    }
    const text = typeof value === "string" ? value : JSON.stringify(value);
    if (Array.isArray(value) && !value.length) return;
    if (EMPTY.has(text.trim().toLowerCase())) return;
    out.push([prefix, text]);
  };
  for (const [key, value] of Object.entries(row)) {
    if (key === "raw" || PLUMBING.has(key) || SHOWN.has(key)) continue;
    if (key === "unmapped" && typeof value === "string") {
      try {
        walk(key, JSON.parse(value));
        continue;
      } catch {
        /* kept as text */
      }
    }
    walk(fieldPath(key), value);
  }
  return out;
}

function savedView(): View {
  try {
    return localStorage.getItem(VIEW) === "raw" ? "raw" : "fields";
  } catch {
    return "fields";
  }
}

export function EventDialog({
  event,
  uid,
  onClose,
  step,
}: {
  /** The row that opened it; its raw record is fetched when missing. */
  event?: EventRow;
  /** Or only the id, from `?event=` or a citation. */
  uid?: string;
  onClose: () => void;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
}) {
  const id = String(event?.event_uid ?? uid ?? "");
  const full = useEvents(event?.raw === undefined && id ? [id] : [], true);
  const row: EventRow | undefined = full.data?.rows[0] ?? event;
  const [view, setView] = useState<View>(savedView);
  const now = useNow();

  const pick = (next: View) => {
    setView(next);
    try {
      localStorage.setItem(VIEW, next);
    } catch {
      /* kept for this dialog */
    }
  };

  const op = String(row?.api_operation ?? row?.activity_name ?? row?.class_name ?? "event");
  const title: ReactNode = row ? (
    <span className="inline-flex min-w-0 items-center gap-2">
      <ProductLogo product={row.metadata_product} size={16} named />
      <span className="truncate">{op}</span>
    </span>
  ) : (
    "Event"
  );
  const head = row ? (
    <>
      {row.status ? (
        <Status tone={row.status === "Success" ? "good" : row.status === "Failure" ? "bad" : "idle"} badge>
          {row.status === "Failure" ? "failed" : String(row.status).toLowerCase()}
        </Status>
      ) : null}
      <span className="sh-mono shrink-0">
        {stamp(String(row.time))} <span className="text-fg-4">· {age(String(row.time), Math.max(now, Date.now()))}</span>
      </span>
    </>
  ) : null;

  let body: ReactNode;
  if (!row && full.isError) body = <ErrorNote error={full.error} onRetry={() => void full.refetch()} />;
  else if (!row && (full.isPending || full.isFetching)) body = <Loading />;
  else if (!row) body = <Empty kind="page" title="No longer in the store" />;
  else
    body = (
      <>
        <Copy value={id} label="Copy event id" className="self-start" />
        <Facts row={row} onClose={onClose} />
        <div className="flex items-center gap-2">
          <Seg<View>
            label="View"
            value={view}
            options={[
              { value: "fields", label: "Fields" },
              { value: "raw", label: "Raw" },
            ]}
            onChange={pick}
          />
        </div>
        {view === "fields" ? (
          <AllFields row={row} />
        ) : row.raw === undefined && full.isPending ? (
          <Loading />
        ) : row.raw === undefined && full.isError ? (
          <ErrorNote error={full.error} onRetry={() => void full.refetch()} />
        ) : (
          <Raw value={row.raw} />
        )}
      </>
    );

  return (
    <Dialog title={title} head={head} onClose={onClose} size="wide" step={step}>
      {body}
    </Dialog>
  );
}

function Loading() {
  return (
    <div className="flex flex-col gap-3" aria-busy="true">
      <span role="status" className="sr-only">
        loading
      </span>
      <Skel kind="row" width="40%" />
      <Skel kind="row" width="70%" />
      <Skel kind="row" width="55%" />
    </div>
  );
}

/** Actor, IP, operation, resource, account, region, each with + − and copy. */
function Facts({ row, onClose }: { row: EventRow; onClose: () => void }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [params] = useSearchParams();
  const pivot = (field: string, value: string, op: "=" | "!="): void => {
    const next = term(field, value, op);
    if (pathname === "/explore") {
      const out = new URLSearchParams(params);
      const q = addTerm(out.get("q") ?? "", next);
      // The term is in the query already: closing is all there is to do, so no history entry repeats it.
      if (q === (out.get("q") ?? "").trim()) return onClose();
      out.set("q", q);
      // A new query starts on its first page, with no event open.
      out.delete("event");
      out.delete("page");
      onClose();
      navigate({ search: `?${out.toString()}` });
      return;
    }
    navigate(exploreHref({ q: next, ...around(String(row.time)) }));
  };
  const rows = FACTS.flatMap(([label, column, field]): [string, ReactNode, Pivot][] => {
    const value = row[column];
    if (value === null || value === undefined || value === "") return [];
    const text = String(value);
    return [
      [
        label,
        <span className="sh-mono sh-mono--strong">{text}</span>,
        { in: () => pivot(field, text, "="), out: () => pivot(field, text, "!="), copy: text },
      ],
    ];
  });
  if (!rows.length) return null;
  return <Fields rows={rows} ruled />;
}

/** Every stored field, filterable. */
function AllFields({ row }: { row: EventRow }) {
  const [filter, setFilter] = useState("");
  const all = useMemo(() => flatten(row), [row]);
  const wanted = filter.trim().toLowerCase();
  const shown = wanted ? all.filter(([k, v]) => k.toLowerCase().includes(wanted) || v.toLowerCase().includes(wanted)) : all;
  return (
    <div className="flex flex-col gap-2">
      <Input small value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter fields" aria-label="Filter fields" />
      {shown.length ? (
        <dl className="sh-fields sh-fields--ruled">
          {shown.map(([key, value]) => (
            <div key={key} className="contents">
              <dt className="!normal-case !tracking-normal font-mono">{key}</dt>
              <dd className="is-mono">{value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <Empty kind="filtered" title="No field matches" onClear={() => setFilter("")} />
      )}
    </div>
  );
}

/** The vendor's record: wrap on or off, and copy. */
function Raw({ value }: { value: unknown }) {
  const [wrap, setWrap] = useState(false);
  if (value === undefined || value === null) return <Empty title="No original record kept" />;
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3">
        <Switch checked={wrap} onChange={setWrap}>
          Wrap
        </Switch>
        <span className="ml-auto inline-flex sh-fields__pivot !opacity-100">
          <CopyButton value={text} label="Copy the record" />
        </span>
      </div>
      <div className={wrap ? "[&_.sh-json]:whitespace-pre-wrap [&_.sh-json]:break-all" : undefined}>
        <Json value={value} />
      </div>
    </div>
  );
}
