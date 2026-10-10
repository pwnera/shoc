/**
 * Intel › Reports: the threat reports the CTI role read, newest first, 100 at
 * most, or with Unread (`?reports=unread`) what it queued and did not read
 * (Queue). A read row is a globe with the source host in its tip, the title
 * and when it was read; techniques, indicators and confidence are in the
 * report dialog, which a row opens (`?report=`); a link to one past the
 * newest 100 opens a dialog that says so. Read a report is the tab's action.
 */
import { useState } from "react";
import { Globe } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { Button, CrewMark } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { FilterBar } from "@/components/ui/filterbar";
import { Empty } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { useFilters } from "@/lib/filters";
import { age, shortId } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useParam } from "@/lib/param";
import { focusRow, useFollow, usePopParam } from "@/lib/popup";
import { useSort } from "@/lib/sort";
import type { IntelReport } from "@/types";
import { Queue } from "./Queue";
import { ReportDialog } from "./ReportDialog";

/** `intel.reports {limit: 100}`: past it the list reads "100+". */
const CAP = 100;

/**
 * Reports withdrawn while the console is open. `stored_count` is kept as read
 * and never drops, and this list remounts on every tab switch, so the memory
 * lives outside it.
 */
const withdrawn = new Set<string>();

type Props = {
  reports: IntelReport[];
  loading: boolean;
  /** A refresh in flight: a report just read may be in its answer. */
  fetching?: boolean;
  error: unknown;
  onRetry: () => void;
};

export function Reports({ onRead, ...read }: Props & { onRead: () => void }) {
  const [shown, setShown] = useParam<"read" | "unread">("reports", "read");
  // Its own text parameter, so the Indicators filter never leaks into this tab.
  const filters = useFilters<IntelReport>([], { text: "rq" });

  return (
    <>
      <FilterBar
        dims={[]}
        value={{}}
        onChange={() => {}}
        text={filters.text}
        onText={filters.setText}
        onClear={filters.clear}
        placeholder="Filter reports"
      >
        <Seg
          label="Reports"
          value={shown}
          onChange={setShown}
          options={[
            { value: "read", label: "Read" },
            { value: "unread", label: "Unread" },
          ]}
        />
        <Button size="sm" variant="crew" onClick={onRead}>
          <CrewMark />
          Read a report
        </Button>
      </FilterBar>
      {shown === "unread" ? (
        <Queue contains={filters.text} filtered={filters.active} onClear={filters.clear} />
      ) : (
        <Read {...read} filtered={filters.active} onClear={filters.clear} />
      )}
    </>
  );
}

function Read({
  reports: given,
  loading,
  fetching,
  error,
  onRetry,
  filtered,
  onClear,
}: Props & { filtered: boolean; onClear: () => void }) {
  const now = useNow();
  const [params] = useSearchParams();
  const columns: Column<IntelReport>[] = [
    {
      label: "Source",
      fit: true,
      sort: (r) => r.source_host,
      cell: (r) => (
        <Tip label={r.source_host || "pasted text"} mono>
          <span className="flex items-center" role="img" aria-label={r.source_host || "pasted text"}>
            <Globe className="h-3.5 w-3.5 text-fg-3" aria-hidden />
          </span>
        </Tip>
      ),
    },
    { label: "Title", strong: true, cell: (r) => r.title },
    { label: "Read", fit: true, mono: true, hide: "md", sort: (r) => r.digested_at, cell: (r) => age(r.digested_at, now) },
  ];
  const sorted = useSort(given, columns);
  const reports = sorted.rows;
  const paged = usePaged(reports, 25, { cap: CAP });
  const pop = usePopParam("report");
  const open = (report: IntelReport | undefined, replace = false) => pop(report && report.report_uid, replace);
  const nav = useListNav(paged.page, (r) => r.report_uid, {
    onOpen: (r) => open(r),
    copy: (r) => r.report_uid,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // J and K in the dialog move the list's row too.
  const asked = params.get("report") ?? "";
  useFollow(nav, asked);
  const at = reports.findIndex((r) => r.report_uid === asked);
  const [, redraw] = useState(0);

  return (
    <>
      <Table
        columns={columns}
        rows={paged.page}
        sort={sorted.sort}
        onSort={paged.first}
        rowKey={(r) => r.report_uid}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        label="Reports"
        empty={
          filtered ? (
            <Empty kind="filtered" title="No report matches" onClear={onClear} />
          ) : (
            <Empty kind="row" title="No reports read" />
          )
        }
      />
      {paged.pager}
      {at >= 0 ? (
        // A fresh dialog per report: the graph's expanded chips belong to the report they came from.
        <ReportDialog
          key={reports[at]!.report_uid}
          report={reports[at]!}
          withdrawn={withdrawn.has(reports[at]!.report_uid)}
          onWithdrawn={(uid) => {
            withdrawn.add(uid);
            redraw((n) => n + 1);
          }}
          // Each step mounts a fresh dialog, whose opener is the page: focus goes back to the row it ended on.
          onClose={() => {
            const uid = reports[at]!.report_uid;
            open(undefined, true);
            focusRow(uid);
          }}
          step={{
            index: at,
            total: reports.length,
            onPrev: at > 0 ? () => open(reports[at - 1], true) : undefined,
            onNext: at < reports.length - 1 ? () => open(reports[at + 1], true) : undefined,
          }}
        />
      ) : asked && !loading && !fetching && !error ? (
        // `intel.reports` takes no report id: one past the newest the list holds cannot open here.
        <Dialog title={shortId(asked)} size="sm" onClose={() => open(undefined, true)}>
          <Empty kind="page" title={reports.length >= CAP ? "Not in the newest 100" : "No such report"} />
        </Dialog>
      ) : null}
    </>
  );
}
