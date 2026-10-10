/**
 * The case's findings: severity, title, when each was first seen (the entity is the case's).
 * `case.get` carries the worst 50; the pager says so when the case holds more.
 * A row opens the finding's page, where J and K step through these rows and
 * Escape comes back here.
 *
 * Capabilities used: none (`case.get`, read by the page).
 */
import { useLocation, useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { age, num } from "@/lib/format";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { SEVERITIES } from "@/lib/labels";
import { useSort } from "@/lib/sort";
import type { CaseFinding } from "@/types";

const PAGE = 25;

export function FindingsTab({ findings, total }: { findings: CaseFinding[]; total: number }) {
  const navigate = useNavigate();
  const location = useLocation();
  const now = useNow();
  const columns: Column<CaseFinding>[] = [
    {
      label: "Severity",
      fit: true,
      sort: (f) => SEVERITIES.indexOf(f.severity),
      cell: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      label: "Title",
      strong: true,
      truncate: false,
      // Every finding names the case's entity, which the header shows once.
      cell: (f) => <span className="block truncate">{f.title}</span>,
    },
    { label: "Seen", width: 72, align: "right", mono: true, sort: (f) => f.first_seen, cell: (f) => age(f.first_seen, now) },
  ];
  const sorted = useSort(findings, columns);
  const rows = sorted.rows;
  const paged = usePaged(rows, PAGE);
  const uids = rows.map((f) => f.finding_uid);
  const nav = useListNav(paged.page, (f) => f.finding_uid, {
    onOpen: (f) =>
      navigate(`/findings/${encodeURIComponent(f.finding_uid)}`, {
        state: { uids, index: uids.indexOf(f.finding_uid), back: `${location.pathname}${location.search}` },
      }),
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  const capped = findings.length < total;
  const last = paged.start + paged.page.length;

  return (
    <>
      <Table
        columns={columns}
        rows={paged.page}
        sort={sorted.sort}
        onSort={paged.first}
        rowKey={(f) => f.finding_uid}
        rowProps={nav.rowProps}
        empty="No findings"
        label="Findings"
      />
      {capped ? (
        <div className="sh-pager">
          <span className="sh-pager__range">
            <b>
              {paged.start + 1}–{last}
            </b>{" "}
            · worst {num(findings.length)} of {num(total)}
          </span>
          {findings.length > PAGE ? (
            <>
              <Button variant="ghost" size="sm" disabled={paged.start === 0} onClick={paged.prev} aria-label="Previous page">
                <ChevronLeft aria-hidden />
              </Button>
              <Button variant="ghost" size="sm" disabled={last >= findings.length} onClick={paged.next} aria-label="Next page">
                <ChevronRight aria-hidden />
              </Button>
            </>
          ) : null}
        </div>
      ) : (
        paged.pager
      )}
    </>
  );
}
