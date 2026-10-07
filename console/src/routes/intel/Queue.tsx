/**
 * Intel › Reports › Unread: what the CTI role queued and did not read
 * (RFC 0029), newest change first, 100 at most. A row is its state, the title
 * and when it last changed; it opens a popup (`?queued=<url>`) with why, the
 * score, the report it repeats, the rest of the record and the link, and Read
 * it, which opens the digest dialog on its link (a person's read is never
 * refused, D122). The kernel filters the text.
 *
 * Capabilities used: intel.reports (`state: "queue"`, and the read ones for
 * titles), intel.digest.
 */
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Button, CrewMark } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Empty } from "@/components/ui/misc";
import { Status } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { useListNav } from "@/lib/commands";
import { age, num, shortId, stamp } from "@/lib/format";
import { queueState } from "@/lib/labels";
import { loadError } from "@/lib/loaded";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { focusRow, useFollow, usePopParam, type Step } from "@/lib/popup";
import { useIntelQueue, useIntelReports } from "@/lib/queries";
import type { QueuedReport } from "@/types";
import { LinkChip } from "@/routes/detection/parts";
import { DigestDialog } from "./DigestDialog";
import { feedName, hostOf } from "./feeds";

/** `intel.reports {limit: 100}`: past it the list reads "100+". */
const CAP = 100;

/** "7", "2.5". */
const score = (n: number) => String(Math.round(n * 10) / 10);

function State({ state }: { state: string }) {
  const word = queueState(state);
  return (
    <Status tone={word.tone} badge>
      {word.word}
    </Status>
  );
}

export function Queue({ contains, filtered, onClear }: { contains: string; filtered: boolean; onClear: () => void }) {
  const [params, setParams] = useSearchParams();
  const now = useNow();
  const [reading, setReading] = useState("");
  const queue = useIntelQueue(contains);
  const rows = queue.data?.rows ?? [];
  const paged = usePaged(rows, 25, { cap: CAP });
  const pop = usePopParam("queued");
  const open = (row: QueuedReport | undefined, replace = false) => pop(row && row.url, replace);
  const nav = useListNav(paged.page, (r) => r.url, {
    onOpen: (r) => open(r),
    copy: (r) => r.url,
    onPrevPage: paged.prev,
    onNextPage: paged.next,
  });
  // J and K in the popup move the list's row too.
  useFollow(nav, params.get("queued") ?? "");
  const at = rows.findIndex((r) => r.url === params.get("queued"));

  const columns: Column<QueuedReport>[] = [
    { label: "", fit: true, cell: (r) => <State state={r.state} /> },
    { label: "", strong: true, cell: (r) => r.title || r.url },
    { label: "", fit: true, mono: true, hide: "md", cell: (r) => age(r.changed_at, now) },
  ];

  return (
    <>
      <Table
        columns={columns}
        rows={paged.page}
        rowKey={(r) => r.url}
        rowProps={nav.rowProps}
        loading={queue.isPending}
        error={loadError(queue)}
        onRetry={() => void queue.refetch()}
        label="Unread reports"
        empty={
          filtered ? (
            <Empty kind="filtered" title="No report matches" onClear={onClear} />
          ) : (
            <Empty kind="row" title="Nothing unread" />
          )
        }
      />
      {paged.pager}
      {at >= 0 ? (
        <QueuedDialog
          row={rows[at]!}
          onClose={() => {
            const url = rows[at]!.url;
            open(undefined, true);
            focusRow(url);
          }}
          step={{
            index: at,
            total: rows.length,
            onPrev: at > 0 ? () => open(rows[at - 1], true) : undefined,
            onNext: at < rows.length - 1 ? () => open(rows[at + 1], true) : undefined,
          }}
          onRead={() => setReading(rows[at]!.url)}
        />
      ) : null}
      {reading ? (
        <DigestDialog
          url={reading}
          onClose={() => setReading("")}
          // The report it became opens on Read, where it now is.
          onRead={(uid) => {
            setReading("");
            setParams((current) => {
              const out = new URLSearchParams(current);
              out.delete("queued");
              out.delete("reports");
              out.set("report", uid);
              return out;
            });
          }}
        />
      ) : null}
    </>
  );
}

/** One unread report: where it came from, why it was not read, and the link. A story read already opens that report. */
function QueuedDialog({ row, onClose, step, onRead }: { row: QueuedReport; onClose: () => void; step: Step; onRead: () => void }) {
  const link = hostOf(row.url) ? row.url : "";
  const reports = useIntelReports();
  const same = row.same_as ? reports.data?.rows.find((r) => r.report_uid === row.same_as)?.title : undefined;
  return (
    <Dialog
      title={row.title || row.url}
      size="sm"
      onClose={onClose}
      step={step}
      head={<State state={row.state} />}
      footer={
        <Button variant="crew" onClick={onRead}>
          <CrewMark />
          Read it
        </Button>
      }
    >
      <Fields
        rows={[
          ["source", <span className="sh-mono sh-mono--strong">{feedName(row.source)}</span>],
          ["score", <span className="sh-mono">{score(row.score)}</span>],
          ["reason", row.reason ? <span className="text-fg-2">{row.reason}</span> : null],
          [
            "same as",
            row.same_as ? (
              <LinkChip to={`?tab=reports&report=${encodeURIComponent(row.same_as)}`} value={same ?? shortId(row.same_as)} />
            ) : null,
          ],
          [
            "link",
            link ? (
              <a className="sh-link truncate font-mono text-xs" href={link} target="_blank" rel="noreferrer noopener">
                {link}
              </a>
            ) : null,
          ],
          ["published", row.published_at ? <span className="sh-mono">{stamp(row.published_at)}</span> : null],
          ["queued", <span className="sh-mono">{stamp(row.queued_at)}</span>],
          ["changed", <span className="sh-mono">{stamp(row.changed_at)}</span>],
          ["tokens", row.tokens ? <span className="sh-mono">{num(row.tokens)}</span> : null],
        ]}
      />
    </Dialog>
  );
}
