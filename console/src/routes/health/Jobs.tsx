/**
 * Health › Jobs: what the worker gave up on in the window (24h by default, so
 * it agrees with the Worker stage), overdue schedules first. The kernel groups
 * failures by their whole error string, so one failure whose message carries a
 * changing tail splits; here a group is a kind and an error class. A kind
 * reads in words ("daily hunts"), its id in a tip. A row opens the job dialog
 * (`?job=`): the errors in full and the screen that owns the kind. There is no
 * Retry: the job's subject is not a field.
 *
 * Capabilities used: health.jobs, health.status (overdue schedules).
 */
import { Link } from "react-router-dom";
import { Bot, Crosshair, Globe, Plug, Telescope, Timer, type LucideIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { CardToolbar } from "@/components/ui/card";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Empty } from "@/components/ui/misc";
import { Seg } from "@/components/ui/seg";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { age, num, stamp } from "@/lib/format";
import { jobWord } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { useFollow, useOpen, type Step } from "@/lib/popup";
import { WINDOWS, type Days, type JobGroup } from "./model";

const FAMILY: Record<string, LucideIcon> = {
  source: Plug,
  mapping: Plug,
  intel: Globe,
  detect: Crosshair,
  detection: Crosshair,
  rule: Crosshair,
  hunt: Telescope,
};
const OWNER: Record<string, { to: string; label: string }> = {
  source: { to: "/connections", label: "Connections" },
  intel: { to: "/intel", label: "Intel" },
  hunt: { to: "/hunts", label: "Hunts" },
  detect: { to: "/detection", label: "Detection" },
  detection: { to: "/detection", label: "Detection" },
};
const prefix = (kind: string) => kind.split(".")[0] ?? kind;
const upper = (words: string) => words.charAt(0).toUpperCase() + words.slice(1);

export function Jobs({
  groups,
  days,
  onDays,
  loading,
  error,
  onRetry,
}: {
  groups: JobGroup[];
  days: Days;
  onDays: (days: Days) => void;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const now = useNow();
  const dialog = useOpen("job", groups.map((g) => g.key));
  const { page, pager, start, prev, next } = usePaged(groups);
  const nav = useListNav(page, (g) => g.key, { onOpen: (g) => dialog.open(g.key), onPrevPage: prev, onNextPage: next });
  useFollow(nav, dialog.value);
  const shown = WINDOWS.find((w) => w.value === days)?.label ?? "24h";
  const picked = groups[dialog.at];

  const columns: Column<JobGroup>[] = [
    {
      label: "",
      width: 28,
      truncate: false,
      cell: (g) => {
        const Icon = g.overdue ? Timer : (FAMILY[prefix(g.kind)] ?? Bot);
        return <Icon className={g.overdue ? "h-3.5 w-3.5 text-bad" : "h-3.5 w-3.5 text-fg-3"} aria-hidden />;
      },
    },
    {
      label: "",
      fit: true,
      cell: (g) => <Badge tone={g.overdue ? "bad" : "muted"}>{g.cls}</Badge>,
    },
    {
      label: "",
      cell: (g) => (
        <>
          <Tip label={g.kind}>
            <span className={g.overdue ? "text-bad" : "text-fg-1"}>
              {g.overdue ? `schedule overdue: ${jobWord(g.kind)}` : jobWord(g.kind)}
            </span>
          </Tip>
          {g.overdue ? null : <span className="sh-mono text-fg-4"> ×{num(g.jobs)}</span>}
        </>
      ),
    },
    { label: "", width: 64, align: "right", mono: true, cell: (g) => (g.last_at ? age(g.last_at, now) : "") },
  ];

  return (
    <>
      <CardToolbar>
        <Seg label="Window" value={days} onChange={onDays} options={WINDOWS} />
      </CardToolbar>
      <Table
        label="Failed jobs"
        columns={columns}
        rows={page}
        start={start}
        rowKey={(g) => g.key}
        rowProps={nav.rowProps}
        loading={loading}
        error={error}
        onRetry={onRetry}
        empty={<Empty kind="clear" title={`No failed jobs in ${shown}`} />}
      />
      {pager}
      {picked ? (
        <JobDialog key={picked.key} group={picked} step={dialog.step} onClose={dialog.close} />
      ) : null}
    </>
  );
}

function JobDialog({
  group,
  step,
  onClose,
}: {
  group: JobGroup;
  step: Step;
  onClose: () => void;
}) {
  const owner = OWNER[prefix(group.kind)];
  return (
    <Dialog
      title={
        <Tip label={group.kind}>
          <span>{group.overdue ? `Schedule overdue: ${jobWord(group.kind)}` : upper(jobWord(group.kind))}</span>
        </Tip>
      }
      head={<Badge tone={group.overdue ? "bad" : "muted"}>{group.cls}</Badge>}
      step={step}
      onClose={onClose}
      footer={
        owner ? (
          <Link to={owner.to} className="sh-btn sh-btn--default sh-btn--md">
            Open {owner.label}
          </Link>
        ) : null
      }
    >
      <Fields
        ruled
        rows={[
          ["Jobs", group.overdue ? null : num(group.jobs)],
          ["Last", group.last_at ? `${stamp(group.last_at)} · ${age(group.last_at)}` : null],
        ]}
      />
      {group.errors.map((error) => (
        <pre key={error} className="sh-code m-0 whitespace-pre-wrap">
          {error}
        </pre>
      ))}
    </Dialog>
  );
}
