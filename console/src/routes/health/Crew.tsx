/**
 * Health › Crew: one row per role with what it is doing (working, idle, down
 * when the model fails, silent when an in-case role says nothing while cases
 * talk, errors when its recent tool calls failed) and when it last acted.
 * Live presence stays in the top bar's pulse; this tab is the history behind
 * it. The model the crew runs on has its home on Connections › Services. A
 * row opens the role dialog (`?role=`).
 *
 * Capabilities used: llm.show (a role's model, in its dialog), stream.tail
 * (the last 2,000 events' openspace messages), health.audit (the last 200
 * calls), ops.alerts.
 */
import { Avatar } from "@/components/ui/avatar";
import { Status, type StatusTone } from "@/components/ui/status";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { useListNav } from "@/lib/commands";
import { age } from "@/lib/format";
import { useNow } from "@/lib/now";
import { useFollow, useOpen } from "@/lib/popup";
import { usePresence } from "@/lib/presence";
import { useAlerts, useAudit, useCrewWindow, useLlm } from "@/lib/queries";
import { useSort } from "@/lib/sort";
import { roleRows, type RoleRow, type RoleState } from "./model";
import { RoleDialog } from "./RoleDialog";

const TONE: Record<RoleState, StatusTone> = { working: "running", idle: "idle", down: "bad", silent: "warn", errors: "warn" };

export function Crew() {
  const llm = useLlm();
  const tail = useCrewWindow();
  const audit = useAudit({ limit: 200 });
  const alerts = useAlerts();
  const presence = usePresence();
  const now = useNow();
  const modelDown = presence.down || (alerts.data?.alerts ?? []).some((a) => a.kind === "llm.failing");
  const roles = roleRows(
    tail.data?.events ?? [],
    audit.data?.recent ?? [],
    new Set(presence.roles.map((r) => r.who.key)),
    modelDown,
  );
  const columns: Column<RoleRow>[] = [
    {
      label: "",
      width: 36,
      truncate: false,
      cell: (r) => (
        <Avatar
          who={r.role.name}
          size={20}
          presence={r.state === "working" ? "working" : r.state === "down" ? "down" : "idle"}
        />
      ),
    },
    {
      label: "State",
      fit: true,
      cell: (r) => (
        <Status tone={TONE[r.state]} badge>
          {r.state}
        </Status>
      ),
    },
    { label: "Role", strong: true, cell: (r) => r.role.name },
    {
      label: "Last",
      width: 72,
      sort: (r) => r.last,
      align: "right",
      truncate: false,
      cell: (r) =>
        r.last ? (
          <span className="sh-mono">{age(r.last, now)}</span>
        ) : (
          <Tip label="Not in the last 2,000 events or 200 calls">
            <span className="sh-mono" tabIndex={-1}>
              —
            </span>
          </Tip>
        ),
    },
  ];
  const sorted = useSort(roles, columns);
  const rows = sorted.rows;
  const dialog = useOpen("role", rows.map((r) => r.role.name));
  const nav = useListNav(rows, (r) => r.role.name, { onOpen: (r) => dialog.open(r.role.name) });
  useFollow(nav, dialog.value);
  const picked = rows[dialog.at];

  return (
    <>
      <Table
        label="Crew roles"
        columns={columns}
        rows={rows}
        sort={sorted.sort}
        rowKey={(r) => r.role.name}
        rowProps={nav.rowProps}
        loading={tail.isPending || audit.isPending}
        error={tail.isLoadingError ? tail.error : audit.isLoadingError ? audit.error : undefined}
        onRetry={() => void Promise.all([tail.refetch(), audit.refetch()])}
      />
      {picked ? (
        <RoleDialog key={picked.role.name} row={picked} llm={llm.data} step={dialog.step} onClose={dialog.close} />
      ) : null}
    </>
  );
}
