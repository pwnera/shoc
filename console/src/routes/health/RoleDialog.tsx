/**
 * One crew role: its model tier and model, whether it sits in cases, its
 * messages in the window as a trace (each opens the case on Discussion), and
 * how many of the last 200 audited calls were its own, linking the audit log
 * filtered to it.
 *
 * Capabilities used: none of its own; it reads the Crew tab's rows.
 */
import { Link, useNavigate } from "react-router-dom";
import { Avatar } from "@/components/ui/avatar";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Empty, Label } from "@/components/ui/misc";
import { Trace, type TraceRow } from "@/components/ui/trace";
import { useListNav } from "@/lib/commands";
import { count, shortId } from "@/lib/format";
import type { Step } from "@/lib/popup";
import type { LlmConfig } from "@/types";
import type { RoleRow } from "./model";

/* A trace row per message draws an avatar and a tip; the newest hundred say enough. */
const SHOWN = 100;
/* "light" as Connections › Services names it: the kernel's model for the narrow roles. */
const TIER = { strong: "strong", cheap: "light", code: "code, no model" } as const;

export function RoleDialog({
  row,
  llm,
  step,
  onClose,
}: {
  row: RoleRow;
  llm: LlmConfig | undefined;
  step: Step;
  onClose: () => void;
}) {
  const navigate = useNavigate();
  const { role } = row;
  const model =
    role.tier === "code" ? null : role.tier === "cheap" ? llm?.model_cheap || llm?.model : llm?.model;
  const items: TraceRow[] = row.messages.slice(0, SHOWN).map((e) => {
    const to = String(e.payload.to ?? "");
    return {
      key: String(e.seq),
      kind: String(e.payload.kind ?? "message"),
      author: String(e.payload.agent ?? role.name),
      text: `${shortId(e.subject)}${to ? ` → ${to}` : ""}`,
      time: e.created_at,
    };
  });
  const open = (item: TraceRow) => {
    const e = row.messages.find((m) => String(m.seq) === item.key);
    if (e) navigate(`/cases/${encodeURIComponent(e.subject)}?tab=discussion`);
  };
  const nav = useListNav(items, (i) => i.key, { onOpen: open });

  return (
    <Dialog title={role.name} head={<Avatar who={role.name} size={20} />} step={step} onClose={onClose}>
      <Fields
        ruled
        rows={[
          ["Tier", TIER[role.tier]],
          ["Model", model ? <span className="sh-mono">{model}</span> : null],
          ["In cases", role.inCase ? "yes" : "no"],
          [
            "Calls",
            // No call means an empty audit view: then the count is plain text.
            row.calls.length ? (
              <Link to={`/access?tab=audit&principal=${encodeURIComponent(`agent:${role.name}`)}`} className="sh-mono underline">
                {count(row.calls.length, "call")} of the last 200
                {row.errors ? ` · ${count(row.errors, "error")}` : ""}
              </Link>
            ) : (
              <span className="sh-mono">no call in the last 200</span>
            ),
          ],
        ]}
      />
      <Label>
        {row.messages.length > SHOWN ? `newest ${SHOWN} of ${row.messages.length} messages` : "messages"}
      </Label>
      {items.length ? (
        <div className="max-h-80 overflow-y-auto">
          <Trace items={items} onOpen={open} rowProps={nav.rowProps} label={`${role.name} messages`} />
        </div>
      ) : (
        <Empty title="Nothing in the last 2,000 events" />
      )}
    </Dialog>
  );
}
