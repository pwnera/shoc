/**
 * One decision, from any screen (`?decide=<action_uid>`): the full approval
 * card with its facts, countdown and fallback. A decided action opens settled
 * ("approved by jane · 14:05", "fell back to Sign Okta user out"), never a dead
 * page. A and R reach the card's confirms; on a phone the card puts Reject |
 * Approve at the foot of the sheet. A failed list says so, never "not found".
 *
 * Capabilities used: action.list (the row, from the shared logs), case.list
 * (its case), policy.show (its autonomy), action.approve and action.reject
 * through the card.
 */
import { useRef } from "react";
import { useCommand } from "@/lib/commands";
import { useActionLog, useCaseLog, usePolicy, useProposals } from "@/lib/queries";
import { ApprovalCard, type ApprovalHandle } from "./ui/approval";
import { Dialog } from "./ui/dialog";
import { Empty, ErrorNote } from "./ui/misc";
import { Skel } from "./ui/state";

export function ApprovalDialog({ uid, onClose }: { uid: string; onClose: () => void }) {
  const proposals = useProposals();
  const log = useActionLog();
  const cases = useCaseLog();
  const policy = usePolicy();
  const card = useRef<ApprovalHandle>(null);
  const action =
    proposals.data?.rows.find((a) => a.action_uid === uid) ?? log.data?.rows.find((a) => a.action_uid === uid);
  const open = action?.state === "proposed";
  useCommand("decide.approve", () => card.current?.approve(), open);
  useCommand("decide.reject", () => card.current?.reject(), open);

  const caseRow = action?.case_uid ? cases.data?.rows.find((c) => c.case_uid === action.case_uid) : undefined;
  const autonomy = action ? policy.data?.data.actions[action.type]?.autonomy : undefined;

  return (
    // The card heads itself with the action's name; the dialog only says what it is for.
    <Dialog title="Decision" id={uid} onClose={onClose}>
      {action ? (
        <ApprovalCard
          ref={card}
          action={action}
          caseRow={caseRow ?? null}
          autonomy={typeof autonomy === "string" ? autonomy : undefined}
          pair
        />
      ) : proposals.isPending || log.isPending ? (
        <Skel kind="block" />
      ) : proposals.isError || log.isError ? (
        <ErrorNote
          error={proposals.error ?? log.error}
          onRetry={() => {
            void proposals.refetch();
            void log.refetch();
          }}
        />
      ) : (
        <Empty kind="page" title="Not among the latest 500 actions" />
      )}
    </Dialog>
  );
}
