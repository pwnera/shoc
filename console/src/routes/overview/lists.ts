/**
 * The lists the inbox is built from, the ones that failed with nothing to show
 * and, when a refresh failed, how old the rows are. Overview's heading and the
 * inbox read the same answer, so a refresh that failed but kept its rows reads
 * as those rows in both, never as "Can't tell".
 */
import type { Needs } from "@/lib/needs";
import { useActionLog, useCaseLog, useProposals, useSourceList } from "@/lib/queries";

export function useInboxLists(needs: Needs) {
  const lists = { approvals: useProposals(), actions: useActionLog(), cases: useCaseLog(), sources: useSourceList() };
  const failed = needs.failed as (keyof typeof lists)[];
  const stale = Object.values(lists).filter((q) => q.isRefetchError);
  const asOf = stale.length ? new Date(Math.min(...stale.map((q) => q.dataUpdatedAt))).toISOString() : null;
  return { lists, failed, asOf };
}
