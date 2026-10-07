/**
 * A query failed only when it has nothing to show: a failed refresh keeps the
 * rows it had, and the screen says how old they are ("as of 14:02").
 */
type Loaded = { isError: boolean; data: unknown; error: unknown; dataUpdatedAt: number };

/** The error of a load that failed with nothing cached, else undefined. */
export const loadError = (q: Pick<Loaded, "isError" | "data" | "error">) => (q.isError && q.data === undefined ? q.error : undefined);

/** When cached data shows over a failed refresh: the time it is from, else null. */
export const staleSince = (q: Pick<Loaded, "isError" | "data" | "dataUpdatedAt">) =>
  q.isError && q.data !== undefined ? new Date(q.dataUpdatedAt).toISOString() : null;
