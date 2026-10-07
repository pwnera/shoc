/**
 * Waiting and failing without lying. A skeleton keeps the content's shape
 * (it appears after 150ms, no shimmer); QueryState walks skeleton → error with
 * Retry → empty → content, and never shows the empty state, a zero or an all
 * clear when any of its queries failed.
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { ErrorNote } from "./misc";

export function Skel({
  kind = "text",
  width,
  className,
}: {
  kind?: "text" | "badge" | "fact" | "block" | "row";
  width?: number | string;
  className?: string;
}) {
  return (
    <span
      className={cn("sh-skel", `sh-skel--${kind}`, className)}
      style={width !== undefined ? { width } : undefined}
      aria-hidden
    />
  );
}

/** What QueryState reads from a TanStack query. */
export type QueryLike = {
  isPending: boolean;
  isError: boolean;
  error: unknown;
  refetch: () => unknown;
};

function Rows() {
  return (
    <div className="flex flex-col gap-3 p-3">
      <Skel kind="row" width="62%" />
      <Skel kind="row" width="48%" />
      <Skel kind="row" width="55%" />
    </div>
  );
}

/** A screen whose code is still loading: a title, a strip and a panel of rows, inside the shell. */
export function PageSkeleton() {
  return (
    <div className="flex flex-col gap-4" aria-busy="true">
      <span role="status" className="sr-only">
        loading
      </span>
      <div className="sh-page">
        <div className="sh-page__row">
          <Skel kind="text" width={240} />
        </div>
        <div className="sh-strip">
          <Skel kind="fact" />
          <Skel kind="fact" />
          <Skel kind="fact" />
        </div>
      </div>
      <div className="sh-card">
        <Rows />
      </div>
    </div>
  );
}

export function QueryState({
  queries,
  skeleton,
  empty,
  isEmpty,
  children,
}: {
  queries: QueryLike | QueryLike[];
  /** Defaults to three skeleton rows. */
  skeleton?: ReactNode;
  empty?: ReactNode;
  /** Whether the loaded data is empty; only then is `empty` shown. */
  isEmpty?: boolean;
  /** A function renders only once every query answered. */
  children: ReactNode | (() => ReactNode);
}) {
  const list = Array.isArray(queries) ? queries : [queries];
  const failed = list.filter((q) => q.isError);
  if (failed.length)
    return (
      <ErrorNote
        error={failed[0]!.error}
        onRetry={() => {
          for (const q of failed) void q.refetch();
        }}
      />
    );
  if (list.some((q) => q.isPending))
    return (
      <div aria-busy="true">
        <span role="status" className="sr-only">
          loading
        </span>
        {skeleton ?? <Rows />}
      </div>
    );
  if (isEmpty && empty !== undefined) return <>{empty}</>;
  return <>{typeof children === "function" ? children() : children}</>;
}
