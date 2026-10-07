import { useState, type ReactNode } from "react";
import { useNavigationType } from "react-router-dom";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tip } from "@/components/ui/tip";
import { num } from "./format";

/**
 * One page of a long list, and the footer that turns it. A list longer than a
 * page ends in the footer, in one grammar: "1–25 of 182" (or `of`, such as
 * "of 30 groups · 69 pages"), "of newest 200" for the newest slice of a longer
 * list (`newest`), or "of 500+" when the list came back at the kernel's cap,
 * the reason in the count's tip. A list that fits one page draws no footer: its tab or title
 * already counts it, unless the list was cut. The page is clamped rather than reset, so a
 * live refresh or a narrower filter never jumps the reader back to the top;
 * `first` does, for a "N new" pill. `start` is the page's first position in
 * the whole list; `prev` and `next` are what `[` and `]` call. Pass `page` and
 * `onPage` to keep the page in the URL. Otherwise the page is remembered per
 * URL, so Back to a list whose row opened a page lands on that row's page, and
 * `useListNav` focuses the row again.
 */
/** The page each list was turned to, by history entry, URL and page size ("" outside the browser's history). */
const turned = new Map<string, number>();
const spot = (size: number) => {
  const idx = (window.history.state as { idx?: number } | null)?.idx;
  return idx === undefined ? "" : `${idx}:${window.location.pathname}${window.location.search}#${size}`;
};

export function usePaged<T>(
  rows: T[],
  size = 25,
  opts: {
    cap?: number;
    /** The rows are the newest of a longer list: "of 500 newest". With `cap`, only once the list reaches it. */
    newest?: boolean;
    /** A controlled page index (from the URL), with `onPage` to change it. */
    page?: number;
    onPage?: (index: number) => void;
    /** What the footer counts when rows are not the unit read: "30 groups · 69 pages". */
    of?: ReactNode;
  } = {},
): {
  page: T[];
  pager: ReactNode;
  start: number;
  prev: () => void;
  next: () => void;
  first: () => void;
  /** Turn to a page by index (a dialog's step past the page edge). */
  go: (index: number) => void;
  /** The page shown, from 0, after clamping. */
  at: number;
  pages: number;
} {
  const back = useNavigationType() === "POP";
  const [own, setOwn] = useState(() => (back ? (turned.get(spot(size)) ?? 0) : 0));
  const index = opts.page ?? own;
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const at = Math.max(0, Math.min(index, pages - 1));
  const go = (n: number) => {
    const to = Math.max(0, Math.min(pages - 1, n));
    if (opts.onPage) return opts.onPage(to);
    if (spot(size)) turned.set(spot(size), to);
    setOwn(to);
  };
  const start = at * size;
  const page = rows.slice(start, start + size);
  const atCap = opts.cap !== undefined && rows.length >= opts.cap;
  const cut = atCap || (opts.newest && opts.cap === undefined);
  // The newest slice says so in words, as Explore's footer does; a list at the kernel's cap reads "500+".
  const total =
    opts.of ??
    (opts.newest && cut ? (
      `newest ${num(rows.length)}`
    ) : cut ? (
      <Tip label={`shoc returns ${num(opts.cap!)} at most`}>
        <span tabIndex={0}>{num(atCap ? opts.cap! : rows.length)}+</span>
      </Tip>
    ) : (
      num(rows.length)
    ));
  const prev = () => go(at - 1);
  const next = () => go(at + 1);
  const first = () => go(0);
  const pager = pages > 1 || (cut && rows.length) ? (
    <div className="sh-pager">
      <span className="sh-pager__range">
        <b>
          {start + 1}–{start + page.length}
        </b>{" "}
        of {total}
      </span>
      {pages > 1 ? (
        <>
          <Button variant="ghost" size="sm" disabled={at === 0} onClick={prev} aria-label="Previous page">
            <ChevronLeft aria-hidden />
          </Button>
          <Button variant="ghost" size="sm" disabled={at === pages - 1} onClick={next} aria-label="Next page">
            <ChevronRight aria-hidden />
          </Button>
        </>
      ) : null}
    </div>
  ) : null;
  return { page, pager, start, prev, next, first, go, at, pages };
}
