/**
 * The structure layer: a page opens with a PageHeader, which carries the
 * screen's state strip; panels (Card) sit under it. Every level has one
 * device, so hierarchy is visible before anything is read.
 */
import { Fragment, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { shortId } from "@/lib/format";
import { place } from "@/lib/nav";
import { Copy } from "./field";

/**
 * A one-line title with its badges, at most one primary control and a ⋯ menu
 * to the right (`aside`), and the state strip above the closing hairline.
 * Crumbs show only on a detail page, where `id` names the record as a chip
 * that copies it; with `copy`, the id is a uid shown short ("CASE-172f…").
 * The heading takes focus after a route change (the shell moves it there).
 */
export function PageHeader({
  title,
  id,
  copy,
  badges,
  aside,
  strip,
}: {
  title: ReactNode;
  id?: string;
  /** `id` is a uid: the crumb shows it short and copies the whole. */
  copy?: boolean;
  badges?: ReactNode;
  aside?: ReactNode;
  strip?: ReactNode;
}) {
  const where = place(useLocation().pathname);
  const crumbs: { label: string; to?: string }[] =
    id && where ? [{ label: where.screen.toLowerCase(), to: where.to }, { label: id }] : [];

  return (
    <header className="sh-page">
      {crumbs.length ? (
        <nav aria-label="Breadcrumb" className="sh-page__crumbs">
          {crumbs.map((crumb, index) => (
            <Fragment key={index}>
              {index ? <i aria-hidden>/</i> : null}
              {crumb.to ? (
                <Link to={crumb.to}>{crumb.label}</Link>
              ) : (
                <span aria-current="page" className="min-w-0">
                  <Copy value={crumb.label} label={`Copy ${crumb.label}`}>
                    {copy ? shortId(crumb.label) : crumb.label}
                  </Copy>
                </span>
              )}
            </Fragment>
          ))}
        </nav>
      ) : null}
      <div className="sh-page__row">
        <h1 className="sh-page__title" tabIndex={-1}>
          {title}
        </h1>
        {badges ? <div className="sh-page__badges">{badges}</div> : null}
        {aside ? <div className="sh-page__actions">{aside}</div> : null}
      </div>
      {strip}
    </header>
  );
}
