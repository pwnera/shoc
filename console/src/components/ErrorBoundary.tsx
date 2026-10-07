/**
 * A screen that throws while rendering takes only itself down: the shell, the
 * rail and the crew chat stay, and the page says so with Reload and the error
 * to copy. The shell resets it by path, so moving to another screen recovers.
 * `quiet` guards a floating layer (a dialog, the palette, the chat): it simply
 * goes away rather than blanking the console. A chunk that will not load is a
 * redeploy, not a bug: the tab reloads once onto the new build.
 */
import { Component, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { reloadForNewBuild, STALE } from "@/lib/stale";
import { useDocumentTitle } from "@/lib/title";
import { Button } from "./ui/button";
import { Copy } from "./ui/field";
import { Empty } from "./ui/misc";
import { PageHeader } from "./ui/page";

type Props = {
  children: ReactNode;
  quiet?: boolean;
  /** A new value clears the error (the URL changed), without remounting what did not fail. */
  resetKey?: string;
};

export class ErrorBoundary extends Component<Props, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: unknown) {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: unknown) {
    if (error instanceof Error && STALE.test(error.message)) reloadForNewBuild();
  }

  componentDidUpdate(previous: Props) {
    if (this.state.error && previous.resetKey !== this.props.resetKey) this.setState({ error: null });
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.quiet) return null;
    return (
      <div className="flex flex-col items-center gap-3">
        <Empty
          kind="page"
          title="This screen failed"
          action={
            <Button size="sm" onClick={() => location.reload()}>
              Reload
            </Button>
          }
        />
        <Copy
          block
          className="max-w-xl"
          value={`${error.name}: ${error.message}${error.stack ? `\n${error.stack}` : ""}`}
          label="Copy the error"
        >
          {`${error.name}: ${error.message}`}
        </Copy>
      </div>
    );
  }
}

/** The 404: the page's heading (which takes focus on arrival, as every screen's does) and the way back. */
export function NotFound() {
  useDocumentTitle("No such screen");
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="No such screen" />
      <Link to="/" className="sh-btn sh-btn--default sh-btn--sm self-start">
        Overview
      </Link>
    </div>
  );
}
