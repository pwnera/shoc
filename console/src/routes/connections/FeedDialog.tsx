/**
 * One threat feed (`?feed=<name>`): whether the worker polls it, its last
 * pull, its last error in full, how many indicators it holds, and Pull now
 * (`intel.refresh {feed}`). A report source also counts its day:
 * reports read, their tokens, and its queue by state (RFC 0029). The switch
 * (`intel.configure`) sends the feed's parser and settings back unchanged,
 * since the capability overwrites whatever is left out; a token without the
 * deployer scope sees the refusal.
 */
import type { ReactNode } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, Fields } from "@/components/ui/dialog";
import { ErrorNote, Spinner, Switch } from "@/components/ui/misc";
import { Status } from "@/components/ui/status";
import { ago, num, stamp } from "@/lib/format";
import { feedState, QUEUE_STATES } from "@/lib/labels";
import type { Step } from "@/lib/popup";
import { useConfigureFeed, useRefreshIntel } from "@/lib/queries";
import type { IntelFeed } from "@/types";
import { feedName, isReportSource } from "../intel/feeds";

export function FeedDialog({ feed, step, onClose }: { feed: IntelFeed; step?: Step; onClose: () => void }) {
  const configure = useConfigureFeed();
  const refresh = useRefreshIntel();
  const state = feedState(feed);
  const rows: [string, ReactNode][] = [
    ["last pull", <span className="sh-mono">{feed.last_ok_at ? `${ago(feed.last_ok_at)} · ${stamp(feed.last_ok_at)}` : "never"}</span>],
    ["indicators", <span className="sh-mono sh-mono--strong">{feed.indicators.toLocaleString()}</span>],
  ];
  if (isReportSource(feed))
    rows.push(
      ["read today", <span className="sh-mono sh-mono--strong">{num(feed.read_today ?? 0)}</span>],
      ["tokens today", <span className="sh-mono">{num(feed.tokens_today ?? 0)}</span>],
      ...QUEUE_STATES.map((s): [string, ReactNode] => [s.word, <span className="sh-mono">{num(feed.queue?.[s.id] ?? 0)}</span>]),
    );
  const toggle = (enabled: boolean) => {
    // The hook types {feed, enabled}; parser and settings ride along so the kernel keeps them.
    const change = { feed: feed.feed, enabled, parser: feed.parser ?? "", settings: feed.settings ?? {} };
    configure.mutate(change);
  };

  return (
    <Dialog
      title={feedName(feed.feed)}
      id={feed.feed}
      size="sm"
      step={step}
      onClose={onClose}
      head={
        <Status tone={state.tone} badge>
          {state.word}
        </Status>
      }
      footer={
        <Button onClick={() => refresh.mutate(feed.feed)} disabled={refresh.isPending || !feed.enabled}>
          {refresh.isPending ? <Spinner /> : <RefreshCw aria-hidden />}
          Pull now
        </Button>
      }
    >
      <Switch checked={feed.enabled} onChange={toggle} disabled={configure.isPending}>
        On
      </Switch>
      {configure.error ? <ErrorNote error={configure.error} inline /> : null}
      <Fields rows={rows} />
      {feed.last_error ? (
        <pre className="sh-code m-0 whitespace-pre-wrap text-bad" aria-label="Last error">
          {feed.last_error}
        </pre>
      ) : null}
      {refresh.error ? <ErrorNote error={refresh.error} inline /> : null}
    </Dialog>
  );
}
