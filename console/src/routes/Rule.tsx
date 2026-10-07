/**
 * One rule: does it work here, what does it match, and what happens when it
 * fires? The header carries its state (and what mutes it, and what the crew
 * proposes about it); the strip its behaviour; the workbench its logic beside
 * a replay, a test run and its SQL; the rail what it maps to and what answers
 * it, and where it was taken from. Running it now lives in ⋯, behind a confirm,
 * and so does Revert, which asks why; rule.list does not say which rules were
 * merged here, so a shipped one shows the kernel's refusal in the confirm.
 *
 * Capabilities used: rule.list, health.rules, suppression.list,
 * detection.backlog, playbook.list, policy.show, rule.backtest, rule.test,
 * detect.run, detection.revert.
 */
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Provenance } from "@/components/Provenance";
import { Badge, SeverityBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Popover } from "@/components/ui/pop";
import { Skel } from "@/components/ui/state";
import { Strip } from "@/components/ui/strip";
import { Tip } from "@/components/ui/tip";
import { useCommand, useEscBack } from "@/lib/commands";
import { copyAndSay } from "@/lib/copy";
import { exploreHref, term } from "@/lib/explore";
import { age, compact, count, num, stamp } from "@/lib/format";
import { foldVerdict, verdictLabel } from "@/lib/labels";
import { useMedia } from "@/lib/media";
import { useNow } from "@/lib/now";
import { useDetectionBacklog, usePlaybooks, usePolicy, useRevertRule, useRunDetections, useSuppressions } from "@/lib/queries";
import { toast } from "@/lib/toast";
import { useDocumentTitle } from "@/lib/title";
import type { Rule as RuleT, Suppression } from "@/types";
import { MoreMenu } from "./detection/MoreMenu";
import { Described, Left, RuleStatus } from "./detection/parts";
import { useRuleRows, type RuleRow } from "./detection/state";
import { ShareBar, type ShareSegment } from "./detection/ShareBar";
import { useStepper, useUrlPick } from "./detection/stepper";
import { SuppressionDialog } from "./detection/SuppressionDialog";
import { Relations } from "./rule/Relations";
import { Workbench } from "./rule/Workbench";
import { yamlText } from "./rule/yaml";

const RUN = "Run now";

export function Rule() {
  const { ruleId = "" } = useParams();
  const { rules, health, rows } = useRuleRows();
  // The page's other reads need only the id, so they start beside rule.list rather than after it.
  useSuppressions(ruleId);
  useDetectionBacklog("open");
  usePlaybooks();
  usePolicy();
  useDocumentTitle(ruleId);
  // Escape steps back to what opened the rule (the list, which kept its page and row, or a playbook),
  // so Back never reopens it; opened from a link, it goes to Detection on the page that holds the rule.
  useEscBack("/detection", { row: ruleId });

  if (rules.isPending) return <Skeleton />;
  // A failed refresh keeps the cached rule; only a first load that failed blanks the page, under its id.
  if (rules.isError && !rules.data)
    return (
      <div className="flex flex-col gap-4">
        <PageHeader title={ruleId} id={ruleId} />
        <ErrorNote error={rules.error} onRetry={() => void rules.refetch()} />
      </div>
    );
  const row = rows.find((r) => r.id === ruleId);
  if (!row)
    return (
      <Empty
        kind="page"
        title={`No rule ${ruleId}`}
        action={
          <Link to="/detection" className="sh-link">
            Detection
          </Link>
        }
      />
    );
  return <RulePage row={row} health={health} />;
}

function Skeleton() {
  return (
    <div className="flex flex-col gap-4" aria-busy="true">
      <span role="status" className="sr-only">
        loading
      </span>
      <Skel kind="text" width="40%" />
      <Skel kind="row" width="60%" />
      <div className="sh-layout--aside">
        <div className="@container">
          <div className="grid gap-4 @min-[760px]:grid-cols-2">
            <Skel kind="block" className="h-72" />
            <Skel kind="block" className="h-72" />
          </div>
        </div>
        <Skel kind="block" className="h-72" />
      </div>
    </div>
  );
}

/**
 * Closed cases by verdict, read-only (no case filter reproduces one rule's
 * slice). Verdicts are not severity: neutral inks told apart by fill, "rule
 * was wrong" in warn, an undecided close dashed.
 */
const VERDICT_FILL: Record<string, Pick<ShareSegment, "tone" | "fill">> = {
  malicious: { tone: "neutral" },
  suspicious: { tone: "neutral", fill: "hatched" },
  benign_expected: { tone: "muted" },
  false_positive: { tone: "warn" },
};

function verdictShare(closed: Record<string, number>): ShareSegment[] {
  const counts = new Map<string, number>();
  for (const [verdict, n] of Object.entries(closed)) {
    const key = verdict === "benign" ? "benign_expected" : foldVerdict(verdict);
    counts.set(key, (counts.get(key) ?? 0) + n);
  }
  const order = [...Object.keys(VERDICT_FILL), ...[...counts.keys()].filter((k) => !(k in VERDICT_FILL))];
  return order.map((key) => ({
    key,
    label: verdictLabel(key).word,
    value: counts.get(key) ?? 0,
    ...(VERDICT_FILL[key] ?? { tone: "idle", fill: "dashed" }),
  }));
}

/** Events the rule reads: its one operation when it names one, else its product. */
function exploreFor(rule: RuleT): string {
  const ops = new Set<string>();
  const walk = (value: unknown) => {
    if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === "object")
      for (const [k, v] of Object.entries(value)) {
        if (k === "api.operation") [v].flat().forEach((op) => typeof op === "string" && ops.add(op));
        else walk(v);
      }
  };
  walk(rule.detection);
  const q = ops.size === 1 ? term("api.operation", [...ops][0]!) : term("metadata_product", rule.logsource.product ?? "", "~");
  return exploreHref({ q, since: "-7d" });
}

function RulePage({ row, health }: { row: RuleRow; health: ReturnType<typeof useRuleRows>["health"] }) {
  const navigate = useNavigate();
  const now = useNow();
  const suppressions = useSuppressions(row.id);
  const backlog = useDetectionBacklog("open");
  const run = useRunDetections();
  const revert = useRevertRule();
  const [menu, setMenu] = useState(false);
  const [asking, setAsking] = useState<string | null>(null);
  const pick = useUrlPick("suppression");

  const { health: h, state, ...rule } = row;
  const copyYaml = () => void copyAndSay(yamlText(rule as unknown as Record<string, unknown>), "YAML");
  useCommand("rule.menu", () => {
    setAsking(null);
    setMenu(true);
  });
  useCommand("rule.run", () => {
    setAsking(RUN);
    setMenu(true);
  });
  useCommand("rule.copy-id", () => void copyAndSay(rule.id));
  useCommand("rule.copy-yaml", copyYaml);

  const muting = (suppressions.data?.suppressions ?? []).filter((s) => s.state === "active");
  const muted = useStepper(muting, (s) => s.suppression_uid, pick);
  const changes = (backlog.data?.items ?? []).filter((i) => i.rule_id === rule.id).length;
  // Every behaviour value reads "—" until health answers for this rule, never "0" or "never".
  const known = health.isSuccess ? h : undefined;
  const verdicts = verdictShare(known?.closed_30d ?? {});
  const product = rule.logsource.product ?? "";
  // From 1024px the badges sit beside the title, and under 768px the header row wraps them
  // under it; between, the row would squeeze them out, so they take their own line above the strip.
  const roomy = !useMedia("(min-width: 768px) and (max-width: 1023px)");

  const badges = (
    <>
      <SeverityBadge severity={rule.severity} />
      {/* Sigma's maturity only when it is not "stable", so it never reads as a second state beside the rule's. */}
      {rule.status && rule.status !== "stable" ? <Badge tone="faint">{rule.status}</Badge> : null}
      {health.isPending ? (
        <Skel kind="badge" />
      ) : state === "no_source" ? (
        <Link to={`/connections?add=${encodeURIComponent(product)}`} aria-label={`Connect ${product}`}>
          <RuleStatus health={h} />
        </Link>
      ) : state === "failing" ? (
        <Popover
          pad
          label="Error"
          trigger={(props) => (
            <button {...props} type="button" className="inline-flex">
              <RuleStatus health={h} />
            </button>
          )}
        >
          <pre className="m-0 font-mono text-xs whitespace-pre-wrap text-bad">{h?.error}</pre>
        </Popover>
      ) : (
        <RuleStatus health={h} />
      )}
      {muting.length ? (
        <Popover
          label="Muted"
          trigger={(props) => (
            <button {...props} type="button" className="sh-badge">
              muted ×{muting.length}
            </button>
          )}
        >
          {(close) => (
            <ul className="m-0 flex min-w-[260px] list-none flex-col p-0" role="list">
              {muting.map((s: Suppression) => (
                <li key={s.suppression_uid}>
                  <button
                    type="button"
                    className="sh-menu__item"
                    onClick={() => {
                      close();
                      muted.open(s);
                    }}
                  >
                    <span className="sh-menu__text font-mono">{s.entity || "whole rule"}</span>
                    <Left row={s} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Popover>
      ) : null}
      {changes ? (
        <Link to={`/detection?tab=changes&rule=${encodeURIComponent(rule.id)}`} className="sh-badge hover:border-line-2">
          {count(changes, "change")}
        </Link>
      ) : null}
    </>
  );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        id={rule.id}
        // The title takes what the badges leave and wraps there; ⓘ stays on the line of its last word.
        title={<Described title={rule.title} description={rule.description} />}
        badges={
          roomy ? (
            // One unbreakable run from 1024px, so the badges keep their width and the title gives way.
            <span className="contents min-[1024px]:flex min-[1024px]:items-center min-[1024px]:gap-2">{badges}</span>
          ) : undefined
        }
        aside={
          <MoreMenu
            label="Rule"
            open={menu}
            asking={asking}
            onOpenChange={setMenu}
            onAsk={setAsking}
            items={[
              {
                label: RUN,
                onSelect: () => run.mutateAsync({ rule_id: rule.id }),
                confirm: { what: `Run ${rule.id} now`, go: "Run" },
              },
              { label: "Copy id", onSelect: () => void copyAndSay(rule.id) },
              { label: "Copy YAML", onSelect: copyYaml },
              { label: "Events in Explore", onSelect: () => navigate(exploreFor(rule)) },
              {
                label: "Revert",
                danger: true,
                onSelect: (reason) =>
                  revert.mutateAsync({ rule_id: rule.id, reason }).then(() => toast({ tone: "ok", text: `Reverted · ${rule.title}` })),
                confirm: {
                  what: `Revert ${rule.title}`,
                  go: "Revert",
                  danger: true,
                  note: { required: true, label: "Reason", placeholder: "Why it goes" },
                },
              },
            ]}
          />
        }
        strip={
          <>
            {roomy ? null : <div className="flex flex-wrap items-center gap-2">{badges}</div>}
            <Strip
              facts={[
                { label: "fires 7d", value: known?.findings_7d, to: `/findings?rule=${encodeURIComponent(rule.id)}` },
                { label: "wrong 7d", value: known?.false_positives_7d, tone: known?.false_positives_7d ? "warn" : undefined },
                {
                  label: "shoc's own 7d",
                  value: known?.self_7d,
                  to: `/findings?rule=${encodeURIComponent(rule.id)}&tab=aside`,
                },
                { label: "tokens 30d", value: known ? compact(known.tokens_30d) : null, tip: known ? num(known.tokens_30d) : undefined },
                {
                  label: "last fired",
                  value: known ? age(known.last_fired, now) : null,
                  tip: known?.last_fired ? stamp(known.last_fired) : undefined,
                },
              ]}
              viz={
                verdicts.some((v) => v.value) ? (
                  <span className="flex w-full min-w-0 items-center gap-2">
                    <ShareBar label="Closed cases in 30 days by verdict" segments={verdicts} className="flex-1" />
                    <span className="[font:var(--text-label)] whitespace-nowrap text-fg-4">verdicts 30d</span>
                  </span>
                ) : null
              }
              aside={
                health.isError ? (
                  <Tip label={health.error instanceof Error ? health.error.message : "health.rules failed"}>
                    <Button variant="ghost" size="sm" onClick={() => void health.refetch()}>
                      Retry
                    </Button>
                  </Tip>
                ) : null
              }
            />
          </>
        }
      />

      <div className="sh-layout--aside">
        <div className="sh-layout__main">
          <Workbench rule={rule} />
        </div>
        <aside className="sh-layout__aside" aria-label="Relations and provenance">
          <Relations rule={rule} />
          {rule.sources?.length || rule.references?.length ? (
            <Card aria-label="Provenance">
              <CardHeader title="Provenance" />
              <div className="px-3 pb-3">
                <Provenance sources={rule.sources} references={rule.references} />
              </div>
            </Card>
          ) : null}
        </aside>
      </div>

      {muted.row ? (
        <SuppressionDialog row={muted.row} title={rule.title} onClose={muted.close} step={muted.step} />
      ) : null}
    </div>
  );
}
