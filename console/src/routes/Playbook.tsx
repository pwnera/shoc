/**
 * One playbook: when it runs (the strip is its trigger), what it does alone
 * and what waits for a person (its steps, each with the policy's autonomy for
 * its action), what the crew asks before a verdict and when the case is
 * benign, its runs, and in the rail the detections it answers. The
 * description sits behind ⓘ after the title, as on the rule page. One merged
 * here has Revert in ⋯, behind a confirm that asks why.
 *
 * Capabilities used: playbook.list, policy.show, playbook.runs (this
 * playbook's, filtered here), rule.list and health.rules (detection titles and
 * states), hunt.results (hunt pack titles and readiness), playbook.revert.
 */
import { Fragment, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { Crosshair, Telescope } from "lucide-react";
import { RunDialog } from "@/components/RunDialog";
import { ConfidenceBar, SeverityBadge, VerdictBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Chip } from "@/components/ui/filterbar";
import { Empty, ErrorNote } from "@/components/ui/misc";
import { PageHeader } from "@/components/ui/page";
import { Skel } from "@/components/ui/state";
import { AutonomyBadge, Mark, Status } from "@/components/ui/status";
import { Strip, type StripFact } from "@/components/ui/strip";
import { Table, type Column } from "@/components/ui/table";
import { Tip } from "@/components/ui/tip";
import { attackUrl } from "@/lib/attack";
import { cn } from "@/lib/cn";
import { useCommand, useEscBack, useListNav } from "@/lib/commands";
import { age, percent, shortId, span } from "@/lib/format";
import { actionLabel, READINESS, RULE_STATES, ruleState, runState, SEVERITIES, type Word } from "@/lib/labels";
import { useNow } from "@/lib/now";
import { usePaged } from "@/lib/paged";
import { usePopValue } from "@/lib/popup";
import { ruleOf } from "@/lib/policy";
import {
  useCaseLog,
  useHuntResults,
  usePlaybooks,
  usePolicy,
  useRevertPlaybook,
  useRuleHealth,
  useRules,
  useRuns,
} from "@/lib/queries";
import { useSort } from "@/lib/sort";
import { toast } from "@/lib/toast";
import { useDocumentTitle } from "@/lib/title";
import type { Case, Playbook as Book, PlaybookRun, Severity, Verdict } from "@/types";
import { MoreMenu } from "./detection/MoreMenu";
import { Described } from "./detection/parts";
import { PolicyDialog } from "./response/Autonomy";
import { PlatformMark, Reach } from "./response/marks";

const DAY = 86_400_000;
const rank = (severity?: Severity | null) => (severity ? SEVERITIES.indexOf(severity) : null);

export function Playbook() {
  const { playbookId = "" } = useParams();
  const playbooks = usePlaybooks();
  const runs = useRuns({ limit: 200 });
  // The steps' and detections' reads need no playbook, so they start beside playbook.list rather than after it.
  usePolicy();
  useRules();
  useRuleHealth();
  useHuntResults("", 7);
  const now = useNow();
  const navigate = useNavigate();
  const book = playbooks.data?.playbooks.find((p) => p.id === playbookId);
  useDocumentTitle(book?.title ?? playbookId);
  useEscBack("/response?tab=playbooks");

  if (playbooks.isPending)
    return (
      <div className="flex flex-col gap-4" aria-busy="true">
        <PageHeader
          title={<Skel kind="text" width={280} />}
          id={playbookId}
          strip={<Strip loading facts={[{ label: "last run", value: null }, { label: "runs 30d", value: null }]} />}
        />
        <div className="sh-layout--aside">
          <div className="sh-layout__main">
            <Skel kind="block" />
            <Skel kind="block" />
          </div>
          <Skel kind="block" />
        </div>
      </div>
    );
  if (!playbooks.data)
    return (
      <div className="flex flex-col gap-4">
        <PageHeader title={playbookId} id={playbookId} />
        <ErrorNote error={playbooks.error} onRetry={() => void playbooks.refetch()} />
      </div>
    );
  if (!book)
    return (
      <Empty
        kind="page"
        title={`No playbook ${playbookId}`}
        action={
          <Button size="sm" variant="ghost" onClick={() => navigate("/response?tab=playbooks")}>
            Response › Playbooks
          </Button>
        }
      />
    );

  const mine = (runs.data?.runs ?? [])
    .filter((r) => r.playbook_id === book.id)
    .sort((a, b) => b.started_at.localeCompare(a.started_at));
  const known = Boolean(runs.data);
  const recent = mine.filter((r) => now - Date.parse(r.started_at) < 30 * DAY).length;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={<Described title={book.title} description={book.description} />}
        id={book.id}
        aside={book.merged_by ? <More book={book} /> : undefined}
        strip={
          <Strip
            facts={[
              ...trigger(book),
              { key: "last", label: "last run", value: known ? (mine[0] ? age(mine[0].started_at, now) : "never") : null },
              { key: "runs", label: recent === 1 ? "run 30d" : "runs 30d", value: known ? recent : null },
            ]}
          />
        }
      />
      <div className="sh-layout--aside">
        <div className="sh-layout__main">
          <StepsCard book={book} />
          <div className="grid items-start gap-4 md:grid-cols-2">
            <Checklist title="Crew asks" lines={book.questions.map((q) => q.ask)} />
            <Checklist title="Benign if" lines={book.benign_when} />
          </div>
          <Runs runs={mine} query={runs} />
        </div>
        <aside className="sh-layout__aside" aria-label="Detections">
          <Detections ids={book.rules} />
        </aside>
      </div>
    </div>
  );
}

/** ⋯ for a playbook merged here: Revert, which asks why and hands its rules back to the playbooks that had them. */
function More({ book }: { book: Book }) {
  const navigate = useNavigate();
  const revert = useRevertPlaybook();
  const [menu, setMenu] = useState(false);
  const [asking, setAsking] = useState<string | null>(null);
  useCommand("playbook.menu", () => {
    setAsking(null);
    setMenu(true);
  });
  return (
    <MoreMenu
      label="Playbook"
      open={menu}
      asking={asking}
      onOpenChange={setMenu}
      onAsk={setAsking}
      items={[
        {
          label: "Revert",
          danger: true,
          onSelect: (reason) =>
            revert.mutateAsync({ playbook_id: book.id, reason }).then(() => {
              toast({ tone: "ok", text: `Reverted · ${book.title}` });
              navigate("/response?tab=playbooks");
            }),
          confirm: {
            what: `Revert ${book.title}`,
            go: "Revert",
            danger: true,
            note: { required: true, label: "Reason", placeholder: "Why it goes" },
          },
        },
      ]}
    />
  );
}

/** The trigger as strip facts: verdict, floors, then entity kinds and techniques when it names any. */
function trigger(book: Book): StripFact[] {
  const t = book.trigger;
  // Three facts, not one, so the strip can wrap between them on a phone.
  const facts: StripFact[] = [
    {
      key: "when",
      label: "",
      // Each verdict as every screen draws it, glyph and word.
      value: t.verdict.length ? (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          {t.verdict.map((v, i) => (
            <Fragment key={v}>
              {i ? <span className="text-xs font-normal text-fg-4">or</span> : null}
              <VerdictBadge verdict={v as Verdict} />
            </Fragment>
          ))}
        </span>
      ) : (
        "any verdict"
      ),
    },
  ];
  if (t.min_confidence)
    facts.push({
      key: "confidence",
      label: "",
      value: (
        <span className="inline-flex items-center gap-1">
          ≥<ConfidenceBar value={t.min_confidence} plain />
        </span>
      ),
    });
  if (t.severity_at_least)
    facts.push({
      key: "severity",
      label: "",
      value: (
        <span className="inline-flex items-center gap-1">
          ≥<SeverityBadge severity={t.severity_at_least as Severity} />
        </span>
      ),
    });
  if (t.entity_kinds.length)
    facts.push({
      key: "kinds",
      label: "",
      value: (
        <span className="inline-flex gap-1.5">
          {t.entity_kinds.map((kind) => (
            <Chip key={kind} value={kind} />
          ))}
        </span>
      ),
    });
  if (t.attack_any.length)
    facts.push({
      key: "attack",
      label: "",
      value: (
        <span className="inline-flex gap-1.5">
          {t.attack_any.map((technique) => (
            <a key={technique} className="sh-chip" href={attackUrl(technique)} target="_blank" rel="noreferrer">
              <span className="sh-chip__value">{technique}</span>
            </a>
          ))}
        </span>
      ),
    });
  return facts;
}

/**
 * The steps as a vertical pipeline: logo, label, the policy's autonomy for the
 * action with its floors, reversible or not, how long it lasts; dashed when
 * optional. Under 768px the floors and how long it lasts stay in the popup,
 * so the label keeps the row. Drawn with the `sh-steps` classes, since the
 * wrapper takes a string label and no logo. A node opens the action's policy,
 * and J and K step through the steps from there.
 */
function StepsCard({ book }: { book: Book }) {
  const policy = usePolicy();
  const data = policy.data?.data;
  const [open, pop] = usePopValue("step");
  const at = open === "" ? -1 : Number(open);
  const picked = book.steps[at];
  // A click opens with a history entry, so Back closes it; J and K step in place.
  const go = (index: number, replace = false) => () => pop(String(index), replace);
  return (
    <Card>
      <CardHeader title="Steps" />
      <div className="px-3 py-2">
        <ol className="sh-steps sh-steps--vertical sh-steps--interactive" aria-label="Steps">
          {book.steps.map((step, index) => {
            const label = actionLabel(step.action);
            const rule = ruleOf(data, step.action);
            // The severity floor is the badge the strip draws for the trigger's.
            const floor = rule.min_confidence !== undefined || rule.severity_at_least ? (
              <span className="hidden items-center gap-1.5 whitespace-nowrap text-fg-3 md:inline-flex">
                {rule.min_confidence !== undefined ? <span>≥ {percent(rule.min_confidence)}</span> : null}
                {rule.min_confidence !== undefined && rule.severity_at_least ? <span className="text-fg-4">·</span> : null}
                {rule.severity_at_least ? (
                  <span className="inline-flex items-center gap-1.5">
                    ≥ <SeverityBadge severity={rule.severity_at_least} />
                  </span>
                ) : null}
              </span>
            ) : null;
            return (
              // The body's padding moves the dot 4px right of where the shared rule draws the joining line.
              <li key={index} className="sh-steps__step before:left-[8px]!" data-state={step.optional ? "skipped" : "todo"}>
                <Tip label={step.name && step.name !== label ? step.name : undefined}>
                  <button type="button" className="sh-steps__body" onClick={go(index)}>
                    {/* A step that always runs is a filled node; an optional one stays dashed and hollow. */}
                    <i className={cn("sh-steps__dot", !step.optional && "border-fg-3 bg-fg-3")} aria-hidden />
                    <PlatformMark id={step.action} />
                    <span className="sh-steps__label">{label}</span>
                    {step.optional ? <span className="sr-only">, optional</span> : null}
                    <span className="sh-steps__value inline-flex items-center gap-2">
                      {data ? (
                        <>
                          {floor}
                          {rule.ttl_minutes ? (
                            <span className="hidden whitespace-nowrap text-fg-3 md:inline">{span(rule.ttl_minutes * 60)}</span>
                          ) : null}
                          <Reach reversible={rule.reversible} />
                          {/* As wide as "auto", so ↺ and the floors line up down the steps when "you" is narrower. */}
                          <span className="inline-flex min-w-[59px] justify-end">
                            <AutonomyBadge level={rule.autonomy} />
                          </span>
                        </>
                      ) : policy.isError ? (
                        "—"
                      ) : (
                        <Skel kind="badge" />
                      )}
                    </span>
                  </button>
                </Tip>
              </li>
            );
          })}
        </ol>
      </div>
      {policy.isError && !data ? <ErrorNote error={policy.error} onRetry={() => void policy.refetch()} inline /> : null}
      {picked && data ? (
        <PolicyDialog
          rule={ruleOf(data, picked.action)}
          policy={data}
          onClose={() => pop(null)}
          step={{
            index: at,
            total: book.steps.length,
            onPrev: at > 0 ? go(at - 1, true) : undefined,
            onNext: at < book.steps.length - 1 ? go(at + 1, true) : undefined,
          }}
        />
      ) : null}
    </Card>
  );
}

/** The playbook's own lines, unnumbered and plain, so they never look clickable. */
function Checklist({ title, lines }: { title: string; lines: string[] }) {
  if (!lines.length) return null;
  return (
    <Card>
      <CardHeader title={title} />
      <ul className="m-0 flex list-none flex-col gap-2 px-3 py-3">
        {lines.map((line, index) => (
          <li key={index} className="flex gap-2 text-fg-2">
            <span className="mt-[7px] h-[7px] w-[7px] shrink-0 rounded-[1px] border border-line-3" aria-hidden />
            <span>{line}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

/** This playbook's runs, ten a page; a row opens RunDialog. */
function Runs({ runs, query }: { runs: PlaybookRun[]; query: ReturnType<typeof useRuns> }) {
  const cases = useCaseLog();
  const now = useNow();
  const [open, pop] = usePopValue("run");
  const byCase = new Map<string, Case>((cases.data?.rows ?? []).map((c) => [c.case_uid, c]));
  const caseOf = (r: PlaybookRun) => ({
    title: r.context?.case?.title ?? byCase.get(r.case_uid)?.title ?? shortId(r.case_uid),
    severity: r.context?.case?.severity ?? byCase.get(r.case_uid)?.severity,
  });
  const columns: Column<PlaybookRun>[] = [
    {
      label: "Severity",
      width: 28,
      sort: (r) => rank(caseOf(r).severity),
      cell: (r) => {
        const severity = caseOf(r).severity;
        return <Mark tone={severity ?? "idle"} label={severity ?? "severity unknown"} />;
      },
    },
    {
      label: "State",
      fit: true,
      cell: (r) => {
        const state = runState(r.state, r.dry_run);
        return (
          <Status tone={state.tone} badge>
            {state.word}
          </Status>
        );
      },
    },
    { label: "Case", strong: true, cell: (r) => caseOf(r).title },
    { label: "When", width: 56, align: "right", mono: true, sort: (r) => r.started_at, cell: (r) => age(r.started_at, now) },
  ];
  const sorted = useSort(runs, columns);
  const { page, pager, prev, next, first } = usePaged(sorted.rows, 10);
  const nav = useListNav(page, (r) => r.run_uid, {
    onOpen: (r) => pop(r.run_uid),
    onPrevPage: prev,
    onNextPage: next,
  });
  return (
    <Card>
      <CardHeader title="Runs" />
      <Table
        columns={columns}
        rows={page}
        sort={sorted.sort}
        onSort={first}
        rowKey={(r) => r.run_uid}
        rowProps={nav.rowProps}
        loading={query.isPending}
        error={query.data ? undefined : query.error}
        onRetry={() => void query.refetch()}
        empty={<Empty kind="row" title="Never ran" />}
        label="Runs"
      />
      {pager}
      {open ? <RunDialog runUid={open} onClose={() => pop(null)} /> : null}
    </Card>
  );
}

type Detection = { id: string; hunt: boolean; title: string; severity?: Severity; state?: Word; rank: number };

/** The rules and hunt packs it answers, ten a page: rules open their page, packs open Hunts on the pack. */
function Detections({ ids }: { ids: string[] }) {
  const rules = useRules();
  const health = useRuleHealth();
  const hunts = useHuntResults("", 7);
  const navigate = useNavigate();
  const location = useLocation();
  const byRule = new Map((rules.data?.rules ?? []).map((r) => [r.id, r]));
  const byHealth = new Map((health.data?.rules ?? []).map((h) => [h.rule_id, h]));
  const byPack = new Map((hunts.data?.readiness ?? []).map((p) => [p.pack_id, p]));

  const rows = ids
    .map((id): Detection => {
      if (id.startsWith("hunt:")) {
        const pack = byPack.get(id.slice(5));
        const state = pack ? READINESS[pack.state] : undefined;
        return { id, hunt: true, title: pack?.title ?? id.slice(5), state, rank: 100 };
      }
      const rule = byRule.get(id);
      const s = ruleState(byHealth.get(id));
      const at = RULE_STATES.findIndex((r) => r.id === s);
      const state = at >= 0 ? { word: RULE_STATES[at]!.word, tone: RULE_STATES[at]!.tone } : undefined;
      return { id, hunt: false, title: rule?.title ?? id, severity: rule?.severity, state, rank: at >= 0 ? at : 50 };
    })
    .sort((a, b) => a.rank - b.rank);

  // A failed rule list leaves the hunt packs, which need only hunt.results.
  const failed = rules.isError && !rules.data;
  const listed = failed ? rows.filter((d) => d.hunt) : rows;
  const ruled = ids.filter((id) => !id.startsWith("hunt:"));
  const live = ruled.filter((id) => ruleState(byHealth.get(id)) === "live").length;

  // A rule remembers it was opened from here, so its Escape steps back rather than adding a history entry.
  const open = (d: Detection) =>
    d.hunt
      ? navigate(`/hunts?pack=${encodeURIComponent(d.id.slice(5))}`)
      : navigate(`/detection/rules/${encodeURIComponent(d.id)}`, { state: { back: location.pathname + location.search } });
  const stateQuery = (d: Detection) => (d.hunt ? hunts : health);

  const columns: Column<Detection>[] = [
    {
      label: "Severity",
      width: 48,
      truncate: false,
      sort: (d) => rank(d.severity),
      cell: (d) => (
        // A block, so the cell centres it on the row instead of sitting it on the text's baseline.
        <span className="flex items-center gap-1 text-fg-4">
          {d.hunt ? (
            <Telescope className="h-3.5 w-3.5" aria-label="hunt" />
          ) : (
            <Crosshair className="h-3.5 w-3.5" aria-label="rule" />
          )}
          {d.severity ? <Mark tone={d.severity} label={d.severity} /> : null}
        </span>
      ),
    },
    {
      label: "Title",
      strong: true,
      truncate: false,
      sort: (d) => d.title,
      // Two lines at most: in a 320px rail, titles that differ only at the end ("… (Microsoft 365 audit)") stay apart.
      cell: (d) => (
        <span className="line-clamp-2 whitespace-normal py-0.5" title={d.title}>
          {d.title}
        </span>
      ),
    },
    {
      // The state as a bare mark, its word in the label and the tip: the title keeps the rail's width.
      label: "State",
      width: 32,
      truncate: false,
      sort: (d) => (d.state ? d.rank : null),
      cell: (d) =>
        d.state ? (
          <Tip label={d.state.word}>
            <span className="flex justify-end">
              <Status tone={d.state.tone} label={d.state.word} />
            </span>
          </Tip>
        ) : stateQuery(d).isPending ? (
          <span className="flex justify-end">
            <Skel kind="text" width={8} />
          </span>
        ) : (
          <span className="flex justify-end text-fg-4">—</span>
        ),
    },
  ];
  const sorted = useSort(listed, columns);
  const { page, pager, prev, next, first } = usePaged(sorted.rows, 10);
  const nav = useListNav(page, (d) => d.id, { onOpen: open, onPrevPage: prev, onNextPage: next });

  return (
    <Card>
      {/* How many of its rules are live: no single row says when none is. */}
      <CardHeader
        title="Detections"
        subtitle={!ruled.length || health.isPending ? undefined : health.data ? `${live} live` : "—"}
      />
      {failed && listed.length ? <ErrorNote error={rules.error} onRetry={() => void rules.refetch()} inline /> : null}
      <Table
        columns={columns}
        rows={page}
        sort={sorted.sort}
        onSort={first}
        rowKey={(d) => d.id}
        rowProps={nav.rowProps}
        loading={rules.isPending}
        error={failed && !listed.length ? rules.error : undefined}
        onRetry={() => void rules.refetch()}
        empty={<Empty kind="row" title="Answers no detection" />}
        label="Detections"
      />
      {rules.isPending ? null : pager}
    </Card>
  );
}
