/**
 * One backlog item as its story: raised (where from, the technique, the case,
 * report, pack or rehearsal behind it), worked by the Detection Engineer
 * (tries, tokens), decided (the decision, by whom, when) and reverted, with
 * each reason in its author's words. An item that names techniques says what
 * the report saw the attacker do, why it matters, the logs that would show it
 * and whether we receive them, and the rules, packs, cases and other reports on
 * the same techniques (`context.tsx`); a rule's health item its findings this
 * week and whom they were mostly on; a case's item the entity, the findings
 * and the closer's words. Reject and Done (R, D)
 * ask why before they settle it, and the reason stays on the item; Reopen (O)
 * acts at once. Revert (V) undoes a merged rule behind a confirm that asks why,
 * and a refusal stays on screen. Merge (M) answers an open item with a rule, or
 * a narrowing of the rule a closed case names, written as YAML and started
 * from what the item says; a rule's health item has no case to narrow from.
 *
 * Capabilities used: detection.decide, detection.revert, detection.merge,
 * intel.reports (report titles), rule.list and hunt.results (titles).
 */
import { useRef, useState } from "react";
import { Check, GitMerge, RotateCcw, Undo2, X } from "lucide-react";
import { productName } from "@/components/brands";
import { RuleEditor } from "@/components/Editors";
import { Avatar } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import { Cites } from "@/components/Citations";
import { Dialog, Fields } from "@/components/ui/dialog";
import { Entity } from "@/components/ui/entity";
import { Quote } from "@/components/ui/field";
import { ErrorNote } from "@/components/ui/misc";
import { Confirm } from "@/components/ui/pop";
import { Tip } from "@/components/ui/tip";
import { keyLabel, useCommand } from "@/lib/commands";
import { who as identify, type Who } from "@/lib/crew";
import { percent, stamp } from "@/lib/format";
import { useMedia } from "@/lib/media";
import { useDecideBacklog, useIntelReports, useRevertRule } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { BacklogItem } from "@/types";
import { contextRows } from "./context";
import { ItemTitle, LinkChip, Priority, RuleLink } from "./parts";
import { decisionOf, mergedRule, revertOf, useDecision, useTitles, type Ending } from "./state";
import { story, type Step } from "./story";
import { useKeepFocus } from "./stepper";

/** Blue is the crew's: a person or shoc itself deciding keeps the neutral node. */
const crew = (who: string | Who | null | undefined) =>
  !!who && (typeof who === "object" ? who : identify(who)).kind === "crew";

/**
 * The trace's rows as plain list items: `ui/trace.tsx` draws every row as a
 * button, and these rows hold links, which a button may not contain.
 */
export function Story({ steps }: { steps: Step[] }) {
  return (
    <ol className="sh-trace" aria-label="Story">
      {steps.map((s) => (
        <li key={s.key} className="sh-trace__item">
          <div className="sh-trace__row cursor-default hover:bg-transparent">
            <span
              className="sh-trace__node"
              data-tone={crew(s.who) ? "crew" : undefined}
              aria-hidden
            >
              <s.glyph className="h-3.5 w-3.5" />
            </span>
            <span className="min-w-0">
              <span className="sh-trace__head">
                {s.who ? <Avatar who={s.who} size={16} /> : null}
                {s.badge}
                {s.text ? <span className="sh-trace__text">{s.text}</span> : null}
              </span>
              {s.chips ? <span className="sh-trace__chips">{s.chips}</span> : null}
            </span>
            <span className="sh-trace__meta">
              {s.meta ? <>{s.meta} · </> : null}
              {stamp(s.time)}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}

/** What a person asked for when they proposed it: the reason, the logic, the look-alike and example events. */
function Request({ item }: { item: BacklogItem }) {
  const e = item.evidence ?? {};
  const text = (value: unknown) => (typeof value === "string" ? value : "");
  const events = (Array.isArray(e.event_uids) ? e.event_uids : []).map(text).filter(Boolean);
  return (
    <Fields
      rows={[
        ["why", item.reason],
        ["source", productName(text(e.product))],
        ["look for", text(e.logic)],
        ["looks the same", text(e.false_positives)],
        ["events", events.length ? <Cites uids={events} /> : null],
      ]}
    />
  );
}

const ASK: Record<Ending, { what: string; go: string }> = {
  rejected: { what: "Reject", go: "Reject" },
  done: { what: "Done without a new rule", go: "Done" },
};

const strings = (value: unknown) => (Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && !!v) : []);

/** What a rule's health or a closed case says about the rule: its findings, and whom they were on. */
function RuleFacts({ item }: { item: BacklogItem }) {
  const e = item.evidence ?? {};
  const findings = strings(e.finding_uids);
  const entity = typeof e.entity === "string" ? e.entity : "";
  const mostly = typeof e.dominant_entity === "string" ? e.dominant_entity : "";
  const closer = typeof e.closer === "string" ? e.closer : "";
  return (
    <>
      <Fields
        rows={[
          ["findings · 7d", typeof e.findings_7d === "number" ? <span className="sh-mono">{e.findings_7d}</span> : null],
          [
            "mostly",
            mostly ? (
              <span className="inline-flex min-w-0 items-center gap-2">
                <Entity value={mostly} button />
                {typeof e.share === "number" ? <span className="sh-mono">{percent(e.share)}</span> : null}
              </span>
            ) : null,
          ],
          ["entity", entity ? <Entity value={entity} button /> : null],
          [
            "findings",
            findings.length && item.case_uid ? (
              <LinkChip to={`/cases/${item.case_uid}?tab=findings`} value={String(findings.length)} />
            ) : null,
          ],
        ]}
      />
      {e.reason ? (
        <Quote by={closer === "human" ? "human:" : null} crew={closer !== "human"} label="closed as">
          {e.reason}
        </Quote>
      ) : null}
    </>
  );
}

/** What a merge from the item starts with: its techniques and product, a promoted pack's own, a narrowing's events. */
function seedOf(item: BacklogItem): Record<string, unknown> {
  const e = item.evidence ?? {};
  const pack = (e.pack ?? {}) as { id?: string; title?: string; attack?: unknown; logsource?: { product?: string } };
  return {
    id: pack.id,
    title: pack.title,
    attack: [...new Set([...strings([e.technique]), ...strings(e.attack), ...strings(pack.attack)])],
    product: typeof e.product === "string" ? e.product : pack.logsource?.product,
    hide_events: strings(e.event_uids),
  };
}

/**
 * Not keyed by item: J and K swap the item under one open native dialog, so
 * focus and the list behind stay put. What belongs to one item (the revert
 * confirm, the reason asked, a failed decide) is keyed by its uid instead.
 */
export function BacklogDialog({
  item,
  step,
  onClose,
}: {
  item: BacklogItem;
  step?: { index: number; total: number; onPrev?: () => void; onNext?: () => void };
  onClose: () => void;
}) {
  const revert = useRevertRule();
  const reports = useIntelReports();
  // The newest 100 name most reports; the item's own context names the rest it cites.
  const reportTitle = (uid: string) =>
    reports.data?.rows.find((r) => r.report_uid === uid)?.title ??
    item.context?.reports.find((r) => r.report_uid === uid)?.title;
  const titles = useTitles();
  // Past 768px the head has room for the item's id.
  const wide = useMedia("(min-width: 768px)", true);
  const keep = useKeepFocus(item.item_uid);
  const revertButton = useRef<HTMLButtonElement>(null);
  const [revertFor, setRevertFor] = useState<string | null>(null);
  const reverting = revertFor === item.item_uid;
  // Reject and Done ask why first; the reason is what the item shows once it is closed.
  const decide = useDecideBacklog();
  const { ending, reject, done, settle, ask, reopen, stop } = useDecision(item, decide, onClose);
  const live = item.state === "open" || item.state === "accepted";
  const merged = mergedRule(item);
  const decision = decisionOf(item);
  const reverted = revertOf(item);
  const [merging, setMerging] = useState(false);
  // A narrowing replays the closed case it names; a rule's health item has none.
  const mergeable = item.state === "open" && (!item.rule_id || Boolean(item.case_uid));

  // Cancel unmounts the focused reason field; focus goes back to the button, so J and K still reach the dialog.
  const stopReverting = () => {
    setRevertFor(null);
    requestAnimationFrame(() => revertButton.current?.focus());
  };
  // The editor over this dialog takes the keys while it is open.
  useCommand("backlog.done", () => ask("done"), live && !merging);
  useCommand("backlog.reject", () => ask("rejected"), live && !merging);
  useCommand("backlog.reopen", reopen, !live && !merging);
  useCommand("backlog.revert", () => setRevertFor(item.item_uid), Boolean(merged) && !merging);
  useCommand("backlog.merge", () => setMerging(true), mergeable && !merging);

  const key = (id: string) => keyLabel(id);
  return (
    <Dialog
      title={<ItemTitle item={item} rule={item.rule_id ? titles(item.rule_id).title : undefined} />}
      id={wide ? item.item_uid : undefined}
      head={<Priority value={item.priority} />}
      step={step}
      onClose={onClose}
      footer={
        <>
          {merged && !reverting ? (
            <Tip label="Undo the merged rule" kbd={key("v")}>
              <Button
                ref={revertButton}
                variant="danger"
                className="mr-auto"
                onClick={() => setRevertFor(item.item_uid)}
                aria-keyshortcuts="V"
              >
                <Undo2 aria-hidden />
                Revert
              </Button>
            </Tip>
          ) : null}
          {live ? (
            <>
              {mergeable ? (
                <Tip label="Merge a rule" kbd={key("m")}>
                  <Button variant="ghost" onClick={() => setMerging(true)} aria-keyshortcuts="M">
                    <GitMerge aria-hidden />
                    Merge
                  </Button>
                </Tip>
              ) : null}
              <Tip label="Reject" kbd={key("r")}>
                <Button
                  ref={reject}
                  variant="ghost"
                  disabled={decide.isPending}
                  onClick={() => ask("rejected")}
                  aria-keyshortcuts="R"
                >
                  <X aria-hidden />
                  Reject
                </Button>
              </Tip>
              <Tip label="Handled without a new rule" kbd={key("d")}>
                <Button
                  ref={done}
                  variant="primary"
                  disabled={decide.isPending}
                  onClick={() => ask("done")}
                  aria-keyshortcuts="D"
                >
                  <Check aria-hidden />
                  Done
                </Button>
              </Tip>
            </>
          ) : (
            <Tip label="Reopen" kbd={key("o")}>
              <Button
                variant="ghost"
                disabled={decide.isPending}
                onClick={reopen}
                aria-keyshortcuts="O"
              >
                <RotateCcw aria-hidden />
                Reopen
              </Button>
            </Tip>
          )}
        </>
      }
    >
      <div ref={keep} className="flex flex-col gap-4">
        <Story steps={story(item, reportTitle, (id) => titles(id).title)} />
        {item.intake === "human" ? <Request item={item} /> : null}
        {item.intake === "health" || item.intake === "case" ? <RuleFacts item={item} /> : null}
        {item.context ? (
          <Fields
            rows={contextRows(item.context, {
              reportUid: typeof item.evidence?.report_uid === "string" ? item.evidence.report_uid : "",
              relevance: true,
            })}
          />
        ) : null}
        {decision?.because ? (
          <Quote by={decision.by} crew={crew(decision.by)} label="because">
            {decision.because}
          </Quote>
        ) : null}
        {reverted?.because ? (
          <Quote by={reverted.by} crew={crew(reverted.by)} label="reverted">
            {reverted.because}
          </Quote>
        ) : null}
        {ending ? (
          <Confirm
            key={`${item.item_uid}:${ending}`}
            inline
            danger={ending === "rejected"}
            what={ASK[ending].what}
            go={ASK[ending].go}
            note={{ required: true, label: "Reason", placeholder: "Why" }}
            onCancel={stop}
            onConfirm={(reason) => settle(ending, reason)}
          />
        ) : null}
        {reverting && merged ? (
          <Confirm
            inline
            danger
            what={
              <>
                Revert <RuleLink id={merged}>{titles(merged).title ?? merged}</RuleLink>
              </>
            }
            go="Revert"
            note={{ required: true, label: "Reason", placeholder: "Why it goes" }}
            onCancel={stopReverting}
            onConfirm={(reason) =>
              revert.mutateAsync({ rule_id: merged, reason }).then(() => {
                toast({ tone: "ok", text: `Reverted · ${titles(merged).title ?? merged}` });
                onClose();
              })
            }
          />
        ) : null}
        {decide.error && decide.variables?.item_uid === item.item_uid && !ending ? (
          <ErrorNote error={decide.error} inline />
        ) : null}
        {merging ? (
          <RuleEditor
            key={item.item_uid}
            itemUid={item.item_uid}
            narrows={item.rule_id || undefined}
            seed={seedOf(item)}
            onClose={() => setMerging(false)}
          />
        ) : null}
      </div>
    </Dialog>
  );
}
