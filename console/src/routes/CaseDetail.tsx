/**
 * One case: what happened, what the crew concluded on what evidence, whether
 * it is contained, and what waits on a person. The header holds the lifecycle
 * and the strip, the decision bar what waits, the story (tactics, graph, time
 * bar) stays above the tabs, and the rail holds the playbook runs. The parts
 * live in `routes/case/`; this file loads the case and holds its dialogs.
 * Escape goes back to the list that opened the case, or to Cases. A refresh
 * that fails keeps the actions and runs on screen; only a list with nothing
 * cached reads as an error.
 *
 * Capabilities used: case.get, timeline.build, case.history, action.list
 * {case_uid}, playbook.runs, playbook.list, ops.alerts (a stalled case),
 * case.investigate (palette); the parts name their own writes.
 */
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { EventDialog } from "@/components/EventDialog";
import { ActionDialog } from "@/components/ActionDialog";
import { RunDialog } from "@/components/RunDialog";
import { Card } from "@/components/ui/card";
import { Empty, ErrorNote, TabPanel, Tabs } from "@/components/ui/misc";
import { Skel } from "@/components/ui/state";
import { ApiError } from "@/lib/api";
import { useCommand, useEscBack, useTabKeys } from "@/lib/commands";
import { copyAndSay } from "@/lib/copy";
import { shortId } from "@/lib/format";
import { useTab } from "@/lib/param";
import { closeParams, useClaim } from "@/lib/popup";
import { usePresence } from "@/lib/presence";
import {
  useAlerts,
  useCase,
  useCaseActions,
  useCaseHistory,
  useInvestigate,
  usePlaybooks,
  useRuns,
  useTimeline,
} from "@/lib/queries";
import { toastError } from "@/lib/toast";
import type { Action, Disposition } from "@/types";
import { resetBrush } from "./case/brush";
import { CloseDialog } from "./case/CloseDialog";
import { DecisionBar } from "./case/DecisionBar";
import { Discussion } from "./case/Discussion";
import { FindingsTab } from "./case/FindingsTab";
import { Header, type MenuAsk } from "./case/Header";
import { exploreOf, useLastVisit } from "./case/links";
import { MessageDialog } from "./case/MessageDialog";
import { visibleMessages, type Mode } from "./case/messages";
import { caseCites, caseMoments, type Open } from "./case/moments";
import { PagesTab } from "./case/PagesTab";
import { PlaybookPicker } from "./case/PlaybookPicker";
import { ProposeDialog } from "./case/ProposeDialog";
import { Rail } from "./case/Rail";
import { ResponseTab } from "./case/ResponseTab";
import { Story } from "./case/Story";
import { CaseStrip } from "./case/Strip";
import { TimelineTab } from "./case/TimelineTab";

const TABS = ["timeline", "discussion", "findings", "response", "pages"] as const;
type Tab = (typeof TABS)[number];

export function CaseDetail() {
  const { caseUid = "" } = useParams();
  // One page per case, so its last visit, brush and dialogs start fresh.
  return <CasePage key={caseUid} uid={caseUid} />;
}

function CasePage({ uid }: { uid: string }) {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const detail = useCase(uid);
  const timeline = useTimeline(uid);
  const actions = useCaseActions(uid);
  const runs = useRuns({ caseUid: uid });
  const history = useCaseHistory(uid);
  const catalogue = usePlaybooks();
  const alerts = useAlerts();
  const presence = usePresence();
  const investigate = useInvestigate();
  const lastVisit = useLastVisit(uid);
  const [tab, setTab] = useTab<Tab>(TABS);
  useTabKeys(TABS.length, (i) => setTab(TABS[i]!));
  useEffect(() => {
    resetBrush();
    return resetBrush;
  }, []);

  const [closing, setClosing] = useState<{ disposition?: Disposition } | null>(null);
  const [proposing, setProposing] = useState<{ again?: Pick<Action, "type" | "params"> } | null>(null);
  const [picking, setPicking] = useState(false);
  // The event and the action open in `?event=` and `?action=`, as `msg` and `run` do; the list they step through stays here.
  useClaim("event");
  useClaim("action");
  const [eventList, setEventList] = useState<string[] | null>(null);
  const [messageList, setMessageList] = useState<number[] | null>(null);
  const [actionList, setActionList] = useState<Action[] | null>(null);
  const [menu, setMenu] = useState<{ open: boolean; ask: MenuAsk }>({ open: false, ask: null });
  const [moving, setMoving] = useState(false);
  const [steer, setSteer] = useState(false);
  const [fresh, setFresh] = useState<string | null>(null);

  const setParam = (name: string, value: string | null, replace = false) =>
    setParams(
      (current) => {
        const out = new URLSearchParams(current);
        if (value) out.set(name, value);
        else out.delete(name);
        return out;
      },
      { replace },
    );

  const open: Open = {
    event: (id, list = [id]) => {
      setEventList(list.includes(id) ? list : [id]);
      setParam("event", id);
    },
    action: (row, list = [row]) => {
      setActionList(list.some((a) => a.action_uid === row.action_uid) ? list : [row]);
      setParam("action", row.action_uid);
    },
    message: (id, list) => {
      setMessageList(list ?? null);
      setParam("msg", String(id));
    },
    run: (id) => setParam("run", id),
    close: (disposition) => setClosing(disposition ? { disposition } : {}),
    propose: (again) => setProposing(again ? { again } : {}),
    playbook: () => setPicking(true),
  };

  const record = detail.data?.case;
  const live = Boolean(record && record.state !== "closed");
  const working = presence.onCase(uid).length > 0;
  useCommand("case.close", () => open.close(), live);
  useCommand("case.move", () => setMoving(true), live);
  useCommand("case.propose", () => open.propose(), live);
  useCommand("case.run-playbook", () => open.playbook(), live);
  useCommand(
    "case.steer",
    () => {
      setTab("discussion");
      setSteer(true);
    },
    live,
  );
  useCommand("case.first-cite", () => document.querySelector<HTMLElement>("[data-evidence] .sh-cite")?.focus(), Boolean(record));
  useCommand("case.menu", () => setMenu({ open: true, ask: null }), Boolean(record));
  useCommand(
    "case.investigate",
    () => investigate.mutate(uid, { onError: (error) => toastError(error, "Re-investigate failed") }),
    live && !working && !investigate.isPending,
  );
  useCommand("case.slack", () => setMenu({ open: true, ask: "slack" }), Boolean(record));
  useCommand("case.copy-id", () => void copyAndSay(uid, shortId(uid)));
  useCommand("case.explore", () => record && navigate(exploreOf(record, timeline.data)), Boolean(record));
  // Bound first, so a brush on the story's time bar takes Escape while it lasts.
  useEscBack("/cases");

  // The header leads every state, so the heading the shell focused while the case loads stays as it arrives.
  if (detail.isPending)
    return (
      <div className="flex flex-col gap-4" aria-busy="true">
        <Header uid={uid} pending />
        <span role="status" className="sr-only">
          loading
        </span>
        <Skel kind="block" className="!h-[320px]" />
      </div>
    );
  if (!detail.data) {
    const missing = detail.error instanceof ApiError && (detail.error.status === 404 || detail.error.code === "not_found");
    return missing ? (
      <Empty
        kind="page"
        title={`No case ${uid}`}
        action={
          <Link className="sh-btn sh-btn--ghost sh-btn--sm" to="/cases">
            Cases
          </Link>
        }
      />
    ) : (
      <div className="flex flex-col gap-4">
        <Header uid={uid} />
        <ErrorNote error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }

  const data = detail.data;
  const rec = data.case;
  const closed = rec.state === "closed";
  const events = timeline.data?.events ?? [];
  const rows = actions.data?.rows ?? [];
  const response = rows.filter((a) => a.state !== "proposed" && a.type !== "notify.page");
  const pages = rows.filter((a) => a.type === "notify.page");
  const cites = caseCites(events, data.openspace);
  const moments = caseMoments({ record: rec, events, findings: data.findings, openspace: data.openspace, actions: rows });
  const stalled = Boolean(alerts.data?.alerts.some((a) => a.kind === "case.stalled" && a.subject === uid));
  const asOf = detail.isRefetchError ? new Date(detail.dataUpdatedAt).toISOString() : null;
  // Every action event refreshes the case's actions: a refresh that fails keeps the rows it had.
  const actionsError = actions.data ? null : actions.error;

  // The message dialog steps through the list that opened it; a shared link, through the Discussion's rows.
  const msgId = params.get("msg");
  const message = msgId ? data.openspace.find((m) => String(m.msg_id) === msgId) : undefined;
  const shown =
    messageList ?? visibleMessages(data.openspace, (params.get("mode") as Mode | null) ?? "outcomes").map((m) => m.msg_id);
  const at = message ? shown.indexOf(message.msg_id) : -1;
  // A link opens a uid outside any list: it steps through itself alone.
  const eventUid = params.get("event") ?? "";
  const eventSteps = eventList?.includes(eventUid) ? eventList : [eventUid];
  const eventIndex = eventSteps.indexOf(eventUid);
  const actionUid = params.get("action") ?? "";
  const actionSteps = actionList?.some((a) => a.action_uid === actionUid) ? actionList : null;
  const actionIndex = actionSteps ? actionSteps.findIndex((a) => a.action_uid === actionUid) : 0;
  const actionRow = actionSteps?.[actionIndex] ?? rows.find((a) => a.action_uid === actionUid);
  const runUid = params.get("run");
  // A closed case shows the rail only once it is known to have runs, so the main column never narrows and widens under the reader.
  const rail = !closed || Boolean(runs.data?.runs.length);

  return (
    <div className="flex flex-col gap-4">
      <Header
        record={rec}
        waiting={rows.some((a) => a.state === "proposed")}
        stalled={stalled}
        working={working}
        window={timeline.data}
        strip={
          <CaseStrip
            data={data}
            timeline={timeline.data}
            actions={actions.data?.rows}
            actionsFailed={actions.isError && !actions.data}
            cites={cites}
            asOf={asOf}
          />
        }
        onClose={() => open.close()}
        menu={menu}
        onMenu={setMenu}
        moving={moving}
        onMoving={setMoving}
      />
      <div className={rail ? "sh-layout--aside" : "flex flex-col"}>
        <div className="sh-layout__main">
          {actionsError && !closed ? (
            <ErrorNote error={actionsError} onRetry={() => void actions.refetch()} inline />
          ) : actions.data ? (
            <DecisionBar
              record={rec}
              actions={rows}
              runs={runs.data?.runs ?? []}
              playbooks={catalogue.data?.playbooks ?? []}
              open={open}
            />
          ) : null}
          <Story
            data={data}
            timeline={timeline.data}
            timelineError={timeline.error}
            onRetry={() => void timeline.refetch()}
            actions={rows}
            history={history.data?.cases ?? []}
            moments={moments}
            cites={cites}
            open={open}
          />
          <Tabs<Tab>
            id="case"
            label="Case"
            value={tab}
            onChange={setTab}
            tabs={[
              { value: "timeline", label: "Timeline" },
              { value: "discussion", label: "Discussion", count: data.openspace_total, crew: true },
              { value: "findings", label: "Findings", count: rec.finding_uids.length },
              { value: "response", label: "Response", count: actions.data ? response.length : null },
              { value: "pages", label: "Pages", count: actions.data ? pages.length : null },
            ]}
          />
          <Card>
            <TabPanel id="case" value={tab}>
              {tab === "timeline" ? (
                <TimelineTab
                  moments={moments}
                  cites={cites}
                  timeline={timeline.data}
                  timelineError={timeline.error}
                  actions={rows}
                  actionsPending={actions.isPending}
                  actionsError={actionsError}
                  openedAt={rec.opened_at}
                  newAfter={lastVisit}
                  open={open}
                />
              ) : tab === "discussion" ? (
                <Discussion data={data} steer={steer} onSteer={setSteer} open={open} />
              ) : tab === "findings" ? (
                <FindingsTab findings={data.findings} total={rec.finding_uids.length} />
              ) : tab === "response" ? (
                <ResponseTab
                  rows={response}
                  loading={actions.isPending}
                  error={actionsError}
                  onRetry={() => void actions.refetch()}
                  fresh={fresh}
                  closed={closed}
                  open={open}
                />
              ) : (
                <PagesTab
                  rows={pages}
                  loading={actions.isPending}
                  error={actionsError}
                  onRetry={() => void actions.refetch()}
                  open={open}
                />
              )}
            </TabPanel>
          </Card>
        </div>
        {rail ? (
          <aside className="sh-layout__aside" aria-label="Playbook runs">
            <Rail
              runs={runs.data?.runs ?? []}
              actions={rows}
              loading={runs.isPending}
              error={runs.data ? null : runs.error}
              onRetry={() => void runs.refetch()}
              playbooks={catalogue.data?.playbooks ?? []}
              closed={closed}
              open={open}
            />
          </aside>
        ) : null}
      </div>

      {closing ? <CloseDialog record={rec} disposition={closing.disposition} onClose={() => setClosing(null)} /> : null}
      {proposing ? (
        <ProposeDialog
          caseUid={uid}
          entities={data.entities}
          again={proposing.again}
          onDone={(row) => {
            setFresh(row.action_uid);
            setTab("response");
          }}
          onClose={() => setProposing(null)}
        />
      ) : null}
      {picking ? <PlaybookPicker caseUid={uid} onClose={() => setPicking(false)} /> : null}
      {eventUid ? (
        <EventDialog
          event={events.find((e) => e.event_uid === eventUid)}
          uid={eventUid}
          // The step list stays: emptying it here would move the stepper under a dialog that is closing.
          onClose={() => closeParams(["event"], navigate)}
          step={{
            index: eventIndex,
            total: eventSteps.length,
            onPrev: eventIndex > 0 ? () => setParam("event", eventSteps[eventIndex - 1]!, true) : undefined,
            onNext: eventIndex < eventSteps.length - 1 ? () => setParam("event", eventSteps[eventIndex + 1]!, true) : undefined,
          }}
        />
      ) : null}
      {actionUid ? (
        <ActionDialog
          action={actionRow}
          uid={actionUid}
          undo={params.get("do") === "undo"}
          onClose={() => closeParams(["action", "do"], navigate)}
          step={
            actionSteps
              ? {
                  index: actionIndex,
                  total: actionSteps.length,
                  onPrev: actionIndex > 0 ? () => setParam("action", actionSteps[actionIndex - 1]!.action_uid, true) : undefined,
                  onNext:
                    actionIndex < actionSteps.length - 1
                      ? () => setParam("action", actionSteps[actionIndex + 1]!.action_uid, true)
                      : undefined,
                }
              : undefined
          }
        />
      ) : null}
      {message ? (
        <MessageDialog
          message={message}
          cites={cites}
          onClose={() => closeParams(["msg"], navigate)}
          step={
            at >= 0
              ? {
                  index: at,
                  total: shown.length,
                  onPrev: at > 0 ? () => setParam("msg", String(shown[at - 1]), true) : undefined,
                  onNext: at < shown.length - 1 ? () => setParam("msg", String(shown[at + 1]), true) : undefined,
                }
              : undefined
          }
        />
      ) : null}
      {runUid ? <RunDialog runUid={runUid} onClose={() => closeParams(["run"], navigate)} /> : null}
    </div>
  );
}
