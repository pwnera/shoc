/**
 * Overview — does anything need me, and what happened while I was away? The
 * heading is the state ("2 need you", "Nothing needs you", "Crew down · 2 need
 * you", "Can't tell" while a list failed with nothing to show, "Checking…"
 * while one loads; a refresh that failed keeps the rows it had). Under
 * it one fact per area (Standing), the inbox, the console's only list of
 * decisions, then what happened since this viewer's last visit; the since chip
 * (S) widens that window. Under 768px the heading wraps and the chip takes its
 * own line under it.
 *
 * Capabilities used: action.list, case.list, source.list, ops.alerts and
 * health.status (crew down, rules), health.sources, finding.list, policy.show,
 * action.approve and action.reject through the approval card. No report
 * capability.
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Menu } from "@/components/ui/pop";
import { Mark } from "@/components/ui/status";
import { Tip } from "@/components/ui/tip";
import { useCommand } from "@/lib/commands";
import { day, time } from "@/lib/format";
import { useCrewDown, useNeedsYou, type CrewDown, type Needs } from "@/lib/needs";
import { useSince, type SinceChoice } from "@/lib/since";
import { Handover } from "./overview/Handover";
import { Inbox } from "./overview/Inbox";
import { useInboxLists } from "./overview/lists";
import { Standing } from "./overview/Standing";

/** Six days back, so a weekday name never stands for two dates. */
const SIX_DAYS = 6 * 24 * 3_600_000;

/** "Tue 14:02" within the week, "Thu 25 Sep" before it. */
function when(iso: string): string {
  const t = Date.parse(iso);
  if (Date.now() - t > SIX_DAYS) return day(iso);
  return `${new Date(t).toLocaleDateString("en-US", { weekday: "short" })} ${time(iso).slice(0, 5)}`;
}

export function Overview() {
  const needs = useNeedsYou();
  const { failed } = useInboxLists(needs);
  const crew = useCrewDown();
  const since = useSince();
  const [menu, setMenu] = useState(false);
  useCommand("overview.since", () => setMenu(true));

  const choices: { id: SinceChoice; label: string; chip: string }[] = [
    { id: "visit", label: `Last visit · ${when(since.visit)}`, chip: `since ${when(since.visit)}` },
    { id: "24h", label: "Last 24 hours", chip: "last 24 hours" },
    { id: "7d", label: "Last 7 days", chip: "last 7 days" },
  ];
  const chosen = choices.find((c) => c.id === since.choice) ?? choices[0]!;

  return (
    // Under 768px the heading may take two lines and the chip one of its own: the state is never cut.
    <div className="flex flex-col gap-4 max-md:[&_.sh-page\_\_actions]:basis-full max-md:[&_.sh-page\_\_actions]:justify-start max-md:[&_.sh-page\_\_title]:whitespace-normal">
      <PageHeader
        title={<Heading needs={needs} failed={failed.length > 0} crew={crew} />}
        strip={<Standing />}
        aside={
          <Menu
            label="Since"
            align="end"
            open={menu}
            onOpenChange={setMenu}
            items={choices.map((c) => ({
              label: c.label,
              check: "radio" as const,
              checked: c.id === since.choice,
              onSelect: () => since.setChoice(c.id),
            }))}
            // Under 768px the chip sits under the heading, so its text starts on the page's edge.
            trigger={(props) => (
              <Tip label="Window" kbd="S">
                <Button {...props} variant="ghost" size="sm" aria-keyshortcuts="S" className="max-md:-ml-2">
                  {chosen.chip}
                  <ChevronDown aria-hidden />
                </Button>
              </Tip>
            )}
          />
        }
      />
      <Inbox needs={needs} />
      <Handover since={since.since} label={when(since.since)} />
    </div>
  );
}

/** The page's one sentence: the state, in its tone. */
function Heading({ needs, failed, crew }: { needs: Needs; failed: boolean; crew: CrewDown }) {
  const n = needs.count;
  const waiting = n === 1 ? "1 needs you" : `${n} need you`;
  const known = !needs.pending && !failed;
  const [tone, text] = crew.down
    ? (["bad", null] as const)
    : failed
      ? (["bad", "Can't tell"] as const)
      : needs.pending
        ? (["idle", "Checking…"] as const)
        : n
          ? (["crew", waiting] as const)
          : (["good", "Nothing needs you"] as const);
  return (
    <span className="inline-flex items-center gap-2 text-[var(--tone-ink)]" data-tone={tone}>
      <Mark tone={tone} large />
      {text ?? (
        <span>
          <Link to={crew.cause === "worker" ? "/health/jobs" : "/health/crew"} className="sh-link text-inherit">
            Crew down
          </Link>
          {known ? ` · ${n ? waiting : "nothing needs you"}` : ""}
        </span>
      )}
    </span>
  );
}
