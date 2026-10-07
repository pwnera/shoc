/**
 * Run a playbook on this case: the playbooks whose trigger matches, each with
 * its steps as autonomy glyphs, and the five closest near misses greyed with
 * what they missed; a miss every one of them shares shows once on top, and
 * so does the case's confidence under the bar most of them want, counted
 * when some want another. A near miss opens its playbook's page; "+N" opens
 * the catalogue. Dry run starts on when the policy says so, and with nothing
 * to run there is no footer. Plan or Run confirms what will happen first, in
 * a popover on the button.
 *
 * Capabilities used: playbook.list {case_uid}, playbook.run, policy.show (the
 * dry-run default and each step's autonomy).
 */
import { useState } from "react";
import { Link } from "react-router-dom";
import { Bell, User, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Empty, Label, Switch } from "@/components/ui/misc";
import { Confirm, Popover } from "@/components/ui/pop";
import { QueryState } from "@/components/ui/state";
import { Tip } from "@/components/ui/tip";
import { cn } from "@/lib/cn";
import { count, percent } from "@/lib/format";
import { actionLabel, AUTONOMY } from "@/lib/labels";
import { usePlaybooks, usePolicy, useStartPlaybook } from "@/lib/queries";
import { toast } from "@/lib/toast";
import type { Playbook } from "@/types";
import { nearMisses } from "./misses";

const GLYPH = { L0: Bell, L1: Zap, L2: User } as const;
const CLOSEST = 5;

const chip = (text: string) => (
  <span key={text} className="sh-chip sh-chip--dashed">
    <span className="sh-chip__value">{text}</span>
  </span>
);

/** One step as its autonomy glyph, in the AutonomyBadge's ramp; the step and its level in the tip. */
function StepGlyph({ name, action, level }: { name: string; action: string; level?: string }) {
  const known = level === "L0" || level === "L1" || level === "L2" ? level : null;
  const Icon = known ? GLYPH[known] : null;
  return (
    <Tip label={`${name || actionLabel(action)}${known ? ` · ${AUTONOMY[known]}` : ""}`}>
      <span className={cn("sh-badge !px-1", known && `sh-auto--${known.toLowerCase()}`)} role="img" aria-label={name || actionLabel(action)}>
        {Icon ? <Icon aria-hidden /> : "·"}
      </span>
    </Tip>
  );
}

export function PlaybookPicker({ caseUid, onClose }: { caseUid: string; onClose: () => void }) {
  const list = usePlaybooks(caseUid);
  const policy = usePolicy();
  const start = useStartPlaybook();
  const [picked, setPicked] = useState<Playbook | null>(null);
  const [dry, setDry] = useState<boolean | null>(null);
  const [asking, setAsking] = useState(false);
  const dryRun = dry ?? policy.data?.data.defaults.dry_run !== false;
  const levels = policy.data?.data.actions ?? {};
  const matches = list.data?.playbooks ?? [];
  const near = nearMisses(list.data?.near_misses ?? []);
  const misses = near.misses;
  const conf = (wants: number) => `confidence ${near.has === null ? "" : `${percent(near.has)} `}< ${percent(wants)}`;
  // The bar on top holds for every near miss, or says how many of them want it.
  const wanting = misses.filter((m) => m.wants === near.bar).length;

  const footer = matches.length ? (
    <>
      <Switch checked={dryRun} onChange={setDry}>
        Dry run
      </Switch>
      <Popover
        open={asking}
        onOpenChange={setAsking}
        label={dryRun ? "Plan" : "Run"}
        align="end"
        trigger={(props) => (
          <Button {...props} variant="primary" disabled={!picked}>
            {dryRun ? "Plan" : "Run"}
          </Button>
        )}
      >
        {picked ? (
          <Confirm
            what={`${dryRun ? "Plan" : "Run"} ${picked.title}`}
            facts={
              <>
                {dryRun ? <Badge tone="idle">dry run</Badge> : <Badge tone="bad">acts for real</Badge>}
                <Badge>{count(picked.steps.length, "step")}</Badge>
              </>
            }
            go={dryRun ? "Plan" : "Run"}
            danger={!dryRun}
            onConfirm={() =>
              start.mutateAsync({ playbook_id: picked.id, case_uid: caseUid, dry_run: dryRun }).then(() => {
                toast({ tone: "ok", text: `${picked.title} · ${dryRun ? "planned" : "started"}` });
                onClose();
              })
            }
            onCancel={() => setAsking(false)}
          />
        ) : null}
      </Popover>
    </>
  ) : undefined;

  return (
    <Dialog title="Run a playbook" onClose={onClose} footer={footer}>
      <QueryState
        queries={list}
        isEmpty={!matches.length && !misses.length}
        empty={<Empty title="No playbook fits this case" />}
      >
        {matches.length ? (
          <div className="flex flex-col gap-1" role="radiogroup" aria-label="Playbooks">
            {matches.map((p) => (
              <button
                key={p.id}
                type="button"
                role="radio"
                aria-checked={picked?.id === p.id}
                onClick={() => {
                  setPicked(p);
                  setAsking(false);
                }}
                className={cn(
                  "flex w-full items-center gap-3 rounded-[var(--radius-1)] border px-3 py-2 text-left",
                  picked?.id === p.id ? "border-line-3 bg-bg-2" : "border-line-1 hover:bg-bg-2",
                )}
              >
                <span className="min-w-0 flex-1 truncate text-fg-1">{p.title}</span>
                <span className="flex shrink-0 gap-1">
                  {p.steps.map((s, i) => (
                    <StepGlyph key={i} name={s.name} action={s.action} level={levels[s.action]?.autonomy as string | undefined} />
                  ))}
                </span>
              </button>
            ))}
          </div>
        ) : null}
        {near.shared.length || near.bar !== null ? (
          <div className="flex flex-wrap items-center gap-1 px-3 pt-2">
            {near.shared.length || wanting === misses.length ? <Label>every playbook</Label> : null}
            {near.shared.map(chip)}
            {near.bar !== null && wanting < misses.length ? (
              <Label>
                {wanting} of {misses.length}
              </Label>
            ) : null}
            {near.bar !== null ? chip(conf(near.bar)) : null}
          </div>
        ) : null}
        {misses.length ? (
          <ul className="m-0 flex list-none flex-col p-0" aria-label="Near misses">
            {misses.slice(0, CLOSEST).map((m) => {
              // The bar shows on the row only when it is not the one on top.
              const bar = m.wants !== null && m.wants !== near.bar ? [conf(m.wants)] : [];
              const own = [...bar, ...m.own];
              return (
                <li key={m.playbook_id}>
                  <Link
                    to={`/response/playbooks/${encodeURIComponent(m.playbook_id)}`}
                    className="flex flex-col gap-1 rounded-[var(--radius-1)] px-3 py-2 hover:bg-bg-2"
                  >
                    <span className="truncate text-fg-4">{m.title}</span>
                    {own.length ? <span className="flex flex-wrap gap-1">{own.map(chip)}</span> : null}
                  </Link>
                </li>
              );
            })}
            {misses.length > CLOSEST ? (
              <li>
                <Link to="/response" className="sh-mono block px-3 py-2 text-fg-4 hover:bg-bg-2 hover:text-fg-1">
                  +{misses.length - CLOSEST}
                </Link>
              </li>
            ) : null}
          </ul>
        ) : null}
      </QueryState>
    </Dialog>
  );
}
