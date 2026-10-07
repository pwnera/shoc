/**
 * Small parts of Detection and the rule page: the rule state badge, the
 * backlog priority and title, a suppression's time left, a rule link that
 * knows `hunt:*` ids are hunt packs, and the title with its description
 * behind ⓘ that the rule and playbook pages share.
 */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Info } from "lucide-react";
import { Countdown } from "@/components/ui/approval";
import { Badge } from "@/components/ui/badge";
import { Popover } from "@/components/ui/pop";
import { Status } from "@/components/ui/status";
import { Chip } from "@/components/ui/filterbar";
import { Tip } from "@/components/ui/tip";
import { tacticLabel, tacticsOf } from "@/lib/attack";
import { cn } from "@/lib/cn";
import { left } from "@/lib/format";
import { ruleState } from "@/lib/labels";
import { useNow } from "@/lib/now";
import type { BacklogItem, RuleHealth, Suppression } from "@/types";
import { ruleHref, stateOf, stateTip } from "./state";

/** The rule's state as an outlined badge, the reason in its tip; "never sent" is dashed. */
export function RuleStatus({ health }: { health: RuleHealth | undefined }) {
  const state = ruleState(health);
  if (!state || !health) return <span className="sh-mono">—</span>;
  const s = stateOf(state);
  return (
    <Tip label={stateTip(health)}>
      <Status tone={s.tone} badge className={state === "never_sent" ? "border-dashed" : undefined}>
        {s.word}
      </Status>
    </Tip>
  );
}

/** A record's title; its description sits behind ⓘ on the line of the last word, so the title wraps before it. */
export function Described({ title, description }: { title: string; description?: string | null }) {
  const cut = title.lastIndexOf(" ") + 1;
  return (
    <span className="block whitespace-normal">
      {title.slice(0, cut)}
      <span className="whitespace-nowrap">
        {title.slice(cut)}
        {description?.trim() ? (
          <Popover
            pad
            label="Description"
            trigger={(props) => (
              <button
                {...props}
                type="button"
                className="sh-btn sh-btn--ghost sh-btn--icon ml-1 align-middle"
                aria-label="Description"
              >
                <Info aria-hidden />
              </button>
            )}
          >
            <p className="m-0 max-w-[320px] whitespace-normal text-fg-2">{description.trim()}</p>
          </Popover>
        ) : null}
      </span>
    </span>
  );
}

export function RuleLink({ id, children }: { id: string; children?: ReactNode }) {
  return (
    <Link to={ruleHref(id)} className="sh-link">
      {children ?? id}
    </Link>
  );
}

/** What a rule-health or a case item says about its rule, after the rule's title. */
const ABOUT: Record<string, string> = { health: stateOf("noisy").word, case: "defect" };

/**
 * A backlog item's title. A coverage gap names its technique in words, by the
 * name a report gave it or else its tactic, and the technique as a chip ("No
 * rule for Ingress Tool Transfer · T1105"), where the kernel writes "no rule
 * maps to T1105"; a rule-health or case item is its rule's title (`rule`) and
 * a word ("Okta MFA reset · noisy"), where the kernel writes
 * "okta_mfa_reset: over its volume"; anything else keeps its own title.
 */
export function ItemTitle({
  item,
  rule,
}: {
  item: Pick<BacklogItem, "kind" | "title" | "evidence" | "context" | "intake" | "rule_id">;
  /** The title of the rule the item names. */
  rule?: string;
}) {
  const about = item.rule_id ? ABOUT[item.intake] : undefined;
  if (about) return <>{`${rule ?? item.rule_id} · ${about}`}</>;
  const technique = item.kind === "coverage" ? item.evidence?.technique : undefined;
  if (typeof technique !== "string" || !technique) return <>{item.title}</>;
  const named = item.context?.techniques.find((t) => t.id === technique)?.name;
  const words = named || tacticsOf([technique]).map(tacticLabel).join(", ");
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5">
      <span className="truncate">No rule for{words ? ` ${words}` : ""}</span>
      <Chip value={technique} className="shrink-0" />
    </span>
  );
}

/** P1–P4, neutral; P1 in the human ink, the one that wants a person. */
export function Priority({ value }: { value: number }) {
  return (
    <Badge className={value <= 1 ? "border-[var(--human-line)] text-human" : undefined}>
      P{value}
    </Badge>
  );
}

const DAY = 86_400_000;

/** How much of a suppression's life has run, as an elapsed countdown, in warn under a day left. */
export function Left({ row }: { row: Pick<Suppression, "created_at" | "expires_at"> }) {
  return <Countdown elapsed from={row.created_at} to={row.expires_at} warnUnder={DAY} />;
}

/** "3d", for a row too narrow for the countdown's bar. */
export function LeftShort({ row }: { row: Pick<Suppression, "expires_at"> }) {
  const now = useNow();
  const rest = Date.parse(row.expires_at) - now;
  return (
    <span className={rest > 0 && rest < DAY ? "text-warn" : undefined}>
      {rest > 0 ? left(row.expires_at, now) : "expired"}
    </span>
  );
}

/** A chip that links: a rule, a case, a report, a hunt or an ATT&CK page. */
export function LinkChip({
  to,
  label,
  value,
  external,
  dashed,
}: {
  to: string;
  label?: string;
  value: string;
  external?: boolean;
  /** Something that cannot see anything here, as a dashed chip. */
  dashed?: boolean;
}) {
  const body = (
    <>
      {label ? <span className="sh-chip__label">{label}</span> : null}
      <span className="sh-chip__value">{value}</span>
      {dashed ? <span className="sr-only">, reads nothing we receive</span> : null}
    </>
  );
  const className = cn("sh-chip hover:border-line-2", dashed && "sh-chip--dashed");
  return external ? (
    <a className={className} href={to} target="_blank" rel="noreferrer noopener">
      {body}
    </a>
  ) : (
    <Link className={className} to={to}>
      {body}
    </Link>
  );
}
