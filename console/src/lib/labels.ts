/**
 * Plain words for the kernel's ids, and the one tone each state is drawn in.
 * Status tones are good, warn, bad, idle and running (outlined, shaped marks);
 * crew is blue; severity hues never appear here. Every screen reads its words
 * from this file, so "planned" means a dry run everywhere.
 */
import type {
  Action,
  Case,
  CaseState,
  HuntOutcome,
  HuntReadiness,
  IntelLookup,
  QueueState,
  RuleHealth,
  Severity,
  Verdict,
} from "@/types";

export type StatusTone = "good" | "warn" | "bad" | "idle" | "running" | "crew";
export type Word = { word: string; tone: StatusTone };

/** Every action type `policy.show` lists (`contract/v1.json` `actions`), in the words a confirm uses. */
export const ACTIONS: Record<string, string> = {
  "aws.disable_access_key": "Disable AWS key",
  "aws.quarantine_user": "Quarantine AWS user",
  "aws.isolate_instance": "Isolate EC2 instance",
  "okta.reset_password": "Reset Okta password",
  "entra.reset_password": "Reset Entra password",
  "google.reset_password": "Reset Google password",
  "aws.revoke_role_sessions": "Revoke AWS role sessions",
  "github.make_repo_private": "Make repo private",
  "okta.revoke_sessions": "Sign Okta user out",
  "entra.revoke_sessions": "Sign Entra user out",
  "okta.suspend_user": "Suspend Okta user",
  "entra.suspend_user": "Disable Entra user",
  "notify.page": "Page on-call",
  "crowdstrike.isolate_host": "Isolate CrowdStrike host",
  "sentinelone.isolate_host": "Isolate SentinelOne host",
  "defender.isolate_host": "Isolate Defender host",
  "cloudflare.block_ip": "Block IP at Cloudflare",
  "wazuh.block_ip": "Block IP on hosts",
  "m365.delete_inbox_rule": "Delete inbox rule",
  "m365.revoke_app_consent": "Revoke app consent",
  "anthropic.disable_api_key": "Disable Claude API key",
  "aws.detach_role_policy": "Detach AWS role policy",
  "aws.detach_user_policy": "Detach AWS user policy",
  "azure.stop_vm": "Stop Azure VM",
  "cloudflare.disable_api_token": "Disable Cloudflare token",
  "crowdstrike.block_hash": "Block file in CrowdStrike",
  "sentinelone.block_hash": "Block file in SentinelOne",
  "defender.block_hash": "Block file in Defender",
  "gcp.disable_firewall_rule": "Disable GCP firewall rule",
  "gcp.disable_service_account": "Disable GCP service account",
  "gcp.disable_service_account_key": "Disable GCP key",
  "github.demote_org_owner": "Demote GitHub owner",
  "github.enable_secret_scanning": "Turn on secret scanning",
  "github.remove_collaborator": "Remove GitHub collaborator",
  "github.remove_deploy_key": "Remove deploy key",
  "gitlab.block_user": "Block GitLab user",
  "google.revoke_app_token": "Revoke Google app token",
  "google.revoke_sessions": "Sign Google user out",
  "google.suspend_user": "Suspend Google user",
  "okta.remove_admin_role": "Remove Okta admin role",
  "entra.remove_admin_role": "Remove Entra admin role",
  "okta.remove_factor": "Remove Okta MFA factor",
  "entra.remove_factor": "Remove Entra MFA method",
  "openai.delete_api_key": "Delete OpenAI key",
  "stripe.block_charge_card": "Block card",
  "tailscale.deauthorize_device": "Remove Tailscale device",
  "tailscale.revoke_key": "Revoke Tailscale key",
  "tailscale.suspend_user": "Suspend Tailscale user",
};

export function actionLabel(type: string): string {
  if (ACTIONS[type]) return ACTIONS[type];
  const words = (type.split(".").pop() ?? type).replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** The platform an action acts on, by its prefix (`shoc/actions/<prefix>.py`). */
const PLATFORMS: Record<string, string> = {
  anthropic: "Anthropic",
  aws: "AWS",
  azure: "Azure",
  cloudflare: "Cloudflare",
  crowdstrike: "CrowdStrike",
  defender: "Defender",
  // Not an action prefix: the log source a hunt pack or a rule reads.
  edr: "EDR",
  entra: "Entra ID",
  gcp: "GCP",
  github: "GitHub",
  gitlab: "GitLab",
  google: "Google Workspace",
  m365: "Microsoft 365",
  notify: "Paging",
  okta: "Okta",
  openai: "OpenAI",
  sentinelone: "SentinelOne",
  stripe: "Stripe",
  tailscale: "Tailscale",
  wazuh: "Wazuh",
};

/** "aws.disable_access_key" → "AWS"; an unknown prefix as it is. */
export function platformName(type: string): string {
  const id = type.split(".")[0] ?? type;
  return PLATFORMS[id] ?? id;
}

/** Why a silent rule is silent, in a few words. "quiet" and "" need none. */
export function silentLabel(reason: string): string {
  if (reason === "not_ingested") return "not ingested";
  const [kind, ...rest] = reason.split(":");
  const what = rest.join(":");
  if (kind === "field_empty") return `field empty: ${what}`;
  if (kind === "value_absent") return `never sent: ${what}`;
  return "";
}

/* -- severity --------------------------------------------------------------- */

/** "info" for informational, which clipped in every badge column. */
export const severityLabel = (severity: Severity | string) =>
  severity === "informational" ? "info" : severity;

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

/* -- cases ------------------------------------------------------------------ */

export const CASE_STATES: CaseState[] = [
  "triage",
  "analysis",
  "containment",
  "eradication",
  "recovery",
  "post_incident",
  "closed",
];

export const caseStateLabel = (state: CaseState | string) => state.replace(/_/g, " ");

/** Plain words for the dispositions a person closes a case with. */
export const DISPOSITIONS = {
  malicious: "Attack",
  suspicious: "Suspicious",
  benign_expected: "Expected",
  false_positive: "Rule was wrong",
} as const;

/** A verdict in neutral ink with a glyph, so severity owns colour; "needs you" is the crew asking. */
export const VERDICTS: Record<Verdict, { word: string; glyph: string; tone?: StatusTone }> = {
  malicious: { word: "attack", glyph: "◆" },
  suspicious: { word: "suspicious", glyph: "◇" },
  benign: { word: "expected", glyph: "○" },
  benign_expected: { word: "expected", glyph: "○" },
  false_positive: { word: "rule was wrong", glyph: "⊘" },
  unknown: { word: "undecided", glyph: "◌" },
  needs_human: { word: "needs you", glyph: "?", tone: "crew" },
};

export const verdictLabel = (verdict: string) => VERDICTS[verdict as Verdict] ?? { word: verdict.replace(/_/g, " "), glyph: "◌" };

/** A closed case the crew handed over and nobody decided is undecided: the one word Cases, the case and Measurement use. */
export const foldVerdict = (verdict: string, closed = true) => (closed && verdict === "needs_human" ? "unknown" : verdict);
export const verdictOf = (row: Pick<Case, "state" | "verdict">): Verdict => foldVerdict(row.verdict, row.state === "closed") as Verdict;

/** The kernel's "closed as expected activity" (memory notes, suppression reasons) in the verdict's word. */
export const closedWord = (said: string) => (said === "expected activity" ? VERDICTS.benign_expected.word : said);

/* -- crew talk -------------------------------------------------------------- */

/** An openspace message's kind as a verb: a person's "Steer the crew" comes back as "steer", never "inject". */
const KIND_WORDS: Record<string, string> = {
  inject: "steer",
  interject: "aside",
  concede: "concedes",
  request: "asks",
  answer: "answers",
  observation: "noticed",
  hypothesis: "suspects",
  challenge: "challenges",
  evidence: "evidence",
  proposal: "proposes",
  decision: "decides",
};
export const kindWord = (kind: string) => KIND_WORDS[kind] ?? kind.replace(/_/g, " ");

/* -- findings ---------------------------------------------------------------- */

export function findingStatus(status: string): string {
  if (status === "self") return "shoc's own";
  // One word for a suppression everywhere: Detection's Muted tab, the rule's "muted ×N", this badge.
  if (status === "suppressed") return "muted";
  // The case verdict, the close dialog and Measurement's word for the same judgement.
  if (status === "false_positive") return VERDICTS.false_positive.word;
  return status.replace(/_/g, " ");
}

/** The Findings tabs, partitioning `status`. */
export const FINDING_TABS = {
  open: ["new", "triage"],
  handled: ["closed", "false_positive"],
  aside: ["self", "suppressed"],
} as const;

export function findingTab(status: string): keyof typeof FINDING_TABS {
  if ((FINDING_TABS.handled as readonly string[]).includes(status)) return "handled";
  if ((FINDING_TABS.aside as readonly string[]).includes(status)) return "aside";
  return "open";
}

/**
 * The case a finding belongs to: `finding.case_uid`, else the Sentinel's when
 * it opened or attached one (`finding.get` leaves `case_uid` out today).
 */
export function findingCase(finding: { case_uid?: string | null; evidence: Record<string, unknown> }): string | null {
  if (finding.case_uid) return finding.case_uid;
  const sentinel = finding.evidence?.sentinel as { decision?: string; case_uid?: string } | undefined;
  return sentinel?.case_uid && (sentinel.decision === "open" || sentinel.decision === "attach") ? sentinel.case_uid : null;
}

/* -- actions ---------------------------------------------------------------- */

/** A page to the on-call human: a notification, never an act, so it has its own tab and no Activity row. */
export const isPage = (action: Pick<Action, "type">) => action.type === "notify.page";

/** One action's state word: a dry run reads "planned", never "done"; an undo reads "undone", "plan undone" for a dry run. */
export function actionState(action: Pick<Action, "state" | "dry_run" | "error" | "approved_by">): Word {
  switch (action.state) {
    case "proposed":
      return { word: "waits", tone: "crew" };
    case "approved":
    case "running":
      return { word: "running", tone: "running" };
    case "done":
      return action.dry_run ? { word: "planned", tone: "idle" } : { word: "done", tone: "good" };
    case "rolled_back":
      return action.dry_run ? { word: "plan undone", tone: "idle" } : { word: "undone", tone: "idle" };
    case "rejected":
      return action.approved_by === "unattended" ? { word: "expired", tone: "idle" } : { word: "rejected", tone: "idle" };
    case "failed":
      return { word: "failed", tone: "bad" };
    case "blocked":
      return { word: "blocked", tone: "warn" };
    default:
      return { word: String(action.state).replace(/_/g, " "), tone: "idle" };
  }
}

/**
 * A page's state, the same on the case's Pages tab, Response › Pages and the
 * page's own dialog: a page is delivered or not, never "done" or "undone".
 */
export function pageState(page: Pick<Action, "state" | "dry_run" | "error" | "approved_by">): Word {
  switch (page.state) {
    case "done":
      return page.dry_run ? { word: "planned", tone: "idle" } : { word: "delivered", tone: "good" };
    case "rolled_back":
      return page.dry_run ? { word: "plan withdrawn", tone: "idle" } : { word: "withdrawn", tone: "idle" };
    case "rejected":
      return { word: "not sent", tone: "idle" };
    default:
      return actionState(page);
  }
}

/** A caller's kind (`policy.principals`, an audit row's `principal_kind`, who closed a case) in one word on every screen. */
export const PRINCIPALS: Record<string, string> = {
  human: "person",
  agent: "crew",
  crew: "crew",
  external_agent: "assistant",
  service: "shoc",
  system: "shoc",
};
export const principalWord = (kind: string) => PRINCIPALS[kind] ?? kind.replace(/_/g, " ");

/** Autonomy as the badge says it: notify only, acts alone, or waits for you. */
export const AUTONOMY: Record<"L0" | "L1" | "L2", string> = { L0: "notify", L1: "auto", L2: "you" };

/* -- playbooks -------------------------------------------------------------- */

/** A playbook run's state. */
export function runState(state: string, dryRun = false): Word {
  switch (state) {
    case "running":
      return { word: "running", tone: "running" };
    case "waiting_approval":
      return { word: "waits", tone: "crew" };
    case "waiting_timer":
      return { word: "scheduled", tone: "idle" };
    case "done":
      return dryRun ? { word: "planned", tone: "idle" } : { word: "done", tone: "good" };
    case "failed":
      return { word: "failed", tone: "bad" };
    case "cancelled":
      return { word: "cancelled", tone: "idle" };
    default:
      return { word: state.replace(/_/g, " "), tone: "idle" };
  }
}

/** `always`: a catalogue step that runs every time, drawn as a neutral filled node. */
export type StepState = "done" | "current" | "running" | "waiting" | "failed" | "skipped" | "todo" | "always";

/** A step's kernel state as `sh-steps` draws it. */
export function stepState(state: string): StepState {
  switch (state) {
    case "done":
    case "rolled_back":
      return "done";
    case "running":
    case "retrying":
      return "running";
    case "waiting":
    case "waiting_approval":
      return "waiting";
    case "failed":
    case "blocked":
    case "rejected":
    case "expired":
      return "failed";
    case "skipped":
      return "skipped";
    default:
      return "todo";
  }
}

/* -- hunting ---------------------------------------------------------------- */

/** Hunt outcomes on the status scale, never severity hues. */
export const OUTCOMES: Record<HuntOutcome, Word> = {
  clear: { word: "clear", tone: "good" },
  explained: { word: "explained", tone: "good" },
  inconclusive: { word: "inconclusive", tone: "idle" },
  suspicious: { word: "suspicious", tone: "warn" },
  gap: { word: "couldn't look", tone: "idle" },
};

export const READINESS: Record<HuntReadiness["state"], Word> = {
  ready: { word: "ready", tone: "good" },
  learning: { word: "learning", tone: "idle" },
  stale: { word: "stale", tone: "warn" },
  not_applicable: { word: "not applicable", tone: "idle" },
};

/* -- intel ------------------------------------------------------------------ */

export function feedState(feed: { enabled: boolean; last_error: string | null }): Word {
  if (!feed.enabled) return { word: "off", tone: "idle" };
  return feed.last_error ? { word: "failing", tone: "bad" } : { word: "ok", tone: "good" };
}

/** A report the CTI role did not read (RFC 0029); only a drop warns: it waited out its week or failed three times. */
export const QUEUE_STATES: { id: QueueState; word: string; tone: StatusTone }[] = [
  { id: "waiting", word: "waiting", tone: "idle" },
  { id: "skipped", word: "skipped", tone: "idle" },
  { id: "same_story", word: "same story", tone: "idle" },
  { id: "dropped", word: "dropped", tone: "warn" },
];

export const queueState = (state: string): Word => QUEUE_STATES.find((s) => s.id === state) ?? { word: state, tone: "idle" };

/** A lookup source that needs an account: off until a person sets it up, then rate-limited by a 429 or at its quota for the day. */
export function lookupState(
  lookup: Pick<IntelLookup, "configured" | "enabled" | "paused_until" | "calls_today" | "per_day">,
  now = Date.now(),
): Word {
  if (!lookup.configured) return { word: "not set up", tone: "idle" };
  if (!lookup.enabled) return { word: "off", tone: "idle" };
  if (lookup.paused_until && Date.parse(lookup.paused_until) > now) return { word: "rate-limited", tone: "warn" };
  return lookup.calls_today >= lookup.per_day ? { word: "quota reached", tone: "warn" } : { word: "ok", tone: "good" };
}

/* -- connections ------------------------------------------------------------ */

/** What one read with a credential returned, a check's or a Save's: it works, the vendor refused it, or there is none to make (PagerDuty). */
export function readWord(ok: boolean | null | undefined): Word {
  if (ok === false) return { word: "refused", tone: "bad" };
  return ok ? { word: "works", tone: "good" } : { word: "no read to try", tone: "idle" };
}

/** `llm.show` provider ids (`shoc/agents/llm.py` from_config) by name; an unknown one as it is. */
const MODEL_PROVIDERS: Record<string, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  "openai-responses": "OpenAI Responses",
  "openai-compatible": "OpenAI-compatible",
  compatible: "OpenAI-compatible",
  none: "None",
};
export const modelProvider = (id: string) => MODEL_PROVIDERS[id.toLowerCase()] ?? id;

/* -- detection -------------------------------------------------------------- */

/** Where a backlog item came from. */
export const INTAKES: Record<string, string> = {
  case: "case",
  cti: "intel",
  health: "rule health",
  hunt: "hunt",
  posture: "posture",
  rehearsal: "rehearsal",
  source: "pack gap",
  human: "a person",
};

export type RuleState = "failing" | "noisy" | "field_empty" | "live" | "armed" | "never_sent" | "no_source";

/** In this order, so the states partition the catalogue: a rule takes the first that holds. */
export const RULE_STATES: { id: RuleState; word: string; tone: StatusTone }[] = [
  { id: "failing", word: "failing", tone: "bad" },
  { id: "noisy", word: "noisy", tone: "warn" },
  { id: "field_empty", word: "field empty", tone: "warn" },
  { id: "live", word: "live", tone: "good" },
  { id: "armed", word: "armed", tone: "idle" },
  { id: "never_sent", word: "never sent", tone: "idle" },
  { id: "no_source", word: "no source", tone: "idle" },
];

/** A rule's state from its health row; undefined while `health.rules` has not answered. */
export function ruleState(health: RuleHealth | undefined): RuleState | undefined {
  if (!health) return undefined;
  if (health.error) return "failing";
  if (health.noisy) return "noisy";
  if (health.silent_reason.startsWith("field_empty")) return "field_empty";
  if (health.findings_7d > 0) return "live";
  if (health.silent_reason.startsWith("value_absent")) return "never_sent";
  if (health.silent_reason === "not_ingested") return "no_source";
  return "armed";
}

/* -- intel ------------------------------------------------------------------ */

/** `intel.lookup` observation sources (`shoc/detect/osint.py`), in plain words. */
const INTEL_SOURCES: Record<string, string> = {
  rdap: "Registration",
  reverse_dns: "Reverse DNS",
  resolve: "DNS",
  cloud_ranges: "Cloud ranges",
  tor_exit: "Tor exits",
  threatfox: "ThreatFox",
  urlhaus: "URLhaus",
  epss: "EPSS",
  nvd: "NVD",
  local_iocs: "Our feeds",
  history: "Our logs",
  disclosure_guard: "Kept internal",
};
export const intelSourceLabel = (source: string) => INTEL_SOURCES[source] ?? source.replace(/_/g, " ");

/** A job kind or schedule in words ("hunt.daily" → "daily hunts"): Health › Jobs, Problems and the worker banner. */
const JOB_WORDS: Record<string, string> = {
  "source.sync": "source pulls",
  "source.onboard": "onboarding",
  "detect.run": "detection",
  "case.investigate": "investigations",
  "case.sweep": "case sweeps",
  "case.recheck": "case rechecks",
  unattended: "case chasing",
  "playbook.run": "playbook runs",
  "playbook.resume": "playbook resumes",
  "action.run": "actions",
  "action.expire": "timed undo",
  "graph.refresh": "graph refresh",
  "posture.survey": "posture survey",
  "detection.backlog": "detection backlog",
  "hunt.daily": "daily hunts",
  "ops.check": "health checks",
  "intel.refresh": "feed pulls",
  "stream.deliver": "webhook delivery",
  "manager.deliver": "Manager delivery",
  retention: "retention",
  "report.weekly": "weekly report",
  "report.exec": "board report",
  "report.exception": "exception report",
};

export const jobWord = (kind: string) => JOB_WORDS[kind] ?? kind.replace(/[._]/g, " ");

/** An action's reach (`blast_radius.principals`, -1 when the kernel could not see it), in the confirm's words. */
export const reachLabel = (principals: number) =>
  principals < 0 ? "reach unknown" : principals === 1 ? "1 account affected" : `${principals} accounts affected`;

/**
 * A missing scope in a person's words ("action.approve: caller lacks scope
 * 'actions:approve'" → "Your role can't approve actions"); undefined for any
 * other refusal.
 */
export function refusal(message: string): string | undefined {
  const [, area, verb] = /lacks scope '(\w+):(\w+)'/.exec(message) ?? [];
  if (!area || !verb) return undefined;
  return verb === "read" ? `Not allowed to read ${area}` : `Your role can't ${verb === "write" ? "change" : verb} ${area}`;
}
