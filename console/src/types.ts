/**
 * The shapes shoc returns.
 *
 * These mirror the capability output schemas in `contract/v1.json`. They are
 * hand-written on purpose: the console should break loudly at build time when
 * the contract changes, not silently at runtime.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Verdict =
  | "unknown"
  | "benign"
  | "benign_expected"
  | "false_positive"
  | "suspicious"
  | "malicious"
  | "needs_human";
export type CaseState =
  "triage" | "analysis" | "containment" | "eradication" | "recovery" | "post_incident" | "closed";

export type Case = {
  case_uid: string;
  title: string;
  severity: Severity;
  state: CaseState;
  verdict: Verdict;
  confidence: number;
  entity_key: string;
  summary: string;
  finding_uids: string[];
  attack: string[];
  rounds: number;
  tokens_used: number;
  opened_at: string;
  updated_at: string;
  closed_at: string | null;
  /** A newer case that follows this closed one names it here. */
  related_case_uid?: string | null;
  closed_by?: "human" | "crew" | "system" | null;
  disposition_reason?: string | null;
  token_cap?: number | null;
  /** When the crew last finished a turn on it. */
  worked_at?: string | null;
  crew_attempts?: number;
  crew_attempted_at?: string | null;
  assignee?: string | null;
  /** Closed without its containment and nobody has acknowledged it since (D152). */
  unacknowledged?: boolean;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
};

/** How a person closes a case (`case.close`). */
export type Disposition = "malicious" | "suspicious" | "benign_expected" | "false_positive";

export type Finding = {
  finding_uid: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  /* "self": shoc's own credentials at work, kept without a case; "suppressed": set aside. */
  status: string;
  entity_key: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  event_uids: string[];
  attack: string[];
  evidence: Record<string, unknown>;
  /** Absent from `finding.list` and `finding.get` today; the Sentinel's decision carries it (section 7 item 22). */
  case_uid?: string | null;
  window_start?: string;
  window_end?: string;
  created_at?: string;
  updated_at?: string;
};

export type OpenspaceMessage = {
  msg_id: number;
  round: number;
  agent: string;
  principal: string;
  kind:
    | "observation"
    | "hypothesis"
    | "evidence"
    | "challenge"
    | "concede"
    | "proposal"
    | "decision"
    | "inject"
    | "request"
    | "answer"
    | "interject";
  to_agent: string;
  body: string;
  cited_event_uids: string[];
  confidence: number | null;
  tokens: number;
  model: string | null;
  created_at: string;
  /* An identical re-post is counted here rather than appended, so a model
     outage no longer fills a case with copies of the same sentence. */
  repeats: number;
  last_repeat_at: string | null;
};

export type Action = {
  action_uid: string;
  case_uid: string | null;
  type: string;
  target: string;
  params: Record<string, unknown>;
  autonomy: "L0" | "L1" | "L2";
  state:
    | "proposed"
    | "approved"
    | "rejected"
    | "running"
    | "done"
    | "failed"
    | "rolled_back"
    | "blocked";
  reversible: boolean;
  dry_run: boolean;
  rationale: string;
  requested_by: string;
  /** Who decided: the approver, or the person or "unattended" that rejected it. */
  approved_by: string | null;
  result: Record<string, unknown>;
  created_at: string;
  /* Older rows may lack the fields below. */
  updated_at?: string;
  approved_at?: string | null;
  executed_at?: string | null;
  /** When a proposal falls back or expires unattended. */
  decide_by?: string | null;
  /** When the Manager paged someone about it. */
  chased_at?: string | null;
  /** The action type that runs if nobody decides; "" for none. */
  fallback?: string;
  blast_radius?: BlastRadius | null;
  /** False when the target came from a log line rather than a typed field. */
  grounded?: boolean;
  /** Why the action failed or was refused, in the kernel's words. */
  error?: string | null;
  run_uid?: string | null;
  undo?: Record<string, unknown>;
};

/** What else an action touches, as the IR Commander counted it. */
export type BlastRadius = {
  /** Distinct principals behind the target; -1 when it could not be seen. */
  principals: number;
  shared_infrastructure?: string;
  declared_as?: string;
  company_loses?: string;
  citations?: string[];
};

export type OcsfEvent = {
  event_uid: string;
  time: string;
  class_name: string | null;
  activity_name: string | null;
  severity_id: number | null;
  status: string | null;
  actor_user_name: string | null;
  actor_session_uid: string | null;
  src_endpoint_ip: string | null;
  api_operation: string | null;
  api_service_name: string | null;
  cloud_account_uid: string | null;
  cloud_region: string | null;
  resource_uid: string | null;
  metadata_product: string | null;
  message: string | null;
};

/** An explorer row: the narrow column set, or every column when raw is asked for. */
export type EventRow = OcsfEvent & Record<string, unknown>;

/** One bar of the histogram, or one value of a field. */
export type EventGroup = {
  key: string;
  count: number;
};

export type SourceHealth = {
  source: string;
  last_ok_at: string | null;
  minutes_since: number | null;
  stale: boolean;
  error: string | null;
  events_seen: number;
};

export type RuleHealth = {
  rule_id: string;
  findings_7d: number;
  cases_7d: number;
  suppressed_7d: number;
  self_7d: number;
  /** Cases closed false_positive. */
  false_positives_7d: number;
  /** Closed cases by verdict. */
  closed_30d: Record<string, number>;
  tokens_30d: number;
  last_fired: string | null;
  error: string | null;
  noisy: boolean;
  silent: boolean;
  /** "", "quiet", "not_ingested", "field_empty:<field>" or "value_absent:<value>". */
  silent_reason: string;
};

export type OpsAlert = {
  kind: string;
  subject: string;
  detail: string;
  severity: string;
};

export type SystemHealth = {
  ok: boolean;
  store: {
    dialect: string;
    ok: boolean;
    event_count: number;
    latest_event: string | null;
    latency_ms?: number;
    detail?: string;
  };
  sources: SourceHealth[];
  rules: { tracked: number; failing: number; fires: number };
  jobs: {
    pending: number;
    running: number;
    failed: number;
    failed_recently: number;
    /** Schedules more than an hour late: no worker is ticking. */
    overdue_schedules?: string[];
  };
  findings: { total: number; open: number; high: number };
};

export type FailedJob = { kind: string; error: string | null; jobs: number; last_at: string };

export type RuleSource = {
  name: string;
  title: string;
  url: string;
  author?: string;
  license?: string;
  relation?: string;
};

export type Rule = {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  status: string;
  confidence: number;
  attack: string[];
  sources?: RuleSource[];
  logsource: Record<string, string>;
  timeframe: string;
  group_by: string[];
  count: string;
  count_distinct?: string;
  entity: string;
  detection: Record<string, unknown>;
  first_seen?: string[];
  lookback?: string | null;
  references?: string[];
  fields: string[];
  created: string | null;
  updated: string | null;
};

export type PlaybookRun = {
  run_uid: string;
  case_uid: string;
  playbook_id: string;
  state: "running" | "waiting_approval" | "waiting_timer" | "done" | "failed" | "cancelled";
  step_index: number;
  dry_run: boolean;
  started_at: string;
  error: string | null;
  finished_at?: string | null;
  updated_at?: string;
  /** What `playbook.runs` joins in: the case the run is for, and its entity. */
  context?: { case?: { title?: string; severity?: Severity }; entity?: string };
};

export type PlaybookStep = {
  step_index: number;
  name: string;
  action_type: string;
  state: string;
  action_uid: string | null;
  result: Record<string, unknown>;
  attempts?: number;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
};

/** `playbook.get`: one run and its steps. */
export type PlaybookRunDetail = {
  run_uid: string;
  playbook_id: string;
  case_uid: string;
  state: PlaybookRun["state"];
  dry_run: boolean;
  steps_done: number;
  steps_total: number;
  /** The action a running step waits on. */
  waiting_on: string;
  /** Proposed actions the run waits for a person on. */
  pending_approval: string[];
  detail: string[];
  steps: PlaybookStep[];
};

export type Indicator = {
  type: string;
  value: string;
  source: string;
  confidence: number;
  severity: Severity;
  description: string;
  tags: string[];
  last_seen: string;
  first_seen?: string;
};

export type HuntSuggestion = {
  value: string;
  field: string;
  reason: string;
  priority: number;
};

/**
 * One feed as `intel.list` returns it (the kernel always sends `parser`,
 * `settings` and `last_run_at`); `intel.configure` must send `parser` and
 * `settings` back unchanged.
 */
export type IntelFeed = {
  feed: string;
  /** The feed's own name when it is a built-in parser. */
  parser?: string;
  enabled: boolean;
  settings?: Record<string, unknown>;
  last_run_at?: string | null;
  last_ok_at: string | null;
  last_error: string | null;
  indicators: number;
  /** A report source's day: reports read, their tokens, and its queue by state (a missing state is 0). */
  read_today?: number;
  tokens_today?: number;
  queue?: Partial<Record<QueueState, number>>;
};

/** A free report source shoc knows by name (`intel.configure {preset}`). */
export type IntelPreset = { name: string; url: string; host: string; grade: number; configured: boolean };

/** A lookup source that needs an account; its key is write-only. */
export type IntelLookup = {
  source: string;
  answers: string;
  hosts: string[];
  configured: boolean;
  enabled: boolean;
  per_day: number;
  calls_today: number;
  paused_until: string | null;
  /** Its free tier is non-commercial: saving needs `settings.commercial_licence`. */
  licence_needed: boolean;
  secret_field: string;
};

/** What CTI may read today and what it has read (RFC 0029). */
export type IntelBudget = { reports_per_day: number; tokens_per_day: number; reports_today: number; tokens_today: number };

/** `intel.list`. A kernel older than RFC 0029 leaves out presets, lookups and budget. */
export type IntelList = {
  rows: Indicator[];
  count: number;
  total: number;
  feeds: IntelFeed[];
  presets?: IntelPreset[];
  lookups?: IntelLookup[];
  budget?: IntelBudget;
};

export type QueueState = "waiting" | "skipped" | "same_story" | "dropped";

/** A report the CTI role queued and did not read, as `intel.reports {state: "queue"}` lists it. */
export type QueuedReport = {
  url: string;
  source: string;
  title: string;
  state: QueueState;
  score: number;
  reason: string;
  /** The report it repeats, for `same_story`. */
  same_as: string | null;
  published_at: string | null;
  queued_at: string;
  changed_at: string;
  tokens: number;
};

/** A report shoc has already read, as `intel.reports` lists it. */
export type IntelReport = {
  report_uid: string;
  url: string;
  source_host: string;
  title: string;
  summary: string;
  relevance: string;
  actors: string[];
  malware: string[];
  campaigns: string[];
  techniques: string[];
  hunts: string[];
  stored_count: number;
  confidence: number;
  digested_at: string;
};

/** What `intel.digest` returns when it has just read one. */
export type Digest = {
  report_uid: string;
  url: string;
  title: string;
  summary: string;
  relevance: string;
  actors: string[];
  malware: string[];
  campaigns: string[];
  targeted_sectors: string[];
  techniques: { id: string; name: string; evidence: string }[];
  indicators: { type: string; value: string; unverified?: boolean }[];
  suggested_hunts: {
    title: string;
    hypothesis: string;
    procedure: string;
    logic: string;
    false_positives: string;
    seen_in: string[];
    would_confirm: string;
    attack: string[];
  }[];
  indicators_stored: number;
  unverified: number;
  confidence: number;
  model: string;
  tokens: number;
  truncated: boolean;
};

export type Observation = {
  source: string;
  verdict: string;
  summary: string;
  data: Record<string, unknown>;
};

export type Lookup = {
  value: string;
  type: string;
  verdict: string;
  score: number;
  confidence: number;
  owner: string;
  shared_infrastructure: boolean;
  internal: boolean;
  seen_in_our_logs: number;
  cached: boolean;
  elapsed_ms: number;
  observations: Observation[];
  sources_ok: string[];
  sources_failed: string[];
};

/** One thing the company has, as the events describe it. */
export type Exposure = {
  entity: string;
  kind: string;
  events: number;
  exposed: boolean;
  privileged: boolean;
  stale: boolean;
  sources: string[];
  countries: string[];
  operations: string[];
  event_uids: string[];
  first_seen: string | null;
  last_seen: string | null;
};

export type Posture = {
  window_days: number;
  /** null until the first survey. */
  taken_at: string | null;
  /** The survey read only the newest `limit` events. */
  truncated?: boolean;
  limit?: number;
  /** The Surveyor's reading; never rendered. */
  reading?: string;
  counts: Record<string, number>;
  exposed: Exposure[];
  privileged: Exposure[];
  stale: Exposure[];
  unwatched: {
    products_with_no_rule?: string[];
    products_seen?: string[];
    rules_by_product?: Record<string, number>;
  };
  caveat: string;
};

export type ExposureAnswer = Omit<Exposure, "event_uids" | "first_seen" | "last_seen"> & {
  known: boolean;
  answer: string;
  caveat: string;
};

export type GraphNode = {
  node_id: string;
  kind: string;
  label: string;
  events: number;
  first_seen: string;
  last_seen: string;
};

export type GraphEdge = {
  src: string;
  dst: string;
  kind: string;
  weight: number;
  last_seen: string;
};

export type Memory = {
  memory_id: string;
  kind: string;
  subject: string;
  body: string;
  source: string;
  confidence: number;
  /** Not returned by `memory.search` today (section 8 item 17); expired facts are already left out. */
  expires_at?: string | null;
  created_at: string;
};

export type ConfiguredSource = {
  source: string;
  enabled: boolean;
  settings: Record<string, unknown>;
  interval_seconds: number;
  has_secret: boolean;
  last_run_at: string | null;
  last_ok_at: string | null;
  last_error: string | null;
  events_seen: number;
  /** The accounts its events have named (source history). */
  accounts?: string[];
  /** The response credentials that act on what it sees, and its accounts none claims. */
  response?: SourceResponse[];
};

/** One response credential a source calls for (`source.list` `response`). */
export type SourceResponse = {
  provider: string;
  credentials: string[];
  missing: string[];
};

/** One response credential, never its secret (`credential.list`). */
export type ResponseCredential = {
  name: string;
  provider: string;
  accounts: string[];
  settings: Record<string, unknown>;
  has_secret: boolean;
  /** Fields its provider needs that are not stored. */
  missing: string[];
  updated_at: string;
  sources: string[];
  /** The last read made with it: when, whether it worked, what came back. */
  checked_at?: string | null;
  check_ok?: boolean | null;
  check_detail?: string;
};

/** A provider the connected sources (or paging) call for, and who covers it. */
export type ResponseNeed = {
  provider: string;
  sources: string[];
  credentials: string[];
  /** Accounts those sources' events named that no credential claims. */
  missing: string[];
};

/** What `credential.configure` takes for one provider, and the actions it runs. */
export type ProviderNeeds = {
  settings: string[];
  optional: string[];
  secret: string[];
  alternative: string[];
  grant: string;
  /** Where to make it on the vendor's side, as a click path. */
  where?: string;
  /** The log connectors whose own credential this is. */
  connectors?: string[];
  actions: string[];
};

export type CredentialList = {
  configured: ResponseCredential[];
  needs: ResponseNeed[];
  providers: Record<string, ProviderNeeds>;
};

/** `credential.configure` and `credential.remove`: the read made with it, when one was tried. */
export type CredentialState = {
  provider: string;
  configured: string[];
  missing: string[];
  verified?: boolean | null;
  verify_detail?: string;
};

/** `slack.show`: never a secret, only whether each is stored. */
export type SlackView = {
  channel: string;
  /** Slack user id → the person's name. */
  approvers: Record<string, string>;
  has_bot_token: boolean;
  verifies_requests: boolean;
};

/** What `source.configure` needs for one connector. */
export type SourceNeeds = {
  permission: string;
  where: string;
  push_where: string;
  settings: string[];
  secret: string[];
};

/** The Integrator's progress on one source (AGT-13). */
export type Onboarding = {
  source: string;
  step: "discover" | "credentials" | "map" | "prove" | "done";
  dark: boolean;
  scopes: string[];
  click_path: string;
  supports: string[];
  cannot_support: string[];
  proof_finding: string | null;
  onboarded_at?: string | null;
  updated_at?: string | null;
};

export type ApiToken = {
  token_id: string;
  who: string;
  role: string | null;
  kind: string;
  scopes: string[];
  created_by: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
};

/** A person who signs in (RFC 0028), as user.list returns them. */
export type User = {
  user_id: string;
  email: string;
  role: string;
  /** How they sign in: the company's provider, or a password and an authenticator. */
  method: "sso" | "password";
  /** Too many wrong codes: refused until the lock ends. */
  locked: boolean;
  last_login_at: string | null;
  created_at: string;
  disabled_at: string | null;
};

/** user.invite and user.reset: the link, returned once, or emailed. */
export type Issued = {
  user_id: string;
  email: string;
  role?: string;
  link: string;
  emailed: boolean;
  expires_at: string | null;
};

/** user.me: who this browser is. `email` is set for an account. */
export type Me = {
  id: string;
  kind: string;
  role: string;
  tenant: string;
  email?: string | null;
};

/** sso.show: the provider's settings; the client secret is never read back. */
export type SsoSettings = {
  configured: boolean;
  issuer: string;
  client_id: string;
  domains: string[];
  /** Whether a client secret is stored. */
  key: "set" | "unset";
  /** What to register at the provider; empty while SHOC_PUBLIC_URL is unset. */
  redirect_uri: string;
  updated_by: string;
};

export type SourceQuality = {
  product: string;
  events: number;
  score: number;
  completeness: number;
  retention: number;
  retention_days: number;
  timeliness: number;
  timeliness_seconds: number;
  field_fidelity: number;
  fields: Record<string, number>;
  readers?: Record<string, string[]>;
  notes: string[];
};

export type HuntOutcome = "clear" | "explained" | "inconclusive" | "suspicious" | "gap";

/** What `hunt.pack` returns. A hunt never opens a case; it raises a finding. */
export type HuntPack = {
  run_uid: string;
  pack_id: string;
  outcome: HuntOutcome;
  rows: number;
  triage: string;
  finding_uid: string;
  error: string;
  hypothesis: string;
  ruled_out: string[];
  unseen: string[];
  observations: {
    tuple: Record<string, string>;
    events: number;
    verdict: string;
    why: string;
    citations: string[];
  }[];
};

export type HuntRun = {
  run_uid: string;
  pack_id: string;
  ran_at: string;
  outcome: HuntOutcome;
  rows_returned: number;
  chosen_because: string;
  triage: string;
  finding_uid: string;
  error: string;
  duration_ms: number;
  query: string;
  query_params: Record<string, unknown>;
  ingested_from: string | null;
  ingested_to: string | null;
  ruled_out: string[];
  unseen: string[];
};

/** Whether a pack can be answered here yet. */
export type HuntReadiness = {
  pack_id: string;
  state: "not_applicable" | "learning" | "stale" | "ready";
  reason: string;
  ready_at: string | null;
  sources: string[];
  accounts: string[];
  title?: string;
  product?: string;
  attack?: string[];
  hypothesis?: string;
  cites?: RuleSource[];
  /** What the pack matches and against what (`hunt.results` only). */
  logic?: HuntLogic;
};

/** A pack's logic: its detection, what counts as new, and what a reader checks next. */
export type HuntLogic = {
  detection: Record<string, unknown>;
  first_seen: string[];
  rare: { by: string[]; among: string; seen_by_fewer_than: number; seen_by_at_least: number } | null;
  lookback: string;
  window: string;
  cadence_days: number;
  pivot: string[];
  triage: string;
  follow_up: string[];
  sensitive: boolean;
};

export type HuntMetrics = {
  days: number;
  by_outcome: Record<string, number>;
  readiness: Record<string, number>;
  detections_proposed: number;
  gaps_open: number;
  gaps_closed: number;
  packs_hunted: number;
};

/**
 * What the deployment holds about an item's techniques, computed on read (D133):
 * their names, what each report said the attacker did, the kinds of logs that
 * would show it with the products that carry them and the ones we receive, and
 * the rules, packs and cases on the same techniques.
 */
export type ItemContext = {
  techniques: { id: string; name: string }[];
  reports: { report_uid: string; title: string; relevance: string; said: { technique: string; procedure: string }[] }[];
  seen_in: { kind: string; label: string; products: { source: string; product: string }[]; received: string[] }[];
  /** Same technique first, then siblings; `live` when it reads a product we receive. */
  rules: { id: string; title: string; live: boolean }[];
  packs: { id: string; title: string; live: boolean }[];
  cases: { case_uid: string; title: string }[];
};

export type HuntBacklogItem = {
  item_uid: string;
  trigger: string;
  title: string;
  hypothesis: string;
  would_confirm: string;
  data_needed: string;
  why_now: string;
  attack: string[];
  pack_id: string;
  priority: number;
  state: string;
  created_at: string;
  /* Where it came from (a report and the feed that carried it), what the report
     saw the attacker do and the shape that leaves, the Hunter's tries, and how it
     ended: the decision and why, the pack that covers it, the products a gap waits
     for, the run that tested it. */
  evidence?: {
    report_uid?: string;
    source?: string;
    procedure?: string;
    logic?: string;
    false_positives?: string;
    seen_in?: string[];
    worked_at?: string;
    tries?: number;
    tokens_today?: number;
    later?: string;
    decision?: string;
    because?: string;
    covered_by?: string;
    waiting_for?: string[];
    run_uid?: string;
    reopened_at?: string;
    /** Why a person put it back in the queue. */
    reopened?: string;
  };
  decided_at?: string | null;
  decided_by?: string | null;
  context?: ItemContext;
};

export type BacklogItem = {
  item_uid: string;
  rule_id: string;
  kind: "defect" | "suppression" | "promote" | "coverage" | "decay";
  intake: string;
  title: string;
  reason: string;
  priority: number;
  observability: "have" | "partial" | "none" | "unknown";
  /* Case items: case_uid, entity, finding_uids, tokens, closer, reason. Source
     gaps: waiting_for. `later` is why the crew put it off; `tries` counts attempts.
     A person's proposal: by, attack, product, logic, false_positives, event_uids.
     Intel: technique, its name, the procedure the report saw and the data that
     shows it. `decision` and `because` say how it ended, `reopened` why it came
     back, `reverted` ({by, because, at}) that the rule it merged was taken back. */
  evidence: {
    reason?: string;
    closer?: string;
    later?: string;
    waiting_for?: string[];
  } & Record<string, unknown>;
  case_uid: string;
  state: string;
  created_at: string;
  decided_by?: string | null;
  decided_at?: string | null;
  context?: ItemContext;
};

export type Suppression = {
  suppression_uid: string;
  rule_id: string;
  entity: string;
  reason: string;
  case_uid: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  state: string;
};

/** One identity in shoc's own footprint (RFC 0021). */
export type OwnIdentity = {
  kind: "credential" | "address" | "operator" | "automation";
  value: string;
  source: string;
  scope: string;
  note: string;
  created_by: string;
  created_at: string;
};

export type Playbook = {
  id: string;
  title: string;
  description: string;
  /** Who merged it here; empty for a playbook shipped in content/ (RFC 0033). */
  merged_by?: string;
  rules: string[];
  questions: { id: string; ask: string }[];
  benign_when: string[];
  steps: { name: string; action: string; optional: boolean }[];
  trigger: {
    verdict: string[];
    entity_kinds: string[];
    attack_any: string[];
    min_confidence: number;
    severity_at_least: string;
  };
};

export type IncidentMetrics = {
  cases: number;
  mttd_minutes: number | null;
  time_to_triage_minutes: number | null;
  time_to_contain_minutes: number | null;
  mttr_minutes: number | null;
};

export type Metrics = {
  days: number;
  by_incident_type: Record<string, IncidentMetrics>;
  dispositions: Record<string, number>;
  false_positive_rate: number | null;
  false_positives_by_rule: {
    rule_id: string;
    findings: number;
    false_positives: number;
    rate: number;
  }[];
  spend_usd: number;
};

export type AuditRow = {
  seq: number;
  ts: string;
  principal_kind: string;
  principal_id: string;
  capability: string;
  error: string | null;
  hash: string;
};

export type CapabilityDoc = {
  name: string;
  summary: string;
  scope: string;
  /** The registry sends L0 or L2 only. */
  autonomy: "L0" | "L2";
  principals: string[];
  audit: boolean;
  tags: string[];
  rest: { method: string; path: string };
  mcp_tool: string;
  cli: string;
  input_schema: JsonSchema;
  output_schema: JsonSchema;
};

/** Enough of JSON Schema to render a capability's arguments. */
export type JsonSchema = {
  type?: string;
  title?: string;
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: string[];
  anyOf?: JsonSchema[];
};

/** The parts of report.get's body the console draws. Every part is optional: shift, weekly and exec differ. */
/** A notice the Manager held back instead of paging, as `report.get` lists them (100 at most). */
export type HeldNotice = {
  notice_uid: string;
  source: string;
  kind: string;
  severity: Severity | string;
  case_uid: string | null;
  body: string;
  created_at: string;
};

/**
 * `report.get`'s body. `held` and `detection.merges` arrive as lists there
 * (`report.send` says `held` as a count): count them with `Array.isArray`.
 */
export type ReportBody = {
  held?: number | HeldNotice[];
  cases?: {
    total: number;
    malicious: number;
    needs_human: number;
    open: number;
    rows?: { case_uid: string; title: string; severity: Severity; verdict: string | null }[];
  };
  findings?: { total: number; serious: number; suppressed?: number; own?: number };
  actions?: { rows: { type: string; state: string; n: number }[]; waiting_for_approval: number };
  top_rules?: { rule_id: string; n: number }[];
  spend?: { usd: number };
  handover?: { unattended?: { acted_without_you: unknown[]; abandoned: unknown[] } };
  metrics?: { false_positive_rate: number | null };
  hunting?: { metrics?: { by_outcome: Record<string, number>; detections_proposed: number } };
  detection?: {
    backlog_open: number;
    not_observable: number;
    suppressions_active: number;
    merges?: number | unknown[];
    costliest_rules?: { rule_id: string; tokens: number }[];
  };
  quality?: { sources: { product: string; score: number }[] };
  posture?: {
    exposed_entities: number;
    what_we_would_not_have_seen: number;
    entities_watched: number;
    indicators_known: number;
    human_actionable_per_day: number;
    weakest_source: string;
  };
};

/** One action type's rule in `policy.show`; every field may be left out, and `lib/policy.ts` fills the defaults. */
export type PolicyRule = {
  autonomy?: "L0" | "L1" | "L2";
  reversible?: boolean;
  min_confidence?: number;
  severity_at_least?: Severity;
  ttl_minutes?: number;
  research_before_action?: boolean;
  review_before_action?: boolean;
  [key: string]: unknown;
};

/** `policy.show`. */
export type PolicyView = {
  version?: number;
  defaults: PolicyRule;
  actions: Record<string, PolicyRule>;
  available_actions: string[];
  action_params: Record<string, { required: string[]; summary: string; reversible: boolean }>;
  guards?: Record<string, unknown>;
  principals?: Record<string, string>;
};

/** One crew role as `lib/crew.ts` draws it. */
export type Role = {
  name: string;
  mono: string;
  /** Model tier: strong for judgement, cheap for narrow work, code for no model. */
  tier: "strong" | "cheap" | "code";
  /** Takes part in cases, so its silence on one is a gap. */
  inCase: boolean;
  /** Names older rows use for the same role. */
  legacy?: string[];
};

/* -- shapes the edition-three screens read (section 9) ---------------------- */

/**
 * A finding as `case.get` returns it: no entity, status, confidence or
 * evidence of its own (the case's entity is its entity).
 */
export type CaseFinding = Pick<
  Finding,
  "finding_uid" | "rule_id" | "title" | "severity" | "event_count" | "first_seen" | "last_seen" | "event_uids" | "attack"
>;

/** `case.get`. Openspace holds the newest 200 messages, oldest first; findings the worst 50. */
export type CaseRecord = {
  case: Case;
  findings: CaseFinding[];
  openspace: OpenspaceMessage[];
  /** Every message on the case; more than `openspace.length` means older ones are not shown. */
  openspace_total: number;
  /** One value per kind (`case.get.entities`). */
  entities: Record<string, string>;
};

/** One event of a case's timeline. */
export type TimelineEvent = OcsfEvent & { cited: boolean; extended?: boolean };

/** `timeline.build` and `timeline.extend`. */
export type TimelineResult = {
  case_uid: string;
  events: TimelineEvent[];
  count: number;
  /** The window held more than `limit` events; these are the oldest. */
  truncated: boolean;
  limit: number;
  window_start: string;
  window_end: string;
  products: string[];
};

/** `case.history`: an earlier case sharing an entity with this one. */
export type CaseHistoryRow = {
  case_uid: string;
  title: string;
  severity: Severity;
  state: CaseState;
  verdict: Verdict;
  closed_by: Case["closed_by"];
  disposition_reason: string | null;
  opened_at: string;
  closed_at: string | null;
  /** The entity keys both cases hold. */
  shared: string[];
};

/** `case.investigate`. */
export type InvestigateResult = {
  case_uid: string;
  verdict: Verdict;
  confidence: number;
  state: CaseState;
  rounds: number;
  messages: number;
  tokens: number;
  model: string;
  peer_calls: number;
  stopped_because: string;
  errors: string[];
  routed: Record<string, unknown>[];
  actions: Record<string, unknown>[];
};

/** `finding.get`. */
export type FindingRecord = { finding: Finding; events: OcsfEvent[]; rule: Rule };

/** `rule.backtest`. */
export type Backtest = {
  rule_id: string;
  days: number;
  findings: number;
  /** Above this, the rule is too noisy to merge. */
  ceiling: number;
  top_entities: Record<string, number>;
  sample: Finding[];
};

/** `rule.test`: the would-be findings of a dry run. */
export type RuleTestResult = {
  rule: Rule;
  canonical_sql: string;
  dialect_sql: string;
  findings: Finding[];
};

/** `detect.run`. */
export type DetectRun = {
  rules_run: number;
  findings_new: number;
  findings_updated: number;
  ioc_matches: number;
  cases_opened: string[];
  errors: Record<string, string>;
};

/** `detection.work`. */
export type DetectionWork = {
  worked: number;
  outcomes: Record<string, number>;
  tokens: number;
  why: string;
  reasoning: string;
};

/** `hunt.daily`. */
export type HuntDaily = {
  chosen: { pack_id: string; reason: string; rank?: number }[];
  runs: HuntPack[];
  outcomes: Record<string, number>;
  readiness: HuntReadiness[];
  tokens: number;
};

/** `snapshot.list`: what a source's own API lists, active or not. */
export type SnapshotRow = {
  source: string;
  entity: string;
  kind: string;
  attributes: Record<string, unknown>;
  last_active: string | null;
  taken_at: string;
};

/** `asset.identify`. */
export type AssetIdentity = {
  target: string;
  is_ours: boolean;
  what_it_is: string;
  source: string;
  /** Distinct principals seen behind it; -1 when unknown. */
  principals: number;
  statements: Record<string, unknown>[];
};

/** `identity.resolve`. */
export type IdentityResolution = {
  identity: string;
  nodes: string[];
  linked: { entity: string; weight: number; first_seen: string; last_seen: string }[];
  listed: { source: string; entity: string; attributes: Record<string, unknown>; last_active: string | null }[];
  registry: Record<string, unknown>[];
  declared: Record<string, unknown>[];
  /** Nothing links this name to another. */
  unbridged: boolean;
};

/** One `platform.lookups` entry. */
export type PlatformLookupDef = {
  lookup: string;
  does: string;
  platforms: string[];
  params: string[];
  configured: boolean;
};

/** `platform.lookup`. */
export type PlatformLookupAnswer = { lookup: string; platforms: string[]; data: Record<string, unknown> };

/** `llm.show`. The key is masked by the kernel. */
export type LlmConfig = {
  provider: string;
  model: string;
  model_cheap: string;
  base_url: string;
  key: string;
  stored: string[];
  spend_usd_per_day: number;
  hunt_tokens_per_day: number;
  /** Left out by a kernel older than RFC 0029. */
  intel_reports_per_day?: number;
  intel_tokens_per_day?: number;
};

/** One day of one model's spend. */
export type SpendRow = {
  day: string;
  model: string;
  calls: number;
  tokens_in: number;
  tokens_out: number;
  usd: number;
};

/** `health.cost`. */
export type CostReport = {
  spend: { rows: SpendRow[]; usd_total: number; usd_today: number; tokens: number; days: number };
  volume: { events: number; days: number; by_product: { product: string; events: number }[] };
};

/** `graph.refresh`. */
export type GraphRefreshResult = {
  nodes: number;
  edges: number;
  events_read: number;
  window_days: number;
  /** Built from the newest `limit` events only. */
  truncated: boolean;
  limit: number;
};

/** `source.sample`. */
export type SourceSample = {
  source: string;
  ok: boolean;
  fetched: number;
  rows: Record<string, unknown>[];
  unmapped_fields: string[];
  needs: string;
  error: string;
};

/** `mapping.test`. */
export type MappingTest = {
  source: string;
  product: string;
  supports: string[];
  cannot_support: string[];
  proof_finding: string;
};

/** `source.onboard`. */
export type OnboardResult = {
  worked: number;
  onboarded: string[];
  waiting: string[];
  dark: string[];
  repaired: string[];
};

/** `source.sync`. */
export type SyncResult = {
  source: string;
  fetched: number;
  loaded: number;
  pages: number;
  detail: string | null;
  error: string | null;
  snapshot_assets: number;
  snapshot_error: string;
};

/** `intel.add`. */
export type IndicatorAddResult = {
  added: { type: string; value: string }[];
  rejected: string[];
  stored_new: number;
  source: string;
  retro_hunt: { indicators?: number; hits?: number; findings?: string[] };
};

/** `report.get`, built on demand and never saved. */
export type ReportEnvelope = {
  report_uid: string;
  kind: "weekly" | "exec";
  period_start: string;
  period_end: string;
  summary: string;
  narrative: string;
  body: ReportBody;
};

/** `events.summarize`. `total` sums the buckets returned. */
export type Summary = { by: string; interval: string; rows: EventGroup[]; total: number; sql: string };

/** `stream.tail`. `latest_seq` is the head of the stream. */
export type StreamTail = {
  events: { seq: number; type: string; subject: string; payload: Record<string, unknown>; created_at: string }[];
  count: number;
  last_seq: number;
  latest_seq: number;
};

/** What `search` and `ask` answer with. */
export type Answer = {
  question: string;
  findings: Finding[];
  events: OcsfEvent[];
  /** Entity keys the answer names. */
  entities: string[];
  needs_human: boolean;
  /** "manager" when the Manager answered; anything else is a model-free search. */
  intent: string;
  consulted: string[];
};

/** One decision only a person can make, as the Overview inbox lists it (`lib/needs.ts`). */
export type NeedsItem = {
  kind: "approval" | "verdict" | "expired" | "unacknowledged" | "credential" | "rejected_credential";
  /** Unique within the inbox: the action uid, the case uid or the source name. */
  key: string;
  /** The case's severity; null for source rows and actions without a case. */
  severity: Severity | null;
  action?: Action;
  case?: Case;
  source?: string;
  /** The row's one time: `decide_by` for approvals, otherwise when it began waiting. */
  at: string | null;
  /** Where the row opens: a path, or `?decide=<uid>` over the current screen. */
  to: string;
};
