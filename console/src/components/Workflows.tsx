/**
 * The front page's workflows, each drawn with the component its own screen
 * uses and played one step at a time while it is on screen:
 *
 * - a case: the case strip's facts, the lifecycle, the Discussion trace
 *   (`agents/loop.py` run_case, playbook contain_leaked_cloud_key);
 * - a hunt run: the run dialog's RunTrace (`agents/hunter.py`);
 * - a backlog item: the backlog dialog's story and the Engineer's reason
 *   (`agents/detection_engineer.py`, a noisy rule from rule health);
 * - a source: the source dialog's onboarding steps and fields
 *   (`agents/integrator.py`, model-free).
 *
 * Test data only (documentation addresses, example.com). The hunt query is the
 * kernel's compiled SQL for its pack. A card plays once when first seen and
 * holds its finished state; Skip and Replay sit in its head. Its body is a
 * picture: inert, out of the tab order and unheard, so the card's label and a
 * one-line description carry its meaning; the MemoryRouter only lets the
 * screens' parts render. What arrives fades in and a changed value fades in its
 * new text (`.sh-play` in shoc.css). Under reduced motion each card shows its
 * finished state from the top.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, MemoryRouter } from "react-router-dom";
import { cn } from "@/lib/cn";
import { actionLabel, kindWord, CASE_STATES, caseStateLabel } from "@/lib/labels";
import { who } from "@/lib/crew";
import { stamp } from "@/lib/format";
import { RunTrace, type TraceRun } from "@/routes/hunts/HuntRunDialog";
import { Story } from "@/routes/detection/BacklogDialog";
import { story } from "@/routes/detection/story";
import { Priority } from "@/routes/detection/parts";
import { Sample } from "@/routes/connections/ProductDialog";
import { deliveryTone, onboardingSteps } from "@/routes/connections/state";
import type { BacklogItem, Onboarding } from "@/types";
import { AvatarStack } from "./ui/avatar";
import { Badge, SeverityBadge, VerdictBadge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardBody, CardHeader } from "./ui/card";
import { Fields } from "./ui/dialog";
import { Quote } from "./ui/field";
import { Seg } from "./ui/seg";
import { Status } from "./ui/status";
import { Steps } from "./ui/steps";
import { Strip, type StripFact } from "./ui/strip";
import { Trace, type TraceRow } from "./ui/trace";
import { ProductLogo } from "./ui/logo";

const STEP_MS = 1400;

/** How many steps are shown: counts up once while the card is on screen, then holds. */
function usePlay(total: number) {
  const still =
    typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const [shown, setShown] = useState(still ? total : 0);
  const [start, setStart] = useState(() => Date.now());
  const [seen, setSeen] = useState(typeof IntersectionObserver !== "function");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver !== "function") return;
    const watch = new IntersectionObserver(([entry]) => setSeen(Boolean(entry?.isIntersecting)), {
      threshold: 0.4,
    });
    watch.observe(el);
    return () => watch.disconnect();
  }, []);

  useEffect(() => {
    if (still || !seen || shown >= total) return;
    const timer = setTimeout(() => setShown(shown + 1), STEP_MS);
    return () => clearTimeout(timer);
  }, [shown, still, seen, total]);

  const skip = () => setShown(total);
  const replay = () => {
    setShown(0);
    setStart(Date.now());
  };
  return { ref, shown, start, still, skip, replay };
}

/** A value that fades in when it changes: a new key mounts a new span. */
function fade(value: ReactNode) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <span key={typeof value === "object" ? "node" : String(value)} className="sh-play__fade">
      {value}
    </span>
  );
}

/** A minute offset from when the play started, as the kernel's timestamps read. */
const at = (start: number, minutes: number) => new Date(start + minutes * 60_000).toISOString();

/** The card: a fixed head and a body of one height on every card, which follows its newest row. */
function Played({
  title,
  id,
  aside,
  label,
  about,
  level,
  total,
  render,
}: {
  title: ReactNode;
  id: string;
  aside?: ReactNode;
  label: string;
  /** What the play shows, in one line, for a reader who cannot see it. */
  about: string;
  /** 3 under a section's heading. */
  level?: 3;
  total: number;
  /** A head (the strip, steps or view switch) stays put; the body under it scrolls. */
  render: (shown: number, start: number) => { head?: ReactNode; body: ReactNode };
}) {
  const { ref, shown, start, still, skip, replay } = usePlay(total);
  const done = shown >= total;
  const body = useRef<HTMLDivElement>(null);
  const [scrolled, setScrolled] = useState(false);
  // Every card has the same body: a run longer than it follows its newest row, as a live list
  // does. Under reduced motion it shows its start.
  useEffect(() => {
    const el = body.current;
    if (!el || still) return;
    el.scrollTo?.({ top: shown ? el.scrollHeight : 0, behavior: shown ? "smooth" : "auto" });
  }, [shown, still]);
  const { head, body: content } = render(shown, start);
  return (
    <div ref={ref} className="min-w-0">
      <MemoryRouter>
        <Card aria-label={label}>
          <CardHeader
            title={title}
            level={level}
            subtitle={id}
            action={
              <>
                {aside}
                {still ? null : (
                  <Button variant="ghost" size="sm" onClick={done ? replay : skip}>
                    {done ? "Replay" : "Skip"}
                  </Button>
                )}
              </>
            }
          />
          <p className="sr-only">{about}</p>
          <div className="sh-play flex h-[360px] flex-col" inert>
            {head ? (
              <CardBody className="flex shrink-0 flex-col gap-3 pb-0">{head}</CardBody>
            ) : null}
            <div
              ref={body}
              onScroll={(event) => setScrolled(event.currentTarget.scrollTop > 0)}
              className={cn(
                "min-h-0 flex-1 overflow-hidden",
                scrolled && "[mask-image:linear-gradient(to_bottom,transparent,black_24px)]",
              )}
            >
              <CardBody className="flex flex-col gap-3">{content}</CardBody>
            </div>
          </div>
        </Card>
      </MemoryRouter>
    </div>
  );
}

const crewOf = (authors: string[]) => authors.filter((a) => ["crew", "code"].includes(who(a).kind));

/* -- a case ------------------------------------------------------------------ */

type Message = { agent: string; kind: string; text: string; confidence?: number; minute: number };
const MESSAGES: Message[] = [
  {
    agent: "shoc",
    kind: "observation",
    text: "Opened from aws_access_key_created and aws_access_key_new_address",
    minute: 0,
  },
  {
    agent: "Investigator",
    kind: "hypothesis",
    text: "ci-deploy's new key is used from 203.0.113.7, an address it never used",
    confidence: 0.7,
    minute: 1,
  },
  {
    agent: "Challenger",
    kind: "challenge",
    text: "A new CI runner would create and use a key the same way",
    minute: 1,
  },
  {
    agent: "Investigator",
    kind: "evidence",
    text: "No runner on that address; the key listed every S3 bucket",
    minute: 2,
  },
  {
    agent: "IR Commander",
    kind: "proposal",
    text: `${actionLabel("aws.disable_access_key")} · ci-deploy`,
    minute: 3,
  },
  { agent: "IR Commander", kind: "decision", text: "Containment", confidence: 0.91, minute: 3 },
  {
    agent: "IR Commander",
    kind: "decision",
    text: "Key disabled, nothing else used it; closing",
    confidence: 0.91,
    minute: 5,
  },
];
/** After which message the case moves: analysis, containment, closed. */
const MOVES: [number, string][] = [
  [2, "analysis"],
  [6, "containment"],
  [7, "closed"],
];

export function CaseFlow() {
  return (
    <Played
      label="Case"
      about="The crew confirms a leaked AWS key, disables it and closes the case in five minutes."
      title="New IAM access key used from a new address"
      id="CASE-7f3a"
      aside={
        <>
          <AvatarStack who={crewOf(MESSAGES.map((m) => m.agent))} max={4} />
          <SeverityBadge severity="high" />
        </>
      }
      total={MESSAGES.length}
      render={(shown, start) => {
        const state = MOVES.reduce((s, [after, to]) => (shown >= after ? to : s), "triage");
        const closed = state === "closed";
        const now = CASE_STATES.indexOf(state as (typeof CASE_STATES)[number]);
        const verdict = shown >= 4;
        const facts: StripFact[] = [
          {
            key: "verdict",
            label: "",
            value: verdict ? fade(<VerdictBadge verdict="malicious" confidence={0.91} />) : null,
          },
          {
            key: "evidence",
            label: "",
            value: (
              <span className="sh-cite-row">
                {["E1", "E2", "E3", "E4", "E5"]
                  .slice(0, shown < 1 ? 0 : shown < 2 ? 2 : shown < 4 ? 3 : 5)
                  .map((e) => (
                    <span key={e} className="sh-cite">
                      {e}
                    </span>
                  ))}
              </span>
            ),
          },
          { key: "dwell", label: "before opening", value: fade(shown ? "2m" : null) },
          { key: "contain", label: "to contain", value: fade(shown >= 6 ? "3m" : null) },
          {
            key: "crew",
            label: "tokens",
            value: fade(shown ? `${[0, 6, 14, 19, 27, 31, 33, 36][shown]}k` : null),
          },
        ];
        const rows: TraceRow[] = MESSAGES.slice(0, shown).map((m, i) => ({
          key: String(i),
          kind: m.kind,
          author: m.agent,
          text: m.text,
          badge: (
            <Badge tone="faint">
              {kindWord(m.kind)}
              {m.confidence !== undefined ? ` ${Math.round(m.confidence * 100)}%` : ""}
            </Badge>
          ),
          time: at(start, m.minute),
        }));
        return {
          head: (
            <>
              <Strip facts={facts} />
              {/* As on the case page: under 768px a step's word is for screen readers only. */}
              <div className="min-w-0 max-md:[&_.sh-steps\_\_label]:sr-only">
                <Steps
                  label="Lifecycle"
                  steps={CASE_STATES.map((s, i) => ({
                    key: s,
                    label: caseStateLabel(s),
                    state: closed
                      ? s === "closed"
                        ? "current"
                        : "done"
                      : i < now
                        ? "done"
                        : i === now
                          ? "current"
                          : "todo",
                  }))}
                />
              </div>
            </>
          ),
          body: <Trace items={rows} label="Discussion" />,
        };
      }}
    />
  );
}

/* -- a hunt run ---------------------------------------------------------------- */

const PACK = "okta_user_two_countries_in_a_day";
/** `compile_pack` for the pack, as `hunt_runs.query` stores it. */
const QUERY =
  "SELECT actor_user_name, COUNT(*) AS event_count, COUNT(DISTINCT src_endpoint_location_country) AS principals, MIN(time) AS first_seen, MAX(time) AS last_seen, MAX(event_uid) AS event_uid FROM ocsf_events WHERE tenant_id = :tenant_id AND time >= :baseline_start AND ingested_at < :ingested_to AND LOWER(metadata_product) IN (:p8) AND (((LOWER(api_operation) = :p1 OR LOWER(api_operation) = :p2 OR LOWER(api_operation) = :p3 OR LOWER(api_operation) = :p4) AND LOWER(status) = :p5 AND LOWER(actor_user_type) = :p6 AND src_endpoint_location_country IS NOT NULL) AND (NOT COALESCE((LOWER(JSON_EXTRACT_SCALAR(raw, '$.securityContext.isProxy')) = :p7), FALSE))) GROUP BY actor_user_name HAVING COUNT(DISTINCT src_endpoint_location_country) >= 2 AND MAX(ingested_at) >= :ingested_from ORDER BY COUNT(*) DESC LIMIT 500";

/** The run as the play has reached it: no parameters, and the strip stands in for the ruled-out step. */
function huntRun(start: number, shown: number): TraceRun {
  return {
    chosen_because:
      "tests 'A stolen session used from a second country' ('Session cookies stolen from Okta tenants')",
    query: QUERY,
    rows: 3,
    ran_at: at(start, 0),
    ingested_from: at(start, -1440),
    ingested_to: at(start, 0),
    duration_ms: 840,
    ruled_out: [],
    unseen: [],
    outcome: "suspicious",
    triage:
      "bob@example.com signed in from FR, then from 198.51.100.4 in VN two hours later. No travel, VPN or second device explains it.",
    finding_uid: shown >= 4 ? "F-3c91d0a47be25f6e18a0c4d2" : "",
    error: "",
  };
}

export function HuntFlow() {
  return (
    <Played
      label="Hunt run"
      about="The Hunter runs a hunt picked from this week's intel, rules out two accounts and raises a finding on the third."
      level={3}
      title="Somebody signs in to Okta from two countries on the same day"
      id={PACK}
      aside={<AvatarStack who={["Hunter"]} />}
      total={4}
      render={(shown, start) => ({
        head: (
          <>
            {/* The Hunts screen's words: running, then the outcome; its counts stand in for the rows and ruled-out steps. */}
            <Strip
              state={
                shown >= 3
                  ? { tone: "warn", word: "Suspicious" }
                  : { tone: "idle", word: "Running" }
              }
              facts={[
                { label: "rows", value: fade(shown >= 2 ? 3 : null) },
                { label: "ruled out", value: fade(shown >= 3 ? 2 : null) },
                { label: "finding", value: fade(shown >= 4 ? 1 : null) },
              ]}
            />
          </>
        ),
        body: shown ? (
          // RunTrace draws a finished run; the play shows why it ran, the query, the outcome, then
          // the finding (`.sh-play__run`).
          <div className="sh-play__run" data-shown={shown}>
            <RunTrace run={huntRun(start, shown)} />
          </div>
        ) : null,
      })}
    />
  );
}

/* -- a backlog item -------------------------------------------------------------- */

const RULE = "github_mass_clone";
const RULE_TITLE = "One account cloned ten or more private repositories in ten minutes";

function backlogItem(start: number, shown: number): BacklogItem {
  return {
    item_uid: "DBL-9e04b7c2d15a83f6e0b1",
    rule_id: RULE,
    kind: "defect",
    intake: "health",
    title: `${RULE}: over its volume`,
    reason: "31 findings in 7 days across 4 case(s); the threshold may be low for this tenant",
    priority: 3,
    observability: "have",
    evidence: {
      findings_7d: 31,
      dominant_entity: "ci-bot",
      ...(shown >= 2 ? { worked_at: at(start, 2), tries: 1, tokens_today: 8400 } : {}),
      ...(shown >= 3
        ? {
            decision: "merged",
            rule_id: RULE,
            because:
              "29 of 31 findings are ci-bot cloning from 192.0.2.10 for the nightly build. Narrowed to skip that account on that address; over 30 days the rule keeps the 2 other findings.",
          }
        : {}),
    },
    case_uid: "",
    state: shown >= 3 ? "done" : "open",
    created_at: at(start, 0),
    decided_at: shown >= 3 ? at(start, 3) : null,
  };
}

export function RuleFlow() {
  return (
    <Played
      label="Backlog item"
      about="The Detection Engineer narrows a noisy rule, backtests it over 30 days and merges it."
      level={3}
      title={`Noisy: ${RULE_TITLE}`}
      id="DBL-9e04…"
      aside={
        <>
          <AvatarStack who={["Detection Engineer"]} />
          <Priority value={3} />
        </>
      }
      total={4}
      render={(shown, start) => {
        const item = backlogItem(start, shown);
        return {
          body: (
            <>
              {shown ? (
                <Story
                  steps={story(
                    item,
                    () => undefined,
                    (id) => (id === RULE ? RULE_TITLE : undefined),
                  )}
                />
              ) : null}
              {shown >= 4 ? (
                <Quote by="Detection Engineer" crew label="because">
                  {String(item.evidence.because)}
                </Quote>
              ) : null}
            </>
          ),
        };
      }}
    />
  );
}

/* -- a source -------------------------------------------------------------------- */

const SUPPORTS = Array.from({ length: 17 }, (_, i) => `rule_${i}`);

/** `source.sample`: a page as Cloudflare's Logpush writes it, the dataset tag the connector adds. */
const SAMPLE = {
  source: "cloudflare_logs",
  ok: true,
  fetched: 200,
  rows: [
    {
      ClientIP: "203.0.113.24",
      ClientRequestHost: "app.example.com",
      EdgeResponseStatus: 200,
      _dataset: "http_requests",
    },
    {
      ClientIP: "198.51.100.7",
      ClientRequestHost: "api.example.com",
      EdgeResponseStatus: 403,
      _dataset: "http_requests",
    },
    {
      ClientIP: "192.0.2.41",
      ClientRequestHost: "app.example.com",
      EdgeResponseStatus: 200,
      _dataset: "http_requests",
    },
    {
      ClientIP: "203.0.113.90",
      ClientRequestHost: "api.example.com",
      EdgeResponseStatus: 429,
      _dataset: "http_requests",
    },
  ],
  unmapped_fields: [],
  needs: "",
  error: "",
};

/** Discover, then prove (the sample mapped, the rules it can carry), then done (its first finding). */
function onboarding(shown: number): Onboarding {
  return {
    source: "cloudflare_logs",
    step: shown >= 2 ? "done" : shown >= 1 ? "prove" : "discover",
    dark: false,
    scopes: [],
    click_path: "",
    supports: shown >= 1 ? SUPPORTS : [],
    cannot_support: shown >= 1 ? ["dns", "email"] : [],
    proof_finding: shown >= 2 ? "F-a71e2c9b05d4f83e6c1b7a20" : null,
  };
}

export function SourceFlow() {
  return (
    <Played
      label="Source"
      about="The Integrator samples Cloudflare logs, lists the 17 rules they can carry and proves them with a first finding."
      level={3}
      title={
        <span className="inline-flex items-center gap-2">
          <ProductLogo product="cloudflare" size={16} />
          Cloudflare logs
        </span>
      }
      id="cloudflare_logs"
      aside={<AvatarStack who={["Integrator"]} />}
      total={4}
      render={(shown, start) => {
        const o = onboarding(shown);
        // The dialog's own views: Onboarding while the Integrator works, Delivery once events flow.
        const view = shown >= 3 ? "delivery" : "onboarding";
        const word = shown >= 2 ? "delivering" : "waiting";
        return {
          head: (
            <span className="flex flex-wrap items-center justify-between gap-2">
              <Seg
                label="View"
                value={view}
                onChange={() => undefined}
                options={[
                  { value: "delivery", label: "Delivery" },
                  { value: "settings", label: "Settings" },
                  { value: "onboarding", label: "Onboarding" },
                  { value: "footprint", label: "shoc's own" },
                ]}
              />
              <Status tone={deliveryTone(word)} badge>
                {fade(word)}
              </Status>
            </span>
          ),
          body:
            view === "onboarding" ? (
              <>
                <Steps steps={onboardingSteps(o.step)} label="Onboarding" />
                <Fields
                  ruled
                  rows={[
                    ["Supports", o.supports.length ? `${o.supports.length} rules` : null],
                    [
                      "Cannot",
                      o.cannot_support.length ? `${o.cannot_support.length} kinds of rule` : null,
                    ],
                    [
                      "Proof",
                      o.proof_finding ? (
                        <Link to={`/findings/${o.proof_finding}`} className="sh-mono underline">
                          {o.proof_finding}
                        </Link>
                      ) : null,
                    ],
                  ]}
                />
              </>
            ) : (
              <>
                <Fields
                  ruled
                  rows={[
                    ["Last run", `${stamp(at(start, 5))} · just now`],
                    ["Last ok", `${stamp(at(start, 5))} · just now`],
                    ["Every", "5m"],
                    ["Events", fade(shown >= 4 ? "18,240" : "1,204")],
                  ]}
                />
                <div className="min-w-0 overflow-x-auto">
                  <Sample data={SAMPLE} />
                </div>
              </>
            ),
        };
      }}
    />
  );
}
