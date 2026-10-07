/**
 * The way in.
 *
 * The console keeps no credential: the kernel's sign-in (RFC 0028) sets an
 * HttpOnly session cookie, and `user.me` says whether this browser has one.
 * `/welcome` takes invitation and reset links before anything else. Signed
 * out, the first paint is the front page: the headline beside a case the crew
 * works live, then a section per workflow (a hunt, a rule tuned, a source
 * onboarded), each card drawn as its own screen draws it (`Workflows.tsx`),
 * then the sources, the autonomy levels and the install snippets. Log in
 * goes to `/login`. Any other address signed out, and an SSO callback that came
 * back with `?signin=<problem>`, opens the login page there, and signing in
 * opens the console at that address (`/login` gives way to `/`). When shoc
 * cannot be reached the console opens and its banner says so.
 *
 * Capabilities used: user.me (the check).
 */
import {
  Fragment,
  Suspense,
  useCallback,
  useEffect,
  useState,
  type MouseEvent,
  type ReactNode,
} from "react";
import {
  Box,
  Check,
  ChevronDown,
  ChevronsRight,
  Crosshair,
  Github,
  Globe,
  Moon,
  Plug,
  Radar,
  ScrollText,
  Server,
  SlidersHorizontal,
  Sun,
  Telescope,
  Undo2,
  Zap,
} from "lucide-react";
import { ApiError, call } from "@/lib/api";
import { cn } from "@/lib/cn";
import { actionLabel } from "@/lib/labels";
import { takeSigninProblem } from "@/lib/signin";
import { lazyNamed } from "@/lib/stale";
import { useTheme } from "@/lib/theme";
import { ROLES } from "@/lib/crew";
import { BRANDS, type Brand } from "./brands";
import { ErrorBoundary } from "./ErrorBoundary";
import { SignIn } from "./SignIn";
import { AvatarStack } from "./ui/avatar";
import { Button } from "./ui/button";
import { Card, CardBody, CardHeader } from "./ui/card";
import { Copy } from "./ui/field";
import { Seg } from "./ui/seg";
import { PageSkeleton, Skel } from "./ui/state";
import { AutonomyBadge, Status } from "./ui/status";
import { Welcome } from "./Welcome";

/* The played cards and the screens' parts they borrow load with the front page, not the console. */
const CaseFlow = lazyNamed(() => import("./Workflows"), "CaseFlow");
const HuntFlow = lazyNamed(() => import("./Workflows"), "HuntFlow");
const RuleFlow = lazyNamed(() => import("./Workflows"), "RuleFlow");
const SourceFlow = lazyNamed(() => import("./Workflows"), "SourceFlow");

const REPO = "https://github.com/pwnera/shoc";

const SNIPPETS = {
  "self-host": `git clone ${REPO}.git && cd shoc/deploy
cp .env.example .env
docker compose run --rm shoc keygen
docker compose up -d`,
  claude: `{ "mcpServers": { "shoc": { "command": "shoc", "args": ["mcp"] } } }`,
};
type Snippet = keyof typeof SNIPPETS;

const AGENTS: Brand[] = [BRANDS.claude, BRANDS.chatgpt, BRANDS.cursor];
const FACTS = ["Apache 2.0", "Self-hosted", "Postgres only"];
const HOW = [
  { title: "Deploy", line: "One container and Postgres, on your own server." },
  { title: "Connect", line: "Add your identity, email, endpoint and cloud sources." },
  {
    title: "Hand over",
    line: "The crew detects, investigates and contains, and pages you when a person must decide.",
  },
];
/* The architecture's principles (docs/architecture.md), as the operator meets them. */
const GUARANTEES = [
  {
    icon: ScrollText,
    title: "Evidence or nothing",
    line: "Every verdict cites the events behind it. One without evidence goes to a person.",
  },
  {
    icon: Undo2,
    title: "Reversible or approved",
    line: "Agents only read. Each action can be undone or waits for a person, and all are audited.",
  },
  {
    icon: Server,
    title: "Your server, your model",
    line: "Logs stay in your Postgres. The crew uses Anthropic, OpenAI or any compatible endpoint.",
  },
];
/* What the crew does, for the login page, each with its screen's icon (`lib/nav.ts`); tuning, in Detection, has its own. */
const FEATURES = [
  { icon: Crosshair, title: "Detection" },
  { icon: Radar, title: "Triage" },
  { icon: Box, title: "Investigation" },
  { icon: Zap, title: "Response" },
  { icon: Telescope, title: "Hunting" },
  { icon: Globe, title: "Threat intel" },
  { icon: SlidersHorizontal, title: "Rule tuning" },
  { icon: Plug, title: "Source onboarding" },
];
const FAQ = [
  {
    q: "Do I need a security team?",
    a: "No. shoc is for teams with few resources or no security specialist, and it needs little upkeep. It still needs one person to approve critical actions, such as suspending a user, isolating a laptop or resetting a password. shoc pages that person when one is waiting.",
  },
  {
    q: "Where do my logs go?",
    a: "Into your own Postgres, or Databricks, Snowflake, Redshift or BigQuery if you use them. The model sees the events of the case it works on, quoted as data.",
  },
  {
    q: "Can it break something?",
    a: "Agents only read. Playbooks act under a policy per action: notify, act and keep the undo, or wait for a person. Every action is audited.",
  },
  {
    q: "Which model does it use?",
    a: "The one you configure: Anthropic, OpenAI or any OpenAI-compatible endpoint. Each case has a token cap.",
  },
  {
    q: "What does it cost?",
    a: "shoc is free under Apache 2.0. You pay for your server and your model provider.",
  },
];
const FOOTER = [
  { label: "Docs", href: `${REPO}/tree/main/docs` },
  { label: "GitHub", href: REPO },
  { label: "Security", href: `${REPO}/blob/main/SECURITY.md` },
  { label: "Contributing", href: `${REPO}/blob/main/CONTRIBUTING.md` },
  { label: "License", href: `${REPO}/blob/main/LICENSE` },
];
const SOURCES: Brand[] = [
  BRANDS.okta,
  BRANDS.entra,
  BRANDS.workspace,
  BRANDS.m365,
  BRANDS.defender,
  BRANDS.crowdstrike,
  BRANDS.sentinelone,
  BRANDS.wazuh,
  BRANDS.aws,
  BRANDS.azure,
  BRANDS.gcp,
  BRANDS.cloudflare,
  BRANDS.github,
  BRANDS.gitlab,
  BRANDS.tailscale,
  BRANDS.stripe,
];

/* The workflows below the headline, each beside what it does; the card alternates sides, the case's being on the right. */
const SECTIONS = [
  {
    key: "hunt",
    heading: "Hunts every day",
    line: "This week's intel picks the hunts, and anything suspicious becomes a finding.",
    card: <HuntFlow />,
  },
  {
    key: "rule",
    heading: "Tunes its own rules",
    line: "A noisy rule is narrowed, backtested and merged overnight, and reverted if it turns noisy again.",
    card: <RuleFlow />,
  },
  {
    key: "source",
    heading: "Onboards a source by itself",
    line: "Connect it once. The Integrator samples it, keeps every field and lists the rules it can carry.",
    card: <SourceFlow />,
  },
];

const LEVELS = [
  { level: "L0", example: actionLabel("notify.page") },
  { level: "L1", example: actionLabel("aws.disable_access_key") },
  { level: "L2", example: actionLabel("okta.suspend_user") },
];

export function TokenGate({ children }: { children: ReactNode }) {
  if (window.location.pathname === "/welcome") return <Welcome />;
  return <Gate>{children}</Gate>;
}

/** Signed in when user.me answers; refused, the front page at `/` and the login page elsewhere; unreachable, the console and its banner. */
function Gate({ children }: { children: ReactNode }) {
  const [problem] = useState(takeSigninProblem);
  const [state, setState] = useState<"probing" | "in" | "out">("probing");
  const probe = useCallback(() => {
    const settle = (next: "in" | "out") => {
      if (next === "in" && window.location.pathname === "/login") history.replaceState(null, "", "/");
      setState(next);
    };
    call("user.me").then(
      () => settle("in"),
      (error: unknown) => settle(error instanceof ApiError && error.isAuth ? "out" : "in"),
    );
  }, []);
  useEffect(probe, [probe]);
  if (state === "in") return <>{children}</>;
  if (state === "out")
    return window.location.pathname === "/" && !problem ? (
      <Landing />
    ) : (
      <Login problem={problem} onSignedIn={probe} />
    );
  // The shell's page padding around the skeleton the console's first screen would show.
  return (
    <div className="sh-shell__page">
      <PageSkeleton />
    </div>
  );
}

function Landing() {
  const [snippet, setSnippet] = useState<Snippet>("self-host");

  function start() {
    setSnippet("self-host");
    document.getElementById("start")?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  /** The header's anchors scroll smoothly instead of jumping. */
  function go(event: MouseEvent<HTMLAnchorElement>) {
    const id = event.currentTarget.hash.slice(1);
    const target = document.getElementById(id);
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <div className="min-h-dvh bg-bg-0">
      <header className="sticky top-0 z-20 border-b border-line-1 bg-bg-0">
        <div className="mx-auto flex h-12 max-w-6xl items-center justify-between gap-2 px-4 sm:px-6">
          <span className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="h-7 w-7" />
            <span className="text-[13px] font-semibold text-fg-1">shoc</span>
          </span>
          <nav className="flex items-center gap-2">
            {[
              ["#how", "How it works"],
              ["#sources", "Sources"],
              ["#faq", "Questions"],
            ].map(([href, label]) => (
              <a
                key={href}
                href={href}
                onClick={go}
                className="sh-btn sh-btn--ghost sh-btn--md hidden lg:inline-flex"
              >
                {label}
              </a>
            ))}
            <a
              href={`${REPO}/tree/main/docs`}
              className="sh-btn sh-btn--ghost sh-btn--md hidden sm:inline-flex"
            >
              Docs
            </a>
            <a
              href={REPO}
              aria-label="GitHub"
              className="sh-btn sh-btn--ghost sh-btn--icon hidden sm:inline-flex"
            >
              <Github aria-hidden />
            </a>
            <ThemeButton />
            <a href="/login" className="sh-btn sh-btn--ghost sh-btn--md">
              Log in
            </a>
            <Button variant="primary" onClick={start}>
              Start
              <ChevronsRight aria-hidden />
            </Button>
          </nav>
        </div>
      </header>

      <main className="mx-auto flex max-w-6xl flex-col gap-4 px-4 sm:px-6">
        <section className="grid items-center gap-10 py-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,520px)] lg:py-20">
          <div className="flex flex-col items-start gap-6">
            <Status tone="running" badge>
              on shift · 24/7
            </Status>
            <h1 className="m-0 text-balance text-4xl font-bold leading-none tracking-[-0.03em] text-fg-1 sm:text-[56px] sm:leading-[56px]">
              Your security team,
              <br />
              <span className="text-crew">run by agents.</span>
            </h1>
            <p className="m-0 max-w-md text-pretty text-base text-fg-3">
              Reads your logs around the clock, contains what it can undo, and pages you for the
              rest.
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
              <Button variant="primary" onClick={start} className="h-10 px-5">
                Start
                <ChevronsRight aria-hidden />
              </Button>
              <span className="flex items-center gap-2">
                <span className="sh-label">Works with</span>
                {AGENTS.map((agent) => (
                  <img
                    key={agent.label}
                    src={agent.src}
                    alt={agent.label}
                    title={agent.label}
                    className="sh-logo h-4 w-4"
                  />
                ))}
              </span>
            </div>
            <ul className="sh-mono m-0 flex list-none flex-wrap gap-x-4 gap-y-1 p-0">
              {FACTS.map((fact) => (
                <li key={fact} className="inline-flex items-center gap-1.5">
                  <Check className="h-3.5 w-3.5 text-fg-4" aria-hidden />
                  {fact}
                </li>
              ))}
            </ul>
          </div>
          <Flow>
            <CaseFlow />
          </Flow>
        </section>

        <section
          id="how"
          aria-label="How it works"
          className="grid scroll-mt-16 gap-6 border-t border-line-1 py-12 md:grid-cols-3"
        >
          {HOW.map((step, i) => (
            <div key={step.title} className="flex flex-col gap-2">
              <span className="sh-index">{String(i + 1).padStart(2, "0")}</span>
              <h2 className="m-0 text-[15px] font-semibold text-fg-1">{step.title}</h2>
              <p className="m-0 max-w-xs text-pretty text-sm text-fg-3">{step.line}</p>
            </div>
          ))}
        </section>

        {SECTIONS.map((section, i) => (
          <section
            key={section.key}
            className="grid items-center gap-6 py-10 lg:grid-cols-2 lg:gap-16 lg:py-16"
          >
            <div className={cn("flex flex-col gap-3", i % 2 === 0 && "lg:order-2")}>
              <h2 className="m-0 text-balance text-2xl font-semibold tracking-[-0.02em] text-fg-1 sm:text-[32px] sm:leading-[36px]">
                {section.heading}
              </h2>
              <p className="m-0 max-w-md text-pretty text-base text-fg-3">{section.line}</p>
            </div>
            <Flow>{section.card}</Flow>
          </section>
        ))}

        <section
          aria-label="Guarantees"
          className="grid gap-8 border-t border-line-1 py-12 md:grid-cols-3"
        >
          {GUARANTEES.map(({ icon: Icon, title, line }) => (
            <div key={title} className="flex flex-col gap-2">
              <span className="inline-flex h-7 w-7 items-center justify-center rounded-control border border-line-1 text-fg-2">
                <Icon className="h-3.5 w-3.5" aria-hidden />
              </span>
              <h2 className="m-0 text-[15px] font-semibold text-fg-1">{title}</h2>
              <p className="m-0 max-w-xs text-pretty text-sm text-fg-3">{line}</p>
            </div>
          ))}
        </section>

        <div className="grid gap-4 md:grid-cols-2">
          <Card id="sources" className="scroll-mt-16 md:col-span-2">
            <CardHeader title="Sources" subtitle={SOURCES.length} />
            <CardBody>
              <ul className="m-0 grid list-none grid-cols-2 gap-x-3 gap-y-2 p-0 sm:grid-cols-4 lg:grid-cols-8">
                {SOURCES.map((source) => (
                  <li key={source.label} className="flex min-w-0 items-center gap-2 text-fg-2">
                    <img src={source.src} alt={source.label} className="sh-logo h-4 w-4" />
                    <span className="truncate text-[12px]" aria-hidden>
                      {source.label}
                    </span>
                  </li>
                ))}
              </ul>
            </CardBody>
          </Card>
          <Card>
            <CardHeader title="Autonomy" subtitle={LEVELS.length} />
            <CardBody className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-x-3 gap-y-2">
              {LEVELS.map(({ level, example }) => (
                <Fragment key={level}>
                  <span>
                    <AutonomyBadge level={level} />
                  </span>
                  <span className="sh-mono">{example}</span>
                </Fragment>
              ))}
            </CardBody>
          </Card>
          <Card id="start">
            <CardHeader
              title="Install"
              action={
                <Seg
                  label="Install"
                  value={snippet}
                  onChange={setSnippet}
                  options={Object.keys(SNIPPETS) as Snippet[]}
                />
              }
            />
            <CardBody>
              <Copy block value={SNIPPETS[snippet]} label={`Copy the ${snippet} snippet`} />
            </CardBody>
          </Card>
        </div>

        <section
          id="faq"
          className="mt-12 grid scroll-mt-16 gap-6 border-t border-line-1 py-12 lg:grid-cols-[1fr_2fr]"
        >
          <h2 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-fg-1 sm:text-[32px] sm:leading-[36px]">
            Questions
          </h2>
          <div className="border-t border-line-1">
            {FAQ.map(({ q, a }) => (
              <details key={q} className="group border-b border-line-1">
                <summary className="flex cursor-pointer list-none items-center justify-between gap-4 py-3 text-[15px] font-medium text-fg-1 [&::-webkit-details-marker]:hidden">
                  {q}
                  <ChevronDown
                    className="h-4 w-4 shrink-0 text-fg-4 transition-transform group-open:rotate-180"
                    aria-hidden
                  />
                </summary>
                <p className="m-0 max-w-2xl pb-4 text-pretty text-sm text-fg-3">{a}</p>
              </details>
            ))}
          </div>
        </section>

        <section className="flex flex-col items-start gap-6 border-t border-line-1 py-16 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="m-0 text-balance text-2xl font-semibold tracking-[-0.02em] text-fg-1 sm:text-[32px] sm:leading-[36px]">
            Run shoc on your own server.
          </h2>
          <div className="flex items-center gap-2">
            <a href={`${REPO}/tree/main/docs`} className="sh-btn sh-btn--ghost sh-btn--md">
              Read the docs
            </a>
            <Button variant="primary" onClick={start} className="h-10 px-5">
              Start
              <ChevronsRight aria-hidden />
            </Button>
          </div>
        </section>
      </main>

      <footer className="border-t border-line-1">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-6 sm:px-6">
          <span className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="h-5 w-5" />
            <span className="text-[13px] font-semibold text-fg-1">shoc</span>
            <span className="sh-mono">v0.0.1 · Apache 2.0</span>
          </span>
          <nav aria-label="Project" className="flex flex-wrap items-center gap-x-4 gap-y-1">
            {FOOTER.map((link) => (
              <a key={link.label} href={link.href} className="text-sm text-fg-3 hover:text-fg-1">
                {link.label}
              </a>
            ))}
          </nav>
        </div>
      </footer>
    </div>
  );
}

/**
 * A played card as it loads, at its own height (a 32px head over a 360px body); one that
 * fails to load leaves its place empty.
 */
function Flow({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary quiet>
      <Suspense fallback={<Skel kind="block" className="h-[394px]" />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

/** The form, and beside it from 1024px the headline, the crew waiting, and what it does. */
function Login({ problem, onSignedIn }: { problem: string; onSignedIn: () => void }) {
  return (
    <div className="grid min-h-dvh bg-bg-0 lg:grid-cols-2">
      <div className="flex flex-col px-4 sm:px-6">
        <header className="flex h-12 items-center justify-between gap-2">
          <a href="/" className="flex items-center gap-2">
            <img src="/favicon.svg" alt="" className="h-7 w-7" />
            <span className="text-[13px] font-semibold text-fg-1">shoc</span>
          </a>
          <span className="flex items-center gap-2">
            <a href={`${REPO}/tree/main/docs`} className="sh-btn sh-btn--ghost sh-btn--md">
              Docs
            </a>
            <ThemeButton />
          </span>
        </header>
        <main className="flex flex-1 items-center justify-center py-12">
          <div className="flex w-full max-w-[360px] flex-col gap-6">
            <div className="flex min-w-0 flex-col gap-1">
              <h1 className="m-0 text-2xl font-semibold tracking-[-0.02em] text-fg-1">Log in</h1>
              <span className="sh-mono truncate">{window.location.host}</span>
            </div>
            <SignIn problem={problem} onSignedIn={onSignedIn} />
            <p className="m-0 border-t border-line-1 pt-4 text-sm text-fg-3">
              No account? Ask an admin to invite you.
            </p>
          </div>
        </main>
      </div>
      <aside className="hidden items-center justify-center border-l border-line-1 bg-bg-1 p-12 lg:flex">
        <div className="flex w-full max-w-md flex-col gap-10">
          <p className="m-0 text-balance text-[40px] font-bold leading-[44px] tracking-[-0.03em] text-fg-1">
            Your security team,
            <br />
            <span className="text-crew">run by agents.</span>
          </p>
          <p className="m-0 flex items-center gap-3 text-base text-fg-2">
            <span aria-hidden>
              <AvatarStack who={ROLES.map((role) => role.name)} max={4} size={24} tip={false} />
            </span>
            {ROLES.length} roles, on shift day and night.
          </p>
          <ul className="m-0 grid list-none grid-cols-2 gap-x-6 gap-y-4 border-t border-line-1 p-0 pt-8">
            {FEATURES.map(({ icon: Icon, title }) => (
              <li key={title} className="flex items-center gap-3 text-[15px] font-medium text-fg-1">
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-control border border-line-1 text-fg-2">
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                </span>
                {title}
              </li>
            ))}
          </ul>
        </div>
      </aside>
    </div>
  );
}

/** Light or dark, the console's own setting (`lib/theme`): it shows the mode it switches to. */
function ThemeButton() {
  const [mode, setMode] = useTheme();
  const dark =
    mode === "dark" ||
    (mode === "system" &&
      typeof matchMedia === "function" &&
      matchMedia("(prefers-color-scheme: dark)").matches);
  const Icon = dark ? Sun : Moon;
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={dark ? "Light mode" : "Dark mode"}
      onClick={() => setMode(dark ? "light" : "dark")}
    >
      <Icon aria-hidden />
    </Button>
  );
}
