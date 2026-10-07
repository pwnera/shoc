import { Suspense } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Shell } from "./components/Shell";
import { TokenGate } from "./components/TokenGate";
import { NotFound } from "./components/ErrorBoundary";
import { Announcer } from "./components/ui/misc";
import { PageSkeleton } from "./components/ui/state";
import { ApiError } from "./lib/api";
import { lazyNamed } from "./lib/stale";

/*
 * Each screen is its own chunk, loaded on first visit; the shell, the palette,
 * the chat and the shared dialogs stay in the main one.
 */
const Overview = lazyNamed(() => import("./routes/Overview"), "Overview");
const Cases = lazyNamed(() => import("./routes/Cases"), "Cases");
const CaseDetail = lazyNamed(() => import("./routes/CaseDetail"), "CaseDetail");
const Findings = lazyNamed(() => import("./routes/Findings"), "Findings");
const Finding = lazyNamed(() => import("./routes/Finding"), "Finding");
const Explore = lazyNamed(() => import("./routes/Explore"), "Explore");
const Detection = lazyNamed(() => import("./routes/Detection"), "Detection");
const Rule = lazyNamed(() => import("./routes/Rule"), "Rule");
const Response = lazyNamed(() => import("./routes/Response"), "Response");
const Playbook = lazyNamed(() => import("./routes/Playbook"), "Playbook");
const Hunts = lazyNamed(() => import("./routes/Hunts"), "Hunts");
const Intel = lazyNamed(() => import("./routes/Intel"), "Intel");
const Posture = lazyNamed(() => import("./routes/Posture"), "Posture");
const Coverage = lazyNamed(() => import("./routes/Coverage"), "Coverage");
const Memory = lazyNamed(() => import("./routes/Memory"), "Memory");
const Connections = lazyNamed(() => import("./routes/Connections"), "Connections");
const Health = lazyNamed(() => import("./routes/Health"), "Health");
const Measurement = lazyNamed(() => import("./routes/Measurement"), "Measurement");
const Access = lazyNamed(() => import("./routes/Access"), "Access");

const client = new QueryClient({
  defaultOptions: {
    queries: {
      // The stream refreshes what changes, so a minute-old answer on focus or mount is still current.
      staleTime: 60_000,
      retry: (failureCount, error) =>
        // A refusal (signed out, a missing record, a bad field) will be refused again; anything else gets two tries.
        error instanceof ApiError && (error.isAuth || (error.status >= 400 && error.status < 500)) ? false : failureCount < 2,
    },
  },
});

/** A renamed screen: an old link lands on the new path with its query (`/api?tab=audit`), which wins over the path's own. */
function Moved({ to }: { to: string }) {
  const { search } = useLocation();
  const [path = to, own] = to.split("?");
  const params = new URLSearchParams(own);
  for (const [k, v] of new URLSearchParams(search)) params.set(k, v);
  const query = params.toString();
  return <Navigate to={query ? `${path}?${query}` : path} replace />;
}

/* Paths as `lib/nav.ts` ROUTES lists them; `/health/jobs` is Health on its Jobs tab. */
export function App() {
  return (
    <QueryClientProvider client={client}>
      {/* The page's polite region, there for the signed-out pages too. */}
      <Announcer />
      <TokenGate>
        <BrowserRouter>
          <Shell>
            <Suspense fallback={<PageSkeleton />}>
              <Routes>
                <Route path="/" element={<Overview />} />
                <Route path="/cases" element={<Cases />} />
                <Route path="/cases/:caseUid" element={<CaseDetail />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/findings/:findingUid" element={<Finding />} />
                <Route path="/explore" element={<Explore />} />
                <Route path="/detection" element={<Detection />} />
                <Route path="/detection/rules/:ruleId" element={<Rule />} />
                <Route path="/response" element={<Response />} />
                <Route path="/response/playbooks/:playbookId" element={<Playbook />} />
                <Route path="/hunts" element={<Hunts />} />
                <Route path="/intel" element={<Intel />} />
                <Route path="/posture" element={<Posture />} />
                <Route path="/coverage" element={<Coverage />} />
                <Route path="/memory" element={<Memory />} />
                <Route path="/connections" element={<Connections />} />
                <Route path="/sources" element={<Moved to="/connections" />} />
                <Route path="/health" element={<Health />} />
                <Route path="/health/:tab" element={<Health />} />
                <Route path="/measurement" element={<Measurement />} />
                <Route path="/access" element={<Access />} />
                <Route path="/api" element={<Moved to="/access?tab=capabilities" />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
          </Shell>
        </BrowserRouter>
      </TokenGate>
    </QueryClientProvider>
  );
}
