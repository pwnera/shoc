-- 013 Daily behavioural hunting (DET-8, DET-9, DET-11, RFC 0005)
--
-- What the code did before was indicator search wearing a hunting label: take
-- one value, look for it. A hunt asks whether a *behaviour* is happening here,
-- and it is a success when the answer is no — which is why a run that finds
-- nothing still has to be written down. Coverage you cannot point at is a
-- feeling.

-- One row per pack, per tenant: when it last ran, what it concluded, and how
-- long it has been waiting. Coverage debt is a query over this table.
CREATE TABLE IF NOT EXISTS shoc.hunt_packs (
    tenant_id    text NOT NULL,
    pack_id      text NOT NULL,
    last_run_at  timestamptz,
    last_outcome text NOT NULL DEFAULT '',
    runs         integer NOT NULL DEFAULT 0,
    true_positives integer NOT NULL DEFAULT 0,  -- twice, and it should become a rule
    cadence_days integer NOT NULL DEFAULT 7,
    enabled      boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id, pack_id)
);
CREATE INDEX IF NOT EXISTS hunt_packs_due ON shoc.hunt_packs (tenant_id, last_run_at);

-- One row per run. `chosen_because` is the honest record of why this pack ran
-- today rather than another: selection is a ranked query, and it must be
-- possible to argue with its ranking afterwards.
CREATE TABLE IF NOT EXISTS shoc.hunt_runs (
    run_uid      text PRIMARY KEY,
    tenant_id    text NOT NULL,
    pack_id      text NOT NULL,
    ran_at       timestamptz NOT NULL DEFAULT now(),
    window_start timestamptz,
    window_end   timestamptz,
    outcome      text NOT NULL DEFAULT 'clear',  -- clear | explained | suspicious | gap
    rows_returned integer NOT NULL DEFAULT 0,
    chosen_because text NOT NULL DEFAULT '',
    rank         integer NOT NULL DEFAULT 0,
    triage       text NOT NULL DEFAULT '',       -- what the model said, if one ran
    model        text NOT NULL DEFAULT 'none',
    tokens       integer NOT NULL DEFAULT 0,
    case_uid     text NOT NULL DEFAULT '',       -- opened when the outcome is suspicious
    error        text NOT NULL DEFAULT '',
    duration_ms  integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS hunt_runs_tenant ON shoc.hunt_runs (tenant_id, ran_at DESC);
CREATE INDEX IF NOT EXISTS hunt_runs_pack ON shoc.hunt_runs (tenant_id, pack_id, ran_at DESC);

-- The rows a run surfaced, with the event UIDs behind them. Evidence or
-- nothing applies to a hunt exactly as it does to a verdict.
CREATE TABLE IF NOT EXISTS shoc.hunt_observations (
    observation_uid text PRIMARY KEY,
    tenant_id    text NOT NULL,
    run_uid      text NOT NULL,
    pack_id      text NOT NULL,
    entity       text NOT NULL DEFAULT '',
    summary      text NOT NULL DEFAULT '',
    row_data     jsonb NOT NULL DEFAULT '{}'::jsonb,
    event_uids   text[] NOT NULL DEFAULT '{}',
    verdict      text NOT NULL DEFAULT 'unreviewed',  -- unreviewed | explained | suspicious
    seen_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hunt_observations_run ON shoc.hunt_observations (tenant_id, run_uid);

-- The backlog (TaHiTI): a hunt starts as a trigger written up as an abstract,
-- prioritised against every other candidate. This is also where "we read about
-- this and cannot look for it" is recorded honestly, as a coverage gap.
--
-- It is not public beyond the security function: it contains hypotheses about
-- active adversaries, including insiders.
CREATE TABLE IF NOT EXISTS shoc.hunt_backlog (
    item_uid     text PRIMARY KEY,
    tenant_id    text NOT NULL,
    trigger      text NOT NULL DEFAULT 'cti',    -- cti | case | rehearsal | source | human
    title        text NOT NULL DEFAULT '',
    hypothesis   text NOT NULL DEFAULT '',
    would_confirm text NOT NULL DEFAULT '',
    data_needed  text NOT NULL DEFAULT '',
    why_now      text NOT NULL DEFAULT '',
    attack       text[] NOT NULL DEFAULT '{}',
    pack_id      text NOT NULL DEFAULT '',       -- set once a pack exists for it
    priority     integer NOT NULL DEFAULT 3,
    state        text NOT NULL DEFAULT 'open',   -- open | packed | rejected | done
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz,
    decided_by   text
);
CREATE INDEX IF NOT EXISTS hunt_backlog_open ON shoc.hunt_backlog (tenant_id, state, priority);

SELECT shoc.enable_tenant_rls();
