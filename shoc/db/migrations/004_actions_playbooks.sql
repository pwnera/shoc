-- 004 response: proposed actions, approvals and playbook runs (RSP-2, RSP-3, RSP-4)

CREATE TABLE IF NOT EXISTS shoc.actions (
    action_uid   text PRIMARY KEY,
    tenant_id    text NOT NULL,
    case_uid     text REFERENCES shoc.cases(case_uid) ON DELETE SET NULL,
    run_uid      text,
    type         text NOT NULL,
    target       text NOT NULL DEFAULT '',
    params       jsonb NOT NULL DEFAULT '{}'::jsonb,
    autonomy     text NOT NULL DEFAULT 'L2',
    state        text NOT NULL DEFAULT 'proposed',
    reversible   boolean NOT NULL DEFAULT true,
    dry_run      boolean NOT NULL DEFAULT true,
    rationale    text NOT NULL DEFAULT '',
    requested_by text NOT NULL DEFAULT '',
    approved_by  text,
    approved_at  timestamptz,
    executed_at  timestamptz,
    result       jsonb NOT NULL DEFAULT '{}'::jsonb,
    undo         jsonb NOT NULL DEFAULT '{}'::jsonb,
    error        text,
    idempotency_key text UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT action_state CHECK (state IN (
        'proposed','approved','rejected','running','done','failed','rolled_back','blocked'))
);
CREATE INDEX IF NOT EXISTS actions_tenant_state ON shoc.actions (tenant_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS actions_case ON shoc.actions (case_uid);

CREATE TABLE IF NOT EXISTS shoc.playbook_runs (
    run_uid      text PRIMARY KEY,
    tenant_id    text NOT NULL,
    case_uid     text REFERENCES shoc.cases(case_uid) ON DELETE CASCADE,
    playbook_id  text NOT NULL,
    state        text NOT NULL DEFAULT 'running',
    step_index   integer NOT NULL DEFAULT 0,
    context      jsonb NOT NULL DEFAULT '{}'::jsonb,
    dry_run      boolean NOT NULL DEFAULT true,
    started_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    error        text,
    CONSTRAINT run_state CHECK (state IN (
        'running','waiting_approval','waiting_timer','done','failed','cancelled'))
);
CREATE INDEX IF NOT EXISTS runs_tenant ON shoc.playbook_runs (tenant_id, started_at DESC);

CREATE TABLE IF NOT EXISTS shoc.playbook_steps (
    run_uid      text NOT NULL REFERENCES shoc.playbook_runs(run_uid) ON DELETE CASCADE,
    step_index   integer NOT NULL,
    name         text NOT NULL,
    action_type  text NOT NULL DEFAULT '',
    state        text NOT NULL DEFAULT 'pending',
    action_uid   text,
    attempts     integer NOT NULL DEFAULT 0,
    result       jsonb NOT NULL DEFAULT '{}'::jsonb,
    error        text,
    started_at   timestamptz,
    finished_at  timestamptz,
    PRIMARY KEY (run_uid, step_index)
);

-- Credentials the playbook runner uses to act. Agents never read this table;
-- only the runner and the capability that writes it do (principle 5).
CREATE TABLE IF NOT EXISTS shoc.action_credentials (
    tenant_id  text NOT NULL,
    provider   text NOT NULL,
    settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, provider)
);
