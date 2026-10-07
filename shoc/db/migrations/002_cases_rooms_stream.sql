-- 002 cases, case rooms and the event stream (RSP-1, AGT-1, API-2)

-- NIST 800-61 states: triage -> analysis -> containment -> eradication ->
-- recovery -> post_incident -> closed. A case is the unit a human acts on.
CREATE TABLE IF NOT EXISTS shoc.cases (
    case_uid     text PRIMARY KEY,
    tenant_id    text NOT NULL,
    title        text NOT NULL,
    severity     text NOT NULL DEFAULT 'medium',
    state        text NOT NULL DEFAULT 'triage',
    verdict      text NOT NULL DEFAULT 'unknown',
    confidence   double precision NOT NULL DEFAULT 0.0,
    entity_key   text NOT NULL DEFAULT '',
    summary      text NOT NULL DEFAULT '',
    assignee     text,
    finding_uids text[] NOT NULL DEFAULT '{}',
    attack       text[] NOT NULL DEFAULT '{}',
    rounds       integer NOT NULL DEFAULT 0,
    tokens_used  integer NOT NULL DEFAULT 0,
    opened_at    timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    closed_at    timestamptz,
    UNIQUE (tenant_id, entity_key, state) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS cases_tenant_open ON shoc.cases (tenant_id, updated_at DESC)
    WHERE state <> 'closed';

ALTER TABLE shoc.findings ADD COLUMN IF NOT EXISTS case_uid text;
CREATE INDEX IF NOT EXISTS findings_case ON shoc.findings (case_uid);

-- The blackboard: one table, typed messages, every claim carrying its evidence.
CREATE TABLE IF NOT EXISTS shoc.room_messages (
    msg_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id    text NOT NULL,
    case_uid     text NOT NULL REFERENCES shoc.cases(case_uid) ON DELETE CASCADE,
    round        integer NOT NULL DEFAULT 1,
    agent        text NOT NULL,
    principal    text NOT NULL DEFAULT 'agent',
    kind         text NOT NULL,
    body         text NOT NULL,
    cited_event_uids text[] NOT NULL DEFAULT '{}',
    confidence   double precision,
    tokens       integer NOT NULL DEFAULT 0,
    model        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT room_message_kind CHECK (kind IN (
        'observation','hypothesis','evidence','challenge','concede',
        'proposal','decision','inject'))
);
CREATE INDEX IF NOT EXISTS room_case_round ON shoc.room_messages (tenant_id, case_uid, round, msg_id);

-- Every state change is an event; SSE and webhooks are just subscribers (API-2).
CREATE TABLE IF NOT EXISTS shoc.stream_events (
    seq        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  text NOT NULL,
    type       text NOT NULL,
    subject    text NOT NULL DEFAULT '',
    payload    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS stream_tenant_seq ON shoc.stream_events (tenant_id, seq);

CREATE TABLE IF NOT EXISTS shoc.webhooks (
    webhook_id text PRIMARY KEY,
    tenant_id  text NOT NULL,
    url        text NOT NULL,
    secret     bytea NOT NULL,
    types      text[] NOT NULL DEFAULT '{}',
    enabled    boolean NOT NULL DEFAULT true,
    last_ok_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Agent memory (AGT-4 groundwork, used by the crew from v0.2 for tenant facts).
CREATE TABLE IF NOT EXISTS shoc.memory (
    memory_id  text PRIMARY KEY,
    tenant_id  text NOT NULL,
    kind       text NOT NULL DEFAULT 'semantic',
    subject    text NOT NULL DEFAULT '',
    body       text NOT NULL,
    source     text NOT NULL DEFAULT 'human',
    confidence double precision NOT NULL DEFAULT 1.0,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    search     tsvector GENERATED ALWAYS AS (to_tsvector('english', subject || ' ' || body)) STORED
);
CREATE INDEX IF NOT EXISTS memory_search ON shoc.memory USING gin (search);
CREATE INDEX IF NOT EXISTS memory_tenant ON shoc.memory (tenant_id, kind);
