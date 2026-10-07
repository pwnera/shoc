-- 001 control plane: tenants, connectors, jobs, schedules, findings, audit (STO-2, DET-3, SEC-1)
CREATE SCHEMA IF NOT EXISTS shoc;

CREATE TABLE IF NOT EXISTS shoc.tenants (
    tenant_id    text PRIMARY KEY,
    name         text NOT NULL,
    backend      text NOT NULL DEFAULT 'postgres',
    schema_name  text NOT NULL,
    settings     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS shoc.connector_state (
    tenant_id    text NOT NULL,
    source       text NOT NULL,
    cursor       jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_run_at  timestamptz,
    last_ok_at   timestamptz,
    last_error   text,
    events_seen  bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, source)
);

CREATE TABLE IF NOT EXISTS shoc.connector_config (
    tenant_id    text NOT NULL,
    source       text NOT NULL,
    enabled      boolean NOT NULL DEFAULT true,
    settings     jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret       bytea,
    interval_seconds integer NOT NULL DEFAULT 300,
    PRIMARY KEY (tenant_id, source)
);

CREATE TABLE IF NOT EXISTS shoc.findings (
    finding_uid  text PRIMARY KEY,
    tenant_id    text NOT NULL,
    rule_id      text NOT NULL,
    title        text NOT NULL,
    severity     text NOT NULL,
    confidence   double precision NOT NULL DEFAULT 0.5,
    status       text NOT NULL DEFAULT 'new',
    entity_key   text NOT NULL DEFAULT '',
    window_start timestamptz NOT NULL,
    window_end   timestamptz NOT NULL,
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    event_count  integer NOT NULL DEFAULT 0,
    event_uids   text[] NOT NULL DEFAULT '{}',
    attack       text[] NOT NULL DEFAULT '{}',
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, rule_id, entity_key, window_start)
);
CREATE INDEX IF NOT EXISTS findings_tenant_time ON shoc.findings (tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS findings_status ON shoc.findings (tenant_id, status);

CREATE TABLE IF NOT EXISTS shoc.jobs (
    job_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id    text NOT NULL,
    kind         text NOT NULL,
    payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
    run_at       timestamptz NOT NULL DEFAULT now(),
    state        text NOT NULL DEFAULT 'pending',
    attempts     integer NOT NULL DEFAULT 0,
    locked_by    text,
    locked_at    timestamptz,
    last_error   text,
    idempotency_key text UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);
CREATE INDEX IF NOT EXISTS jobs_claim ON shoc.jobs (state, run_at) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS shoc.schedules (
    schedule_id      text PRIMARY KEY,
    tenant_id        text NOT NULL,
    kind             text NOT NULL,
    payload          jsonb NOT NULL DEFAULT '{}'::jsonb,
    interval_seconds integer NOT NULL DEFAULT 300,
    next_run_at      timestamptz NOT NULL DEFAULT now(),
    enabled          boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS shoc.rule_state (
    tenant_id    text NOT NULL,
    rule_id      text NOT NULL,
    last_run_at  timestamptz,
    watermark    timestamptz,
    fires        bigint NOT NULL DEFAULT 0,
    last_error   text,
    PRIMARY KEY (tenant_id, rule_id)
);

-- SEC-1: append-only, hash-chained audit of every audited capability call.
CREATE TABLE IF NOT EXISTS shoc.audit_log (
    seq            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      text NOT NULL,
    ts             timestamptz NOT NULL DEFAULT now(),
    principal_kind text NOT NULL,
    principal_id   text NOT NULL,
    capability     text NOT NULL,
    input_hash     text NOT NULL,
    output_hash    text,
    error          text,
    prev_hash      text NOT NULL,
    hash           text NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant_ts ON shoc.audit_log (tenant_id, seq);

CREATE OR REPLACE FUNCTION shoc.audit_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'shoc.audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON shoc.audit_log;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON shoc.audit_log
    FOR EACH ROW EXECUTE FUNCTION shoc.audit_append_only();
