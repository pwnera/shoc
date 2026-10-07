-- 005 threat intelligence: indicators, feed state and hunts (DET-4)

CREATE TABLE IF NOT EXISTS shoc.iocs (
    tenant_id   text NOT NULL,
    type        text NOT NULL,          -- ip, domain, url, sha256, cve
    value       text NOT NULL,
    source      text NOT NULL,
    confidence  double precision NOT NULL DEFAULT 0.5,
    severity    text NOT NULL DEFAULT 'medium',
    description text NOT NULL DEFAULT '',
    tags        text[] NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,
    retro_hunted_at timestamptz,
    PRIMARY KEY (tenant_id, type, value)
);
CREATE INDEX IF NOT EXISTS iocs_pending_retro ON shoc.iocs (tenant_id, retro_hunted_at)
    WHERE retro_hunted_at IS NULL;
CREATE INDEX IF NOT EXISTS iocs_type ON shoc.iocs (tenant_id, type);

CREATE TABLE IF NOT EXISTS shoc.intel_feeds (
    tenant_id   text NOT NULL,
    feed        text NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    settings    jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret      bytea,
    last_run_at timestamptz,
    last_ok_at  timestamptz,
    last_error  text,
    indicators  bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, feed)
);

CREATE TABLE IF NOT EXISTS shoc.hunts (
    hunt_uid    text PRIMARY KEY,
    tenant_id   text NOT NULL,
    kind        text NOT NULL DEFAULT 'ioc',
    query       text NOT NULL,
    window_days integer NOT NULL DEFAULT 90,
    matches     integer NOT NULL DEFAULT 0,
    findings    text[] NOT NULL DEFAULT '{}',
    run_by      text NOT NULL DEFAULT '',
    ran_at      timestamptz NOT NULL DEFAULT now(),
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS hunts_tenant ON shoc.hunts (tenant_id, ran_at DESC);
