-- 010 CTI research: cached lookups and digested reports (DET-6, DET-7, RFC 0004)

-- One row per indicator we have researched, with every source's answer. The TTL
-- is what keeps a busy case from asking RDAP the same question forty times.
CREATE TABLE IF NOT EXISTS shoc.intel_lookups (
    tenant_id    text NOT NULL,
    type         text NOT NULL,          -- ip, domain, url, sha256, md5, cve, email
    value        text NOT NULL,
    verdict      text NOT NULL DEFAULT 'unknown',
    score        double precision NOT NULL DEFAULT 0,
    confidence   double precision NOT NULL DEFAULT 0,
    payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
    looked_up_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL DEFAULT now() + interval '12 hours',
    PRIMARY KEY (tenant_id, type, value)
);
CREATE INDEX IF NOT EXISTS intel_lookups_fresh ON shoc.intel_lookups (tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS intel_lookups_verdict ON shoc.intel_lookups (tenant_id, verdict);

-- One row per threat report we have read. `raw_sha256` makes digesting the same
-- report twice idempotent, and keeps the model bill down.
CREATE TABLE IF NOT EXISTS shoc.intel_reports (
    report_uid   text PRIMARY KEY,
    tenant_id    text NOT NULL,
    url          text NOT NULL DEFAULT '',
    source_host  text NOT NULL DEFAULT '',
    title        text NOT NULL DEFAULT '',
    summary      text NOT NULL DEFAULT '',
    relevance    text NOT NULL DEFAULT '',
    actors       text[] NOT NULL DEFAULT '{}',
    malware      text[] NOT NULL DEFAULT '{}',
    campaigns    text[] NOT NULL DEFAULT '{}',
    techniques   text[] NOT NULL DEFAULT '{}',
    indicators   jsonb NOT NULL DEFAULT '[]'::jsonb,
    extracted    jsonb NOT NULL DEFAULT '{}'::jsonb,
    hunts        text[] NOT NULL DEFAULT '{}',
    findings     text[] NOT NULL DEFAULT '{}',
    stored_count integer NOT NULL DEFAULT 0,
    confidence   double precision NOT NULL DEFAULT 0,
    raw_sha256   text NOT NULL DEFAULT '',
    model        text NOT NULL DEFAULT '',
    tokens       integer NOT NULL DEFAULT 0,
    digested_by  text NOT NULL DEFAULT '',
    digested_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS intel_reports_tenant ON shoc.intel_reports (tenant_id, digested_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS intel_reports_sha
    ON shoc.intel_reports (tenant_id, raw_sha256) WHERE raw_sha256 <> '';

-- An indicator that came out of a report, rather than off a feed, is marked so
-- it can be told apart later — and withdrawn in one statement if the report
-- turns out to have been wrong, or hostile (RFC 0004).
ALTER TABLE shoc.iocs ADD COLUMN IF NOT EXISTS report_uid text;
ALTER TABLE shoc.iocs ADD COLUMN IF NOT EXISTS unverified boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS iocs_report ON shoc.iocs (tenant_id, report_uid)
    WHERE report_uid IS NOT NULL;

-- Migration 009 made RLS a function over every table with a tenant_id.
SELECT shoc.enable_tenant_rls();
