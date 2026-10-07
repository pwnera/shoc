-- 041 lookups that need an account (DET-6, RFC 0030)
--
-- A keyed lookup source is configured by a person with `intel.configure
-- --lookup`, its key sealed like a feed's (`shoc.db.secrets.SEALED`). Each one
-- has a daily quota per tenant; `lookup_usage` counts the calls and holds the
-- pause a 429 with Retry-After asked for.
CREATE TABLE IF NOT EXISTS shoc.lookup_sources (
    tenant_id  text NOT NULL,
    source     text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret     bytea,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source)
);

CREATE TABLE IF NOT EXISTS shoc.lookup_usage (
    tenant_id    text NOT NULL,
    day          date NOT NULL,
    source       text NOT NULL,
    calls        integer NOT NULL DEFAULT 0,
    paused_until timestamptz,
    PRIMARY KEY (tenant_id, day, source)
);

SELECT shoc.enable_tenant_rls();
