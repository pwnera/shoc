-- 040 configuration snapshots (D49, AGT-8), and what the survey and Ops keep (D47).
-- One row per thing a source's own API says exists, replaced on every pass, so
-- a user deleted at the vendor is gone after the next one.
CREATE TABLE IF NOT EXISTS shoc.snapshots (
    tenant_id    text NOT NULL,
    source       text NOT NULL,
    entity       text NOT NULL,   -- typed like the survey: user:alice@example.com, network:203.0.113.0/24
    kind         text NOT NULL,   -- user | network
    attributes   jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_active  timestamptz,     -- the vendor's own last sign-in, when it keeps one
    taken_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source, entity)
);
CREATE INDEX IF NOT EXISTS snapshots_kind ON shoc.snapshots (tenant_id, kind);

-- An entity the latest survey did not see keeps its row with `present` false,
-- and its flags say what is true now rather than what an old survey saw.
ALTER TABLE shoc.exposures ADD COLUMN IF NOT EXISTS present boolean NOT NULL DEFAULT true;

-- What Ops' model made of a source's outage, and when (D47). A diagnosis older
-- than the source's last good pull is about an earlier outage and is not read.
ALTER TABLE shoc.connector_state ADD COLUMN IF NOT EXISTS diagnosis text NOT NULL DEFAULT '';
ALTER TABLE shoc.connector_state ADD COLUMN IF NOT EXISTS diagnosed_at timestamptz;

SELECT shoc.enable_tenant_rls();
