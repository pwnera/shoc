-- 012 Posture: what the company actually has (AGT-3, RFC 0006 §3)
--
-- Four agents used to guess at this — the Investigator asking whether an
-- identity is privileged, the IR Commander asking what suspending it costs, CTI
-- asking whether a CVE is relevant, the Rehearsal being told its entry points in
-- YAML. The Surveyor derives all of it from events we already ingest.
--
-- Everything here is *observed*, never declared. An entity that did nothing in
-- the window is not in these tables, and the honest limit says so.

-- One row per entity the Surveyor knows about, with how it was seen.
CREATE TABLE IF NOT EXISTS shoc.exposures (
    tenant_id    text NOT NULL,
    entity       text NOT NULL,                  -- typed: user:alice, key:AKIA…, ip:…
    kind         text NOT NULL,                  -- user | key | ip | resource | account
    exposed      boolean NOT NULL DEFAULT false, -- acted from outside our own ranges
    privileged   boolean NOT NULL DEFAULT false, -- performed an administrative operation
    stale        boolean NOT NULL DEFAULT false, -- not seen inside the freshness window
    events       integer NOT NULL DEFAULT 0,
    sources      text[] NOT NULL DEFAULT '{}',   -- the products that saw it
    countries    text[] NOT NULL DEFAULT '{}',
    operations   text[] NOT NULL DEFAULT '{}',   -- the privileged operations observed
    event_uids   text[] NOT NULL DEFAULT '{}',   -- evidence: an answer with no citation is not one
    first_seen   timestamptz,
    last_seen    timestamptz,
    surveyed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity)
);
CREATE INDEX IF NOT EXISTS exposures_exposed ON shoc.exposures (tenant_id, exposed, last_seen DESC);
CREATE INDEX IF NOT EXISTS exposures_kind ON shoc.exposures (tenant_id, kind);

-- What the picture looked like on a given day, so a change can be described
-- rather than merely noticed. The Hunter's daily attack-surface hunt (DET-10)
-- diffs consecutive snapshots; the Surveyor owns the table underneath them.
CREATE TABLE IF NOT EXISTS shoc.posture_snapshots (
    snapshot_uid text PRIMARY KEY,
    tenant_id    text NOT NULL,
    taken_at     timestamptz NOT NULL DEFAULT now(),
    window_days  integer NOT NULL DEFAULT 30,
    counts       jsonb NOT NULL DEFAULT '{}'::jsonb,
    gaps         jsonb NOT NULL DEFAULT '{}'::jsonb,
    caveat       text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS posture_snapshots_tenant
    ON shoc.posture_snapshots (tenant_id, taken_at DESC);

SELECT shoc.enable_tenant_rls();
