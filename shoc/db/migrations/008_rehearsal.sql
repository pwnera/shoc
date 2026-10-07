-- 008 weekly attack rehearsal (AGT-7)
CREATE TABLE IF NOT EXISTS shoc.rehearsals (
    rehearsal_uid text PRIMARY KEY,
    tenant_id   text NOT NULL,
    persona     text NOT NULL,
    ran_at      timestamptz NOT NULL DEFAULT now(),
    rounds      integer NOT NULL DEFAULT 0,
    paths       jsonb NOT NULL DEFAULT '[]'::jsonb,
    coverage    jsonb NOT NULL DEFAULT '{}'::jsonb,
    gaps        text[] NOT NULL DEFAULT '{}',
    summary     text NOT NULL DEFAULT '',
    snapshot_nodes integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS rehearsals_tenant ON shoc.rehearsals (tenant_id, ran_at DESC);
