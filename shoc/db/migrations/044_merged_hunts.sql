-- 044 the Hunter writes packs for its backlog (DET-8, AGT-3, RFC 0032, D128)
--
-- A pack the Hunter merges lives here, per tenant, next to the shipped packs in
-- content/hunts: the loader adds these by id, and a shipped id is refused at
-- the gate. Reverting sets the state and the pack stops running.
CREATE TABLE IF NOT EXISTS shoc.merged_hunts (
    tenant_id   text NOT NULL,
    pack_id     text NOT NULL,
    body        jsonb NOT NULL,                  -- the pack, as content/hunts YAML would parse
    fixtures    jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {source, surfaced, baseline}
    checked     jsonb NOT NULL DEFAULT '{}'::jsonb,  -- what the gate ran over our own data
    item_uid    text NOT NULL DEFAULT '',        -- the hunt backlog item it answers
    state       text NOT NULL DEFAULT 'merged',  -- merged | reverted
    reason      text NOT NULL DEFAULT '',
    merged_by   text NOT NULL,
    merged_at   timestamptz NOT NULL DEFAULT now(),
    reverted_at timestamptz,
    PRIMARY KEY (tenant_id, pack_id)
);

SELECT shoc.enable_tenant_rls();
