-- 045 people merge playbooks at runtime (RSP-2, API-4, RFC 0033, D129)
--
-- A playbook a person merges lives here, per tenant, next to the shipped ones
-- in content/playbooks: the loader adds these by id and gives each the rules it
-- names, and a shipped id is refused at the gate. Its steps use the actions
-- shoc already has. Reverting sets the state, and its rules go back to the
-- playbooks that answered them before.
CREATE TABLE IF NOT EXISTS shoc.merged_playbooks (
    tenant_id   text NOT NULL,
    playbook_id text NOT NULL,
    body        jsonb NOT NULL,                  -- the playbook, as content/playbooks YAML would parse
    state       text NOT NULL DEFAULT 'merged',  -- merged | reverted
    reason      text NOT NULL DEFAULT '',
    merged_by   text NOT NULL,
    merged_at   timestamptz NOT NULL DEFAULT now(),
    reverted_at timestamptz,
    PRIMARY KEY (tenant_id, playbook_id)
);

SELECT shoc.enable_tenant_rls();
