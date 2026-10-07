-- 019 the Detection Engineer merges its own rules (AGT-3, D48)
--
-- A rule the Detection Engineer merges lives here, per tenant, next to the
-- shipped rules in content/: the loader lays these over content/ by id, so a
-- row with the id of a shipped rule is that rule narrowed. Reverting sets the
-- state and the shipped rule, if there is one, comes back.
CREATE TABLE IF NOT EXISTS shoc.merged_rules (
    tenant_id   text NOT NULL,
    rule_id     text NOT NULL,
    body        jsonb NOT NULL,                  -- the rule, as content/rules YAML would parse
    playbook_id text NOT NULL,                   -- the playbook that answers it (RFC 0013)
    ads         jsonb NOT NULL DEFAULT '{}'::jsonb,
    fixtures    jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {source, positive, negative}
    backtest    jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {days, findings}
    item_uid    text NOT NULL DEFAULT '',        -- the backlog item it answers
    state       text NOT NULL DEFAULT 'merged',  -- merged | reverted
    reason      text NOT NULL DEFAULT '',
    merged_by   text NOT NULL,
    merged_at   timestamptz NOT NULL DEFAULT now(),
    reverted_at timestamptz,
    PRIMARY KEY (tenant_id, rule_id)
);

-- The rehearsal is gone (018) and its gaps were still open on the backlog,
-- where nothing could ever close them.
UPDATE shoc.detection_backlog
   SET state = 'rejected', decided_at = now(), decided_by = 'migration:019'
 WHERE intake = 'rehearsal' AND state = 'open';

SELECT shoc.enable_tenant_rls();
