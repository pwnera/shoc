-- 007 row-level security on every tenant-scoped table (SEC-1)
--
-- Defence in depth for the application path: `shoc.tenant_id` is set on every
-- capability call, so a query inside a capability body cannot read another
-- tenant's rows even if it forgets its WHERE clause. A session that never sets
-- the variable — psql, `shoc migrate`, a backup job — is unaffected, which is
-- what keeps operations possible; isolation for those paths is the database
-- user's own privileges.
DO $$
DECLARE
    t text;
    tables text[] := ARRAY[
        'tenants', 'connector_state', 'connector_config', 'findings', 'jobs', 'schedules',
        'rule_state', 'audit_log', 'cases', 'room_messages', 'stream_events', 'webhooks',
        'memory', 'case_entities', 'actions', 'playbook_runs', 'action_credentials',
        'iocs', 'intel_feeds', 'hunts', 'llm_spend', 'rule_proposals', 'reports',
        'graph_nodes', 'graph_edges'
    ];
BEGIN
    FOREACH t IN ARRAY tables LOOP
        EXECUTE format('ALTER TABLE shoc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE shoc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON shoc.%I', t);
        EXECUTE format($p$
            CREATE POLICY tenant_isolation ON shoc.%I
            USING (
                current_setting('shoc.tenant_id', true) IS NULL
                OR current_setting('shoc.tenant_id', true) = ''
                OR current_setting('shoc.tenant_id', true) = 'shoc:all'
                OR tenant_id = current_setting('shoc.tenant_id', true)
            )
            WITH CHECK (
                current_setting('shoc.tenant_id', true) IS NULL
                OR current_setting('shoc.tenant_id', true) = ''
                OR current_setting('shoc.tenant_id', true) = 'shoc:all'
                OR tenant_id = current_setting('shoc.tenant_id', true)
            )$p$, t);
    END LOOP;
END $$;
