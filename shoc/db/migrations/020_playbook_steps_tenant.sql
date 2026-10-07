-- 020 playbook steps carry their tenant (SEC-1)
--
-- Row-level security covers every table with a tenant_id, and playbook_steps
-- had none, so a step's result was readable from any tenant. The column is
-- filled from the run each step belongs to.
ALTER TABLE shoc.playbook_steps ADD COLUMN IF NOT EXISTS tenant_id text;

UPDATE shoc.playbook_steps s SET tenant_id = r.tenant_id
  FROM shoc.playbook_runs r
 WHERE r.run_uid = s.run_uid AND s.tenant_id IS NULL;

ALTER TABLE shoc.playbook_steps ALTER COLUMN tenant_id SET NOT NULL;

SELECT shoc.enable_tenant_rls();
