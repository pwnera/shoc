-- 057 a playbook run records what its steps act on (RSP-2, RFC 0026)
--
-- A run was one per playbook and case, so a second key or account that joined
-- an open case was never answered by the playbook. `targets` is a hash of the
-- values a run's step targets rendered to (shoc/cases/playbooks.py `targets`);
-- a start whose hash differs from every earlier run's is a run of its own. Runs
-- from before this are NULL and hashed from their stored context when compared.
ALTER TABLE shoc.playbook_runs ADD COLUMN IF NOT EXISTS targets text;
CREATE INDEX IF NOT EXISTS runs_case_playbook
    ON shoc.playbook_runs (tenant_id, case_uid, playbook_id);
