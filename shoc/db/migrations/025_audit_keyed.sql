-- 025 audit log: keyed chain, no TRUNCATE (SEC-1)
--
-- The row trigger from 001 stops UPDATE and DELETE but not TRUNCATE, which
-- emptied a tenant's log and left a chain that verified.
DROP TRIGGER IF EXISTS audit_no_truncate ON shoc.audit_log;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON shoc.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION shoc.audit_append_only();

-- `ts` is now part of each row's hash, so the writer supplies the value it
-- hashed. Without a default, a process still running the code from before this
-- migration fails to append instead of writing a row that would never verify.
ALTER TABLE shoc.audit_log ALTER COLUMN ts DROP DEFAULT;

-- The fingerprint of the key the chain is keyed with, one per install like
-- SHOC_MASTER_KEY itself. A process holding another key refuses to append
-- rather than write a row that breaks the chain for good.
CREATE TABLE IF NOT EXISTS shoc.audit_key (
    id           boolean PRIMARY KEY DEFAULT true CHECK (id),
    fingerprint  text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- A broken chain pages the operator (shoc/agents/manager.py, audit_broken).
ALTER TABLE shoc.notices DROP CONSTRAINT IF EXISTS notice_condition;
ALTER TABLE shoc.notices ADD CONSTRAINT notice_condition CHECK (condition IN
    ('', 'critical_severity', 'uncontainable_and_active', 'coverage_dark', 'deadline_expired',
     'audit_broken'));

-- After this file runs, `shoc migrate` records the key's fingerprint and closes
-- each tenant's existing chain with a keyed `audit.checkpoint` row
-- (shoc/db/audit.py, seal_legacy).
