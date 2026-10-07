-- 048 a malicious case nothing contained pages (RFC 0015)
--
-- A high or critical case the crew found malicious, with no response action
-- run on it for real, pages under its own condition (shoc/agents/manager.py,
-- uncontained). Dry run, or no credential to act with, left such a case alone
-- and woke nobody.
ALTER TABLE shoc.notices DROP CONSTRAINT IF EXISTS notice_condition;
ALTER TABLE shoc.notices ADD CONSTRAINT notice_condition CHECK (condition IN
    ('', 'critical_severity', 'uncontainable_and_active', 'coverage_dark', 'deadline_expired',
     'audit_broken', 'malicious_uncontained'));
