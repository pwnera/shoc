-- 053 a case closed without its containment waits for a person to acknowledge it (D152)
--
-- The crew closes a case once its verify searches find nothing, and an action
-- nobody approved in time was rejected without running. Quiet logs do not
-- revoke a key, so such a case stays in the inbox and the exception report
-- until a person acknowledges it (`case.acknowledge`, shoc/cases/engine.py).
ALTER TABLE shoc.cases ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;
ALTER TABLE shoc.cases ADD COLUMN IF NOT EXISTS acknowledged_by text;
