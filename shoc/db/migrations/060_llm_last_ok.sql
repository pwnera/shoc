-- 060 when each model last answered, and when a push was last refused (AGT-1, OPS-1)
--
-- The case sweep stood down whenever any model had failed in the last 15
-- minutes, even while the investigator's model answered every call. A provider
-- is failing only when nothing has come back since its last failure, and that
-- needs the time of the last success next to the time of the last failure.
ALTER TABLE shoc.llm_spend ADD COLUMN IF NOT EXISTS last_ok_at timestamptz;

-- A pushed source GitHub keeps signing with an old key looked quiet for a
-- week: a refused delivery left no trace. The first refusal since the last
-- delivery that loaded (ING-2, OPS-1).
ALTER TABLE shoc.connector_state ADD COLUMN IF NOT EXISTS push_refused_at timestamptz;
