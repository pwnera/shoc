-- 042 the last check of each response credential (RSP-4, D125)
--
-- `credential.configure` and `credential.check` make one read with a
-- credential; what came back stays here, so a product's Response review says
-- whether the credential still works and since when, not only right after a
-- save. NULL `check_ok` is a credential never checked, or a provider with no
-- read to try (a PagerDuty routing key).
ALTER TABLE shoc.action_credentials ADD COLUMN IF NOT EXISTS checked_at timestamptz;
ALTER TABLE shoc.action_credentials ADD COLUMN IF NOT EXISTS check_ok boolean;
ALTER TABLE shoc.action_credentials ADD COLUMN IF NOT EXISTS check_detail text NOT NULL DEFAULT '';
