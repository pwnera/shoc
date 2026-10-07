-- 038 Which credentials an action acts with (RSP-4, RFC 0025)
--
-- A provider can hold several credentials, `aws` and `aws:staging`, each for
-- its own accounts. The ones an action was routed to, from the accounts its
-- target was seen in, are chosen when it is proposed so the approver sees the
-- tenant, and kept so its undo runs where it acted. NULL on older rows: they
-- act with the provider's only credential, as before.
ALTER TABLE shoc.actions ADD COLUMN IF NOT EXISTS acts_in text[];
