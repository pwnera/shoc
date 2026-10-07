-- 037 audit key epochs (SEC-1, RFC 0024)
--
-- `shoc rotate-key` retires the chain key derived from the old SHOC_MASTER_KEY.
-- The rows it keyed are still checked with it: the retired key is kept here,
-- sealed with the new master key, beside the first row it no longer covers.
-- Like `audit_key`, it is one per install, not per tenant. `shoc migrate`
-- grants the runtime role SELECT on it and nothing else.
CREATE TABLE IF NOT EXISTS shoc.audit_epochs (
    until_seq    bigint PRIMARY KEY,
    fingerprint  text NOT NULL,
    sealed       bytea NOT NULL,
    retired_at   timestamptz NOT NULL DEFAULT now()
);
