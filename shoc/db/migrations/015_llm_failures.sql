-- 015 Model-call failures belong in the spend table (OPS-1)
--
-- A gateway that answers HTTP 200 with an error body left no trace anywhere: the
-- crew recorded no tokens, the case kept its `needs_human` verdict, and
-- `ops.alerts` had nothing to say while no agent in the company was working.
-- Failures are counted next to the calls that succeeded, so "the provider is
-- failing" is one query over data we already keep.
ALTER TABLE shoc.llm_spend ADD COLUMN IF NOT EXISTS failures bigint NOT NULL DEFAULT 0;
ALTER TABLE shoc.llm_spend ADD COLUMN IF NOT EXISTS last_error text NOT NULL DEFAULT '';
ALTER TABLE shoc.llm_spend ADD COLUMN IF NOT EXISTS last_error_at timestamptz;
