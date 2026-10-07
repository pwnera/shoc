-- 038 What the IR Commander attached to a proposal (AGT-13, D45, RSP-7)
--
-- The Commander names a fallback for every L2 and counts the blast radius of
-- every proposal. Both were dropped before the policy saw the proposal, so an
-- expired L2 was rejected instead of falling back. The fallback is proposed
-- when nobody answers, with the blast radius and grounding of the action it
-- replaces: a target a log line supplied must not run alone through its fallback.
ALTER TABLE shoc.actions
    ADD COLUMN IF NOT EXISTS fallback text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS blast_radius jsonb,
    ADD COLUMN IF NOT EXISTS grounded boolean NOT NULL DEFAULT true;
