-- 046 what a report says about each technique it names (DET-7, DET-8, D132)
--
-- One entry per technique: its id and name, what the report saw the attacker
-- do with it, and the data that would show it. The Detection Engineer's
-- coverage item carries the procedure rather than the id alone; `techniques`
-- keeps the ids the agenda and coverage join on.
ALTER TABLE shoc.intel_reports
    ADD COLUMN IF NOT EXISTS procedures jsonb NOT NULL DEFAULT '[]'::jsonb;
