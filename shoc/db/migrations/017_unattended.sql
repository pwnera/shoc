-- 017 What happens when nobody is watching (RSP-3, AGT-1, OPS-1)
--
-- shoc runs for a company whose only technical person does not open it most
-- days. Everything whose resting state was "a human will look at this" was
-- therefore a no-op: an L2 action sat `proposed` for ever, a `needs_human` case
-- sat in `analysis` for ever, and the crew ran once per case and never again.
--
-- Three columns, and the scheduled work in `shoc/worker.py` that reads them.

-- When a waiting action stops being worth waiting for. Past this, the case is
-- either escalated to a page or the action is abandoned with a reason — both of
-- which are outcomes, unlike waiting.
ALTER TABLE shoc.actions
    ADD COLUMN IF NOT EXISTS decide_by timestamptz,
    ADD COLUMN IF NOT EXISTS chased_at timestamptz;
CREATE INDEX IF NOT EXISTS actions_undecided
    ON shoc.actions (tenant_id, decide_by)
    WHERE state = 'proposed';

-- Actions nobody has run. `approved` used to be a terminal state in practice:
-- only the playbook runner executed anything, and only its own steps.
CREATE INDEX IF NOT EXISTS actions_approved_unrun
    ON shoc.actions (tenant_id, updated_at)
    WHERE state = 'approved' AND run_uid IS NULL;

-- When the crew last did any work on a case. The sweep used to ask
-- `tokens_used = 0`, which means "nobody has ever spoken here" and is true
-- exactly once: a case that gained ten new findings, or that a human posted a
-- fact into, or whose containment has since completed, was finished for good
-- after its first run.
ALTER TABLE shoc.cases
    ADD COLUMN IF NOT EXISTS worked_at timestamptz;
CREATE INDEX IF NOT EXISTS cases_open_worked
    ON shoc.cases (tenant_id, worked_at)
    WHERE state <> 'closed';

-- A case that has been worked once carries the timestamp of its last message,
-- so the first sweep after this migration does not treat every open case as
-- brand new.
UPDATE shoc.cases c SET worked_at = m.last_message
FROM (
    SELECT tenant_id, case_uid, max(created_at) AS last_message
    FROM shoc.openspace_messages GROUP BY tenant_id, case_uid
) m
WHERE c.worked_at IS NULL AND c.tenant_id = m.tenant_id AND c.case_uid = m.case_uid;

SELECT shoc.enable_tenant_rls();
