-- 011 Four dispositions and the two places a closure is repaired (AGT-3, RFC 0006)
--
-- A case used to close `benign`, which merged two different answers: the
-- activity was real and expected here, or the rule should never have fired at
-- all. One is repaired with a scoped suppression, the other with a change to
-- the detection, and they are owned by different people. Splitting the verdict
-- is only half the work — each half now has somewhere to go.

-- A suppression says "stop raising this exact thing, until this date". Every
-- one carries an expiry and the case that justified it, because exclusions are
-- how coverage erodes quietly (docs/agent-specs.md §11).
CREATE TABLE IF NOT EXISTS shoc.suppressions (
    suppression_uid text PRIMARY KEY,
    tenant_id    text NOT NULL,
    rule_id      text NOT NULL,
    entity       text NOT NULL DEFAULT '',       -- what is excluded; '' means the whole rule
    reason       text NOT NULL DEFAULT '',
    case_uid     text NOT NULL DEFAULT '',       -- the case that justified it
    created_by   text NOT NULL DEFAULT 'Orchestrator',
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,           -- NOT NULL: nothing is suppressed forever
    reviewed_at  timestamptz,
    state        text NOT NULL DEFAULT 'active'  -- active | expired | revoked
);
CREATE INDEX IF NOT EXISTS suppressions_live
    ON shoc.suppressions (tenant_id, rule_id, expires_at);

-- The Detection Engineer's backlog: every idea for a detection change, from
-- whichever of the six intakes produced it, ranked and decided by a human.
CREATE TABLE IF NOT EXISTS shoc.detection_backlog (
    item_uid     text PRIMARY KEY,
    tenant_id    text NOT NULL,
    rule_id      text NOT NULL DEFAULT '',
    kind         text NOT NULL,                  -- defect | suppression | promote | coverage | decay
    intake       text NOT NULL DEFAULT 'case',   -- case | hunt | rehearsal | cti | review | health
    title        text NOT NULL DEFAULT '',
    reason       text NOT NULL DEFAULT '',
    priority     integer NOT NULL DEFAULT 3,     -- 1 is most urgent
    observability text NOT NULL DEFAULT 'unknown', -- have | partial | none
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    case_uid     text NOT NULL DEFAULT '',
    state        text NOT NULL DEFAULT 'open',   -- open | accepted | rejected | done
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz,
    decided_by   text
);
CREATE INDEX IF NOT EXISTS detection_backlog_open
    ON shoc.detection_backlog (tenant_id, state, priority);

-- What a closure did about itself, so "every disposition goes somewhere" is a
-- record and not a claim in a document.
CREATE TABLE IF NOT EXISTS shoc.case_routing (
    tenant_id    text NOT NULL,
    case_uid     text NOT NULL,
    disposition  text NOT NULL,
    routed_to    text NOT NULL,                  -- the agent or table that received it
    reference    text NOT NULL DEFAULT '',       -- the row it produced, if any
    note         text NOT NULL DEFAULT '',
    routed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, case_uid, routed_to)
);

-- Cases closed before the split read as the safer of the two halves: an
-- environment that is unusual, not a detection that is wrong. Nothing is
-- suppressed as a result — this only renames the verdict.
UPDATE shoc.cases SET verdict = 'benign_expected' WHERE verdict = 'benign';

-- Migration 009 made RLS a function over every table with a tenant_id.
SELECT shoc.enable_tenant_rls();
