-- 021 where each source stands with the Integrator (AGT-13, D50)
--
-- One row per source: the step it has reached, what the operator must grant if
-- it is stuck on credentials, what the sampled events left unmapped, which rules
-- it can and cannot carry, and the finding that proved it. `onboarded_at` is set
-- only from that finding, never from the model's say-so.
CREATE TABLE IF NOT EXISTS shoc.source_onboarding (
    tenant_id       text NOT NULL,
    source          text NOT NULL,
    step            text NOT NULL DEFAULT 'discover',
    dark            boolean NOT NULL DEFAULT false,
    scopes          jsonb NOT NULL DEFAULT '[]'::jsonb,
    click_path      text NOT NULL DEFAULT '',
    unmapped_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
    supports        jsonb NOT NULL DEFAULT '[]'::jsonb,
    cannot_support  jsonb NOT NULL DEFAULT '[]'::jsonb,
    proof_finding   text,
    onboarded_at    timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source),
    CONSTRAINT onboarding_step CHECK (step IN ('discover','credentials','map','prove','done'))
);

SELECT shoc.enable_tenant_rls();
