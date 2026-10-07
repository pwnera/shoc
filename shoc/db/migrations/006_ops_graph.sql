-- 006 operations and the world graph (OPS-1, AGT-4, AGT-3)

-- What the crew costs, per day and model. Written by the agent loop.
CREATE TABLE IF NOT EXISTS shoc.llm_spend (
    tenant_id   text NOT NULL,
    day         date NOT NULL,
    model       text NOT NULL,
    calls       bigint NOT NULL DEFAULT 0,
    tokens_in   bigint NOT NULL DEFAULT 0,
    tokens_out  bigint NOT NULL DEFAULT 0,
    usd         numeric(12,4) NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day, model)
);

-- Tuning proposals: what the Tuner would change, for a human to merge.
CREATE TABLE IF NOT EXISTS shoc.rule_proposals (
    proposal_uid text PRIMARY KEY,
    tenant_id    text NOT NULL,
    rule_id      text NOT NULL,
    kind         text NOT NULL DEFAULT 'tune',   -- tune | suppress | new
    reason       text NOT NULL DEFAULT '',
    diff         text NOT NULL DEFAULT '',
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    state        text NOT NULL DEFAULT 'open',   -- open | merged | dismissed
    created_by   text NOT NULL DEFAULT 'Tuner',
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz,
    decided_by   text
);
CREATE INDEX IF NOT EXISTS rule_proposals_open ON shoc.rule_proposals (tenant_id, state);

-- Reports the Reporter writes, kept so "what did you tell me on Tuesday" has an answer.
CREATE TABLE IF NOT EXISTS shoc.reports (
    report_uid  text PRIMARY KEY,
    tenant_id   text NOT NULL,
    kind        text NOT NULL,                   -- shift | weekly | exec | rehearsal
    period_start timestamptz NOT NULL,
    period_end   timestamptz NOT NULL,
    summary     text NOT NULL DEFAULT '',
    body        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reports_tenant ON shoc.reports (tenant_id, kind, period_end DESC);

-- The world graph (AGT-4): who and what this company is made of.
CREATE TABLE IF NOT EXISTS shoc.graph_nodes (
    tenant_id  text NOT NULL,
    node_id    text NOT NULL,                    -- "user:jane@acme.com"
    kind       text NOT NULL,                    -- user | key | ip | resource | account | host
    label      text NOT NULL DEFAULT '',
    attrs      jsonb NOT NULL DEFAULT '{}'::jsonb,
    events     bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, node_id)
);
CREATE INDEX IF NOT EXISTS graph_nodes_kind ON shoc.graph_nodes (tenant_id, kind);

CREATE TABLE IF NOT EXISTS shoc.graph_edges (
    tenant_id  text NOT NULL,
    src        text NOT NULL,
    dst        text NOT NULL,
    kind       text NOT NULL DEFAULT 'observed_with',
    weight     bigint NOT NULL DEFAULT 1,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, src, dst, kind)
);
CREATE INDEX IF NOT EXISTS graph_edges_src ON shoc.graph_edges (tenant_id, src);
CREATE INDEX IF NOT EXISTS graph_edges_dst ON shoc.graph_edges (tenant_id, dst);
