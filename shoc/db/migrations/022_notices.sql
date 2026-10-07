-- 022 the SOC Manager's notices (RFC 0015, D58)
--
-- One row per thing a role or a playbook wants the operator to know. Nothing
-- reaches the operator except through the Manager, which reads these, groups
-- them by incident, and decides with a query whether one page goes out.
-- `outcome` is what the gate did: `paged`, `merged` into a page that already
-- went out, `digest` for the weekly, or `failed` when the page could not be
-- sent. `delivered_uid` is the notify.page action that stood for it.
CREATE TABLE IF NOT EXISTS shoc.notices (
    tenant_id     text NOT NULL,
    notice_uid    text NOT NULL,
    source        text NOT NULL,
    case_uid      text,
    group_key     text NOT NULL,
    kind          text NOT NULL,
    severity      text NOT NULL DEFAULT 'medium',
    condition     text NOT NULL DEFAULT '',
    body          text NOT NULL,
    citations     text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now(),
    delivered_at  timestamptz,
    outcome       text,
    delivered_uid text,
    PRIMARY KEY (tenant_id, notice_uid),
    CONSTRAINT notice_kind CHECK (kind IN ('page','decision','digest')),
    CONSTRAINT notice_condition CHECK (condition IN
        ('', 'critical_severity', 'uncontainable_and_active', 'coverage_dark', 'deadline_expired')),
    CONSTRAINT notice_outcome CHECK (outcome IS NULL OR outcome IN
        ('paged', 'merged', 'digest', 'failed'))
);

CREATE INDEX IF NOT EXISTS notices_pending
    ON shoc.notices (tenant_id, created_at) WHERE delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS notices_group
    ON shoc.notices (tenant_id, group_key, delivered_at);

-- The case no longer posts itself to Slack, and the shift report is gone (D52).
DELETE FROM shoc.schedules WHERE kind = 'report.shift';
DELETE FROM shoc.jobs WHERE kind IN ('report.shift', 'slack.notify') AND state = 'pending';

SELECT shoc.enable_tenant_rls();
