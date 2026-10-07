-- 049 what the content audit of 2026-10-07 left in the data (DET-4, DET-7, DET-8, AGT-13)
--
-- The code changes stop each of these from happening again. This puts right
-- what they had already written: rows that match nothing a tenant has, so on
-- every other install these statements change nothing.

-- Reports CTI judged not to apply here steer nothing. The Star Blizzard
-- campaign's domains were stored before `keep` gated storage, and the
-- techniques of it and of the DPRK paper reached the Detection Engineer. A
-- second read of the IIS webshell report queued its hunts after the first had
-- discarded it; the three the Hunter has already worked wait for no source.
DELETE FROM shoc.iocs WHERE report_uid = 'RPT-8335467838457bca';
UPDATE shoc.intel_reports SET stored_count = 0, techniques = '{}'
 WHERE report_uid = 'RPT-8335467838457bca';
UPDATE shoc.intel_reports SET techniques = '{}' WHERE report_uid = 'RPT-158ec6ff6b3d5cca';
UPDATE shoc.hunt_backlog
   SET state = 'rejected', decided_at = now(), decided_by = 'migration:049',
       evidence = (evidence - 'waiting_for') || jsonb_build_object(
           'decision', 'report_discarded',
           'because', 'CTI judged the report does not apply here; a second read queued its hunts')
 WHERE evidence->>'report_uid' = 'RPT-ca13adc83ac65b21'
   AND (state = 'open' OR evidence->>'decision' = 'source_gap');

-- One form and one week for every suppression. Rows written before the
-- 7-day cap kept 30 days; the crew may not quieten a hunt pack or an indicator,
-- or the operator's own account; and a `user:`-typed entity never matched a
-- finding, whose entity is the bare value.
UPDATE shoc.suppressions
   SET expires_at = LEAST(expires_at, created_at + interval '7 days')
 WHERE state = 'active';

UPDATE shoc.suppressions
   SET state = 'revoked', reviewed_at = now()
 WHERE state = 'active' AND created_by NOT LIKE 'human:%'
   AND (rule_id LIKE 'hunt:%' OR rule_id LIKE 'ioc\_%');

UPDATE shoc.suppressions s
   SET state = 'revoked', reviewed_at = now()
 WHERE s.state = 'active' AND s.created_by NOT LIKE 'human:%'
   AND (
       EXISTS (SELECT 1 FROM shoc.own_identities o
                WHERE o.tenant_id = s.tenant_id AND o.kind = 'operator'
                  AND lower(o.value) = lower(regexp_replace(
                      s.entity, '^(user|key|ip|host|resource|account|entity):', '')))
       OR EXISTS (SELECT 1 FROM shoc.users u
                   WHERE u.tenant_id = s.tenant_id AND u.disabled_at IS NULL
                     AND u.role IN ('admin', 'operator')
                     AND u.email = lower(regexp_replace(
                         s.entity, '^(user|key|ip|host|resource|account|entity):', '')))
   );

-- A typed row whose bare twin exists is a duplicate; any other becomes bare,
-- under the id the code now derives from the bare entity.
UPDATE shoc.suppressions s
   SET state = 'revoked', reviewed_at = now()
 WHERE s.state = 'active'
   AND s.entity ~ '^(user|key|ip|host|resource|account|entity):'
   AND EXISTS (SELECT 1 FROM shoc.suppressions b
                WHERE b.tenant_id = s.tenant_id AND b.rule_id = s.rule_id
                  AND b.entity = regexp_replace(
                      s.entity, '^(user|key|ip|host|resource|account|entity):', ''));
UPDATE shoc.suppressions s
   SET entity = bare.entity,
       suppression_uid = 'SUP-' || left(encode(sha256(convert_to(
           s.tenant_id || '|' || s.rule_id || '|' || bare.entity, 'UTF8')), 'hex'), 20)
  FROM (SELECT suppression_uid,
               regexp_replace(entity, '^(user|key|ip|host|resource|account|entity):', '') AS entity
          FROM shoc.suppressions) bare
 WHERE bare.suppression_uid = s.suppression_uid
   AND s.entity ~ '^(user|key|ip|host|resource|account|entity):'
   AND s.state = 'active';

-- Feodo rows were read by column position: the header became an indicator
-- named `dst_ip` and a date was stored as the malware family. The next refresh
-- stores what was online in the last 30 days.
DELETE FROM shoc.iocs WHERE source = 'abuse.ch/feodo';

SELECT shoc.enable_tenant_rls();
