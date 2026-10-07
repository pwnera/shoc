-- 047 a finding's status follows its case (RSP-1, D136)
--
-- Nothing moved a finding when its case changed, so every finding in a case
-- still read `new`, closed cases included. From here `engine.settle` keeps it:
-- `triage` while the case is open, `false_positive` once it closes on that
-- verdict, `closed` on any other.
UPDATE shoc.findings f
   SET status = CASE WHEN c.state <> 'closed' THEN 'triage'
                     WHEN c.verdict = 'false_positive' THEN 'false_positive'
                     ELSE 'closed' END
  FROM shoc.cases c
 WHERE c.tenant_id = f.tenant_id AND c.case_uid = f.case_uid;
