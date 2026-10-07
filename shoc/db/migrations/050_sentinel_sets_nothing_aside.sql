-- 050 Sentinel sets nothing aside (AGT-13, D145)
--
-- Sentinel deferred a finding on a person's close of another rule on the same
-- resource, and the case it emptied was closed with nobody having worked it.
-- Sentinel no longer defers. A finding it deferred loses both marks and goes
-- back to the queue, so the next detection cycle puts it in a case like any
-- new finding.
UPDATE shoc.findings
   SET status = 'new', evidence = evidence - 'intake' - 'sentinel'
 WHERE status = 'deferred';
