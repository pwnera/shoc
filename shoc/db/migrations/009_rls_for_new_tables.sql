-- 009 keep row-level security true for tables added later (SEC-1)
--
-- Migration 007 enabled RLS on the tables that existed then, which meant the
-- next migration to add one (008's `rehearsals`) quietly had none. This makes
-- it a function over "every table in shoc with a tenant_id", and `shoc migrate`
-- calls it after every run, so a new table is covered the moment it exists.
CREATE OR REPLACE FUNCTION shoc.enable_tenant_rls() RETURNS integer AS $$
DECLARE
    t text;
    n integer := 0;
BEGIN
    FOR t IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace ns ON ns.oid = c.relnamespace
        JOIN information_schema.columns col
          ON col.table_schema = 'shoc' AND col.table_name = c.relname
        WHERE ns.nspname = 'shoc' AND c.relkind = 'r' AND col.column_name = 'tenant_id'
    LOOP
        EXECUTE format('ALTER TABLE shoc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE shoc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON shoc.%I', t);
        EXECUTE format($p$
            CREATE POLICY tenant_isolation ON shoc.%I
            USING (
                current_setting('shoc.tenant_id', true) IS NULL
                OR current_setting('shoc.tenant_id', true) = ''
                OR current_setting('shoc.tenant_id', true) = 'shoc:all'
                OR tenant_id = current_setting('shoc.tenant_id', true)
            )
            WITH CHECK (
                current_setting('shoc.tenant_id', true) IS NULL
                OR current_setting('shoc.tenant_id', true) = ''
                OR current_setting('shoc.tenant_id', true) = 'shoc:all'
                OR tenant_id = current_setting('shoc.tenant_id', true)
            )$p$, t);
        n := n + 1;
    END LOOP;
    RETURN n;
END $$ LANGUAGE plpgsql;

SELECT shoc.enable_tenant_rls();
