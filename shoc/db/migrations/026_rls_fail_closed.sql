-- 026 row-level security fails closed (SEC-1)
--
-- 007 and 009 let a session that never set `shoc.tenant_id`, or set it to '',
-- see and write every tenant's rows. A capability call whose connection missed
-- its pin therefore ran unscoped rather than failing. Now an unset or empty
-- setting matches no row. `shoc:all` stays the one way to act across tenants,
-- and the paths that need it (`shoc migrate`, `shoc grant-readonly`, the
-- worker's queue) set it explicitly.
--
-- The function is replaced so every table that gains a tenant_id later gets
-- the same policy, and it is run now to replace the policies already in place.
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
                current_setting('shoc.tenant_id', true) = 'shoc:all'
                OR tenant_id = current_setting('shoc.tenant_id', true)
            )
            WITH CHECK (
                current_setting('shoc.tenant_id', true) = 'shoc:all'
                OR tenant_id = current_setting('shoc.tenant_id', true)
            )$p$, t);
        n := n + 1;
    END LOOP;
    RETURN n;
END $$ LANGUAGE plpgsql;

SELECT shoc.enable_tenant_rls();
