-- First statement of the fresh installation script.
-- Extension scripts run this even when preload hooks are absent, the
-- firewall is disabled, or superuser bypass is on. Failure aborts the
-- extension transaction, so a rejected install leaves no objects.
DO $sqlfw_utf8$
BEGIN
    IF pg_catalog.current_setting('server_encoding')
        OPERATOR(pg_catalog.<>) 'UTF8'::pg_catalog.text
    THEN
        RAISE EXCEPTION
            'sql_firewall: UTF8 database encoding is required; server_encoding is %',
            pg_catalog.current_setting('server_encoding')
            USING ERRCODE = '0A000';
    END IF;
END
$sqlfw_utf8$;
