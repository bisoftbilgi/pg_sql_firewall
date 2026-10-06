-- QA fixture (qa/package_upgrade_check.sh): the update script of a
-- hypothetical release 0.0.1, written as every real update script must start
-- (README 6.9a): refuse without preload, and until the server runs the
-- library of the release being installed.
\echo Use "ALTER EXTENSION sql_firewall UPDATE TO '0.0.1'" to load this file. \quit
SELECT public.sql_firewall_require_preload();
DO $sqlfw_update$
DECLARE
    running text := (SELECT running_version FROM public.sql_firewall_library_version());
BEGIN
    IF running IS DISTINCT FROM '0.0.1' THEN
        RAISE EXCEPTION 'sql_firewall: the server runs library %, not 0.0.1; install the 0.0.1 package, restart PostgreSQL, and update again', coalesce(running, 'none')
            USING ERRCODE = '55000';
    END IF;
END
$sqlfw_update$;
-- The release's own change (a fixture: a comment).
COMMENT ON TABLE public.sql_firewall_command_approvals IS 'Command approvals per role (sql_firewall 0.0.1)';
