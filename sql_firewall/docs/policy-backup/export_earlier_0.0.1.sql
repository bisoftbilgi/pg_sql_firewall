-- sql_firewall: prepare an EARLIER 0.0.1 installation for pg_dump.
--
-- Use only in a database whose sql_firewall was installed by a 0.0.1 script
-- from before policy backup support (README 6.9). Such an installation does
-- not register its policy tables with pg_dump, so a dump of it contains no
-- policy rows. This script copies the policy rows, from one snapshot, into
-- ordinary tables in the schema sql_firewall_policy_export, and records the
-- id sequence positions next to them. A sequence position is not part of a
-- snapshot: it is read when the copy runs and is at or ahead of every copied
-- id, unless it was set back by hand. A normal pg_dump of the database then
-- carries the copies. Nothing belonging to the extension is changed or removed.
--
-- Run as a superuser, immediately before pg_dump:
--   psql -X -v ON_ERROR_STOP=1 -d mydb -f export_earlier_0.0.1.sql
-- After restoring the dump into a new database, run
-- import_earlier_0.0.1.sql there. The schema can be dropped from this
-- database once the dump has been verified.
BEGIN ISOLATION LEVEL REPEATABLE READ;

DO $sqlfw_export$
DECLARE
    config pg_catalog.oid[];
BEGIN
    SELECT e.extconfig INTO config
    FROM pg_catalog.pg_extension AS e
    WHERE e.extname OPERATOR(pg_catalog.=) 'sql_firewall';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'sql_firewall is not installed in this database';
    END IF;
    IF config IS NOT NULL
        AND 'public.sql_firewall_regex_rules'::pg_catalog.regclass::pg_catalog.oid
            OPERATOR(pg_catalog.=) ANY (config)
    THEN
        RAISE EXCEPTION 'this sql_firewall installation already registers its policy with pg_dump; no export is needed';
    END IF;
END
$sqlfw_export$;

CREATE SCHEMA sql_firewall_policy_export;
REVOKE ALL ON SCHEMA sql_firewall_policy_export FROM PUBLIC;

CREATE TABLE sql_firewall_policy_export.command_approvals AS
    TABLE public.sql_firewall_command_approvals;
CREATE TABLE sql_firewall_policy_export.query_fingerprints AS
    TABLE public.sql_firewall_query_fingerprints;
CREATE TABLE sql_firewall_policy_export.regex_rules AS
    TABLE public.sql_firewall_regex_rules;
CREATE TABLE sql_firewall_policy_export.sequences AS
    SELECT 'public.sql_firewall_command_approvals_id_seq'::pg_catalog.text AS sequence_name,
           last_value, is_called
    FROM public.sql_firewall_command_approvals_id_seq
    UNION ALL
    SELECT 'public.sql_firewall_query_fingerprints_id_seq', last_value, is_called
    FROM public.sql_firewall_query_fingerprints_id_seq
    UNION ALL
    SELECT 'public.sql_firewall_regex_rules_id_seq', last_value, is_called
    FROM public.sql_firewall_regex_rules_id_seq;

COMMIT;
