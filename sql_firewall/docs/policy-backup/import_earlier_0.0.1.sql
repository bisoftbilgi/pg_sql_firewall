-- sql_firewall: load policy exported by export_earlier_0.0.1.sql.
--
-- Run as a superuser in the NEW database, right after restoring a dump that
-- was taken after export_earlier_0.0.1.sql, and before any application
-- traffic:
--   psql -X -v ON_ERROR_STOP=1 -d newdb -f import_earlier_0.0.1.sql
-- The restore installed the current sql_firewall, which registers its policy
-- with pg_dump, so later dumps of the new database need no export.
--
-- This is not a merge. It refuses to run unless the new installation's
-- policy is exactly what CREATE EXTENSION created: no approvals, no
-- fingerprints, no removal records, and one regex rule, the installation
-- default with its installed pattern, description, action, activation, and
-- roles (its id and created_at are not compared). A refusal changes nothing
-- and keeps sql_firewall_policy_export. On success it replaces that default
-- with the exported rule set, restores the exported rows with their ids,
-- counters, and timestamps, sets the id sequences to the exported positions,
-- and drops sql_firewall_policy_export.
--
-- READ COMMITTED is set here, for this transaction only, whatever the
-- connection, role, or database default is. Each statement then takes a new
-- snapshot, so the check that follows LOCK TABLE sees a change that a writer
-- committed while the import waited for the lock. Under REPEATABLE READ or
-- SERIALIZABLE the first statement would fix the snapshot before the lock,
-- and the check could miss that change and merge into it.
BEGIN ISOLATION LEVEL READ COMMITTED;

DO $sqlfw_import$
BEGIN
    IF pg_catalog.to_regnamespace('sql_firewall_policy_export') IS NULL THEN
        RAISE EXCEPTION 'schema sql_firewall_policy_export not found; restore a dump taken after export_earlier_0.0.1.sql';
    END IF;
    IF pg_catalog.to_regclass('public.sql_firewall_regex_default_removals') IS NULL THEN
        RAISE EXCEPTION 'this database has an sql_firewall installation without policy backup support; restore into a database where the current version is installed';
    END IF;
END
$sqlfw_import$;

-- Until this transaction ends, no other session can change these tables
-- (the approval worker waits too); plain reads, such as the firewall's own
-- policy lookups, continue. The check below therefore sees every committed
-- change, and nothing can change between the check and the replacement.
LOCK TABLE public.sql_firewall_command_approvals,
           public.sql_firewall_query_fingerprints,
           public.sql_firewall_regex_rules,
           public.sql_firewall_regex_default_removals
    IN EXCLUSIVE MODE;

DO $sqlfw_import$
BEGIN
    IF EXISTS (SELECT 1 FROM public.sql_firewall_command_approvals)
        OR EXISTS (SELECT 1 FROM public.sql_firewall_query_fingerprints)
        OR EXISTS (SELECT 1 FROM public.sql_firewall_regex_default_removals)
        OR (SELECT pg_catalog.count(*) FROM public.sql_firewall_regex_rules)
            OPERATOR(pg_catalog.<>) 1
        OR NOT EXISTS (
            SELECT 1 FROM public.sql_firewall_regex_rules
            WHERE installation_default OPERATOR(pg_catalog.=) 'simple_sql_injection'
              AND pattern OPERATOR(pg_catalog.=) '(or|--|#)\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\s*=\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)'
              AND description OPERATOR(pg_catalog.=) 'Block simple SQL injection pattern'
              AND action OPERATOR(pg_catalog.=) 'BLOCK'
              AND is_active
              AND allowed_roles IS NULL)
    THEN
        RAISE EXCEPTION 'sql_firewall policy in this database is not freshly installed; this import does not merge policy. Nothing was changed; sql_firewall_policy_export is kept';
    END IF;
END
$sqlfw_import$;

-- Replace the new installation's default with the exported rule set.
-- Deleting it records it as removed; the exported copy, if any, reinstates it.
DELETE FROM public.sql_firewall_regex_rules;

INSERT INTO public.sql_firewall_command_approvals
    (id, role_name, command_type, is_approved, created_at, updated_at)
SELECT id, role_name, command_type, is_approved, created_at, updated_at
FROM sql_firewall_policy_export.command_approvals;

INSERT INTO public.sql_firewall_query_fingerprints
    (id, fingerprint, normalized_query, role_name, command_type, sample_query,
     hit_count, is_approved, first_seen_at, last_seen_at)
SELECT id, fingerprint, normalized_query, role_name, command_type, sample_query,
       hit_count, is_approved, first_seen_at, last_seen_at
FROM sql_firewall_policy_export.query_fingerprints;

-- The earlier script inserted one rule. A row that still has that rule's
-- pattern is that rule, whatever else was edited; otherwise it stays removed.
INSERT INTO public.sql_firewall_regex_rules
    (id, pattern, description, action, is_active, allowed_roles, created_at,
     installation_default)
SELECT id, pattern, description, action, is_active, allowed_roles, created_at,
       CASE WHEN pattern OPERATOR(pg_catalog.=) '(or|--|#)\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\s*=\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)'
            THEN 'simple_sql_injection' END
FROM sql_firewall_policy_export.regex_rules;

-- setval is not undone by a rollback, so it runs after the checks and the
-- row loads; nothing after it is expected to fail.
SELECT pg_catalog.setval(sequence_name::pg_catalog.regclass, last_value, is_called)
FROM sql_firewall_policy_export.sequences;

DROP SCHEMA sql_firewall_policy_export CASCADE;

COMMIT;
