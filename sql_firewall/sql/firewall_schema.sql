-- Core tables for sql_firewall. These definitions mirror the legacy C extension
-- but grant the necessary privileges so any role can interact with the firewall.

CREATE TABLE IF NOT EXISTS public.sql_firewall_activity_log (
    log_id           SERIAL PRIMARY KEY,
    log_time         TIMESTAMPTZ DEFAULT now() NOT NULL,
    role_name        NAME,
    database_name    NAME,
    query_text       TEXT,
    application_name TEXT,
    client_ip        TEXT,
    command_type     TEXT,
    action           TEXT,
    reason           TEXT,
    decision         TEXT CHECK (decision IN ('allowed', 'learn', 'would_block', 'unchecked')),
    query_truncated  BOOLEAN NOT NULL DEFAULT false,
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_activity_log IS 'Firewall decisions for allowed statements, written by the approval worker from the activity queue (README 6.7).';
COMMENT ON COLUMN public.sql_firewall_activity_log.log_time IS 'When the firewall decided (the statement was inspected).';
COMMENT ON COLUMN public.sql_firewall_activity_log.recorded_at IS 'When the worker wrote the row.';
COMMENT ON COLUMN public.sql_firewall_activity_log.action IS 'Action performed: ALLOWED, ALLOWED (LEARN MODE - AUTO), ALLOWED (PERMISSIVE - ...), LEARNED (FINGERPRINT AUTO), etc.';
COMMENT ON COLUMN public.sql_firewall_activity_log.decision IS 'allowed: policy satisfied; learn: allowed by learn mode; would_block: allowed by permissive mode, enforce would reject; unchecked: an OTHER command outside enforce. NULL for rows not written by the firewall.';
COMMENT ON COLUMN public.sql_firewall_activity_log.reason IS 'Reason for the action: Rate limit, blacklisted keyword, etc.';
COMMENT ON COLUMN public.sql_firewall_activity_log.query_truncated IS 'True if the statement text was longer than the 2 kB the queue carries.';

ALTER TABLE public.sql_firewall_activity_log SET LOGGED;

CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_time
    ON public.sql_firewall_activity_log(role_name, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_role_cmd_time
    ON public.sql_firewall_activity_log(role_name, command_type, log_time);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_action
    ON public.sql_firewall_activity_log(action);
CREATE INDEX IF NOT EXISTS idx_sqlfw_activity_time_id
    ON public.sql_firewall_activity_log(log_time, log_id);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from tampering with firewall logs and configuration

-- Dedicated table for blocked queries - separate from activity log for security analysis
-- ENHANCED: Now with 2KB query buffer, truncation flag, and richer metadata
CREATE TABLE IF NOT EXISTS public.sql_firewall_blocked_queries (
    block_id         SERIAL PRIMARY KEY,
    blocked_at       TIMESTAMPTZ DEFAULT now() NOT NULL,
    role_name        NAME,
    database_name    NAME,
    query_text       TEXT,               -- Up to 2KB query text (enforced by ring buffer)
    query_truncated  BOOLEAN DEFAULT false, -- True if query was larger than 2KB
    application_name TEXT,
    client_addr      TEXT,               -- Renamed from client_ip for consistency
    command_type     TEXT,
    reason           TEXT,               -- Renamed from block_reason for consistency with activity log
    decision         TEXT NOT NULL DEFAULT 'blocked' CHECK (decision = 'blocked'),
    recorded_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_blocked_queries IS 'Dedicated log for blocked queries - useful for security analysis and auditing.';
COMMENT ON COLUMN public.sql_firewall_blocked_queries.query_truncated IS 'True if query was truncated at 2KB limit during capture.';
COMMENT ON COLUMN public.sql_firewall_blocked_queries.reason IS 'Reason why the query was blocked: No approval, regex match, rate limit, etc.';
COMMENT ON COLUMN public.sql_firewall_blocked_queries.blocked_at IS 'When the firewall rejected the statement.';
COMMENT ON COLUMN public.sql_firewall_blocked_queries.recorded_at IS 'When the worker wrote the row.';

ALTER TABLE public.sql_firewall_blocked_queries SET LOGGED;

CREATE INDEX IF NOT EXISTS idx_sqlfw_blocked_role_time
    ON public.sql_firewall_blocked_queries(role_name, blocked_at);
CREATE INDEX IF NOT EXISTS idx_sqlfw_blocked_command_time
    ON public.sql_firewall_blocked_queries(command_type, blocked_at);
CREATE INDEX IF NOT EXISTS idx_sqlfw_blocked_time_id
    ON public.sql_firewall_blocked_queries(blocked_at, block_id);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from tampering with security audit logs

-- ENHANCED: is_approved column tracks whether approval was granted or pending
CREATE TABLE IF NOT EXISTS public.sql_firewall_command_approvals (
    id           SERIAL PRIMARY KEY,
    role_name    NAME        NOT NULL,
    command_type TEXT        NOT NULL,
    is_approved  BOOLEAN     NOT NULL DEFAULT false,  -- TRUE = approved, FALSE = pending admin review
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),  -- Track when approval status last changed
    UNIQUE (role_name, command_type)
);

COMMENT ON TABLE  public.sql_firewall_command_approvals IS 'Approval status of command types per role.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.is_approved IS 'If true, this role is allowed to execute the command type. If false, approval is pending admin review.';
COMMENT ON COLUMN public.sql_firewall_command_approvals.updated_at IS 'Timestamp when approval status was last changed (useful for auditing approval grants).';

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from approving their own commands

CREATE TABLE IF NOT EXISTS public.sql_firewall_regex_rules (
    id            SERIAL PRIMARY KEY,
    pattern       TEXT    NOT NULL UNIQUE,
    description   TEXT,
    action        TEXT    NOT NULL DEFAULT 'BLOCK' CHECK (action = 'BLOCK'),
    is_active     BOOLEAN NOT NULL DEFAULT true,
    allowed_roles TEXT[], -- NULL means rule applies to all roles, non-NULL means rule only applies to listed roles
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Key of a rule CREATE EXTENSION inserted; NULL for administrator rules.
    -- The default marks a statement that did not name the column (see below).
    installation_default TEXT UNIQUE DEFAULT '(new rule)'
);

COMMENT ON TABLE  public.sql_firewall_regex_rules IS 'Regex rules used to match and block SQL queries.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.pattern IS 'Regex pattern to apply on the query text.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.allowed_roles IS 'List of roles for which this rule applies. NULL means applies to all roles.';
COMMENT ON COLUMN public.sql_firewall_regex_rules.installation_default IS 'Key of a rule inserted by CREATE EXTENSION, NULL for rules added later. Identifies the rule through pg_dump and restore; cannot be changed. A row that states it is a loaded row (pg_dump states every column).';

-- CRITICAL: Validate regex patterns to prevent ReDoS attacks
CREATE OR REPLACE FUNCTION validate_firewall_regex_pattern()
RETURNS TRIGGER AS $$
BEGIN
    -- Check for dangerous patterns that can cause ReDoS
    IF NEW.pattern ~ '.*\(\?.*\{.*\}.*\).*' THEN
        RAISE EXCEPTION 'Complex nested quantifiers not allowed (ReDoS risk)';
    END IF;
    
    -- Check for excessive repetition operators
    IF NEW.pattern ~ '.*((\+\+)|(\*\*)|(\+\*)).*' THEN
        RAISE EXCEPTION 'Multiple adjacent quantifiers not allowed (ReDoS risk)';
    END IF;
    
    -- Test pattern with a simple string to ensure it's valid
    BEGIN
        PERFORM 'test' ~ NEW.pattern;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Invalid regex pattern: %', SQLERRM;
    END;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_regex_trigger
BEFORE INSERT OR UPDATE ON public.sql_firewall_regex_rules
FOR EACH ROW EXECUTE FUNCTION validate_firewall_regex_pattern();

-- SECURITY: No direct grants to PUBLIC - all access through admin functions
-- Users can query via SECURITY DEFINER functions but cannot modify

-- The installation default. Its installation_default key, not its id or
-- pattern, identifies it through pg_dump and restore (triggers below). It is
-- installed inactive: it reads raw text and matches ordinary SQL such as
-- "WHERE a = 1 OR b = 2" and comments like "-- ticket = 4711" (README 6.6).
INSERT INTO public.sql_firewall_regex_rules (pattern, description, installation_default, is_active)
SELECT '(or|--|#)\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\s*=\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)', 'Block simple SQL injection pattern', 'simple_sql_injection', false
WHERE NOT EXISTS (
    SELECT 1 FROM public.sql_firewall_regex_rules WHERE pattern = '(or|--|#)\s+([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)\s*=\s*([[:alpha:]_][[:alnum:]_]*|''[^'']*''|[0-9]+)'
);

-- Installation defaults an administrator deleted. pg_dump carries these rows
-- with the rules, so a restore deletes the fresh copy CREATE EXTENSION made
-- instead of bringing a deleted rule back.
CREATE TABLE IF NOT EXISTS public.sql_firewall_regex_default_removals (
    installation_default TEXT PRIMARY KEY,
    removed_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.sql_firewall_regex_default_removals IS
    'Installation default regex rules that were deleted. Maintained by triggers; kept by pg_dump.';

-- A restore runs CREATE EXTENSION, which inserts the installation defaults,
-- and then loads the dumped rules and removal records into the new tables, in
-- an order that neither pg_dump nor this script controls: the rows of one
-- table in scan order, and the two tables in either order or concurrently
-- (pg_restore --jobs). Every loaded row can therefore settle the fresh copy
-- on its own:
--  * pg_dump names every column, so a loaded rule states installation_default
--    (NULL for an administrator rule). A statement that does not name it gets
--    '(new rule)', which becomes NULL: a new rule, with ordinary uniqueness.
--  * A loaded rule takes the place of any installation default it collides
--    with on key, id, or pattern. In a restore that is only ever the fresh
--    copy, because the dumped rules were unique among themselves. So an
--    unchanged or edited default arrives as dumped, and an administrator rule
--    that took the default's pattern or id loads in any order.
--  * A loaded removal record deletes the default with its key, so a default
--    that was deleted stays deleted.
--  * Taking a default's place is not a removal: it records nothing, so it
--    cannot collide with a removal record being loaded at the same time.
-- In normal use, deleting or truncating a default records its removal, and
-- inserting a row with its key clears the record. The key cannot be changed.
CREATE OR REPLACE FUNCTION public.sql_firewall_regex_default_changed()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.installation_default OPERATOR(pg_catalog.=) '(new rule)' THEN
            -- The statement did not name installation_default: a new rule.
            NEW.installation_default := NULL;
            RETURN NEW;
        END IF;
        -- A loaded rule. It takes the place of every installation default it
        -- would collide with, by key, id, or pattern. That is not a removal.
        PERFORM pg_catalog.set_config('sql_firewall_internal.displacing_default', 'on', true);
        DELETE FROM public.sql_firewall_regex_rules
        WHERE installation_default IS NOT NULL
          AND (installation_default OPERATOR(pg_catalog.=) NEW.installation_default
               OR id OPERATOR(pg_catalog.=) NEW.id
               OR pattern OPERATOR(pg_catalog.=) NEW.pattern);
        PERFORM pg_catalog.set_config('sql_firewall_internal.displacing_default', 'off', true);
        IF NEW.installation_default IS NOT NULL THEN
            DELETE FROM public.sql_firewall_regex_default_removals
            WHERE installation_default OPERATOR(pg_catalog.=) NEW.installation_default;
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.installation_default IS DISTINCT FROM OLD.installation_default THEN
            RAISE EXCEPTION 'sql_firewall: installation_default of a regex rule cannot be changed'
                USING ERRCODE = '0A000';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.installation_default IS NOT NULL
           AND pg_catalog.current_setting('sql_firewall_internal.displacing_default', true)
               IS DISTINCT FROM 'on'
        THEN
            INSERT INTO public.sql_firewall_regex_default_removals (installation_default)
            VALUES (OLD.installation_default)
            ON CONFLICT (installation_default) DO NOTHING;
        END IF;
        RETURN NULL;
    END IF;
    -- TRUNCATE
    INSERT INTO public.sql_firewall_regex_default_removals (installation_default)
    SELECT installation_default FROM public.sql_firewall_regex_rules
    WHERE installation_default IS NOT NULL
    ON CONFLICT (installation_default) DO NOTHING;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

CREATE OR REPLACE FUNCTION public.sql_firewall_regex_default_removed()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM public.sql_firewall_regex_rules
    WHERE installation_default OPERATOR(pg_catalog.=) NEW.installation_default;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- ENABLE ALWAYS: also with session_replication_role = replica.
CREATE TRIGGER sql_firewall_regex_default_write
    BEFORE INSERT OR UPDATE ON public.sql_firewall_regex_rules
    FOR EACH ROW EXECUTE FUNCTION public.sql_firewall_regex_default_changed();
CREATE TRIGGER sql_firewall_regex_default_delete
    AFTER DELETE ON public.sql_firewall_regex_rules
    FOR EACH ROW EXECUTE FUNCTION public.sql_firewall_regex_default_changed();
CREATE TRIGGER sql_firewall_regex_default_truncate
    BEFORE TRUNCATE ON public.sql_firewall_regex_rules
    FOR EACH STATEMENT EXECUTE FUNCTION public.sql_firewall_regex_default_changed();
CREATE TRIGGER sql_firewall_regex_default_removed
    AFTER INSERT ON public.sql_firewall_regex_default_removals
    FOR EACH ROW EXECUTE FUNCTION public.sql_firewall_regex_default_removed();
ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_regex_default_write;
ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_regex_default_delete;
ALTER TABLE public.sql_firewall_regex_rules ENABLE ALWAYS TRIGGER sql_firewall_regex_default_truncate;
ALTER TABLE public.sql_firewall_regex_default_removals ENABLE ALWAYS TRIGGER sql_firewall_regex_default_removed;

-- Trigger functions cannot be called directly; firing does not check EXECUTE.
REVOKE ALL ON FUNCTION public.sql_firewall_regex_default_changed() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_regex_default_removed() FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_regex_default_removals FROM PUBLIC;

CREATE TABLE IF NOT EXISTS public.sql_firewall_query_fingerprints (
    id               SERIAL PRIMARY KEY,
    fingerprint      TEXT        NOT NULL,
    normalized_query TEXT        NOT NULL,
    role_name        NAME        NOT NULL,
    command_type     TEXT        NOT NULL,
    sample_query     TEXT        NOT NULL,
    hit_count        INTEGER     NOT NULL DEFAULT 1,
    is_approved      BOOLEAN     NOT NULL DEFAULT false,
    auto_approval_disabled BOOLEAN NOT NULL DEFAULT false,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (fingerprint, role_name, command_type)
);

-- Decision order for queued learning (policy_visibility.rs). Every
-- administrator transaction that writes a policy table advances its row once,
-- before the statement changes any policy row, and holds the row lock until it
-- ends, so the values follow commit order. A backend reads the value in the
-- same snapshot as the policy lookup that produced a learn event and carries
-- it in the event. The worker takes the row FOR SHARE, so it waits for an
-- administrator transaction in progress, and discards an event when
-- sql_firewall_policy_history has an administrator change to the same key
-- (or a TRUNCATE) with a later epoch. Runtime coordination for this
-- installation, not policy data: not dumped; a restore starts at 0.
-- Backends read it as the calling user, like the policy tables.
CREATE TABLE public.sql_firewall_policy_epoch (
    kind TEXT PRIMARY KEY CHECK (kind IN ('approvals', 'fingerprints')),
    epoch BIGINT NOT NULL DEFAULT 0 CHECK (epoch >= 0)
);
INSERT INTO public.sql_firewall_policy_epoch (kind) VALUES ('approvals'), ('fingerprints');
REVOKE ALL ON TABLE public.sql_firewall_policy_epoch FROM PUBLIC;
GRANT SELECT ON TABLE public.sql_firewall_policy_epoch TO PUBLIC;

COMMENT ON TABLE public.sql_firewall_policy_epoch IS
    'Commit-ordered counter of administrator policy transactions, per policy table. Runtime state; not dumped.';

-- Committed history of policy decisions. Written by the policy triggers in the
-- writing transaction, so a rolled-back change leaves no row. Administrator
-- rows: every row change and TRUNCATE, through the management functions or
-- direct DML. Learn rows: only the approval-worker changes that alter a
-- decision (a new approved row, or is_approved/auto_approval_disabled
-- changing); a discovered pending fingerprint and hit counting are not
-- decisions. old_* is the row before the change (UPDATE, DELETE), new_* after
-- it (INSERT, UPDATE); TRUNCATE has neither.
-- A change is identified within its installation (cluster system identifier,
-- database OID, extension OID): pg_dump keeps the rows, and the rows a restore
-- itself writes into the new installation cannot collide with them.
-- transaction_id joins pg_xact_commit_timestamp() when track_commit_timestamp
-- is on; changed_at is the time of the change, not of the commit.
CREATE TABLE public.sql_firewall_policy_history (
    system_identifier          NUMERIC(20,0) NOT NULL,
    database_oid               OID         NOT NULL,
    extension_oid              OID         NOT NULL,
    change_id                  BIGSERIAL,
    policy_epoch               BIGINT      NOT NULL,
    changed_at                 TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    transaction_id             XID8        NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
    policy_table               TEXT        NOT NULL CHECK (policy_table IN ('command_approvals', 'query_fingerprints')),
    operation                  TEXT        NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')),
    source                     TEXT        NOT NULL CHECK (source IN ('administrator', 'learn')),
    session_role               NAME        NOT NULL,
    effective_role             NAME        NOT NULL,
    old_role_name              NAME,
    old_command_type           TEXT,
    old_fingerprint            TEXT,
    old_is_approved            BOOLEAN,
    old_auto_approval_disabled BOOLEAN,
    new_role_name              NAME,
    new_command_type           TEXT,
    new_fingerprint            TEXT,
    new_is_approved            BOOLEAN,
    new_auto_approval_disabled BOOLEAN,
    PRIMARY KEY (system_identifier, database_oid, extension_oid, change_id)
);

COMMENT ON TABLE public.sql_firewall_policy_history IS
    'Committed policy decision changes: who (session and effective role), when, source (administrator or learn worker), and the values before and after.';

-- The worker's barrier lookup: recent administrator changes of this installation.
CREATE INDEX idx_sqlfw_policy_history_barrier
    ON public.sql_firewall_policy_history (extension_oid, database_oid, policy_table, policy_epoch)
    WHERE source = 'administrator';
CREATE INDEX idx_sqlfw_policy_history_time
    ON public.sql_firewall_policy_history (changed_at);

REVOKE ALL ON TABLE public.sql_firewall_policy_history FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_policy_history_change_id_seq FROM PUBLIC;

COMMENT ON TABLE  public.sql_firewall_query_fingerprints IS 'Normalized query fingerprints tracked per role.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.hit_count IS 'Number of times this fingerprint has been observed.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.is_approved IS 'If true, queries matching this fingerprint are allowed.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.auto_approval_disabled IS 'Set by an administrator to keep Learn from automatically reapproving a blocked fingerprint; explicit approval clears it.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.first_seen_at IS 'Timestamp when this fingerprint was first recorded.';
COMMENT ON COLUMN public.sql_firewall_query_fingerprints.last_seen_at IS 'Timestamp when this fingerprint was last observed.';

CREATE INDEX IF NOT EXISTS idx_sqlfw_fingerprint_role
    ON public.sql_firewall_query_fingerprints(role_name, fingerprint);
CREATE INDEX IF NOT EXISTS idx_sqlfw_fingerprint_last_seen
    ON public.sql_firewall_query_fingerprints(last_seen_at);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions
-- This prevents users from tampering with learned fingerprints

-- NEW: Fingerprint hits table for background worker event processing
CREATE TABLE IF NOT EXISTS public.sql_firewall_fingerprint_hits (
    fingerprint      TEXT PRIMARY KEY,
    normalized_query TEXT        NOT NULL,
    role_name        NAME,
    command_type     TEXT,
    sample_query     TEXT,
    hit_count        BIGINT      NOT NULL DEFAULT 1,
    is_approved      BOOLEAN     NOT NULL DEFAULT false,
    first_hit_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_hit_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  public.sql_firewall_fingerprint_hits IS 'Fingerprint hit tracking populated by background worker from ring buffer events.';
COMMENT ON COLUMN public.sql_firewall_fingerprint_hits.hit_count IS 'Number of times this fingerprint has been observed (incremented by ON CONFLICT).';
COMMENT ON COLUMN public.sql_firewall_fingerprint_hits.is_approved IS 'If true, queries matching this fingerprint are allowed.';

CREATE INDEX IF NOT EXISTS idx_sqlfw_fphits_approved
    ON public.sql_firewall_fingerprint_hits(is_approved, hit_count DESC);
CREATE INDEX IF NOT EXISTS idx_sqlfw_fphits_last_hit
    ON public.sql_firewall_fingerprint_hits(last_hit_at DESC);

-- SECURITY: No direct grants to PUBLIC - all access through SECURITY DEFINER functions

-- ============================================================================
-- SECURITY DEFINER Functions for Controlled Admin Access
-- ============================================================================
-- These management functions authorize session_user via pg_catalog.pg_authid
-- (rolsuper is the column behind pg_user.usesuper). Each sets
-- search_path = pg_catalog, pg_temp, with pg_temp listed explicitly and last.
-- If pg_temp is omitted, PostgreSQL searches it before pg_catalog for relations.
-- Extension tables are schema-qualified. Standard types and operators then
-- resolve in pg_catalog; pg_temp is not searched for operators.

-- Function to approve a command for a role (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_approve_command(
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can approve commands'
            USING ERRCODE = '42501';
    END IF;
    
    INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved)
    VALUES (p_role_name, p_command_type, true)
    ON CONFLICT (role_name, command_type) 
    DO UPDATE SET is_approved = true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

COMMENT ON FUNCTION public.sql_firewall_approve_command IS 
'Approve a command type for a specific role. Only callable by superusers.';

-- Function to revoke command approval (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_revoke_command(
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can revoke commands'
            USING ERRCODE = '42501';
    END IF;

    -- An explicit denial, also for a command not observed yet: Learn never
    -- approves a command that already has a row.
    INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved)
    VALUES (p_role_name, p_command_type, false)
    ON CONFLICT (role_name, command_type)
    DO UPDATE SET is_approved = false;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Function to approve a fingerprint (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_approve_fingerprint(
    p_fingerprint TEXT,
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can approve fingerprints'
            USING ERRCODE = '42501';
    END IF;
    
    UPDATE public.sql_firewall_query_fingerprints
    SET is_approved = true,
        auto_approval_disabled = false
    WHERE fingerprint = p_fingerprint 
      AND role_name = p_role_name 
      AND command_type = p_command_type;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Function to block a fingerprint (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_block_fingerprint(
    p_fingerprint TEXT,
    p_role_name NAME,
    p_command_type TEXT
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can block fingerprints'
            USING ERRCODE = '42501';
    END IF;
    
    UPDATE public.sql_firewall_query_fingerprints
    SET is_approved = false,
        auto_approval_disabled = true
    WHERE fingerprint = p_fingerprint 
      AND role_name = p_role_name 
      AND command_type = p_command_type;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Function to add a regex rule (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_add_regex_rule(
    p_pattern TEXT,
    p_description TEXT DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_rule_id INTEGER;
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can add regex rules'
            USING ERRCODE = '42501';
    END IF;
    
    INSERT INTO public.sql_firewall_regex_rules (pattern, description)
    VALUES (p_pattern, p_description)
    RETURNING id INTO v_rule_id;
    
    RETURN v_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Function to delete a regex rule (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_delete_regex_rule(
    p_rule_id INTEGER
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can delete regex rules'
            USING ERRCODE = '42501';
    END IF;
    
    DELETE FROM public.sql_firewall_regex_rules
    WHERE id = p_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Function to toggle regex rule active status (only superusers can call this)
CREATE OR REPLACE FUNCTION public.sql_firewall_toggle_regex_rule(
    p_rule_id INTEGER,
    p_is_active BOOLEAN
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can modify regex rules'
            USING ERRCODE = '42501';
    END IF;
    
    UPDATE public.sql_firewall_regex_rules
    SET is_active = p_is_active
    WHERE id = p_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- Superuser-only management functions. PostgreSQL grants EXECUTE to PUBLIC
-- by default, so removing a GRANT is not enough: revoke it. The bodies above
-- still reject a non-superuser (SQLSTATE 42501) if EXECUTE is granted later.
-- No separate administrative role is introduced.
REVOKE ALL ON FUNCTION public.sql_firewall_approve_command(NAME, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_revoke_command(NAME, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_approve_fingerprint(TEXT, NAME, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_block_fingerprint(TEXT, NAME, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_add_regex_rule(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_delete_regex_rule(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_toggle_regex_rule(INTEGER, BOOLEAN) FROM PUBLIC;


-- ============================================================================
-- SECURITY DEFINER Wrappers for Extension Internal Operations
-- ============================================================================
-- These functions allow the extension to write to catalog tables
-- without granting INSERT/UPDATE/DELETE to PUBLIC

-- Log activity (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_log_activity(
    p_role_name NAME,
    p_database_name NAME,
    p_query_text TEXT,
    p_application_name TEXT,
    p_client_ip TEXT,
    p_command_type TEXT,
    p_action TEXT,
    p_reason TEXT
) RETURNS VOID AS $$
DECLARE
    v_role NAME := p_role_name;
BEGIN
    -- SECURITY: not called by the extension any more (README 6.7) and not
    -- executable by PUBLIC. If EXECUTE is granted again, it still does not
    -- trust the identity the caller passes in: a non-superuser may only log
    -- as session_user or a role it is a member of, which covers SET ROLE.
    IF NOT (SELECT usesuper FROM pg_catalog.pg_user WHERE usename = session_user) THEN
        -- NOTE: the pg_roles existence test must come first. pg_has_role()
        -- RAISES for a role name that does not exist, which would turn a forged
        -- (or merely stale) role name into a failed statement instead of a
        -- correctly attributed log row.
        IF v_role IS NULL
           OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role)
           OR NOT pg_catalog.pg_has_role(session_user, v_role, 'MEMBER')
        THEN
            v_role := session_user;
        END IF;
    END IF;

    INSERT INTO public.sql_firewall_activity_log (
        role_name, database_name, query_text, application_name,
        client_ip, command_type, action, reason
    ) VALUES (
        v_role, current_database(), p_query_text, p_application_name,
        p_client_ip, p_command_type, p_action, p_reason
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;

-- Log blocked query to dedicated table (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_log_blocked_query(
    p_role_name NAME,
    p_database_name NAME,
    p_query_text TEXT,
    p_application_name TEXT,
    p_client_ip TEXT,
    p_command_type TEXT,
    p_block_reason TEXT
) RETURNS VOID AS $$
DECLARE
    v_conn TEXT;
    v_result TEXT;
BEGIN
    -- Use dblink to perform autonomous transaction that survives rollback
    -- This ensures blocked queries are logged even when the main transaction aborts
    BEGIN
        -- Connect to current database using dblink (safely quote database name)
        v_conn := 'dbname=' || quote_ident(current_database());
        PERFORM dblink_connect('firewall_log_conn', v_conn);
        
        -- Execute INSERT in autonomous transaction
        PERFORM dblink_exec('firewall_log_conn',
            format('INSERT INTO public.sql_firewall_blocked_queries 
                (role_name, database_name, query_text, application_name, client_addr, command_type, reason) 
                VALUES (%L, %L, %L, %L, %L, %L, %L)',
                p_role_name, p_database_name, p_query_text, p_application_name,
                p_client_ip, p_command_type, p_block_reason
            )
        );
        
        -- Disconnect dblink
        PERFORM dblink_disconnect('firewall_log_conn');
    EXCEPTION WHEN OTHERS THEN
        -- If dblink fails, fall back to regular INSERT (which may rollback)
        BEGIN
            PERFORM dblink_disconnect('firewall_log_conn');
        EXCEPTION WHEN OTHERS THEN
            -- Ignore disconnect errors
        END;
        
        -- Fallback: regular insert (will rollback with transaction)
        INSERT INTO public.sql_firewall_blocked_queries (
            role_name, database_name, query_text, application_name,
            client_addr, command_type, reason
        ) VALUES (
            p_role_name, p_database_name, p_query_text, p_application_name,
            p_client_ip, p_command_type, p_block_reason
        );
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Record or update fingerprint (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_upsert_fingerprint(
    p_fingerprint TEXT,
    p_normalized_query TEXT,
    p_role_name NAME,
    p_command_type TEXT,
    p_sample_query TEXT,
    p_is_approved BOOLEAN
) RETURNS VOID AS $$
BEGIN
    INSERT INTO public.sql_firewall_query_fingerprints (
        fingerprint, normalized_query, role_name, command_type,
        sample_query, hit_count, is_approved, last_seen_at
    ) VALUES (
        p_fingerprint, p_normalized_query, p_role_name, p_command_type,
        p_sample_query, 1, p_is_approved, now()
    )
    ON CONFLICT (fingerprint, role_name, command_type) DO UPDATE
    SET hit_count = sql_firewall_query_fingerprints.hit_count + 1,
        last_seen_at = now();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create or update approval (called by extension internally)
CREATE OR REPLACE FUNCTION public.sql_firewall_internal_upsert_approval(
    p_role_name NAME,
    p_command_type TEXT,
    p_is_approved BOOLEAN
) RETURNS VOID AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can use this internal function'
            USING ERRCODE = '42501';
    END IF;
    
    INSERT INTO public.sql_firewall_command_approvals (
        role_name, command_type, is_approved
    ) VALUES (
        p_role_name, p_command_type, p_is_approved
    )
    ON CONFLICT (role_name, command_type) DO UPDATE
    SET is_approved = p_is_approved;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

-- SECURITY: PostgreSQL grants EXECUTE to PUBLIC by default, so each function
-- must be revoked explicitly. Removing a GRANT line is not enough.
--
-- sql_firewall_internal_log_activity is no longer called by backends: the
-- approval worker writes activity rows from the activity queue. Callable by
-- PUBLIC, it let any role write rows that looked like firewall decisions;
-- it is now superuser-only like the rest.
--
-- The other three were callable by any role with no privilege check at all:
--   * upsert_fingerprint let a user approve their own query fingerprint
--   * log_blocked_query let a user forge blocked-query records
--   * upsert_approval was the background worker's approval write
-- log_blocked_query, upsert_fingerprint and upsert_approval have no caller in
-- the extension (the worker writes directly and never overrides an existing
-- decision, README 6.1b); they are kept only for compatibility. A superuser
-- call is an administrator write like any other.
REVOKE ALL ON FUNCTION public.sql_firewall_internal_log_activity(NAME, NAME, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_internal_log_blocked_query(NAME, NAME, TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_internal_upsert_fingerprint(TEXT, TEXT, NAME, TEXT, TEXT, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_internal_upsert_approval(NAME, TEXT, BOOLEAN) FROM PUBLIC;


-- ========================================
-- LOG CLEANUP FUNCTIONS
-- ========================================

-- Clean activity log entries older than specified interval
CREATE OR REPLACE FUNCTION public.sql_firewall_cleanup_activity_log(
    p_retention_interval INTERVAL DEFAULT '30 days'
)
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    v_deleted_count BIGINT;
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can cleanup firewall logs'
            USING ERRCODE = '42501';
    END IF;
    
    DELETE FROM public.sql_firewall_activity_log
    WHERE log_time < (pg_catalog.now() - p_retention_interval);
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN QUERY SELECT v_deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

COMMENT ON FUNCTION public.sql_firewall_cleanup_activity_log(INTERVAL) IS 
'Delete activity log entries older than specified interval. Default: 30 days. Superuser only.';

-- Clean blocked queries log entries older than specified interval
CREATE OR REPLACE FUNCTION public.sql_firewall_cleanup_blocked_queries(
    p_retention_interval INTERVAL DEFAULT '90 days'
)
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    v_deleted_count BIGINT;
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can cleanup firewall logs'
            USING ERRCODE = '42501';
    END IF;
    
    DELETE FROM public.sql_firewall_blocked_queries
    WHERE blocked_at < (pg_catalog.now() - p_retention_interval);
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN QUERY SELECT v_deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

COMMENT ON FUNCTION public.sql_firewall_cleanup_blocked_queries(INTERVAL) IS 
'Delete blocked query log entries older than specified interval. Default: 90 days (longer retention for security analysis). Superuser only.';

-- Cleanup both logs in one transaction
CREATE OR REPLACE FUNCTION public.sql_firewall_cleanup_all_logs(
    p_activity_retention INTERVAL DEFAULT '30 days',
    p_blocked_retention INTERVAL DEFAULT '90 days'
)
RETURNS TABLE(
    activity_deleted BIGINT,
    blocked_deleted BIGINT,
    total_deleted BIGINT
) AS $$
DECLARE
    v_activity_count BIGINT;
    v_blocked_count BIGINT;
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can cleanup firewall logs'
            USING ERRCODE = '42501';
    END IF;
    
    -- Cleanup activity log
    DELETE FROM public.sql_firewall_activity_log
    WHERE log_time < (pg_catalog.now() - p_activity_retention);
    GET DIAGNOSTICS v_activity_count = ROW_COUNT;
    
    -- Cleanup blocked queries log
    DELETE FROM public.sql_firewall_blocked_queries
    WHERE blocked_at < (pg_catalog.now() - p_blocked_retention);
    GET DIAGNOSTICS v_blocked_count = ROW_COUNT;
    
    RETURN QUERY SELECT 
        v_activity_count,
        v_blocked_count,
        v_activity_count + v_blocked_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

COMMENT ON FUNCTION public.sql_firewall_cleanup_all_logs(INTERVAL, INTERVAL) IS 
'Cleanup both activity and blocked query logs in one transaction. Defaults: activity=30 days, blocked=90 days. Superuser only.';

-- Truncate all logs (emergency cleanup)
CREATE OR REPLACE FUNCTION public.sql_firewall_truncate_logs()
RETURNS TABLE(status TEXT) AS $$
BEGIN
    -- session_user, not current_user: SECURITY DEFINER changes current_user.
    -- pg_catalog.pg_authid.rolsuper is the catalog column behind pg_user.usesuper.
    -- No row, or rolsuper not TRUE, is a denial (missing auth must not pass).
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_authid AS a
        WHERE a.rolname = session_user
          AND a.rolsuper IS TRUE
    ) THEN
        RAISE EXCEPTION 'Only superusers can truncate firewall logs'
            USING ERRCODE = '42501';
    END IF;
    
    TRUNCATE TABLE public.sql_firewall_activity_log;
    TRUNCATE TABLE public.sql_firewall_blocked_queries;
    
    RETURN QUERY SELECT 'All firewall logs truncated successfully'::pg_catalog.text;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

COMMENT ON FUNCTION public.sql_firewall_truncate_logs() IS 
'Emergency function to truncate ALL firewall logs. Use with caution! Superuser only.';

-- Same PUBLIC-execute revocation as the command/rule functions above.
REVOKE ALL ON FUNCTION public.sql_firewall_cleanup_activity_log(INTERVAL) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_cleanup_blocked_queries(INTERVAL) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_cleanup_all_logs(INTERVAL, INTERVAL) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_truncate_logs() FROM PUBLIC;

-- ========================================
-- SECURITY: REVOKE DIRECT TABLE ACCESS
-- ========================================
-- All interaction with firewall tables must go through SECURITY DEFINER functions
-- This prevents users from tampering with firewall configuration and logs

-- Revoke all privileges on firewall tables from PUBLIC
REVOKE ALL ON TABLE public.sql_firewall_activity_log FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_blocked_queries FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_command_approvals FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_query_fingerprints FROM PUBLIC;
REVOKE ALL ON TABLE public.sql_firewall_regex_rules FROM PUBLIC;

-- Revoke sequence access
REVOKE ALL ON SEQUENCE public.sql_firewall_activity_log_log_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_blocked_queries_block_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_command_approvals_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_query_fingerprints_id_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.sql_firewall_regex_rules_id_seq FROM PUBLIC;

-- SECURITY: audit data is NOT world-readable.
-- sql_firewall_activity_log stores full query text including literal values;
-- granting SELECT to PUBLIC let the least privileged role in the database read
-- every other role's queries. Same for blocked_queries.
-- Reading these requires an explicit grant by the DBA.

-- Policy tables stay readable: the extension evaluates them over SPI as the
-- CALLING user, so revoking SELECT here would break the firewall itself.
GRANT SELECT ON TABLE public.sql_firewall_command_approvals TO PUBLIC;
GRANT SELECT ON TABLE public.sql_firewall_regex_rules TO PUBLIC;
GRANT SELECT ON TABLE public.sql_firewall_query_fingerprints TO PUBLIC;

-- Row security (README 6.1b "Who can read policy"). The firewall's own
-- lookups read the current role's rows only (policy_visibility.rs), so a role
-- sees its own approvals and fingerprints, including its own sample queries,
-- and not those of other roles. Superusers and the tables' owner are not
-- subject to row security. Members of pg_read_all_data see every row. There
-- is no write policy: only a superuser session writes these tables
-- (sql_firewall_guard), so a write grant neither changes policy nor reveals
-- other roles' rows.
-- The regex rules apply across roles and stay readable in full.
ALTER TABLE public.sql_firewall_command_approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY sql_firewall_read_own ON public.sql_firewall_command_approvals
    FOR SELECT TO PUBLIC
    USING (role_name OPERATOR(pg_catalog.=) CURRENT_USER
           OR pg_catalog.pg_has_role('pg_read_all_data', 'MEMBER'));

ALTER TABLE public.sql_firewall_query_fingerprints ENABLE ROW LEVEL SECURITY;
CREATE POLICY sql_firewall_read_own ON public.sql_firewall_query_fingerprints
    FOR SELECT TO PUBLIC
    USING (role_name OPERATOR(pg_catalog.=) CURRENT_USER
           OR pg_catalog.pg_has_role('pg_read_all_data', 'MEMBER'));

-- Configuration changes still require SECURITY DEFINER functions (no INSERT/UPDATE/DELETE)

-- ========================================
-- BACKUP: pg_dump keeps the policy rows
-- ========================================
-- Extension configuration relations: pg_dump writes all of their rows (the
-- condition is empty) and the positions of the id sequences, and a restore
-- loads them after CREATE EXTENSION. See README 6.9.
-- Not registered, so not in a dump: the activity and blocked-query logs
-- (audit records), sql_firewall_fingerprint_hits (nothing reads or writes
-- it), the policy epoch, and the consumer checkpoint below (runtime state of
-- one installation).
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_command_approvals', '');
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_command_approvals_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_query_fingerprints', '');
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_query_fingerprints_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_regex_rules', '');
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_regex_rules_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_regex_default_removals', '');
-- Decision history is kept by a dump. Its change_id sequence is not: change
-- ids are numbered within an installation (see the table).
SELECT pg_catalog.pg_extension_config_dump('public.sql_firewall_policy_history', '');

-- Consumer progress for the current shared-memory ring. Not a durable event
-- queue and not extension configuration data: pg_dump must not reload an old
-- cursor into a new ring. One singleton row, created uninitialized.
-- This unreleased build expects a fresh 0.0.0 installation.
CREATE TABLE IF NOT EXISTS public.sql_firewall_consumer_checkpoint (
    singleton        integer PRIMARY KEY,
    initialized      boolean NOT NULL,
    ring_generation  numeric(20,0),
    extension_oid    oid,
    next_position    numeric(20,0),
    CONSTRAINT sql_firewall_consumer_checkpoint_singleton CHECK (singleton = 1),
    CONSTRAINT sql_firewall_consumer_checkpoint_metadata CHECK (
        (NOT initialized
            AND ring_generation IS NULL
            AND extension_oid IS NULL
            AND next_position IS NULL)
        OR
        (initialized
            AND ring_generation IS NOT NULL
            AND extension_oid IS NOT NULL
            AND extension_oid <> 0
            AND next_position IS NOT NULL
            AND ring_generation >= 0
            AND ring_generation <= 18446744073709551615
            AND next_position >= 0
            AND next_position <= 18446744073709551615)
    )
);

INSERT INTO public.sql_firewall_consumer_checkpoint (singleton, initialized)
SELECT 1, false
WHERE NOT EXISTS (
    SELECT 1 FROM public.sql_firewall_consumer_checkpoint WHERE singleton = 1
);

COMMENT ON TABLE public.sql_firewall_consumer_checkpoint IS
    'Per-database consumer progress for the current ring generation. Not dumped as extension configuration.';

REVOKE ALL ON TABLE public.sql_firewall_consumer_checkpoint FROM PUBLIC;

-- The activity consumer's position in the current activity ring
-- (activity_queue.rs), updated in the transaction that writes the rows.
-- Runtime state of one installation, not dumped.
CREATE TABLE IF NOT EXISTS public.sql_firewall_activity_checkpoint (
    singleton       integer PRIMARY KEY CHECK (singleton = 1),
    ring_generation numeric(20,0),
    extension_oid   oid,
    next_position   numeric(20,0)
);
INSERT INTO public.sql_firewall_activity_checkpoint (singleton) VALUES (1);

-- Audit retention progress of this database's consumer (audit_retention.rs).
-- Written in the pruning transaction on success and in its own transaction
-- after a failure, so a stalled or failing cleanup is visible. Runtime state,
-- not dumped.
CREATE TABLE IF NOT EXISTS public.sql_firewall_retention_status (
    singleton                integer PRIMARY KEY CHECK (singleton = 1),
    runs                     bigint NOT NULL DEFAULT 0,
    failures                 bigint NOT NULL DEFAULT 0,
    last_run_at              timestamptz,
    last_success_at          timestamptz,
    last_activity_deleted    bigint,
    last_blocked_deleted     bigint,
    total_activity_deleted   bigint NOT NULL DEFAULT 0,
    total_blocked_deleted    bigint NOT NULL DEFAULT 0,
    last_error_sqlstate      text,
    last_error_at            timestamptz
);
INSERT INTO public.sql_firewall_retention_status (singleton) VALUES (1);
COMMENT ON TABLE public.sql_firewall_retention_status IS
    'Progress and failures of the audit retention the approval worker runs for this database. Not dumped.';
REVOKE ALL ON TABLE public.sql_firewall_retention_status FROM PUBLIC;
COMMENT ON TABLE public.sql_firewall_activity_checkpoint IS
    'Per-database activity consumer position in the current activity ring. Not dumped as extension configuration.';
REVOKE ALL ON TABLE public.sql_firewall_activity_checkpoint FROM PUBLIC;
