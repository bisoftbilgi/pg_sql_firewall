#!/usr/bin/env bash
# Phase 3C1: the consumer retries a copied event until its transaction commits.
# Failure switches are committed from this session, outside the worker transaction.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.worker_retry
EV=worker_retry
DB=qa_c1
OTHER=qa_c1_other
STOP=qa_c1_stop

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Retry uses the copied event. A committed switch in qa_c1_fail controls real SQL errors. The cursor advances only after commit." ""

qa_create_db "$DB" sql_firewall.mode=learn sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$OTHER" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$STOP" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

qa_admin postgres \
    "CREATE ROLE qa_c1_blk LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c1_learn LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c1_fp_a LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c1_fp_b LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c1_other LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c1_stop LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_c1_blk, qa_c1_learn, qa_c1_fp_a, qa_c1_fp_b" \
    "GRANT CONNECT ON DATABASE $OTHER TO qa_c1_other" \
    "GRANT CONNECT ON DATABASE $STOP TO qa_c1_stop" \
    "ALTER ROLE qa_c1_blk IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_c1_other IN DATABASE $OTHER SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_c1_stop IN DATABASE $STOP SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi
if ! qa_wait_worker_live "$OTHER" 40; then
    fail "$ID.ready_other" "$QA_INFRA_REASON"
    exit 0
fi
if ! qa_wait_worker_live "$STOP" 40; then
    fail "$ID.ready_stop" "$QA_INFRA_REASON"
    exit 0
fi

install_controls() {
    local db=$1
    qa_admin "$db" \
        "CREATE TABLE public.qa_c1_fail (id integer PRIMARY KEY, blocked boolean NOT NULL, approval boolean NOT NULL, fingerprint boolean NOT NULL, deferred boolean NOT NULL)" \
        "INSERT INTO public.qa_c1_fail VALUES (1, false, false, false, false)" \
        "CREATE FUNCTION public.qa_c1_block() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c1_fail WHERE id = 1 AND blocked) THEN RAISE EXCEPTION 'qa_c1 blocked' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END \$\$" \
        "CREATE FUNCTION public.qa_c1_approval() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c1_fail WHERE id = 1 AND approval) THEN RAISE EXCEPTION 'qa_c1 approval' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END \$\$" \
        "CREATE FUNCTION public.qa_c1_fp() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c1_fail WHERE id = 1 AND fingerprint) THEN RAISE EXCEPTION 'qa_c1 fingerprint' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END \$\$" \
        "CREATE FUNCTION public.qa_c1_defer() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c1_fail WHERE id = 1 AND deferred) THEN RAISE EXCEPTION 'qa_c1 commit' USING ERRCODE = '23514'; END IF; RETURN NULL; END \$\$" \
        "CREATE TRIGGER qa_c1_block BEFORE INSERT ON public.sql_firewall_blocked_queries FOR EACH ROW EXECUTE FUNCTION public.qa_c1_block()" \
        "CREATE TRIGGER qa_c1_approval BEFORE INSERT OR UPDATE ON public.sql_firewall_command_approvals FOR EACH ROW EXECUTE FUNCTION public.qa_c1_approval()" \
        "CREATE TRIGGER qa_c1_fp BEFORE INSERT OR UPDATE ON public.sql_firewall_query_fingerprints FOR EACH ROW EXECUTE FUNCTION public.qa_c1_fp()" \
        "CREATE CONSTRAINT TRIGGER qa_c1_deferred AFTER INSERT ON public.sql_firewall_blocked_queries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.qa_c1_defer()" ||
        return $?
}

install_controls "$DB" || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
install_controls "$OTHER" || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
install_controls "$STOP" || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }

worker_pid() {
    qa_admin "$1" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_WORKER_PID=${QA_STEP_OUT[1]}
}

db_oid() {
    qa_admin postgres "SELECT oid::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) '$1'" || return $?
    QA_DB_OID=${QA_STEP_OUT[1]}
}

set_flag() { # db column value
    qa_admin "$1" "UPDATE public.qa_c1_fail SET $2 = $3 WHERE id = 1" || return $?
}

wait_retry() { # oid type sqlstate
    local deadline=$((SECONDS + 15))
    while ((SECONDS < deadline)); do
        if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "retry database oid $1 " | grep -F "type $2 " | grep -F "SQLSTATE $3" >/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Blocked-query ERROR, same PID, then the original row and a later row.
worker_pid "$DB" || { infra "$ID.blocked" "$QA_INFRA_REASON"; exit 0; }
pid_blocked=$QA_WORKER_PID
[[ $pid_blocked =~ ^[0-9]+$ ]] || { infra "$ID.blocked" "worker pid '$pid_blocked'"; exit 0; }
db_oid "$DB" || { infra "$ID.blocked" "$QA_INFRA_REASON"; exit 0; }
oid_db=$QA_DB_OID
set_flag "$DB" blocked true || { infra "$ID.blocked" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c1_blk "$DB" qa_c1 "SELECT 'qa_c1_blk_first'" || true
if ! wait_retry "$oid_db" blocked_query P0001; then
    fail "$ID.blocked.attempt" "no P0001 retry for blocked query on oid ${oid_db}"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_blk_first') > 0" ||
    { infra "$ID.blocked" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.blocked.rollback" "blocked row was visible while the switch was on (${QA_STEP_OUT[1]})"
    exit 0
fi
worker_pid "$DB" || { infra "$ID.blocked" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_WORKER_PID != "$pid_blocked" ]]; then
    fail "$ID.blocked.pid" "worker pid changed from $pid_blocked to $QA_WORKER_PID"
    exit 0
fi
set_flag "$DB" blocked false || { infra "$ID.blocked" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_blk_first') > 0" \
    1 20; then
    fail "$ID.blocked.persist" "original blocked event was not persisted after repair (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_sql_steps qa_c1_blk "$DB" qa_c1 "SELECT 'qa_c1_blk_later'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_blk_later') > 0" \
    1 20; then
    fail "$ID.blocked.later" "event after the retried blocked query was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.blocked" "pid $pid_blocked retried SQLSTATE P0001, rolled back, then persisted qa_c1_blk_first and qa_c1_blk_later"

# Approval retry.
set_flag "$DB" approval true || { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c1_learn "$DB" qa_c1 "SELECT 'qa_c1_appr_marker'" ||
    { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
if ! wait_retry "$oid_db" approval P0001; then
    fail "$ID.approval.attempt" "no P0001 retry for approval on oid ${oid_db}"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) 'qa_c1_learn'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text" ||
    { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.approval.rollback" "approval row existed while the switch was on"
    exit 0
fi
set_flag "$DB" approval false || { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) 'qa_c1_learn'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text AND is_approved" \
    1 20; then
    fail "$ID.approval.persist" "approval was not persisted after repair (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.approval" "approval SQLSTATE P0001 rolled back, then one SELECT approval committed"

# Fingerprint: seed hit_count 5 for a second role, fail the worker upsert, then expect 6.
qa_sql_steps qa_c1_fp_a "$DB" qa_c1 "SELECT 'qa_c1_fp_token'" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_c1_fp_a'::name AND strpos(sample_query, 'qa_c1_fp_token') > 0" \
    1 20; then
    fail "$ID.fingerprint.seed" "role A fingerprint was not stored (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, first_seen_at, last_seen_at, hit_count, is_approved) SELECT fingerprint, normalized_query, 'qa_c1_fp_b', command_type, sample_query, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 5, false FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_c1_fp_a'::name AND strpos(sample_query, 'qa_c1_fp_token') > 0" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
set_flag "$DB" fingerprint true || { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c1_fp_b "$DB" qa_c1 "SELECT 'qa_c1_fp_token'" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if ! wait_retry "$oid_db" fingerprint_hit P0001; then
    fail "$ID.fingerprint.attempt" "no P0001 retry for fingerprint on oid ${oid_db}"
    exit 0
fi
qa_admin "$DB" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_c1_fp_b'::name" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 5 ]]; then
    fail "$ID.fingerprint.rollback" "hit_count was ${QA_STEP_OUT[1]} while the switch was on, expected 5"
    exit 0
fi
set_flag "$DB" fingerprint false || { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_c1_fp_b'::name" \
    6 20; then
    fail "$ID.fingerprint.persist" "hit_count did not become 6 after one committed retry (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.fingerprint" "fingerprint stayed at hit_count 5 across rollback and committed exactly once to 6"

# Deferred constraint: INSERT succeeds and commit fails with 23514.
set_flag "$DB" deferred true || { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c1_blk "$DB" qa_c1 "SELECT 'qa_c1_defer_first'" || true
if ! wait_retry "$oid_db" blocked_query 23514; then
    fail "$ID.deferred.attempt" "no 23514 commit-boundary retry on oid ${oid_db}"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_defer_first') > 0" ||
    { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.deferred.rollback" "deferred insert was visible before a successful commit"
    exit 0
fi
set_flag "$DB" deferred false || { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_defer_first') > 0" \
    1 20; then
    fail "$ID.deferred.persist" "deferred event was not persisted after repair (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_sql_steps qa_c1_blk "$DB" qa_c1 "SELECT 'qa_c1_defer_later'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_defer_later') > 0" \
    1 20; then
    fail "$ID.deferred.later" "event after the deferred retry was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.deferred" "SQLSTATE 23514 at commit rolled back qa_c1_defer_first, then the retry and a later event committed"

# While qa_c1 is retrying, the other database's consumer still delivers.
set_flag "$DB" blocked true || { infra "$ID.isolation" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c1_blk "$DB" qa_c1 "SELECT 'qa_c1_iso_a'" || true
if ! wait_retry "$oid_db" blocked_query P0001; then
    fail "$ID.isolation.attempt" "oid ${oid_db} did not enter retry before the other database was checked"
    exit 0
fi
qa_sql_steps qa_c1_other "$OTHER" qa_c1 "SELECT 'qa_c1_iso_b'" || true
if ! qa_poll "$OTHER" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_iso_b') > 0" \
    1 20; then
    fail "$ID.isolation.deliver" "other database did not persist qa_c1_iso_b while oid ${oid_db} was retrying (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_iso_b') > 0" ||
    { infra "$ID.isolation" "$QA_INFRA_REASON"; exit 0; }
in_a=${QA_STEP_OUT[1]}
qa_admin "$OTHER" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_iso_a') > 0" ||
    { infra "$ID.isolation" "$QA_INFRA_REASON"; exit 0; }
in_b=${QA_STEP_OUT[1]}
if [[ $in_a != 0 || $in_b != 0 ]]; then
    fail "$ID.isolation.cross" "cross-database rows a=$in_a b=$in_b"
    exit 0
fi
set_flag "$DB" blocked false || { infra "$ID.isolation" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.isolation" "oid ${oid_db} was retrying while $OTHER persisted qa_c1_iso_b only in that database"

# Persistent retry, then SIGTERM during latch backoff. The event is not claimed to survive.
if ! qa_wait_worker_live "$STOP" 20; then
    fail "$ID.shutdown.ready" "$QA_INFRA_REASON"
    exit 0
fi
worker_pid "$STOP" || { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
pid_stop=$QA_WORKER_PID
db_oid "$STOP" || { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
oid_stop=$QA_DB_OID
set_flag "$STOP" blocked true || { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c1_stop "$STOP" qa_c1 "SELECT 'qa_c1_stop_marker'" || true
stop_deadline=$((SECONDS + 20))
attempts=0
while ((SECONDS < stop_deadline)); do
    attempts=$(tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "retry database oid ${oid_stop} position" | grep -F "type blocked_query" | grep -c "SQLSTATE P0001" || true)
    if [[ $attempts -ge 2 ]]; then
        qa_admin "$STOP" "SELECT wait_event_type FROM pg_catalog.pg_stat_activity WHERE pid OPERATOR(pg_catalog.=) ${pid_stop}" ||
            { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
        [[ ${QA_STEP_OUT[1]} == Extension ]] && break
    fi
    sleep 0.2
done
if [[ $attempts -lt 2 ]]; then
    fail "$ID.shutdown.attempts" "saw $attempts P0001 retries for oid ${oid_stop}, wanted at least 2"
    exit 0
fi
qa_admin "$STOP" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c1_stop_marker') > 0" ||
    { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.shutdown.partial" "stop marker was persisted while the switch stayed on"
    exit 0
fi
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${pid_stop})" ||
    { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
stop_deadline=$((SECONDS + 10))
gone=0
while ((SECONDS < stop_deadline)); do
    if grep -F "worker exiting with uncommitted event" "$QA_SERVER_LOG" | grep -F "[$pid_stop]" >/dev/null \
        && grep -F "approval worker shutting down" "$QA_SERVER_LOG" >/dev/null; then
        gone=1
        break
    fi
    sleep 0.2
done
if [[ $gone -ne 1 ]]; then
    fail "$ID.shutdown.exit" "pid $pid_stop did not log an uncommitted exit"
    exit 0
fi
if grep -F "PANIC:" "$QA_SERVER_LOG" >/dev/null; then
    fail "$ID.shutdown.panic" "postmaster log contains PANIC"
    exit 0
fi
qa_admin postgres "SELECT 1" || { infra "$ID.shutdown" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.shutdown" "oid ${oid_stop} pid $pid_stop logged $attempts P0001 retries, kept the row absent, and exited on SIGTERM during backoff without PANIC"

exit 0
