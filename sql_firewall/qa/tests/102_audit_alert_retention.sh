#!/usr/bin/env bash
# Rejected statements are recorded outside their failed transaction; the
# consumer owns NOTIFY and bounded retention (README 6.5, 6.7, 6.8).
# Phase 7: every rejection reason, including an unusable policy catalog in
# enforce, leaves a row; blocked_at and log_time are the decision times, not
# the time the worker wrote the row; a failing blocked-row write is retried
# and notified once; retention records its progress and failures, keeps
# policy and runtime tables, honours the row limit, and does not hold up
# other events.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.audit_alert_retention
EV=audit_alert_retention
DB=qa_audit
ROLE=qa_audit_app

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" "One row per denial after rollback, one notification after persistence, event times kept through queue waits, and worker-owned bounded cleanup with its status." ""

qa_create_db "$DB" \
    sql_firewall.mode=enforce \
    sql_firewall.activity_log_prune_interval_seconds=5 \
    sql_firewall.activity_log_retention_days=1 \
    sql_firewall.retention_days=1 \
    sql_firewall.enable_alert_notifications=on \
    sql_firewall.alert_channel=qa_audit_events || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO $ROLE" \
    "ALTER ROLE $ROLE IN DATABASE $DB SET sql_firewall.enable_activity_logging = off" \
    "ALTER ROLE $ROLE IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off" || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 30 || { infra "$ID.setup" "$QA_INFRA_REASON"; exit 0; }

assert_block() { # case role app SQL SQLSTATE reason-fragment marker
    local case_name=$1 role=$2 app=$3 sql=$4 state=$5 reason=$6 marker=$7
    qa_check_rejection "$role" "$DB" "$app" "$sql" "$state" 'sql_firewall:.*'
    if [[ $QA_VERDICT != PASS ]]; then
        fail "$ID.$case_name" "$QA_DETAIL"
        return 1
    fi
    if ! qa_poll "$DB" \
        "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, '$marker') > 0" \
        1 20; then
        fail "$ID.$case_name" "blocked row did not commit exactly once: $QA_INFRA_REASON"
        return 1
    fi
    qa_admin "$DB" \
        "SELECT coalesce(reason, '') FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, '$marker') > 0" \
        "SELECT count(*)::text FROM public.sql_firewall_activity_log WHERE action LIKE 'BLOCKED%' AND pg_catalog.strpos(query_text, '$marker') > 0" || {
        infra "$ID.$case_name" "$QA_INFRA_REASON"
        return 1
    }
    if [[ ${QA_STEP_OUT[1]} != *"$reason"* || ${QA_STEP_OUT[2]} != 0 ]]; then
        fail "$ID.$case_name" "reason='${QA_STEP_OUT[1]}', rolled-back activity rows=${QA_STEP_OUT[2]}"
        return 1
    fi
    ok "$ID.$case_name" "one durable blocked row with the expected reason; no rolled-back activity row"
}

# An independent listener must see the consumer's committed event, even
# though the rejecting client's transaction aborts.
listen_sql="$QA_RUN_DIR/audit-listen.sql"
listen_out="$QA_RUN_DIR/audit-listen.out"
listen_err="$QA_RUN_DIR/audit-listen.err"
cat >"$listen_sql" <<'SQL'
LISTEN qa_audit_events;
\echo QA_LISTEN_READY
SELECT pg_catalog.pg_sleep(8);
SQL
env PGAPPNAME=qa_audit_listener PGCONNECT_TIMEOUT=10 \
    timeout 15 "$QA_PSQL" -X -A -t -h "$QA_SOCK" -p "$QA_PORT" \
    -U "$QA_SUPERUSER" -d "$DB" -f "$listen_sql" >"$listen_out" 2>"$listen_err" &
listener_pid=$!
ready=0
deadline=$((SECONDS + 5))
while ((SECONDS < deadline)); do
    if grep -q 'QA_LISTEN_READY' "$listen_out"; then ready=1; break; fi
    kill -0 "$listener_pid" 2>/dev/null || break
    sleep 0.1
done
if ((ready == 0)); then
    wait "$listener_pid" || true
    infra "$ID.notify" "listener did not become ready: $(head -c 300 "$listen_err")"
    exit 0
fi
assert_block command "$ROLE" qa_audit_client "SELECT 'qa_audit_command_marker'" 42501 'No rule found for command' qa_audit_command_marker || true
wait "$listener_pid" || { infra "$ID.notify" "listener exited with an error: $(head -c 300 "$listen_err")"; exit 0; }
notifications=$(grep -c 'Asynchronous notification.*qa_audit_events' "$listen_out" || true)
qa_admin "$DB" "SELECT block_id FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_command_marker') > 0" ||
    { infra "$ID.notify" "$QA_INFRA_REASON"; exit 0; }
if [[ $notifications == 1 ]] && grep -q "{\"event\":\"query_block\",\"block_id\":${QA_STEP_OUT[1]},\"command\":\"SELECT\"}" "$listen_out"; then
    ok "$ID.notify" "one notification, naming the committed row ${QA_STEP_OUT[1]}, arrived after the blocked row committed"
else
    fail "$ID.notify" "expected one committed notification for row ${QA_STEP_OUT[1]}, got $notifications: $(tr '\n' ' ' <"$listen_out" | head -c 400)"
fi

qa_admin "$DB" \
    "SELECT public.sql_firewall_approve_command('$ROLE', 'BEGIN')" \
    "SELECT public.sql_firewall_approve_command('$ROLE', 'SAVEPOINT')" \
    "SELECT public.sql_firewall_approve_command('$ROLE', 'ROLLBACK')" || {
    infra "$ID.rollback" "$QA_INFRA_REASON"
    exit 0
}
qa_sql_steps "$ROLE" "$DB" qa_audit_client \
    "BEGIN" \
    "SAVEPOINT audit_savepoint" \
    "SELECT 'qa_audit_rollback_marker'" \
    "ROLLBACK TO SAVEPOINT audit_savepoint" \
    "ROLLBACK" || { infra "$ID.rollback" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_ERR[3]} != true || ${QA_STEP_STATE[3]} != 42501 || ${QA_STEP_ERR[4]} != false || ${QA_STEP_ERR[5]} != false ]]; then
    fail "$ID.rollback" "failed statement/savepoint outcome: ${QA_STEP_STATE[3]} ${QA_STEP_MSG[3]:-}; ${QA_STEP_STATE[4]} ${QA_STEP_STATE[5]}"
elif qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_rollback_marker') > 0" \
    1 20; then
    ok "$ID.rollback" "failed statement survived savepoint and outer rollback exactly once"
else
    fail "$ID.rollback" "$QA_INFRA_REASON"
fi

# Separate roles keep each policy's reason unambiguous.
qa_admin postgres \
    "CREATE ROLE qa_audit_keyword LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_audit_quiet LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_audit_application LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_audit_rate LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_audit_keyword, qa_audit_quiet, qa_audit_application, qa_audit_rate" \
    "ALTER ROLE qa_audit_keyword IN DATABASE $DB SET sql_firewall.blacklisted_keywords = 'qa_audit_forbidden'" \
    "ALTER ROLE qa_audit_quiet IN DATABASE $DB SET sql_firewall.enable_quiet_hours = on" \
    "ALTER ROLE qa_audit_quiet IN DATABASE $DB SET sql_firewall.quiet_hours_start = '00:00'" \
    "ALTER ROLE qa_audit_quiet IN DATABASE $DB SET sql_firewall.quiet_hours_end = '00:00'" \
    "ALTER ROLE qa_audit_application IN DATABASE $DB SET sql_firewall.enable_application_blocking = on" \
    "ALTER ROLE qa_audit_application IN DATABASE $DB SET sql_firewall.blocked_applications = 'qa_audit_bad_app'" \
    "ALTER ROLE qa_audit_rate IN DATABASE $DB SET sql_firewall.select_limit_count = 1" \
    "ALTER ROLE qa_audit_rate IN DATABASE $DB SET sql_firewall.command_limit_seconds = 60" \
    "ALTER ROLE qa_audit_rate IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off" || {
    infra "$ID.policy_setup" "$QA_INFRA_REASON"
    exit 0
}
qa_admin "$DB" \
    "SELECT public.sql_firewall_approve_command('qa_audit_rate', 'SELECT')" \
    "INSERT INTO public.sql_firewall_regex_rules (pattern, description, installation_default) VALUES ('qa_audit_regex_marker', 'QA audit regression', NULL)" || {
    infra "$ID.policy_setup" "$QA_INFRA_REASON"
    exit 0
}

# The keyword is an SQL name here; inside a literal it would not count (README 6.6).
assert_block keyword qa_audit_keyword qa_audit_client "SELECT 1 AS qa_audit_forbidden" 42000 'blacklisted keyword' qa_audit_forbidden || true
assert_block quiet qa_audit_quiet qa_audit_client "SELECT 'qa_audit_quiet_marker'" 42501 'quiet hours' qa_audit_quiet_marker || true
assert_block application qa_audit_application qa_audit_bad_app "SELECT 'qa_audit_application_marker'" 42501 'application' qa_audit_application_marker || true
assert_block regex "$ROLE" qa_audit_client "SELECT 'qa_audit_regex_marker'" 42501 'security regex pattern' qa_audit_regex_marker || true

qa_sql_steps qa_audit_rate "$DB" qa_audit_client \
    "SELECT 'qa_audit_rate_warmup'" \
    "SELECT 'qa_audit_rate_marker'" || { infra "$ID.rate" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_ERR[1]} != false || ${QA_STEP_ERR[2]} != true || ${QA_STEP_STATE[2]} != 53400 ]]; then
    fail "$ID.rate" "unexpected rate outcomes: ${QA_STEP_STATE[1]} ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-}"
else
    if qa_poll "$DB" \
        "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_rate_marker') > 0 AND reason LIKE '%Rate limit%'" \
        1 20; then
        ok "$ID.rate" "rate rejection persisted exactly once"
    else
        fail "$ID.rate" "$QA_INFRA_REASON"
    fi
fi

# An unusable policy catalog in enforce is a rejection like any other.
qa_admin "$DB" "REVOKE SELECT ON TABLE public.sql_firewall_command_approvals FROM PUBLIC" ||
    { infra "$ID.catalog" "$QA_INFRA_REASON"; exit 0; }
assert_block catalog "$ROLE" qa_audit_client "SELECT 'qa_audit_catalog_marker'" 55000 'required policy catalog is unavailable: sql_firewall_command_approvals' qa_audit_catalog_marker || true
qa_admin "$DB" "GRANT SELECT ON TABLE public.sql_firewall_command_approvals TO PUBLIC" ||
    { infra "$ID.catalog" "$QA_INFRA_REASON"; exit 0; }

# Event times: decided while the worker is paused, written after the resume.
qa_admin "$DB" "SELECT public.sql_firewall_approve_command('qa_audit_rate', 'SHOW')" || { infra "$ID.event_time" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "ALTER ROLE qa_audit_rate IN DATABASE $DB SET sql_firewall.enable_activity_logging = on" ||
    { infra "$ID.event_time" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" "SELECT pg_catalog.clock_timestamp()" ||
    { infra "$ID.event_time" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == 'approval worker paused epoch='* ]] || { infra "$ID.event_time" "pause: ${QA_STEP_OUT[1]}"; exit 0; }
t_before=${QA_STEP_OUT[2]}
qa_check_rejection "$ROLE" "$DB" qa_audit_client "SELECT 'qa_audit_time_marker'" 42501 'sql_firewall:.*'
qa_sql_steps qa_audit_rate "$DB" qa_audit_client "SHOW /* qa_audit_time_activity */ work_mem" || { infra "$ID.event_time" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT pg_catalog.clock_timestamp()" || { infra "$ID.event_time" "$QA_INFRA_REASON"; exit 0; }
t_after=${QA_STEP_OUT[1]}
sleep 3
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" || { infra "$ID.event_time" "$QA_INFRA_REASON"; exit 0; }
if qa_poll "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_time_marker') > 0" 1 20 &&
    qa_admin "$DB" \
        "SELECT (blocked_at BETWEEN '$t_before' AND '$t_after') || ',' || (recorded_at >= blocked_at + interval '2.5 seconds') FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_time_marker') > 0" \
        "SELECT (log_time BETWEEN '$t_before' AND '$t_after') || ',' || (recorded_at >= log_time + interval '2.5 seconds') || ',' || decision FROM public.sql_firewall_activity_log WHERE pg_catalog.strpos(query_text, 'qa_audit_time_activity') > 0"; then
    if [[ ${QA_STEP_OUT[1]} == "true,true" && ${QA_STEP_OUT[2]} == "true,true,allowed" ]]; then
        ok "$ID.event_time" "blocked_at and log_time are the decision times ($t_before .. $t_after); recorded_at is at least the 3 s pause later"
    else
        fail "$ID.event_time" "blocked (in window, recorded later)=${QA_STEP_OUT[1]}; activity (in window, recorded later, decision)=${QA_STEP_OUT[2]}"
    fi
else
    infra "$ID.event_time" "$QA_INFRA_REASON"
fi

# A failing blocked-row write is retried; the notification follows the one
# successful commit, not the failed attempts.
qa_admin "$DB" \
    "CREATE TABLE public.qa_audit_gate (open boolean NOT NULL)" \
    "INSERT INTO public.qa_audit_gate VALUES (false)" \
    "CREATE FUNCTION public.qa_audit_gate_check() RETURNS trigger LANGUAGE plpgsql AS \$f\$ BEGIN IF strpos(NEW.query_text, 'qa_audit_retry_marker') > 0 AND NOT (SELECT open FROM public.qa_audit_gate) THEN RAISE EXCEPTION 'qa_audit_gate closed' USING ERRCODE = 'QAG01'; END IF; RETURN NEW; END \$f\$" \
    "CREATE TRIGGER qa_audit_gate_check BEFORE INSERT ON public.sql_firewall_blocked_queries FOR EACH ROW EXECUTE FUNCTION public.qa_audit_gate_check()" ||
    { infra "$ID.retry_notify" "$QA_INFRA_REASON"; exit 0; }
retry_out="$QA_RUN_DIR/audit-retry-listen.out"
cat >"$QA_RUN_DIR/audit-retry-listen.sql" <<'SQL'
LISTEN qa_audit_events;
\echo QA_LISTEN_READY
SELECT pg_catalog.pg_sleep(9);
SQL
env PGAPPNAME=qa_audit_listener PGCONNECT_TIMEOUT=10 timeout 20 "$QA_PSQL" -X -A -t -h "$QA_SOCK" -p "$QA_PORT" \
    -U "$QA_SUPERUSER" -d "$DB" -f "$QA_RUN_DIR/audit-retry-listen.sql" >"$retry_out" 2>"$retry_out.err" &
retry_listener=$!
deadline=$((SECONDS + 5))
until grep -q QA_LISTEN_READY "$retry_out" || ((SECONDS >= deadline)); do sleep 0.1; done
LOGR=$(qa_server_log_offset)
qa_check_rejection "$ROLE" "$DB" qa_audit_client "SELECT 'qa_audit_retry_marker'" 42501 'sql_firewall:.*'
sleep 3
qa_admin "$DB" "SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_retry_marker') > 0" \
    "UPDATE public.qa_audit_gate SET open = true" || { infra "$ID.retry_notify" "$QA_INFRA_REASON"; exit 0; }
rows_closed=${QA_STEP_OUT[1]}
wait "$retry_listener" || true
retries=$(tail -c +"$((LOGR + 1))" "$QA_SERVER_LOG" | grep -c 'SQLSTATE QAG01' || true)
notified=$(grep -c 'Asynchronous notification.*qa_audit_events' "$retry_out" || true)
qa_admin "$DB" "SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE pg_catalog.strpos(query_text, 'qa_audit_retry_marker') > 0" \
    "DROP TRIGGER qa_audit_gate_check ON public.sql_firewall_blocked_queries" "DROP FUNCTION public.qa_audit_gate_check()" ||
    { infra "$ID.retry_notify" "$QA_INFRA_REASON"; exit 0; }
if [[ $rows_closed == 0 && $retries -ge 1 && $notified == 1 && ${QA_STEP_OUT[1]} == 1 ]]; then
    ok "$ID.retry_notify" "while the write failed ($retries logged retries, SQLSTATE QAG01) there was no row and no notification; after it succeeded one row and one notification"
else
    fail "$ID.retry_notify" "rows while failing=$rows_closed retries=$retries notifications=$notified rows after=${QA_STEP_OUT[1]}"
fi

# The consumer's configured 1-day cutoff removes old rows but keeps fresh
# rows. A 1,001-row activity burst is reduced to the configured 1,000 target.
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_blocked_queries (blocked_at, role_name, database_name, query_text, command_type, reason) VALUES (pg_catalog.now() - pg_catalog.make_interval(days => 2), '$ROLE', pg_catalog.current_database(), 'qa_audit_old_block', 'SELECT', 'seed'), (pg_catalog.now(), '$ROLE', pg_catalog.current_database(), 'qa_audit_new_block', 'SELECT', 'seed')" \
    "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) SELECT pg_catalog.now() - pg_catalog.make_interval(days => 2), '$ROLE', pg_catalog.current_database(), 'qa_audit_old_activity_' || g::pg_catalog.text, 'SELECT', 'ALLOWED', 'seed' FROM pg_catalog.generate_series(1, 1001) AS g" || {
    infra "$ID.retention" "$QA_INFRA_REASON"
    exit 0
}
if qa_poll "$DB" \
    "SELECT (SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE query_text = 'qa_audit_old_block')::text || '|' || (SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE query_text = 'qa_audit_new_block')::text || '|' || (SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text LIKE 'qa_audit_old_activity_%')::text" \
    '0|1|0' 20; then
    ok "$ID.retention" "consumer removed old blocked and activity rows in bounded batches; fresh blocked row remained"
else
    fail "$ID.retention" "$QA_INFRA_REASON"
fi

# Retention progress is visible, and the tables it must not touch are intact.
qa_admin "$DB" \
    "SELECT (runs > 0) || ',' || (last_success_at IS NOT NULL) || ',' || (total_activity_deleted >= 1001) || ',' || (total_blocked_deleted >= 1) FROM public.sql_firewall_retention_status" \
    "SELECT (SELECT count(*) FROM public.sql_firewall_command_approvals) || ',' || (SELECT count(*) FROM public.sql_firewall_regex_rules) || ',' || (SELECT initialized FROM public.sql_firewall_consumer_checkpoint)" ||
    { infra "$ID.retention_status" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} == "true,true,true,true" && ${QA_STEP_OUT[2]} == *",true" ]]; then
    ok "$ID.retention_status" "sql_firewall_retention_status shows successful runs and the deleted rows; policy rows and the checkpoint were kept (${QA_STEP_OUT[2]})"
else
    fail "$ID.retention_status" "status ${QA_STEP_OUT[1]}; kept ${QA_STEP_OUT[2]}"
fi

# A failing cleanup is recorded and retried; other events keep flowing.
qa_admin "$DB" \
    "CREATE FUNCTION public.qa_audit_no_delete() RETURNS trigger LANGUAGE plpgsql AS \$f\$ BEGIN RAISE EXCEPTION 'qa_audit_no_delete' USING ERRCODE = 'QAR01'; END \$f\$" \
    "CREATE TRIGGER qa_audit_no_delete BEFORE DELETE ON public.sql_firewall_activity_log FOR EACH ROW EXECUTE FUNCTION public.qa_audit_no_delete()" \
    "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) SELECT pg_catalog.now() - pg_catalog.make_interval(days => 2), '$ROLE', pg_catalog.current_database(), 'qa_audit_stuck_' || g::pg_catalog.text, 'SELECT', 'ALLOWED', 'seed' FROM pg_catalog.generate_series(1, 10) AS g" ||
    { infra "$ID.retention_failure" "$QA_INFRA_REASON"; exit 0; }
if qa_poll "$DB" "SELECT coalesce(last_error_sqlstate, '') FROM public.sql_firewall_retention_status" QAR01 30; then
    started=$SECONDS
    if qa_worker_progress "$DB" 20; then
        ok "$ID.retention_failure" "a failing cleanup was recorded (last_error_sqlstate QAR01) and a blocked-query event was still delivered in $((SECONDS - started)) s"
    else
        fail "$ID.retention_failure" "no event delivered while cleanup failed: $QA_INFRA_REASON"
    fi
else
    fail "$ID.retention_failure" "failure not recorded: $QA_INFRA_REASON"
fi
qa_admin "$DB" "DROP TRIGGER qa_audit_no_delete ON public.sql_firewall_activity_log" "DROP FUNCTION public.qa_audit_no_delete()" ||
    { infra "$ID.retention_failure" "$QA_INFRA_REASON"; exit 0; }
if qa_poll "$DB" "SELECT count(*)::text FROM public.sql_firewall_activity_log WHERE query_text LIKE 'qa_audit_stuck_%'" 0 30; then
    ok "$ID.retention_retry" "after the failure was removed the next cleanup deleted the old rows"
else
    fail "$ID.retention_retry" "$QA_INFRA_REASON"
fi

# Row limit: the oldest rows beyond sql_firewall.activity_log_max_rows go.
qa_admin postgres "ALTER DATABASE $DB SET sql_firewall.activity_log_max_rows = 1000" ||
    { infra "$ID.max_rows" "$QA_INFRA_REASON"; exit 0; }
# The worker reads settings when it starts; restart it so it sees the limit.
qa_admin "$DB" "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = current_database() AND backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.max_rows" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) SELECT pg_catalog.now() - pg_catalog.make_interval(mins => 1500 - g), '$ROLE', pg_catalog.current_database(), 'qa_audit_many_' || g::pg_catalog.text, 'SELECT', 'ALLOWED', 'seed' FROM pg_catalog.generate_series(1, 1500) AS g" ||
    { infra "$ID.max_rows" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 60 || { infra "$ID.max_rows" "$QA_INFRA_REASON"; exit 0; }
if qa_poll "$DB" "SELECT (count(*) <= 1000)::text FROM public.sql_firewall_activity_log" true 60; then
    qa_admin "$DB" "SELECT min(substr(query_text, 15)::int) FROM public.sql_firewall_activity_log WHERE query_text LIKE 'qa_audit_many_%'" ||
        { infra "$ID.max_rows" "$QA_INFRA_REASON"; exit 0; }
    if ((${QA_STEP_OUT[1]:-0} > 500)); then
        ok "$ID.max_rows" "the table was reduced to the 1000-row limit by removing the oldest rows (oldest seeded row kept: ${QA_STEP_OUT[1]})"
    else
        fail "$ID.max_rows" "oldest kept seeded row is ${QA_STEP_OUT[1]}"
    fi
else
    fail "$ID.max_rows" "$QA_INFRA_REASON"
fi

# Catching up: far more rows than the limit are reduced to it promptly, in
# consecutive 1,000-row transactions, not one batch per prune interval
# (before the fix: at most 200 rows a second, so an activity rate above that
# grew the table past the limit without bound, perf run sqlfw-perf.thTfGZ).
qa_admin "$DB" "INSERT INTO public.sql_firewall_activity_log (log_time, role_name, database_name, query_text, command_type, action, reason) SELECT pg_catalog.now() - pg_catalog.make_interval(secs => 30000 - g), '$ROLE', pg_catalog.current_database(), 'qa_audit_bulk_' || g::pg_catalog.text, 'SELECT', 'ALLOWED', 'seed' FROM pg_catalog.generate_series(1, 30000) AS g" ||
    { infra "$ID.max_rows.catch_up" "$QA_INFRA_REASON"; exit 0; }
started=$SECONDS
if qa_poll "$DB" "SELECT (count(*) <= 1000)::text FROM public.sql_firewall_activity_log" true 20; then
    qa_admin "$DB" "SELECT min(substr(query_text, 15)::int) FROM public.sql_firewall_activity_log WHERE query_text LIKE 'qa_audit_bulk_%'" ||
        { infra "$ID.max_rows.catch_up" "$QA_INFRA_REASON"; exit 0; }
    if ((${QA_STEP_OUT[1]:-0} > 29000)); then
        ok "$ID.max_rows.catch_up" "30,000 rows over the 1,000-row limit were removed oldest first within $((SECONDS - started)) s (one batch per 5 s interval would take about 150 s; oldest kept: ${QA_STEP_OUT[1]})"
    else
        fail "$ID.max_rows.catch_up" "oldest kept bulk row is ${QA_STEP_OUT[1]}"
    fi
else
    fail "$ID.max_rows.catch_up" "not reduced to the limit within 20 s: $QA_INFRA_REASON"
fi
exit 0
