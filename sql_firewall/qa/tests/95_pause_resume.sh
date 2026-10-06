#!/usr/bin/env bash
# Phase 3D: shared pause/resume, truthful status, and administrative authorization.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.pause_resume
EV=pause_resume
DB=qa_pause
OTHER=qa_pause_other
LIFE=qa_pause_life

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Pause is shared by database and extension installation. A consumer acknowledges it only outside a persistence transaction. Resume continues from the copied event or checkpoint. Administrative calls require a superuser session." ""

qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$OTHER" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$LIFE" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE qa_pause_app LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_pause_other LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_pause_learn LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_pause_life LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_pause_user LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_pause_app, qa_pause_learn, qa_pause_user" \
    "GRANT CONNECT ON DATABASE $OTHER TO qa_pause_other" \
    "GRANT CONNECT ON DATABASE $LIFE TO qa_pause_life" \
    "ALTER ROLE qa_pause_app IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_pause_other IN DATABASE $OTHER SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_pause_learn IN DATABASE $DB SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE qa_pause_life IN DATABASE $LIFE SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

worker_pid() {
    qa_admin "$1" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_WORKER_PID=${QA_STEP_OUT[1]}
}

checkpoint_next() {
    qa_admin "$1" "SELECT coalesce(next_position::text, 'null') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" || return $?
    QA_NEXT=${QA_STEP_OUT[1]}
}

status_of() {
    qa_admin "$1" "SELECT public.sql_firewall_approval_worker_status()" || return $?
    QA_STATUS=${QA_STEP_OUT[1]}
}

wait_status() {
    local db=$1 prefix=$2 deadline=$((SECONDS + ${3:-20}))
    while ((SECONDS < deadline)); do
        status_of "$db" || return $?
        [[ $QA_STATUS == "$prefix"* ]] && return 0
        sleep 0.2
    done
    QA_INFRA_REASON="status in $db stayed '${QA_STATUS:-}' waiting for $prefix"
    return 1
}

wait_log() {
    local offset=$1 text=$2 deadline=$((SECONDS + $3))
    while ((SECONDS < deadline)); do
        if tail -c +"$((offset + 1))" "$QA_SERVER_LOG" | grep -F "$text" >/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi
if ! qa_wait_worker_live "$OTHER" 40; then
    fail "$ID.ready_other" "$QA_INFRA_REASON"
    exit 0
fi

# 1. Cross-session pause, isolation, and resume.
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* ]]; then
    fail "$ID.cross.pause" "pause returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
pause_reply=${QA_STEP_OUT[1]}
status_of "$DB" || { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS != paused\ epoch=* ]]; then
    fail "$ID.cross.status" "second session saw '${QA_STATUS}'"
    exit 0
fi
checkpoint_next "$DB" || { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
held_next=$QA_NEXT
qa_sql_steps qa_pause_app "$DB" qa_pause "SELECT 'qa_pause_held'" || true
qa_sql_steps qa_pause_other "$OTHER" qa_pause "SELECT 'qa_pause_other_live'" || true
if ! qa_poll "$OTHER" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_other_live') > 0" \
    1 20; then
    fail "$ID.cross.other" "the other database did not keep processing (${QA_INFRA_REASON:-})"
    exit 0
fi
status_of "$DB" || { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_held') > 0" ||
    { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS != paused\ epoch=* || $QA_NEXT != "$held_next" || ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.cross.quiescent" "status '$QA_STATUS' checkpoint $QA_NEXT count ${QA_STEP_OUT[1]}"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.cross" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ running\ epoch=* ]]; then
    fail "$ID.cross.resume" "resume returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_held') > 0" \
    1 20; then
    fail "$ID.cross.deliver" "retained event was not persisted after resume (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.cross" "$pause_reply isolated qa_pause_held until resume; qa_pause_other_live proceeded"

# 2. Pause stays pending while event SQL is blocked, then acknowledges.
qa_admin "$DB" \
    "CREATE TABLE public.qa_gate (id integer PRIMARY KEY)" \
    "INSERT INTO public.qa_gate VALUES (1)" \
    "CREATE TABLE public.qa_fail (id integer PRIMARY KEY, blocked boolean NOT NULL)" \
    "INSERT INTO public.qa_fail VALUES (1, false)" \
    "CREATE FUNCTION public.qa_pause_wait() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_fail WHERE id = 1 AND blocked) THEN LOCK TABLE public.qa_gate IN ACCESS EXCLUSIVE MODE; END IF; RETURN NEW; END \$\$" \
    "CREATE TRIGGER qa_pause_wait BEFORE INSERT ON public.sql_firewall_blocked_queries FOR EACH ROW EXECUTE FUNCTION public.qa_pause_wait()" ||
    { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
env PGAPPNAME=qa_lock_owner "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "SELECT pg_catalog.pg_advisory_lock(942001); SELECT pg_catalog.pg_sleep(120);" \
    >"$QA_RUN_DIR/owner.out" 2>"$QA_RUN_DIR/owner.err" &
owner_pid=$!
deadline=$((SECONDS + 10))
owner_backend=
while ((SECONDS < deadline)); do
    if qa_admin "$DB" "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE application_name OPERATOR(pg_catalog.=) 'qa_lock_owner' AND query LIKE '%pg_sleep%'"; then
        [[ ${QA_STEP_OUT[1]} =~ ^[0-9]+$ ]] && owner_backend=${QA_STEP_OUT[1]} && break
    fi
    sleep 0.2
done
if [[ -z $owner_backend ]]; then
    kill "$owner_pid" 2>/dev/null || true
    wait "$owner_pid" 2>/dev/null || true
    infra "$ID.inflight" "advisory owner did not start"
    exit 0
fi
env PGAPPNAME=qa_hold "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "BEGIN; LOCK TABLE public.qa_gate IN EXCLUSIVE MODE; SELECT pg_catalog.pg_advisory_lock(942001); COMMIT;" \
    >"$QA_RUN_DIR/hold.out" 2>"$QA_RUN_DIR/hold.err" &
hold_pid=$!
deadline=$((SECONDS + 10))
holding=0
while ((SECONDS < deadline)); do
    if qa_admin "$DB" "SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE application_name OPERATOR(pg_catalog.=) 'qa_hold' AND wait_event_type OPERATOR(pg_catalog.=) 'Lock'"; then
        [[ ${QA_STEP_OUT[1]} == 1 ]] && holding=1 && break
    fi
    sleep 0.2
done
if [[ $holding -ne 1 ]]; then
    kill "$hold_pid" 2>/dev/null || true
    wait "$hold_pid" 2>/dev/null || true
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner_backend})" || true
    wait "$owner_pid" 2>/dev/null || true
    infra "$ID.inflight" "lock holder did not block"
    exit 0
fi
qa_admin "$DB" "UPDATE public.qa_fail SET blocked = true WHERE id = 1" || { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
before_lock=$QA_NEXT
qa_sql_steps qa_pause_app "$DB" qa_pause "SELECT 'qa_pause_inflight'" || true
deadline=$((SECONDS + 10))
waiting=0
while ((SECONDS < deadline)); do
    if qa_admin "$DB" "SELECT count(*)::text FROM pg_catalog.pg_stat_activity a WHERE a.backend_type LIKE 'sql_firewall_worker_%' AND a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) current_database()) AND a.wait_event_type OPERATOR(pg_catalog.=) 'Lock'"; then
        [[ ${QA_STEP_OUT[1]} == 1 ]] && waiting=1 && break
    fi
    sleep 0.2
done
if [[ $waiting -ne 1 ]]; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner_backend})" || true
    wait "$owner_pid" 2>/dev/null || true
    wait "$hold_pid" 2>/dev/null || true
    fail "$ID.inflight.wait" "consumer did not block inside event SQL"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != pause\ pending\ epoch=* ]]; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner_backend})" || true
    wait "$owner_pid" 2>/dev/null || true
    wait "$hold_pid" 2>/dev/null || true
    fail "$ID.inflight.pending" "pause during SQL returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_inflight') > 0" ||
    { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
inflight_count=${QA_STEP_OUT[1]}
checkpoint_next "$DB" || { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
if [[ $inflight_count != 0 || $QA_NEXT != "$before_lock" ]]; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner_backend})" || true
    wait "$owner_pid" 2>/dev/null || true
    wait "$hold_pid" 2>/dev/null || true
    fail "$ID.inflight.open" "event or checkpoint changed while SQL was in flight"
    exit 0
fi
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner_backend})" ||
    { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
wait "$owner_pid" 2>/dev/null || true
wait "$hold_pid" || { infra "$ID.inflight" "lock holder did not finish"; exit 0; }
if ! wait_status "$DB" "paused" 20; then
    fail "$ID.inflight.ack" "$QA_INFRA_REASON"
    exit 0
fi
checkpoint_next "$DB" || { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
paused_next=$QA_NEXT
qa_sql_steps qa_pause_app "$DB" qa_pause "SELECT 'qa_pause_after_ack'" || true
status_of "$DB" || { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_after_ack') > 0" ||
    { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
later_count=${QA_STEP_OUT[1]}
if [[ $QA_STATUS != paused\ epoch=* || $QA_NEXT != "$paused_next" || $later_count != 0 ]]; then
    fail "$ID.inflight.later" "status '$QA_STATUS' checkpoint $QA_NEXT later count $later_count"
    exit 0
fi
qa_admin "$DB" "UPDATE public.qa_fail SET blocked = false WHERE id = 1" \
    "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.inflight" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_after_ack') > 0" \
    1 20; then
    fail "$ID.inflight.deliver" "event after acknowledgement was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.inflight" "pause stayed pending while event SQL held a lock, then stopped later events until resume"

# 3. Copied retry stays unapplied while paused and increments a fingerprint once.
qa_admin "$DB" \
    "CREATE FUNCTION public.qa_pause_fp() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_fail WHERE id = 1 AND blocked) THEN RAISE EXCEPTION 'qa_pause fingerprint' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END \$\$" \
    "CREATE TRIGGER qa_pause_fp BEFORE INSERT OR UPDATE ON public.sql_firewall_query_fingerprints FOR EACH ROW EXECUTE FUNCTION public.qa_pause_fp()" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_pause_learn "$DB" qa_pause "SELECT 'qa_pause_fp_token'" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_pause_learn'::name AND strpos(sample_query, 'qa_pause_fp_token') > 0" \
    1 20; then
    fail "$ID.retry.seed" "fingerprint seed was not stored (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" \
    "CREATE ROLE qa_pause_learn_b LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_pause_learn_b" \
    "ALTER ROLE qa_pause_learn_b IN DATABASE $DB SET sql_firewall.mode = 'learn'" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, first_seen_at, last_seen_at, hit_count, is_approved) SELECT fingerprint, normalized_query, 'qa_pause_learn_b', command_type, sample_query, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 5, false FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_pause_learn'::name AND strpos(sample_query, 'qa_pause_fp_token') > 0" \
    "UPDATE public.qa_fail SET blocked = true WHERE id = 1" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
worker_pid "$DB" || { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
db_oid_text=$QA_WORKER_PID
qa_admin postgres "SELECT oid::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) '$DB'" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
oid_db=${QA_STEP_OUT[1]}
mark=$(qa_server_log_offset)
qa_sql_steps qa_pause_learn_b "$DB" qa_pause "SELECT 'qa_pause_fp_token'" || true
if ! wait_log "$mark" "retry database oid ${oid_db} " 15; then
    fail "$ID.retry.attempt" "fingerprint retry was not observed"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* ]]; then
    fail "$ID.retry.pause" "pause during retry returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$DB" "UPDATE public.qa_fail SET blocked = false WHERE id = 1" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_pause_learn_b'::name AND strpos(sample_query, 'qa_pause_fp_token') > 0" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
held_hits=${QA_STEP_OUT[1]}
status_of "$DB" || { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
if [[ $held_hits != 5 || $QA_STATUS != paused\ epoch=* ]]; then
    fail "$ID.retry.held" "hit_count $held_hits status '$QA_STATUS' while paused"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.retry" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_pause_learn_b'::name AND strpos(sample_query, 'qa_pause_fp_token') > 0" \
    6 20; then
    fail "$ID.retry.commit" "hit_count did not become 6 after one resume (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.retry" "copied fingerprint stayed at 5 while paused on pid $db_oid_text and committed once to 6"

# 6. Overwrite while an acknowledged pause is held.
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* ]]; then
    fail "$ID.gap.pause" "pause returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
checkpoint_next "$DB" || { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
gap_from=$QA_NEXT
{
    for i in $(seq 0 1028); do
        printf "SELECT 'qa_pause_gap_%04d';\n" "$i"
    done
} >"$QA_RUN_DIR/pause_gap.sql"
env PGAPPNAME=qa_pause "$QA_PSQL" -X -q -v ON_ERROR_STOP=0 -h "$QA_SOCK" -p "$QA_PORT" -U qa_pause_app -d "$DB" -f "$QA_RUN_DIR/pause_gap.sql" >/dev/null 2>&1 || true
status_of "$DB" || { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS != paused\ epoch=* || $QA_NEXT != "$gap_from" ]]; then
    fail "$ID.gap.held" "status '$QA_STATUS' checkpoint moved from $gap_from to $QA_NEXT during pause"
    exit 0
fi
mark=$(qa_server_log_offset)
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
gap_to=$((gap_from + 5))
if ! wait_log "$mark" "skipped shared-stream positions [${gap_from}, ${gap_to})" 20; then
    actual=$(grep -F "skipped shared-stream positions" "$QA_SERVER_LOG" | tail -1 || true)
    fail "$ID.gap.range" "expected [${gap_from}, ${gap_to}); last='${actual}'"
    exit 0
fi
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_gap_0005') > 0" \
    1 30; then
    fail "$ID.gap.retained" "retained event was not delivered (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_gap_0000') > 0" ||
    { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.gap.lost" "overwritten qa_pause_gap_0000 was delivered"
    exit 0
fi
ok "$ID.gap" "paused consumer left checkpoint at $gap_from; resume skipped [${gap_from}, ${gap_to}) and delivered qa_pause_gap_0005"

# 4. Replacement honors the pause. A request before attachment stays pending.
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
worker_pid "$DB" || { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
old_pid=$QA_WORKER_PID
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${old_pid})" ||
    { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 20))
new_pid=
while ((SECONDS < deadline)); do
    worker_pid "$DB" || { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $QA_WORKER_PID && $QA_WORKER_PID != "$old_pid" ]]; then
        new_pid=$QA_WORKER_PID
        break
    fi
    sleep 0.2
done
[[ -n $new_pid ]] || { fail "$ID.replace.worker" "replacement for $old_pid did not appear"; exit 0; }
if ! wait_status "$DB" "paused" 20; then
    fail "$ID.replace.pause" "$QA_INFRA_REASON"
    exit 0
fi
qa_sql_steps qa_pause_app "$DB" qa_pause "SELECT 'qa_pause_replaced'" || true
status_of "$DB" || { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
replaced_next=$QA_NEXT
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_replaced') > 0" ||
    { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
replaced_count=${QA_STEP_OUT[1]}
if [[ $QA_STATUS != paused\ epoch=* || $QA_NEXT != "$replaced_next" || $replaced_count != 0 ]]; then
    fail "$ID.replace.held" "replacement $new_pid status '$QA_STATUS' count $replaced_count"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.replace" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_replaced') > 0" \
    1 20; then
    fail "$ID.replace.deliver" "event was not persisted after the replacement resumed (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.replace" "paused pid $old_pid was replaced by $new_pid, which stayed paused until resume"

qa_admin postgres \
    "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE backend_type OPERATOR(pg_catalog.=) 'sql_firewall_launcher'" ||
    { infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
launcher_pid=${QA_STEP_OUT[1]}
kill -STOP "$launcher_pid" || { infra "$ID.attach" "could not stop the launcher"; exit 0; }
worker_pid "$LIFE" || { kill -CONT "$launcher_pid" 2>/dev/null || true; infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
if [[ -n $QA_WORKER_PID ]]; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${QA_WORKER_PID})" || true
fi
deadline=$((SECONDS + 10))
while ((SECONDS < deadline)); do
    worker_pid "$LIFE" || break
    [[ -z $QA_WORKER_PID ]] && break
    sleep 0.2
done
qa_admin "$LIFE" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { kill -CONT "$launcher_pid" 2>/dev/null || true; infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != pause\ pending\ epoch=* ]]; then
    kill -CONT "$launcher_pid" 2>/dev/null || true
    fail "$ID.attach.pending" "pause before attachment returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
status_of "$LIFE" || { kill -CONT "$launcher_pid" 2>/dev/null || true; infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS == paused\ epoch=* ]]; then
    kill -CONT "$launcher_pid" 2>/dev/null || true
    fail "$ID.attach.false" "absence was reported as paused: '$QA_STATUS'"
    exit 0
fi
kill -CONT "$launcher_pid" || { infra "$ID.attach" "could not continue the launcher"; exit 0; }
if ! wait_status "$LIFE" "paused" 30; then
    fail "$ID.attach.honor" "$QA_INFRA_REASON"
    exit 0
fi
qa_sql_steps qa_pause_life "$LIFE" qa_pause "SELECT 'qa_pause_before_attach'" || true
status_of "$LIFE" || { infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$LIFE" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_before_attach') > 0" ||
    { infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
attach_count=${QA_STEP_OUT[1]}
if [[ $QA_STATUS != paused\ epoch=* || $attach_count != 0 ]]; then
    fail "$ID.attach.quiescent" "status '$QA_STATUS' count $attach_count"
    exit 0
fi
qa_admin "$LIFE" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.attach" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$LIFE" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_before_attach') > 0" \
    1 20; then
    fail "$ID.attach.deliver" "pre-attachment event was not persisted after resume (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.attach" "a pause issued with no consumer stayed pending, then the new consumer honored it"

# 5. Installation lifecycle and shared-memory restart.
if ! qa_wait_worker_live "$LIFE" 20; then
    fail "$ID.life.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$LIFE" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$LIFE" "DROP EXTENSION sql_firewall" "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_pause_life "$LIFE" qa_pause "SELECT 'qa_pause_new_install'" || true
if ! qa_poll "$LIFE" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_new_install') > 0" \
    1 30; then
    fail "$ID.life.new" "new installation stayed paused (${QA_INFRA_REASON:-})"
    exit 0
fi
status_of "$LIFE" || { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS == paused\ epoch=* || $QA_STATUS == pause\ pending* ]]; then
    fail "$ID.life.transfer" "old pause still controls the new installation: '$QA_STATUS'"
    exit 0
fi
ok "$ID.life.recreate" "DROP/CREATE did not transfer the old pause; qa_pause_new_install persisted"

qa_admin "$LIFE" "BEGIN; DROP EXTENSION sql_firewall; ROLLBACK" ||
    { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$LIFE" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != approval\ worker\ paused\ epoch=* ]]; then
    fail "$ID.life.rollback" "pause after rolled-back DROP returned '${QA_STEP_OUT[1]}'"
    exit 0
fi
qa_admin "$LIFE" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.life.rollback" "rolled-back DROP kept the installation controllable"

worker_pid "$OTHER" || { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
drop_pid=$QA_WORKER_PID
qa_admin "$OTHER" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$OTHER" "DROP EXTENSION sql_firewall" || { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 20))
gone=0
while ((SECONDS < deadline)); do
    worker_pid "$OTHER" || { infra "$ID.life" "$QA_INFRA_REASON"; exit 0; }
    if [[ $QA_WORKER_PID != "$drop_pid" ]] && wait_log "$(qa_server_log_offset)" "extension dropped" 1; then
        # The exit line is already in the log; accept either a gone pid or the message.
        gone=1
        break
    fi
    if [[ $QA_WORKER_PID != "$drop_pid" ]]; then
        gone=1
        break
    fi
    sleep 0.2
done
if [[ $gone -ne 1 ]]; then
    fail "$ID.life.drop" "paused consumer $drop_pid did not exit after DROP"
    exit 0
fi
ok "$ID.life.drop" "paused consumer $drop_pid exited after DROP EXTENSION"

exe=$(readlink "/proc/$QA_PM_PID/exe")
pg_ctl=$(dirname "$exe")/pg_ctl
data=$(tr '\0' '\n' <"/proc/$QA_PM_PID/cmdline" | awk 'f { print; exit } /\-D/ { f=1 }')
"$pg_ctl" -D "$data" -l "$QA_SERVER_LOG" -w -t 60 restart >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 ||
    { infra "$ID.restart" "pg_ctl restart failed"; exit 0; }
# The launcher registers at most four consumers per five-second scan.
deadline=$((SECONDS + 120))
live=
while ((SECONDS < deadline)); do
    worker_pid "$DB" || { infra "$ID.restart" "$QA_INFRA_REASON"; exit 0; }
    [[ -n $QA_WORKER_PID ]] && live=$QA_WORKER_PID && break
    sleep 0.2
done
[[ -n $live ]] || { fail "$ID.restart.worker" "consumer did not attach after postmaster restart"; exit 0; }
status_of "$DB" || { infra "$ID.restart" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS == paused\ epoch=* || $QA_STATUS == pause\ pending* ]]; then
    fail "$ID.restart.pause" "old pause survived shared-memory restart: '$QA_STATUS'"
    exit 0
fi
qa_sql_steps qa_pause_app "$DB" qa_pause "SELECT 'qa_pause_after_restart'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_pause_after_restart') > 0" \
    1 30; then
    fail "$ID.restart.deliver" "event was not processed under the running default (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.restart" "postmaster restart cleared pause state; pid $live processed qa_pause_after_restart"

# 7. Overlapping pause/resume and cancellation.
env PGAPPNAME=qa_lock_owner2 "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "SELECT pg_catalog.pg_advisory_lock(942002); SELECT pg_catalog.pg_sleep(120);" \
    >"$QA_RUN_DIR/owner2.out" 2>"$QA_RUN_DIR/owner2.err" &
owner2_pid=$!
deadline=$((SECONDS + 10))
owner2_backend=
while ((SECONDS < deadline)); do
    if qa_admin "$DB" "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE application_name OPERATOR(pg_catalog.=) 'qa_lock_owner2' AND query LIKE '%pg_sleep%'"; then
        [[ ${QA_STEP_OUT[1]} =~ ^[0-9]+$ ]] && owner2_backend=${QA_STEP_OUT[1]} && break
    fi
    sleep 0.2
done
if [[ -z $owner2_backend ]]; then
    kill "$owner2_pid" 2>/dev/null || true
    wait "$owner2_pid" 2>/dev/null || true
    infra "$ID.race" "second advisory owner did not start"
    exit 0
fi
qa_admin "$DB" "UPDATE public.qa_fail SET blocked = true WHERE id = 1" || { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
env PGAPPNAME=qa_hold2 "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "BEGIN; LOCK TABLE public.qa_gate IN EXCLUSIVE MODE; SELECT pg_catalog.pg_advisory_lock(942002); COMMIT;" \
    >"$QA_RUN_DIR/hold2.out" 2>"$QA_RUN_DIR/hold2.err" &
hold2=$!
qa_sql_steps qa_pause_app "$DB" qa_pause "SELECT 'qa_pause_overlap'" || true
deadline=$((SECONDS + 10))
waiting=0
while ((SECONDS < deadline)); do
    if qa_admin "$DB" "SELECT count(*)::text FROM pg_catalog.pg_stat_activity a WHERE a.backend_type LIKE 'sql_firewall_worker_%' AND a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) current_database()) AND a.wait_event_type OPERATOR(pg_catalog.=) 'Lock'"; then
        [[ ${QA_STEP_OUT[1]} == 1 ]] && waiting=1 && break
    fi
    sleep 0.2
done
if [[ $waiting -ne 1 ]]; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner2_backend})" || true
    wait "$owner2_pid" 2>/dev/null || true
    wait "$hold2" 2>/dev/null || true
    fail "$ID.race.wait" "consumer did not block for the overlap test"
    exit 0
fi
env PGAPPNAME=qa_pause_wait "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "SELECT public.sql_firewall_pause_approval_worker()" \
    >"$QA_RUN_DIR/pause_wait.out" 2>"$QA_RUN_DIR/pause_wait.err" &
pause_wait=$!
if ! wait_status "$DB" "pause pending" 10; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner2_backend})" || true
    wait "$owner2_pid" 2>/dev/null || true
    wait "$hold2" 2>/dev/null || true
    wait "$pause_wait" 2>/dev/null || true
    fail "$ID.race.pending" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
wait "$pause_wait" || true
if ! grep -F "pause superseded" "$QA_RUN_DIR/pause_wait.out" >/dev/null; then
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner2_backend})" || true
    wait "$owner2_pid" 2>/dev/null || true
    wait "$hold2" 2>/dev/null || true
    fail "$ID.race.super" "waiting pause returned '$(tr '\n' ' ' <"$QA_RUN_DIR/pause_wait.out")'"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" ||
    { infra "$ID.cancel" "$QA_INFRA_REASON"; exit 0; }
# The consumer is still inside SQL, so this pause is pending and stored.
env PGAPPNAME=qa_pause_cancel "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "SELECT public.sql_firewall_pause_approval_worker()" \
    >"$QA_RUN_DIR/pause_cancel.out" 2>"$QA_RUN_DIR/pause_cancel.err" &
cancel_pid=$!
deadline=$((SECONDS + 10))
cancel_backend=
while ((SECONDS < deadline)); do
    if qa_admin "$DB" "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE application_name OPERATOR(pg_catalog.=) 'qa_pause_cancel'"; then
        [[ ${QA_STEP_OUT[1]} =~ ^[0-9]+$ ]] && cancel_backend=${QA_STEP_OUT[1]} && break
    fi
    sleep 0.2
done
if [[ -n $cancel_backend ]]; then
    qa_admin postgres "SELECT pg_catalog.pg_cancel_backend(${cancel_backend})" || true
fi
wait "$cancel_pid" 2>/dev/null || true
qa_admin "$DB" "UPDATE public.qa_fail SET blocked = false WHERE id = 1" ||
    { infra "$ID.cancel" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${owner2_backend})" ||
    { infra "$ID.cancel" "$QA_INFRA_REASON"; exit 0; }
wait "$owner2_pid" 2>/dev/null || true
wait "$hold2" 2>/dev/null || true
if ! wait_status "$DB" "paused" 20; then
    fail "$ID.cancel.persist" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM pg_catalog.pg_stat_activity WHERE pid OPERATOR(pg_catalog.=) ${cancel_backend:-0} AND state OPERATOR(pg_catalog.=) 'idle in transaction'" ||
    { infra "$ID.cancel" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.cancel.stuck" "cancelled administrative backend is idle in transaction"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" ||
    { infra "$ID.cancel" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.overlap" "a later resume superseded the waiting pause; cancelling a waiter left the issued pause and no idle transaction"

# 8. Authorization and hostile name resolution.
# Learn mode lets the statement reach the function. Enforce mode would reject
# the SELECT itself and would not exercise the administrative check.
qa_admin postgres "ALTER ROLE qa_pause_user IN DATABASE $DB SET sql_firewall.mode = 'learn'" ||
    { infra "$ID.auth" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_pause_user "$DB" qa_pause \
    "SELECT public.sql_firewall_pause_approval_worker()" \
    "SELECT public.sql_firewall_approval_worker_status()" \
    "SELECT public.sql_firewall_clear_approval_cache()" ||
    { infra "$ID.auth" "$QA_INFRA_REASON"; exit 0; }
for step in 1 2 3; do
    if [[ ${QA_STEP_ERR[$step]} != true || ${QA_STEP_STATE[$step]} != 42501 || ${QA_STEP_MSG[$step]} != *permission\ denied\ for\ function* ]]; then
        fail "$ID.auth.acl" "step $step state ${QA_STEP_STATE[$step]:-} ${QA_STEP_MSG[$step]:-}"
        exit 0
    fi
done
status_of "$DB" || { infra "$ID.auth" "$QA_INFRA_REASON"; exit 0; }
before_auth=$QA_STATUS
qa_admin "$DB" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_pause_approval_worker() TO qa_pause_user" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_approval_worker_status() TO qa_pause_user" \
    "GRANT EXECUTE ON FUNCTION public.sql_firewall_clear_approval_cache() TO qa_pause_user" \
    "CREATE FUNCTION public.qa_wrap_pause() RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS \$\$ SELECT public.sql_firewall_pause_approval_worker() \$\$" \
    "GRANT EXECUTE ON FUNCTION public.qa_wrap_pause() TO qa_pause_user" ||
    { infra "$ID.auth" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_pause_user "$DB" qa_pause \
    "CREATE TEMP TABLE pg_authid (rolname name, rolsuper boolean)" \
    "INSERT INTO pg_temp.pg_authid VALUES (SESSION_USER, true)" \
    "SELECT set_config('search_path', 'pg_temp, public', false)" \
    "SELECT public.sql_firewall_pause_approval_worker()" \
    "SELECT public.qa_wrap_pause()" \
    "SELECT public.sql_firewall_clear_approval_cache()" ||
    { infra "$ID.auth" "$QA_INFRA_REASON"; exit 0; }
for step in 4 5 6; do
    if [[ ${QA_STEP_ERR[$step]} != true || ${QA_STEP_STATE[$step]} != 42501 ]]; then
        fail "$ID.auth.runtime" "step $step state ${QA_STEP_STATE[$step]:-} ${QA_STEP_MSG[$step]:-}"
        exit 0
    fi
    if [[ ${QA_STEP_MSG[$step]} != *only\ a\ superuser\ session* ]]; then
        fail "$ID.auth.runtime" "step $step message '${QA_STEP_MSG[$step]:-}'"
        exit 0
    fi
done
status_of "$DB" || { infra "$ID.auth" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_STATUS != "$before_auth" ]]; then
    fail "$ID.auth.state" "unauthorized calls changed status from '$before_auth' to '$QA_STATUS'"
    exit 0
fi
ok "$ID.auth" "ordinary and SECURITY DEFINER sessions were denied with SQLSTATE 42501 and left status '$QA_STATUS'"

exit 0
