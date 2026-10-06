#!/usr/bin/env bash
# Phase 3C2 revision: idle installation changes, invalid checkpoint metadata,
# and an ahead-of-head cursor on an already running consumer.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.checkpoint_revision
EV=checkpoint_revision
IDLE=qa_rev_idle
DROPDB=qa_rev_drop
BAD=qa_rev_bad

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "An idle consumer notices DROP/CREATE. Invalid checkpoint metadata is left unchanged. An ahead-of-head cursor is not treated as acknowledgement, and a repaired row is picked up without restarting the worker." ""

qa_create_db "$IDLE" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$DROPDB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$BAD" sql_firewall.mode=learn sql_firewall.enable_fingerprint_learning=on ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE qa_rev_idle_app LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_rev_drop_app LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_rev_blk LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_rev_learn LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $IDLE TO qa_rev_idle_app" \
    "GRANT CONNECT ON DATABASE $DROPDB TO qa_rev_drop_app" \
    "GRANT CONNECT ON DATABASE $BAD TO qa_rev_blk, qa_rev_learn" \
    "ALTER ROLE qa_rev_idle_app IN DATABASE $IDLE SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_rev_drop_app IN DATABASE $DROPDB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_rev_blk IN DATABASE $BAD SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_rev_learn IN DATABASE $BAD SET sql_firewall.mode = 'learn'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

worker_pid() {
    qa_admin "$1" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_WORKER_PID=${QA_STEP_OUT[1]}
}

checkpoint_text() {
    qa_admin "$1" \
        "SELECT initialized::text || '|' || coalesce(ring_generation::text, '') || '|' || coalesce(extension_oid::text, '') || '|' || coalesce(next_position::text, '') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
        return $?
    QA_CHECKPOINT=${QA_STEP_OUT[1]}
}

# Two identical observations of pid and checkpoint. The wait is only the poll interval.
wait_stable() {
    local db=$1 prev_pid="" prev_cp="" deadline=$((SECONDS + 20))
    while ((SECONDS < deadline)); do
        worker_pid "$db" || return $?
        checkpoint_text "$db" || return $?
        if [[ -n $QA_WORKER_PID && $QA_WORKER_PID == "$prev_pid" && $QA_CHECKPOINT == "$prev_cp" && $QA_CHECKPOINT == true\|* ]]; then
            return 0
        fi
        prev_pid=$QA_WORKER_PID
        prev_cp=$QA_CHECKPOINT
        sleep 0.2
    done
    QA_INFRA_REASON="consumer in $db did not stay initialized and idle"
    return 1
}

wait_log() { # offset text timeout
    local offset=$1 text=$2 deadline=$((SECONDS + $3))
    while ((SECONDS < deadline)); do
        if tail -c +"$((offset + 1))" "$QA_SERVER_LOG" | grep -F "$text" >/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

if ! qa_wait_worker_live "$IDLE" 40; then
    fail "$ID.idle.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_sql_steps qa_rev_idle_app "$IDLE" qa_rev "SELECT 'qa_rev_seed'" || true
if ! qa_poll "$IDLE" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_seed') > 0" \
    1 20; then
    fail "$ID.idle.seed" "seed event was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
wait_stable "$IDLE" || { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
idle_pid=$QA_WORKER_PID
idle_cp=$QA_CHECKPOINT
mark=$(qa_server_log_offset)
if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "retry database oid" >/dev/null; then
    fail "$ID.idle.retry" "a retry was already pending before DROP/CREATE"
    exit 0
fi
qa_admin "$IDLE" "DROP EXTENSION sql_firewall" "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$IDLE" "SELECT oid::text FROM pg_catalog.pg_extension WHERE extname OPERATOR(pg_catalog.=) 'sql_firewall'" ||
    { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
new_ext=${QA_STEP_OUT[1]}
if ! wait_log "$mark" "extension dropped" 20 && ! wait_log "$mark" "discarding local consumer progress" 1; then
    fail "$ID.idle.detect" "idle consumer did not notice DROP/CREATE"
    exit 0
fi
deadline=$((SECONDS + 30))
adopted=0
while ((SECONDS < deadline)); do
    checkpoint_text "$IDLE" || { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
    if [[ $QA_CHECKPOINT == true\|*\|${new_ext}\|* ]]; then
        adopted=1
        break
    fi
    sleep 0.2
done
if [[ $adopted -ne 1 ]]; then
    fail "$ID.idle.adopt" "checkpoint was not initialized for extension $new_ext (saw '${QA_CHECKPOINT:-}')"
    exit 0
fi
qa_sql_steps qa_rev_idle_app "$IDLE" qa_rev "SELECT 'qa_rev_new_install'" || true
if ! qa_poll "$IDLE" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_new_install') > 0" \
    1 20; then
    fail "$ID.idle.new" "new installation event was not processed without restarting the worker (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$IDLE" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_seed') > 0" ||
    { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.idle.old" "old installation event was applied to the new extension"
    exit 0
fi
checkpoint_text "$IDLE" || { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_CHECKPOINT != true\|*\|${new_ext}\|* ]]; then
    fail "$ID.idle.checkpoint" "checkpoint is '$QA_CHECKPOINT', expected extension $new_ext"
    exit 0
fi
worker_pid "$IDLE" || { infra "$ID.idle" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.idle" "idle pid $idle_pid checkpoint $idle_cp noticed extension $new_ext; qa_rev_new_install persisted on pid ${QA_WORKER_PID} without a manual restart"

if ! qa_wait_worker_live "$DROPDB" 40; then
    fail "$ID.drop.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_sql_steps qa_rev_drop_app "$DROPDB" qa_rev "SELECT 'qa_rev_drop_seed'" || true
if ! qa_poll "$DROPDB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_drop_seed') > 0" \
    1 20; then
    fail "$ID.drop.seed" "seed event was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
wait_stable "$DROPDB" || { infra "$ID.drop" "$QA_INFRA_REASON"; exit 0; }
drop_pid=$QA_WORKER_PID
mark=$(qa_server_log_offset)
qa_admin "$DROPDB" "DROP EXTENSION sql_firewall" || { infra "$ID.drop" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 20))
gone=0
while ((SECONDS < deadline)); do
    worker_pid "$DROPDB" || { infra "$ID.drop" "$QA_INFRA_REASON"; exit 0; }
    if [[ $QA_WORKER_PID != "$drop_pid" ]] && wait_log "$mark" "extension dropped" 1; then
        gone=1
        break
    fi
    sleep 0.2
done
if [[ $gone -ne 1 ]]; then
    fail "$ID.drop" "consumer $drop_pid did not exit after DROP EXTENSION (now '${QA_WORKER_PID:-}')"
    exit 0
fi
ok "$ID.drop" "consumer $drop_pid exited after DROP EXTENSION and was not recreated"

if ! qa_wait_worker_live "$BAD" 40; then
    fail "$ID.bad.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_sql_steps qa_rev_blk "$BAD" qa_rev "SELECT 'qa_rev_marker'" || true
if ! qa_poll "$BAD" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_marker') > 0" \
    1 20; then
    fail "$ID.bad.marker" "blocked marker was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_sql_steps qa_rev_learn "$BAD" qa_rev "SELECT 'qa_rev_fp_token'" ||
    { infra "$ID.bad" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$BAD" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_rev_learn'::name AND strpos(sample_query, 'qa_rev_fp_token') > 0" \
    1 20; then
    fail "$ID.bad.fingerprint" "fingerprint was not stored (${QA_INFRA_REASON:-})"
    exit 0
fi
wait_stable "$BAD" || { infra "$ID.bad" "$QA_INFRA_REASON"; exit 0; }
saved_cp=$QA_CHECKPOINT
saved_pid=$QA_WORKER_PID
IFS='|' read -r saved_init saved_gen saved_ext saved_next <<<"$saved_cp"

qa_sql_steps "$QA_SUPERUSER" "$BAD" qa_admin \
    "UPDATE public.sql_firewall_consumer_checkpoint SET ring_generation = 18446744073709551616 WHERE singleton = 1" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = -1 WHERE singleton = 1" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET ring_generation = NULL WHERE singleton = 1" ||
    { infra "$ID.constraint" "$QA_INFRA_REASON"; exit 0; }
for step in 1 2 3; do
    if [[ ${QA_STEP_ERR[$step]} != true || ${QA_STEP_STATE[$step]} != 23514 ]]; then
        fail "$ID.constraint" "step $step state ${QA_STEP_STATE[$step]:-} ${QA_STEP_MSG[$step]:-}"
        exit 0
    fi
done
checkpoint_text "$BAD" || { infra "$ID.constraint" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_CHECKPOINT != "$saved_cp" ]]; then
    fail "$ID.constraint.unchanged" "checkpoint changed to '$QA_CHECKPOINT'"
    exit 0
fi
ok "$ID.constraint" "overflow, negative, and NULL checkpoint writes were rejected with SQLSTATE 23514"

qa_admin "$BAD" "ALTER TABLE public.sql_firewall_consumer_checkpoint DROP CONSTRAINT sql_firewall_consumer_checkpoint_metadata" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET ring_generation = 18446744073709551616 WHERE singleton = 1" ||
    { infra "$ID.overflow" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${saved_pid})" ||
    { infra "$ID.overflow" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 20))
new_pid=
while ((SECONDS < deadline)); do
    worker_pid "$BAD" || { infra "$ID.overflow" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $QA_WORKER_PID && $QA_WORKER_PID != "$saved_pid" ]]; then
        new_pid=$QA_WORKER_PID
        break
    fi
    sleep 0.2
done
[[ -n $new_pid ]] || { fail "$ID.overflow.worker" "replacement for $saved_pid did not appear"; exit 0; }
if ! wait_log "$mark" "consumer checkpoint metadata is invalid; not resetting progress" 20; then
    fail "$ID.overflow.detect" "replacement did not reject the overflowing generation"
    exit 0
fi
qa_admin "$BAD" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_marker') > 0" ||
    { infra "$ID.overflow" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.overflow.replay" "qa_rev_marker count is ${QA_STEP_OUT[1]} after the invalid generation"
    exit 0
fi
qa_admin "$BAD" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_rev_learn'::name AND strpos(sample_query, 'qa_rev_fp_token') > 0" ||
    { infra "$ID.overflow" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.overflow.fingerprint" "hit_count is ${QA_STEP_OUT[1]} after the invalid generation"
    exit 0
fi
checkpoint_text "$BAD" || { infra "$ID.overflow" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_CHECKPOINT != *\|18446744073709551616\|* ]]; then
    fail "$ID.overflow.rewrite" "invalid checkpoint was rewritten to '$QA_CHECKPOINT'"
    exit 0
fi
ok "$ID.overflow" "generation 18446744073709551616 was left unchanged; qa_rev_marker stayed at 1 and hit_count stayed at 1"

qa_admin "$BAD" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET initialized = true, ring_generation = ${saved_gen}, extension_oid = ${saved_ext}, next_position = ${saved_next} WHERE singleton = 1" \
    "ALTER TABLE public.sql_firewall_consumer_checkpoint ADD CONSTRAINT sql_firewall_consumer_checkpoint_metadata CHECK ((NOT initialized AND ring_generation IS NULL AND extension_oid IS NULL AND next_position IS NULL) OR (initialized AND ring_generation IS NOT NULL AND extension_oid IS NOT NULL AND extension_oid <> 0 AND next_position IS NOT NULL AND ring_generation >= 0 AND ring_generation <= 18446744073709551615 AND next_position >= 0 AND next_position <= 18446744073709551615))" ||
    { infra "$ID.restore" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_rev_blk "$BAD" qa_rev "SELECT 'qa_rev_after_restore'" || true
if ! qa_poll "$BAD" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_after_restore') > 0" \
    1 20; then
    fail "$ID.restore" "processing did not resume after valid metadata was restored (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.restore" "restored checkpoint generation $saved_gen resumed processing without another worker restart"
wait_stable "$BAD" || { infra "$ID.null" "$QA_INFRA_REASON"; exit 0; }
IFS='|' read -r saved_init saved_gen saved_ext saved_next <<<"$QA_CHECKPOINT"

qa_admin "$BAD" "ALTER TABLE public.sql_firewall_consumer_checkpoint DROP CONSTRAINT sql_firewall_consumer_checkpoint_metadata" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET ring_generation = NULL WHERE singleton = 1" ||
    { infra "$ID.null" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_rev_blk "$BAD" qa_rev "SELECT 'qa_rev_null_meta'" || true
if ! wait_log "$mark" "consumer checkpoint metadata is invalid; not resetting progress" 20; then
    fail "$ID.null.detect" "running consumer did not reject NULL generation"
    exit 0
fi
qa_admin "$BAD" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_null_meta') > 0" ||
    { infra "$ID.null" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.null.apply" "event was applied while generation was NULL"
    exit 0
fi
qa_admin "$BAD" "UPDATE public.sql_firewall_consumer_checkpoint SET ring_generation = ${saved_gen}, next_position = -1 WHERE singleton = 1" ||
    { infra "$ID.negative" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_rev_blk "$BAD" qa_rev "SELECT 'qa_rev_negative'" || true
if ! wait_log "$mark" "consumer checkpoint metadata is invalid; not resetting progress" 20; then
    fail "$ID.negative.detect" "running consumer did not reject next_position -1"
    exit 0
fi
checkpoint_text "$BAD" || { infra "$ID.negative" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_CHECKPOINT != *\|-1 ]]; then
    fail "$ID.negative.rewrite" "checkpoint was rewritten to '$QA_CHECKPOINT'"
    exit 0
fi
qa_admin "$BAD" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_negative') > 0" ||
    { infra "$ID.negative" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.negative.apply" "event was applied while next_position was negative"
    exit 0
fi
qa_admin "$BAD" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_rev_learn'::name AND strpos(sample_query, 'qa_rev_fp_token') > 0" ||
    { infra "$ID.negative" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.negative.fingerprint" "hit_count is ${QA_STEP_OUT[1]} while metadata was invalid"
    exit 0
fi
qa_admin "$BAD" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET initialized = true, ring_generation = ${saved_gen}, extension_oid = ${saved_ext}, next_position = ${saved_next} WHERE singleton = 1" \
    "ALTER TABLE public.sql_firewall_consumer_checkpoint ADD CONSTRAINT sql_firewall_consumer_checkpoint_metadata CHECK ((NOT initialized AND ring_generation IS NULL AND extension_oid IS NULL AND next_position IS NULL) OR (initialized AND ring_generation IS NOT NULL AND extension_oid IS NOT NULL AND extension_oid <> 0 AND next_position IS NOT NULL AND ring_generation >= 0 AND ring_generation <= 18446744073709551615 AND next_position >= 0 AND next_position <= 18446744073709551615))" ||
    { infra "$ID.negative" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$BAD" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_negative') > 0" \
    1 20; then
    fail "$ID.negative.resume" "qa_rev_negative was not persisted after metadata was restored (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$BAD" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_null_meta') > 0" ||
    { infra "$ID.negative" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.null.resume" "qa_rev_null_meta count is ${QA_STEP_OUT[1]} after restore"
    exit 0
fi
ok "$ID.invalid_live" "NULL and negative metadata were left unchanged and did not duplicate qa_rev_marker or the fingerprint; both retained events persisted after restore"

worker_pid "$BAD" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
ahead_pid=$QA_WORKER_PID
[[ $ahead_pid =~ ^[0-9]+$ ]] || { infra "$ID.ahead" "worker pid '$ahead_pid'"; exit 0; }
checkpoint_text "$BAD" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
ahead_saved_next=${QA_CHECKPOINT##*|}
qa_admin "$BAD" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = 10000000000000000000 WHERE singleton = 1" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_rev_blk "$BAD" qa_rev "SELECT 'qa_rev_ahead_live'" || true
if ! wait_log "$mark" "is ahead of ring head" 20; then
    fail "$ID.ahead.detect" "running consumer did not report an ahead-of-head checkpoint"
    exit 0
fi
if ! wait_log "$mark" "not acknowledging" 5; then
    fail "$ID.ahead.ack" "ahead-of-head checkpoint was acknowledged"
    exit 0
fi
qa_admin "$BAD" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_ahead_live') > 0" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.ahead.apply" "qa_rev_ahead_live was applied while the checkpoint was ahead of the ring head"
    exit 0
fi
checkpoint_text "$BAD" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_CHECKPOINT != *\|10000000000000000000 ]]; then
    fail "$ID.ahead.rewrite" "checkpoint was rewritten to '$QA_CHECKPOINT'"
    exit 0
fi
worker_pid "$BAD" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_WORKER_PID != "$ahead_pid" ]]; then
    fail "$ID.ahead.pid" "worker changed from $ahead_pid to $QA_WORKER_PID before repair"
    exit 0
fi
qa_admin "$BAD" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = ${ahead_saved_next} WHERE singleton = 1" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$BAD" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_ahead_live') > 0" \
    1 20; then
    fail "$ID.ahead.resume" "qa_rev_ahead_live was not persisted after the checkpoint was repaired (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_sql_steps qa_rev_blk "$BAD" qa_rev "SELECT 'qa_rev_ahead_later'" || true
if ! qa_poll "$BAD" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_ahead_later') > 0" \
    1 20; then
    fail "$ID.ahead.later" "later event was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$BAD" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_rev_ahead_live') > 0" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.ahead.once" "qa_rev_ahead_live count is ${QA_STEP_OUT[1]}"
    exit 0
fi
worker_pid "$BAD" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_WORKER_PID != "$ahead_pid" ]]; then
    fail "$ID.ahead.same" "repair required a new worker pid $QA_WORKER_PID (was $ahead_pid)"
    exit 0
fi
qa_admin "$BAD" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_rev_learn'::name AND strpos(sample_query, 'qa_rev_fp_token') > 0" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.ahead.fingerprint" "qa_rev_fp_token hit_count is ${QA_STEP_OUT[1]} after repair"
    exit 0
fi
ok "$ID.ahead" "pid $ahead_pid kept qa_rev_ahead_live unacknowledged while next_position was 10000000000000000000, then persisted it and qa_rev_ahead_later once after repair; qa_rev_fp_token stayed at 1"

exit 0
