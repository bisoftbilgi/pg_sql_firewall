#!/usr/bin/env bash
# Phase 3C2: restart recovery from the transactional checkpoint.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.restart_recovery
EV=restart_recovery
DB=qa_c2
OTHER=qa_c2_other
META=qa_c2_meta
CAP=1024

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "Checkpoint and event effects commit together. A replacement consumer resumes from that position. A new ring generation does not reuse the old cursor." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$OTHER" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$META" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres \
    "CREATE ROLE qa_c2_app LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c2_other LOGIN NOSUPERUSER" \
    "CREATE ROLE qa_c2_meta LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO qa_c2_app" \
    "GRANT CONNECT ON DATABASE $OTHER TO qa_c2_other" \
    "GRANT CONNECT ON DATABASE $META TO qa_c2_meta" \
    "ALTER ROLE qa_c2_app IN DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_c2_other IN DATABASE $OTHER SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE qa_c2_meta IN DATABASE $META SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

worker_pid() {
    qa_admin "$1" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        return $?
    QA_WORKER_PID=${QA_STEP_OUT[1]}
}

stop_worker() {
    worker_pid "$1" || return $?
    [[ -z $QA_WORKER_PID ]] && return 0
    [[ $QA_WORKER_PID =~ ^[0-9]+$ ]] || return 1
    qa_admin postgres "SELECT pg_catalog.pg_terminate_backend(${QA_WORKER_PID})" || return $?
    local deadline=$((SECONDS + 10))
    while ((SECONDS < deadline)); do
        worker_pid "$1" || return $?
        [[ -z $QA_WORKER_PID || $QA_WORKER_PID != "$2" ]] && return 0
        sleep 0.2
    done
    return 1
}

checkpoint_next() {
    qa_admin "$1" "SELECT coalesce(next_position::text, 'null') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" || return $?
    QA_NEXT=${QA_STEP_OUT[1]}
}

launcher_pid() {
    qa_admin postgres \
        "SELECT coalesce(pid::text, '') FROM pg_catalog.pg_stat_activity WHERE backend_type OPERATOR(pg_catalog.=) 'sql_firewall_launcher'" ||
        return $?
    QA_LAUNCHER_PID=${QA_STEP_OUT[1]}
}

# The launcher does not hold the ring spinlock while it waits between scans.
# Stopping it keeps a terminated consumer from being replaced mid-measurement.
freeze_launcher() {
    launcher_pid || return $?
    [[ $QA_LAUNCHER_PID =~ ^[0-9]+$ ]] || return 1
    kill -STOP "$QA_LAUNCHER_PID"
}

thaw_launcher() {
    [[ ${QA_LAUNCHER_PID:-} =~ ^[0-9]+$ ]] || return 0
    kill -CONT "$QA_LAUNCHER_PID" 2>/dev/null || true
}

# 1. Events published before the consumer initializes are still recovered.
freeze_launcher || { infra "$ID.first" "could not stop the launcher"; exit 0; }
worker_pid "$DB" || { thaw_launcher; infra "$ID.first" "$QA_INFRA_REASON"; exit 0; }
if [[ -n $QA_WORKER_PID ]]; then
    stop_worker "$DB" "$QA_WORKER_PID" || { thaw_launcher; infra "$ID.first" "could not stop the first consumer"; exit 0; }
fi
worker_pid "$DB" || { thaw_launcher; infra "$ID.first" "$QA_INFRA_REASON"; exit 0; }
if [[ -n $QA_WORKER_PID ]]; then
    thaw_launcher
    fail "$ID.first" "consumer pid $QA_WORKER_PID was still attached when the early events were published"
    exit 0
fi
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_early_a'" "SELECT 'qa_c2_early_b'" || true
worker_pid "$DB" || { thaw_launcher; infra "$ID.first" "$QA_INFRA_REASON"; exit 0; }
if [[ -n $QA_WORKER_PID ]]; then
    thaw_launcher
    fail "$ID.first" "consumer pid $QA_WORKER_PID attached before publication finished"
    exit 0
fi
thaw_launcher
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.first" "$QA_INFRA_REASON"
    exit 0
fi
for marker in qa_c2_early_a qa_c2_early_b; do
    if ! qa_poll "$DB" \
        "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '${marker}') > 0" \
        1 20; then
        fail "$ID.first" "$marker was not recovered (${QA_INFRA_REASON:-})"
        exit 0
    fi
done
ok "$ID.first" "events published before the consumer initialized were persisted"

# 2. Replacement after downtime recovers retained events and does not duplicate.
worker_pid "$DB" || { infra "$ID.down" "$QA_INFRA_REASON"; exit 0; }
old_pid=$QA_WORKER_PID
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_before_down'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_before_down') > 0" \
    1 20; then
    fail "$ID.down.progress" "could not establish committed progress (${QA_INFRA_REASON:-})"
    exit 0
fi
stop_worker "$DB" "$old_pid" || { infra "$ID.down" "could not stop pid $old_pid"; exit 0; }
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_while_down'" || true
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.down.replace" "$QA_INFRA_REASON"
    exit 0
fi
worker_pid "$DB" || { infra "$ID.down" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_WORKER_PID == "$old_pid" ]]; then
    fail "$ID.down.replace" "consumer pid did not change from $old_pid"
    exit 0
fi
new_pid=$QA_WORKER_PID
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_while_down') > 0" \
    1 20; then
    fail "$ID.down.recover" "qa_c2_while_down was not recovered by pid $new_pid (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_before_down') > 0" ||
    { infra "$ID.down" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.down.dup" "qa_c2_before_down count is ${QA_STEP_OUT[1]}"
    exit 0
fi
ok "$ID.down" "pid $old_pid was replaced by $new_pid; qa_c2_while_down was recovered and qa_c2_before_down stayed at 1"

# 3 and 5. SQL error and deferred commit failure leave the checkpoint unchanged.
qa_admin "$DB" \
    "CREATE TABLE public.qa_c2_fail (id integer PRIMARY KEY, blocked boolean NOT NULL, deferred boolean NOT NULL)" \
    "INSERT INTO public.qa_c2_fail VALUES (1, false, false)" \
    "CREATE FUNCTION public.qa_c2_block() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c2_fail WHERE id = 1 AND blocked) THEN RAISE EXCEPTION 'qa_c2 blocked' USING ERRCODE = 'P0001'; END IF; RETURN NEW; END \$\$" \
    "CREATE FUNCTION public.qa_c2_defer() RETURNS trigger LANGUAGE plpgsql AS \$\$ BEGIN IF EXISTS (SELECT 1 FROM public.qa_c2_fail WHERE id = 1 AND deferred) THEN RAISE EXCEPTION 'qa_c2 commit' USING ERRCODE = '23514'; END IF; RETURN NULL; END \$\$" \
    "CREATE TRIGGER qa_c2_block BEFORE INSERT ON public.sql_firewall_blocked_queries FOR EACH ROW EXECUTE FUNCTION public.qa_c2_block()" \
    "CREATE CONSTRAINT TRIGGER qa_c2_deferred AFTER INSERT ON public.sql_firewall_blocked_queries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.qa_c2_defer()" ||
    { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
next_before=$QA_NEXT
qa_admin "$DB" "UPDATE public.qa_c2_fail SET blocked = true WHERE id = 1" || { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
worker_pid "$DB" || { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
pid_retry=$QA_WORKER_PID
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_retry_me'" || true
mark=$(qa_server_log_offset)
deadline=$((SECONDS + 15))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "SQLSTATE P0001" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.fail.attempt" "no P0001 retry"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_NEXT != "$next_before" ]]; then
    fail "$ID.fail.checkpoint" "checkpoint moved from $next_before to $QA_NEXT during the SQL error"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_retry_me') > 0" ||
    { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == 0 ]] || { fail "$ID.fail.row" "row visible during P0001"; exit 0; }
stop_worker "$DB" "$pid_retry" || { infra "$ID.fail" "could not stop retrying pid $pid_retry"; exit 0; }
qa_admin "$DB" "UPDATE public.qa_c2_fail SET blocked = false WHERE id = 1" || { infra "$ID.fail" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.fail.replace" "$QA_INFRA_REASON"
    exit 0
fi
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_retry_me') > 0" \
    1 20; then
    fail "$ID.fail.recover" "replacement did not persist qa_c2_retry_me (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.fail" "P0001 left checkpoint at $next_before and no row; replacement persisted qa_c2_retry_me once"

checkpoint_next "$DB" || { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
next_before=$QA_NEXT
qa_admin "$DB" "UPDATE public.qa_c2_fail SET deferred = true WHERE id = 1" || { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_defer_me'" || true
deadline=$((SECONDS + 15))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "SQLSTATE 23514" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.deferred.attempt" "no 23514 retry"; exit 0; }
checkpoint_next "$DB" || { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_NEXT != "$next_before" ]]; then
    fail "$ID.deferred.checkpoint" "checkpoint moved from $next_before to $QA_NEXT before commit"
    exit 0
fi
qa_admin "$DB" "UPDATE public.qa_c2_fail SET deferred = false WHERE id = 1" || { infra "$ID.deferred" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_defer_me') > 0" \
    1 20; then
    fail "$ID.deferred.persist" "deferred event was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.deferred" "SQLSTATE 23514 rolled back effects and checkpoint at $next_before, then the retry committed"

# 7. Rolled-back DROP keeps the checkpoint. A committed DROP/CREATE rejects old events.
qa_admin "$DB" "BEGIN; DROP EXTENSION sql_firewall; ROLLBACK" || { infra "$ID.drop" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT initialized::text FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.drop" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == true ]] || { fail "$ID.drop.rollback" "checkpoint initialized=${QA_STEP_OUT[1]} after rolled-back DROP"; exit 0; }
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_after_rollback'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_after_rollback') > 0" \
    1 20; then
    fail "$ID.drop.rollback" "event after rolled-back DROP was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$DB" "UPDATE public.qa_c2_fail SET blocked = true WHERE id = 1" || { infra "$ID.recreate" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_old_install'" || true
mark=$(qa_server_log_offset)
deadline=$((SECONDS + 15))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "SQLSTATE P0001" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.recreate.hold" "old installation event was not awaiting retry"; exit 0; }
qa_admin "$DB" "DROP EXTENSION sql_firewall" "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.recreate" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "ALTER ROLE qa_c2_app IN DATABASE $DB SET sql_firewall.mode = 'enforce'" ||
    { infra "$ID.recreate" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.recreate.worker" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_old_install') > 0" ||
    { infra "$ID.recreate" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.recreate.old" "old installation event was applied to the new extension"
    exit 0
fi
qa_sql_steps qa_c2_app "$DB" qa_c2 "SELECT 'qa_c2_new_install'" || true
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_new_install') > 0" \
    1 20; then
    fail "$ID.recreate.new" "new installation did not persist its own event (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.lifecycle" "rolled-back DROP kept recovery; recreated extension ignored qa_c2_old_install and persisted qa_c2_new_install"

# 9. Ordinary role cannot change the checkpoint. A missing row does not reset progress.
qa_sql_steps qa_c2_meta "$META" qa_c2 "SELECT 'qa_c2_meta_seed'" || true
if ! qa_poll "$META" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_meta_seed') > 0" \
    1 20; then
    fail "$ID.priv.seed" "seed event was not persisted (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_sql_steps qa_c2_meta "$META" qa_c2 \
    "SELECT count(*) FROM public.sql_firewall_consumer_checkpoint" \
    "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = 0" \
    "DELETE FROM public.sql_firewall_consumer_checkpoint" ||
    { infra "$ID.priv" "$QA_INFRA_REASON"; exit 0; }
for step in 1 2 3; do
    if [[ ${QA_STEP_ERR[$step]} != true || ${QA_STEP_STATE[$step]} != 42501 ]]; then
        fail "$ID.priv" "step $step state ${QA_STEP_STATE[$step]:-} ${QA_STEP_MSG[$step]:-}"
        exit 0
    fi
done
ok "$ID.priv" "qa_c2_meta cannot read or modify the checkpoint (SQLSTATE 42501)"
checkpoint_next "$META" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
saved_next=$QA_NEXT
qa_admin "$META" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = 10000000000000000000 WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
worker_pid "$META" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
stop_worker "$META" "$QA_WORKER_PID" || { infra "$ID.ahead" "could not stop the consumer"; exit 0; }
mark=$(qa_server_log_offset)
deadline=$((SECONDS + 20))
saw=0
while ((SECONDS < deadline)); do
    worker_pid "$META" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $QA_WORKER_PID ]] && tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "is ahead of ring head" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.ahead" "replacement did not diagnose a checkpoint ahead of the ring head"; exit 0; }
qa_sql_steps qa_c2_meta "$META" qa_c2 "SELECT 'qa_c2_meta_ahead'" || true
qa_admin "$META" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_meta_ahead') > 0" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.ahead.apply" "event was applied while the checkpoint was ahead of the ring head"
    exit 0
fi
checkpoint_next "$META" || { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
if [[ $QA_NEXT != 10000000000000000000 ]]; then
    fail "$ID.ahead.reset" "checkpoint next_position became $QA_NEXT"
    exit 0
fi
qa_admin "$META" "UPDATE public.sql_firewall_consumer_checkpoint SET next_position = ${saved_next} WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.ahead" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.ahead" "checkpoint next_position 10000000000000000000 was left unchanged and qa_c2_meta_ahead was not applied"
qa_admin "$META" \
    "ALTER EXTENSION sql_firewall DROP TABLE public.sql_firewall_consumer_checkpoint" \
    "ALTER TABLE public.sql_firewall_consumer_checkpoint RENAME TO sql_firewall_consumer_checkpoint_member" \
    "CREATE TABLE public.sql_firewall_consumer_checkpoint (singleton integer PRIMARY KEY, initialized boolean NOT NULL, ring_generation numeric(20,0), extension_oid oid, next_position numeric(20,0))" \
    "INSERT INTO public.sql_firewall_consumer_checkpoint VALUES (1, true, 1, 1, 0)" ||
    { infra "$ID.substitute" "$QA_INFRA_REASON"; exit 0; }
worker_pid "$META" || { infra "$ID.substitute" "$QA_INFRA_REASON"; exit 0; }
stop_worker "$META" "$QA_WORKER_PID" || { infra "$ID.substitute" "could not stop the consumer"; exit 0; }
mark=$(qa_server_log_offset)
deadline=$((SECONDS + 20))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "consumer checkpoint is missing or is not a member" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.substitute" "worker did not refuse the substituted non-member table"; exit 0; }
qa_sql_steps qa_c2_meta "$META" qa_c2 "SELECT 'qa_c2_meta_substituted'" || true
qa_admin "$META" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_meta_substituted') > 0" ||
    { infra "$ID.substitute" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.substitute.apply" "event was applied through the substituted checkpoint table"
    exit 0
fi
ok "$ID.substitute" "a same-named non-member table was not used as recovery state"
qa_admin "$META" \
    "DROP TABLE public.sql_firewall_consumer_checkpoint" \
    "DROP TABLE public.sql_firewall_consumer_checkpoint_member" ||
    { infra "$ID.corrupt" "$QA_INFRA_REASON"; exit 0; }
mark=$(qa_server_log_offset)
qa_sql_steps qa_c2_meta "$META" qa_c2 "SELECT 'qa_c2_meta_after_corrupt'" || true
deadline=$((SECONDS + 15))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "consumer checkpoint is missing or is not a member" >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.corrupt" "worker did not refuse the missing checkpoint"; exit 0; }
qa_admin "$META" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_meta_seed') > 0" ||
    { infra "$ID.corrupt" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.corrupt.replay" "seed count is ${QA_STEP_OUT[1]} after the checkpoint row was removed"
    exit 0
fi
qa_admin "$META" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_meta_after_corrupt') > 0" ||
    { infra "$ID.corrupt" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.corrupt.progress" "event was persisted after the checkpoint row was removed"
    exit 0
fi
ok "$ID.corrupt" "missing checkpoint was not recreated; qa_c2_meta_seed stayed at 1 and the later event was not applied"

# 6. Consumer left behind the retained window. Replacement reports the gap.
if ! qa_wait_worker_live "$OTHER" 40; then
    fail "$ID.gap.ready" "$QA_INFRA_REASON"
    exit 0
fi
freeze_launcher || { infra "$ID.gap" "could not stop the launcher"; exit 0; }
worker_pid "$OTHER" || { thaw_launcher; infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
stop_worker "$OTHER" "$QA_WORKER_PID" || { thaw_launcher; infra "$ID.gap" "could not stop $OTHER"; exit 0; }
worker_pid "$OTHER" || { thaw_launcher; infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
if [[ -n $QA_WORKER_PID ]]; then
    thaw_launcher
    fail "$ID.gap" "consumer pid $QA_WORKER_PID was still attached during the overwrite"
    exit 0
fi
checkpoint_next "$OTHER" || { thaw_launcher; infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
gap_from=$QA_NEXT
{
    for i in $(seq 0 $((CAP + 4))); do
        printf "SELECT 'qa_c2_gap_%04d';\n" "$i"
    done
} >"$QA_RUN_DIR/gap.sql"
env PGAPPNAME=qa_c2 "$QA_PSQL" -X -q -v ON_ERROR_STOP=0 -h "$QA_SOCK" -p "$QA_PORT" -U qa_c2_other -d "$OTHER" -f "$QA_RUN_DIR/gap.sql" >/dev/null 2>&1 || true
worker_pid "$OTHER" || { thaw_launcher; infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
if [[ -n $QA_WORKER_PID ]]; then
    thaw_launcher
    fail "$ID.gap" "consumer attached while the retained window was being overwritten"
    exit 0
fi
thaw_launcher
deadline=$((SECONDS + 20))
replacement=
while ((SECONDS < deadline)); do
    worker_pid "$OTHER" || { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $QA_WORKER_PID ]]; then
        replacement=$QA_WORKER_PID
        break
    fi
    sleep 0.2
done
[[ -n $replacement ]] || { fail "$ID.gap.worker" "launcher did not replace the stopped consumer"; exit 0; }
gap_to=$((gap_from + 5))
if ! grep -F "skipped shared-stream positions [${gap_from}, ${gap_to})" "$QA_SERVER_LOG" >/dev/null; then
    actual=$(grep -F "skipped shared-stream positions" "$QA_SERVER_LOG" | tail -1 || true)
    fail "$ID.gap.range" "log did not report skipped positions [${gap_from}, ${gap_to}); last='${actual}'"
    exit 0
fi
if ! qa_poll "$OTHER" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_gap_0005') > 0" \
    1 30; then
    fail "$ID.gap.retained" "retained event qa_c2_gap_0005 was not delivered (${QA_INFRA_REASON:-})"
    exit 0
fi
qa_admin "$OTHER" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_gap_0000') > 0" ||
    { infra "$ID.gap" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 0 ]]; then
    fail "$ID.gap.lost" "overwritten event qa_c2_gap_0000 was delivered"
    exit 0
fi
ok "$ID.gap" "replacement pid $replacement skipped [${gap_from}, ${gap_to}) and delivered retained qa_c2_gap_0005"

# 8. Postmaster restart creates a new ring generation. The old cursor must not skip new events.
checkpoint_next "$OTHER" || true
exe=$(readlink "/proc/$QA_PM_PID/exe")
pg_ctl=$(dirname "$exe")/pg_ctl
data=$(tr '\0' '\n' <"/proc/$QA_PM_PID/cmdline" | awk 'f { print; exit } /\-D/ { f=1 }')
[[ -n $data && -x $pg_ctl ]] || { infra "$ID.generation" "could not find postmaster data dir"; exit 0; }
"$pg_ctl" -D "$data" -l "$QA_SERVER_LOG" -w -t 60 restart >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 ||
    { infra "$ID.generation" "pg_ctl restart failed"; exit 0; }
new_pm=$(head -1 "$data/postmaster.pid" 2>/dev/null || true)
[[ $new_pm =~ ^[0-9]+$ && $new_pm != "$QA_PM_PID" ]] ||
    { infra "$ID.generation" "replacement postmaster pid '$new_pm'"; exit 0; }
# The launcher registers at most four consumers per five-second scan, so a
# late database in a large cluster is not attached on the first scan.
deadline=$((SECONDS + 120))
replacement=
while ((SECONDS < deadline)); do
    worker_pid "$OTHER" || { infra "$ID.generation" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n $QA_WORKER_PID ]]; then
        replacement=$QA_WORKER_PID
        break
    fi
    sleep 0.2
done
[[ -n $replacement ]] || { fail "$ID.generation.worker" "no consumer attached after postmaster $new_pm started"; exit 0; }
qa_sql_steps qa_c2_other "$OTHER" qa_c2 "SELECT 'qa_c2_after_restart'" || true
if ! qa_poll "$OTHER" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_after_restart') > 0" \
    1 20; then
    fail "$ID.generation" "event after postmaster restart was not processed (${QA_INFRA_REASON:-})"
    exit 0
fi
if ! grep -F "replaced by generation" "$QA_SERVER_LOG" | grep -F "resume at 0" >/dev/null; then
    fail "$ID.generation.log" "log did not reinitialize the checkpoint at position 0 for the new ring"
    exit 0
fi
ok "$ID.generation" "postmaster $new_pm created a new ring; consumer $replacement resumed at 0 and processed qa_c2_after_restart"

exit 0
