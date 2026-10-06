#!/usr/bin/env bash
# Phase 9: the database consumer as a PostgreSQL process (finding 16).
#
# Contract:
#   reload         a configuration reload reaches the running consumer: after
#                  ALTER SYSTEM + pg_reload_conf() it uses the new retention
#                  interval without being restarted
#   error_exit     an ERROR that is not an event's persistence error (here the
#                  startup check failing on a database-level lock_timeout)
#                  ends only that consumer, with exit code 1: the server is not
#                  crash-restarted and other sessions survive; the launcher's
#                  next consumer works once the cause is removed
#   crash_restart  after a backend is killed (SIGKILL) the postmaster
#                  reinitializes shared memory and restarts: the launcher
#                  comes back and the consumer processes events again, with
#                  no "ring is not attached / cannot accept" warnings
#   pm_death       when the postmaster dies, the consumer and launcher exit on
#                  their own, so the data directory can be started again
#
# pm_death kills this run's postmaster and starts the data directory again.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.worker_process
EV=worker_process
DB=qa_wproc

ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }

qa_evidence "$EV" "# $ID" ""
qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "SHOW data_directory" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
DATA=${QA_STEP_OUT[1]}
PG_EXE=$(readlink "/proc/$QA_PM_PID/exe")
PG_CTL=$(dirname "$PG_EXE")/pg_ctl

consumer_pid() { # -> CPID ('' if none)
    qa_admin postgres "SELECT coalesce(string_agg(pid::text, ','), '') FROM pg_catalog.pg_stat_activity WHERE backend_type = 'sql_firewall_worker_' || (SELECT oid FROM pg_catalog.pg_database WHERE datname = '$DB')" ||
        return 1
    CPID=${QA_STEP_OUT[1]}
}

# --- reload ----------------------------------------------------------------
# A consumer's first cleanup comes one interval after it starts (default
# 300 s), so without the reload no run is recorded within this window.
consumer_pid || { infra "$ID.reload" "$QA_INFRA_REASON"; exit 0; }
pid_before=$CPID
qa_admin "$DB" "SELECT runs FROM public.sql_firewall_retention_status" || { infra "$ID.reload" "$QA_INFRA_REASON"; exit 0; }
runs_before=${QA_STEP_OUT[1]:-0}
qa_admin postgres "ALTER SYSTEM SET sql_firewall.activity_log_prune_interval_seconds = 5" "SELECT pg_reload_conf()" ||
    { infra "$ID.reload" "$QA_INFRA_REASON"; exit 0; }
started=$SECONDS
if qa_poll "$DB" "SELECT (runs >= $((runs_before + 2)))::text FROM public.sql_firewall_retention_status" true 30; then
    consumer_pid; pid_after=$CPID
    if [[ $pid_after == "$pid_before" && $pid_before =~ ^[0-9]+$ ]]; then
        ok "$ID.reload" "after pg_reload_conf() the running consumer (pid $pid_before) ran cleanup on the new 5 s interval ($((SECONDS - started)) s for two runs; runs $runs_before -> ${runs_before}+2)"
    else
        fail "$ID.reload" "cleanup ran, but the consumer changed from '$pid_before' to '$pid_after' (a restart, not a reload)"
    fi
else
    qa_admin "$DB" "SELECT runs FROM public.sql_firewall_retention_status"
    fail "$ID.reload" "the consumer kept its old interval: runs ${QA_STEP_OUT[1]:-?} (before $runs_before) 30 s after the reload"
fi
qa_admin postgres "ALTER SYSTEM RESET sql_firewall.activity_log_prune_interval_seconds" "SELECT pg_reload_conf()" >/dev/null ||
    { infra "$ID.reload.restore" "$QA_INFRA_REASON"; exit 0; }

# --- error_exit --------------------------------------------------------------
# The replacement consumer's first query reads pg_extension. A session holds
# that catalog locked, and the database's lock_timeout makes the wait an ERROR.
# The old consumer may itself be waiting for that lock (it reads pg_extension
# to watch the installation) and a SIGTERM does not end a lock wait, so it is
# also cancelled until it has exited.
consumer_pid || { infra "$ID.error_exit" "$QA_INFRA_REASON"; exit 0; }
old_consumer=$CPID
[[ $old_consumer =~ ^[0-9]+$ ]] || { infra "$ID.error_exit" "consumer not uniquely present: '$old_consumer'"; exit 0; }
qa_admin postgres "ALTER DATABASE $DB SET lock_timeout = '200ms'" || { infra "$ID.error_exit" "$QA_INFRA_REASON"; exit 0; }
FIFO=$QA_RUN_DIR/wproc.fifo HOLD_OUT=$QA_RUN_DIR/wproc-holder.out
rm -f "$FIFO"; mkfifo "$FIFO"
"$QA_PSQL" -X -A -t -v ON_ERROR_STOP=0 -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" <"$FIFO" >"$HOLD_OUT" 2>&1 &
holder=$!
exec 7>"$FIFO"
printf '%s\n' "SET lock_timeout = 0;" "BEGIN;" "LOCK TABLE pg_catalog.pg_extension IN ACCESS EXCLUSIVE MODE;" \
    "SELECT 'locked ' || pg_backend_pid();" >&7
deadline=$((SECONDS + 20))
until grep -q '^locked ' "$HOLD_OUT" || ((SECONDS >= deadline)); do sleep 0.2; done
holder_pid=$(sed -n 's/^locked //p' "$HOLD_OUT" | head -1)
if [[ ! $holder_pid =~ ^[0-9]+$ ]]; then
    exec 7>&-; wait "$holder" 2>/dev/null
    qa_admin postgres "ALTER DATABASE $DB RESET lock_timeout" >/dev/null
    infra "$ID.error_exit" "could not hold pg_extension: $(tr '\n' ' ' <"$HOLD_OUT")"
    exit 0
fi
LOG0=$(qa_server_log_offset)
qa_admin postgres "SELECT pg_terminate_backend($old_consumer)" || { infra "$ID.error_exit" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 20))
while kill -0 "$old_consumer" 2>/dev/null && ((SECONDS < deadline)); do
    qa_admin postgres "SELECT pg_cancel_backend($old_consumer)" >/dev/null
    sleep 0.5
done
kill -0 "$old_consumer" 2>/dev/null && { infra "$ID.error_exit" "old consumer $old_consumer did not exit"; exit 0; }
# The launcher notices the exit and registers a replacement within one scan
# (5 s). Wait until a replacement has ended, or the server has restarted.
deadline=$((SECONDS + 30))
while ((SECONDS < deadline)); do
    window=$(tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG")
    grep -qE 'sql_firewall_worker_[0-9]+.*(exited with exit code|terminated by signal)' <<<"$window" && break
    sleep 0.5
done
sleep 1
window=$(tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG")
printf '%s\n' "SELECT 'alive ' || pg_backend_pid();" "COMMIT;" >&7
exec 7>&-
wait "$holder" 2>/dev/null
alive_pid=$(sed -n 's/^alive //p' "$HOLD_OUT" | head -1)
exits=$(grep -oE 'background worker "sql_firewall_worker_[0-9]+" \(PID [0-9]+\) (exited with exit code [0-9]+|was terminated by signal [0-9]+[^"]*)' <<<"$window" | sort -u | head -5)
timeout_error=$(grep -m1 -oE 'ERROR: +canceling statement due to lock timeout' <<<"$window")
crash=$(grep -m3 -E 'terminated by signal|terminating any other active server processes|all server processes terminated; reinitializing|failed to initiate panic' <<<"$window")
qa_evidence "$EV" "- consumer $old_consumer terminated while pid $holder_pid held pg_extension" \
    "- server log after the replacement started:" "$(sed 's/^/    /' <<<"$exits")" \
    "- holder session afterwards: ${alive_pid:-gone} ($(tail -2 "$HOLD_OUT" | tr '\n' ' '))"
qa_admin postgres "ALTER DATABASE $DB RESET lock_timeout" || { infra "$ID.error_exit" "$QA_INFRA_REASON"; exit 0; }
if [[ -z $crash && $exits == *"exited with exit code 1"* && -n $timeout_error && $alive_pid == "$holder_pid" ]]; then
    ok "$ID.error_exit" "the replacement consumer's lock-timeout ERROR ended only that process (exit code 1); no crash restart, and the session holding the lock (pid $holder_pid) survived"
else
    fail "$ID.error_exit" "exits: ${exits:-none}; lock-timeout ERROR logged: ${timeout_error:+yes}; crash lines: ${crash:-none}; holder before/after: $holder_pid/${alive_pid:-gone}"
fi
if qa_wait_worker_live "$DB" 90; then
    ok "$ID.error_exit.recovered" "with the lock released and lock_timeout reset, the launcher's next consumer processed a canary"
else
    fail "$ID.error_exit.recovered" "$QA_INFRA_REASON"
fi

# --- crash_restart -------------------------------------------------------------
LOG0=$(qa_server_log_offset)
SLEEP_OUT=$QA_RUN_DIR/wproc-sleeper.out
"$QA_PSQL" -X -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d postgres -c "SELECT pg_sleep(120) /* qa_wproc_victim */" >"$SLEEP_OUT" 2>&1 &
sleeper=$!
victim=""
deadline=$((SECONDS + 15))
while [[ -z $victim ]] && ((SECONDS < deadline)); do
    qa_admin postgres "SELECT coalesce((SELECT pid::text FROM pg_catalog.pg_stat_activity WHERE query LIKE '%qa_wproc_victim%' AND pid <> pg_backend_pid() LIMIT 1), '')" >/dev/null
    victim=${QA_STEP_OUT[1]:-}
    [[ -n $victim ]] || sleep 0.3
done
if [[ ! $victim =~ ^[0-9]+$ ]]; then
    kill "$sleeper" 2>/dev/null; wait "$sleeper" 2>/dev/null
    infra "$ID.crash_restart" "no victim backend found"
    exit 0
fi
pm_before=$QA_PM_PID
kill -KILL "$victim"
wait "$sleeper" 2>/dev/null
deadline=$((SECONDS + 60))
until tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG" | grep -q 'database system is ready to accept connections' || ((SECONDS >= deadline)); do sleep 0.5; done
window=$(tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG")
if ! grep -q 'all server processes terminated; reinitializing' <<<"$window"; then
    infra "$ID.crash_restart" "the server did not reinitialize after pid $victim was killed: $(grep -m3 -E 'terminated|reinitializing' <<<"$window" | tr '\n' ' ')"
    exit 0
fi
if qa_wait_worker_live "$DB" 90; then
    window=$(tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG")
    ring_warn=$(grep -m2 -E 'ring is not attached|ring cannot accept|activity ring is not attached' <<<"$window")
    qa_admin postgres "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE backend_type = 'sql_firewall_launcher'" ||
        { infra "$ID.crash_restart" "$QA_INFRA_REASON"; exit 0; }
    launchers=${QA_STEP_OUT[1]}
    if [[ -z $ring_warn && $launchers == 1 && $QA_PM_PID == "$pm_before" ]] && kill -0 "$pm_before" 2>/dev/null; then
        ok "$ID.crash_restart" "after backend $victim was killed and the server reinitialized, the launcher returned and the consumer processed a canary; no ring warnings"
    else
        fail "$ID.crash_restart" "canary processed, but ring warnings: '${ring_warn:-none}', launchers: $launchers"
    fi
else
    window=$(tail -c +"$((LOG0 + 1))" "$QA_SERVER_LOG")
    fail "$ID.crash_restart" "no consumer processed a canary within 90 s of the reinitialization ($QA_INFRA_REASON); log: $(grep -m3 -E 'ring|launcher' <<<"$window" | tr '\n' ' ' | cut -c1-400)"
fi

# --- pm_death ----------------------------------------------------------------
own_pg_processes() { # -> pid:title lines of this server's processes
    local p
    for p in /proc/[0-9]*; do
        [[ $(readlink "$p/exe" 2>/dev/null) == "$PG_EXE" ]] || continue
        printf '%s:%s\n' "${p#/proc/}" "$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)"
    done
}
consumer_pid || { infra "$ID.pm_death" "$QA_INFRA_REASON"; exit 0; }
before=$(own_pg_processes | grep -E 'sql_firewall' | tr '\n' ';')
[[ $before == *sql_firewall_worker_* && $before == *launcher* ]] ||
    { infra "$ID.pm_death" "firewall processes not found before the kill: $before"; exit 0; }
kill -KILL "$QA_PM_PID"
deadline=$((SECONDS + 20))
while ((SECONDS < deadline)); do
    left=$(own_pg_processes | grep -E 'sql_firewall' | tr '\n' ';')
    [[ -z $left ]] && break
    sleep 0.5
done
qa_evidence "$EV" "- firewall processes before the postmaster was killed: $before" "- left after up to 20 s: ${left:-none}"
if [[ -z $left ]]; then
    ok "$ID.pm_death" "after the postmaster was killed, the launcher and every consumer exited within $((20 - deadline + SECONDS)) s"
else
    fail "$ID.pm_death" "processes still running 20 s after the postmaster died: $left"
    for p in $(own_pg_processes | grep -E 'sql_firewall' | cut -d: -f1); do kill -KILL "$p" 2>/dev/null; done
fi
# Every other process of the old server exits on its own; then start again.
deadline=$((SECONDS + 30))
while [[ -n $(own_pg_processes) ]] && ((SECONDS < deadline)); do sleep 0.5; done
[[ -z $(own_pg_processes) ]] || { infra "$ID.pm_death.restart" "old server processes remain: $(own_pg_processes | tr '\n' ';')"; exit 0; }
"$PG_CTL" -D "$DATA" -l "$QA_SERVER_LOG" -w -t 60 start >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 ||
    { infra "$ID.pm_death.restart" "pg_ctl start failed: $(tail -5 "$QA_RUN_DIR/logs/pg_ctl.log" | tr '\n' ' ')"; exit 0; }
QA_PM_PID=$(head -1 "$DATA/postmaster.pid")
if qa_wait_worker_live "$DB" 90; then
    ok "$ID.pm_death.restart" "the data directory started again and its consumer processed a canary"
else
    fail "$ID.pm_death.restart" "$QA_INFRA_REASON"
fi
exit 0
