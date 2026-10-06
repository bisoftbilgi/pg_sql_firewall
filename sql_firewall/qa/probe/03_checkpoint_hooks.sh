#!/usr/bin/env bash
# Probe-only checkpoint boundaries. Not the release library.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.checkpoint_probe
EV=checkpoint_probe
DB=qa_c2_probe

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "queue_probe build. Exit-after-commit, a fault before the checkpoint update, and two racing appliers use the production checkpoint transaction." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
# Probe events name these roles. The worker discards a learn event whose role
# name does not belong to the observed role OID (Phase 5 role lifecycle).
qa_admin postgres "CREATE ROLE qa_c2_appr NOLOGIN" "CREATE ROLE qa_c2_fp NOLOGIN" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.ready" "$QA_INFRA_REASON"
    exit 0
fi

# Commit effects and checkpoint, then exit before the local cursor moves.
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_exit_after_commit(true)" ||
    { infra "$ID.exit" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.exit" "$QA_INFRA_REASON"; exit 0; }
old_pid=${QA_STEP_OUT[1]}
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(1, 'qa_c2_exit_commit')" ||
    { infra "$ID.exit" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_exit_commit-0') > 0" \
    1 20; then
    fail "$ID.exit.row" "committed event was not visible (${QA_INFRA_REASON:-})"
    exit 0
fi
deadline=$((SECONDS + 20))
new_pid=
while ((SECONDS < deadline)); do
    qa_admin "$DB" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        { infra "$ID.exit" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n ${QA_STEP_OUT[1]} && ${QA_STEP_OUT[1]} != "$old_pid" ]]; then
        new_pid=${QA_STEP_OUT[1]}
        break
    fi
    sleep 0.2
done
[[ -n $new_pid ]] || { fail "$ID.exit.replace" "worker $old_pid was not replaced"; exit 0; }
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_exit_commit-0') > 0" ||
    { infra "$ID.exit" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.exit.dup" "qa_c2_exit_commit-0 count is ${QA_STEP_OUT[1]} after replacement pid $new_pid"
    exit 0
fi
ok "$ID.exit" "pid $old_pid committed qa_c2_exit_commit-0 and exited; replacement $new_pid left the count at 1"

# Approval committed, then the worker exits before its local cursor moves.
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.approval.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_exit_after_commit(true)" ||
    { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
old_pid=${QA_STEP_OUT[1]}
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_one_approval('qa_c2_appr')" ||
    { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) 'qa_c2_appr'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text AND is_approved" \
    1 20; then
    fail "$ID.approval.row" "approval was not committed before the worker exited (${QA_INFRA_REASON:-})"
    exit 0
fi
deadline=$((SECONDS + 20))
new_pid=
while ((SECONDS < deadline)); do
    qa_admin "$DB" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n ${QA_STEP_OUT[1]} && ${QA_STEP_OUT[1]} != "$old_pid" ]]; then
        new_pid=${QA_STEP_OUT[1]}
        break
    fi
    sleep 0.2
done
[[ -n $new_pid ]] || { fail "$ID.approval.replace" "worker $old_pid was not replaced"; exit 0; }
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_command_approvals WHERE role_name OPERATOR(pg_catalog.=) 'qa_c2_appr'::name AND command_type OPERATOR(pg_catalog.=) 'SELECT'::text AND is_approved" ||
    { infra "$ID.approval" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.approval.dup" "qa_c2_appr approval count is ${QA_STEP_OUT[1]} after replacement pid $new_pid"
    exit 0
fi
ok "$ID.approval" "pid $old_pid committed one qa_c2_appr approval and exited; replacement $new_pid left that approval at 1"

# Fingerprint hit_count increments once across the commit-to-local-cursor gap.
qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, first_seen_at, last_seen_at, hit_count, is_approved) VALUES ('c2c2c2c2c2c2c2c2', 'select \$1', 'qa_c2_fp', 'SELECT', 'qa_c2_fp_seed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 5, false)" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if ! qa_wait_worker_live "$DB" 40; then
    fail "$ID.fingerprint.ready" "$QA_INFRA_REASON"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_exit_after_commit(true)" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" \
    "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
old_pid=${QA_STEP_OUT[1]}
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_one_fingerprint('qa_c2_fp', 'c2c2c2c2c2c2c2c2', 'qa_c2_fp_hit')" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_c2_fp'::name AND fingerprint OPERATOR(pg_catalog.=) 'c2c2c2c2c2c2c2c2'" \
    6 20; then
    fail "$ID.fingerprint.row" "hit_count did not become 6 before the worker exited (${QA_INFRA_REASON:-})"
    exit 0
fi
deadline=$((SECONDS + 20))
new_pid=
while ((SECONDS < deadline)); do
    qa_admin "$DB" \
        "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
        { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
    if [[ -n ${QA_STEP_OUT[1]} && ${QA_STEP_OUT[1]} != "$old_pid" ]]; then
        new_pid=${QA_STEP_OUT[1]}
        break
    fi
    sleep 0.2
done
[[ -n $new_pid ]] || { fail "$ID.fingerprint.replace" "worker $old_pid was not replaced"; exit 0; }
qa_admin "$DB" "SELECT hit_count::text FROM public.sql_firewall_query_fingerprints WHERE role_name OPERATOR(pg_catalog.=) 'qa_c2_fp'::name AND fingerprint OPERATOR(pg_catalog.=) 'c2c2c2c2c2c2c2c2'" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 6 ]]; then
    fail "$ID.fingerprint.dup" "hit_count is ${QA_STEP_OUT[1]} after replacement pid $new_pid"
    exit 0
fi
ok "$ID.fingerprint" "pid $old_pid incremented qa_c2_fp from 5 to 6 and exited; replacement $new_pid left hit_count at 6"

# Fault after the insert statement and before the checkpoint update.
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fail_before_checkpoint(true)" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT coalesce(next_position::text, 'null') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
next_before=${QA_STEP_OUT[1]}
qa_admin "$DB" "SELECT oid::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) current_database()" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
mid_oid=${QA_STEP_OUT[1]}
mark=$(qa_server_log_offset)
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(1, 'qa_c2_mid')" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
deadline=$((SECONDS + 15))
saw=0
while ((SECONDS < deadline)); do
    if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "retry database oid ${mid_oid} " | grep -F "type blocked_query " >/dev/null; then
        saw=1
        break
    fi
    sleep 0.2
done
[[ $saw -eq 1 ]] || { fail "$ID.mid.retry" "pre-checkpoint fault did not produce a blocked_query retry"; exit 0; }
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_mid-0') > 0" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == 0 ]] || { fail "$ID.mid.row" "row visible while the pre-checkpoint fault was armed"; exit 0; }
qa_admin "$DB" "SELECT coalesce(next_position::text, 'null') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == "$next_before" ]] || { fail "$ID.mid.checkpoint" "checkpoint moved to ${QA_STEP_OUT[1]}"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fail_before_checkpoint(false)" ||
    { infra "$ID.mid" "$QA_INFRA_REASON"; exit 0; }
if ! qa_poll "$DB" \
    "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, 'qa_c2_mid-0') > 0" \
    1 20; then
    fail "$ID.mid.persist" "event was not persisted after the fault was cleared (${QA_INFRA_REASON:-})"
    exit 0
fi
ok "$ID.mid" "pre-checkpoint fault kept the row absent and next_position at $next_before; the retry then committed"

# Two backends race the production checkpoint transaction while the consumer is held.
qa_admin "$DB" \
    "SELECT coalesce(string_agg(a.pid::text, ','), '') FROM pg_catalog.pg_stat_activity a WHERE a.datid OPERATOR(pg_catalog.=) (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) AND a.backend_type LIKE 'sql_firewall_worker_%'" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
target_pid=${QA_STEP_OUT[1]}
[[ $target_pid =~ ^[0-9]+$ ]] || { infra "$ID.race" "expected one consumer pid, saw '${target_pid}'"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_arm(${target_pid})" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
hold_deadline=$((SECONDS + 10))
quiescent=
while ((SECONDS < hold_deadline)); do
    qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_status()" ||
        { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
    case ${QA_STEP_OUT[1]} in
        quiescent\ pid=${target_pid}\ db=*\ epoch=*)
            quiescent=${QA_STEP_OUT[1]}
            break
            ;;
        waiting\ pid=${target_pid}\ *)
            ;;
        *)
            infra "$ID.race" "unexpected hold status '${QA_STEP_OUT[1]}'"
            exit 0
            ;;
    esac
    sleep 0.2
done
[[ -n $quiescent ]] || { infra "$ID.race" "consumer pid ${target_pid} did not acknowledge hold"; exit 0; }
qa_admin "$DB" "SELECT coalesce(next_position::text, '') FROM public.sql_firewall_consumer_checkpoint WHERE singleton OPERATOR(pg_catalog.=) 1" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
race_pos=${QA_STEP_OUT[1]}
[[ $race_pos =~ ^[0-9]+$ ]] || { infra "$ID.race" "checkpoint next_position '$race_pos'"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_fill(1, 'qa_c2_race_gap')" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.race" "could not publish the event both consumers claim"
    exit 0
fi
env PGAPPNAME=qa_race "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "SELECT public.sql_firewall_queue_probe_apply_blocked('qa_c2_race_a', ${race_pos})" \
    >"$QA_RUN_DIR/race_a.out" 2>"$QA_RUN_DIR/race_a.err" &
pid_a=$!
env PGAPPNAME=qa_race "$QA_PSQL" -X -q -A -t -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -d "$DB" \
    -c "SELECT public.sql_firewall_queue_probe_apply_blocked('qa_c2_race_b', ${race_pos})" \
    >"$QA_RUN_DIR/race_b.out" 2>"$QA_RUN_DIR/race_b.err" &
pid_b=$!
wait "$pid_a" || { qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_hold(false)" || true; infra "$ID.race" "first racer failed"; exit 0; }
wait "$pid_b" || { qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_hold(false)" || true; infra "$ID.race" "second racer failed"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_hold(false)" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
race_out=$(cat "$QA_RUN_DIR/race_a.out" "$QA_RUN_DIR/race_b.out")
if [[ $race_out != *applied\ * || $race_out != *already\ * ]]; then
    fail "$ID.race" "expected one applied and one already result, saw $(tr '\n' ' ' <<<"$race_out")"
    exit 0
fi
qa_admin "$DB" "SELECT count(*)::text FROM public.sql_firewall_blocked_queries WHERE query_text OPERATOR(pg_catalog.=) 'qa_c2_race_a' OR query_text OPERATOR(pg_catalog.=) 'qa_c2_race_b'" ||
    { infra "$ID.race" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_OUT[1]} != 1 ]]; then
    fail "$ID.race" "racing appliers persisted ${QA_STEP_OUT[1]} rows"
    exit 0
fi
ok "$ID.race" "while ${quiescent}, two checkpoint transactions returned one applied and one already result and persisted one blocked row"

exit 0
