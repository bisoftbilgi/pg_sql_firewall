#!/usr/bin/env bash
# Phase 9 (P9-03): hot standby and promotion (README 6.10).
#
# A physical standby of the run's server is made with pg_basebackup -R and
# started from the same staged installation on its own port, in the run's
# private socket directory. The test stops it on every exit path.
#
# Contract on the standby (in recovery):
#   recovery          the standby is in recovery and runs no firewall launcher
#                     or consumer (they start at RecoveryFinished)
#   status            sql_firewall_status() names the hot standby
#   enforce           replicated command approvals decide: an approved SELECT
#                     runs, a role without one is refused
#   fingerprint       a fingerprint approved on the primary authorizes the
#                     same shape on the standby (one installation identity);
#                     another shape is refused
#   policy_replay     a revoke and a re-approval committed on the primary
#                     apply on the standby once replayed, also after the
#                     standby had allowed the statement (no stale cache)
#   learn/permissive  learn- and permissive-mode statements run and return
#                     their rows; nothing is written on the standby
#   regex             regex rules are evaluated (internal subtransaction)
#   read_only         an approved INSERT gets PostgreSQL's own 25006
#   events_held       refusals and activity are published to the standby's
#                     shared queues (statistics), not written
#   log               the standby's log has no firewall worker or audit write
#                     failure and no crash
# After promotion (pg_ctl promote):
#   workers           the launcher and the database's consumer start; a
#                     canary is persisted on the promoted server
#   held_events       a refusal and an activity record made on the standby
#                     and still in its queues are written by the new consumer
#   learn             a learn-mode observation made on the standby is applied
#   cache             a revoke on the promoted server applies at once
#   primary           the original server's consumer is still live
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.standby
EV=standby
DB=qa_sb
ENF=qa_sb_enf
NOP=qa_sb_none
FPR=qa_sb_fp
LRN=qa_sb_learn
PRM=qa_sb_perm
WRT=qa_sb_write
TAG=qa_sb_$RANDOM$RANDOM

ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }

qa_evidence "$EV" "# $ID" ""

# --- primary setup ------------------------------------------------------------
qa_create_db "$DB" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
setup=()
for r in "$ENF" "$NOP" "$FPR" "$LRN" "$PRM" "$WRT"; do
    setup+=("CREATE ROLE $r LOGIN NOSUPERUSER" "GRANT CONNECT ON DATABASE $DB TO $r")
done
for r in "$ENF" "$NOP" "$FPR" "$WRT"; do setup+=("ALTER ROLE $r IN DATABASE $DB SET sql_firewall.mode = 'enforce'"); done
setup+=("ALTER ROLE $LRN IN DATABASE $DB SET sql_firewall.mode = 'learn'"
    "ALTER ROLE $PRM IN DATABASE $DB SET sql_firewall.mode = 'permissive'")
# Only the fingerprint role is gated by fingerprints.
for r in "$ENF" "$NOP" "$LRN" "$PRM" "$WRT"; do
    setup+=("ALTER ROLE $r IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off")
done
qa_admin postgres "${setup[@]}" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "CREATE TABLE public.qa_sb_t (id integer PRIMARY KEY, v text)" \
    "INSERT INTO public.qa_sb_t SELECT g, 'v' || g FROM generate_series(1, 5) g" \
    "GRANT SELECT ON public.qa_sb_t TO $ENF, $NOP, $FPR, $LRN, $PRM, $WRT" \
    "GRANT INSERT ON public.qa_sb_t TO $WRT" \
    "SELECT public.sql_firewall_approve_command('$ENF', 'SELECT')" \
    "SELECT public.sql_firewall_approve_command('$FPR', 'SELECT')" \
    "SELECT public.sql_firewall_approve_command('$WRT', 'SELECT')" \
    "SELECT public.sql_firewall_approve_command('$WRT', 'INSERT')" \
    "SELECT public.sql_firewall_add_regex_rule('qa_sb_forbidden_[0-9]+', 'standby test')" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

# The fingerprint role's shape: refused once (enforce publishes it pending),
# then explicitly approved, then allowed on the primary.
FP_SQL="SELECT v FROM public.qa_sb_t WHERE id = 1"
qa_sql_steps "$FPR" "$DB" qa_sb "$FP_SQL" || { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 60 || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_fp_identify "$DB" "$FPR" SELECT "$FP_SQL"
[[ $QA_FP_STATE == found ]] || { infra "$ID.fingerprint" "pending fingerprint not located ($QA_FP_STATE): $QA_FP_DUMP"; exit 0; }
FP=$QA_FP_FINGERPRINT
qa_admin "$DB" "SELECT public.sql_firewall_approve_fingerprint('$FP', '$FPR', 'SELECT')" ||
    { infra "$ID.fingerprint" "$QA_INFRA_REASON"; exit 0; }
qa_check_success "$FPR" "$DB" qa_sb "SELECT v FROM public.qa_sb_t WHERE id = 2" v2
[[ $QA_VERDICT == PASS ]] || { infra "$ID.fingerprint" "approved shape not allowed on the primary: $QA_DETAIL"; exit 0; }
qa_evidence "$EV" "- primary: fingerprint $FP approved for $FPR (\`$FP_SQL\`)"

# --- standby ------------------------------------------------------------------
STAGE_BIN=$(dirname "$(readlink "/proc/$QA_PM_PID/exe")")
SB_DATA=$QA_RUN_DIR/standby
SB_LOG=$QA_RUN_DIR/logs/standby.log
SB_PORT=$((QA_PORT + 1))
SB_PM=""
stop_standby() {
    [[ -f $SB_DATA/postmaster.pid ]] || return 0
    "$STAGE_BIN/pg_ctl" -D "$SB_DATA" -m fast -w -t 60 stop >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 ||
        "$STAGE_BIN/pg_ctl" -D "$SB_DATA" -m immediate -w -t 30 stop >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1
}
trap stop_standby EXIT
# Commands against the standby: the lib helpers read QA_PORT and QA_PM_PID.
on_sb() { QA_PORT=$SB_PORT QA_PM_PID=${SB_PM:-$QA_PM_PID} "$@"; }

if ! "$STAGE_BIN/pg_basebackup" -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" -D "$SB_DATA" -R -X stream -c fast --no-sync \
    >"$QA_RUN_DIR/logs/standby_basebackup.log" 2>&1; then
    infra "$ID" "pg_basebackup failed: $(tail -3 "$QA_RUN_DIR/logs/standby_basebackup.log" | tr '\n' ' ')"
    exit 0
fi
printf '\n# standby of run %s\nport = %s\nhot_standby = on\n' "$(basename "$QA_RUN_DIR")" "$SB_PORT" >>"$SB_DATA/postgresql.conf"
if ! "$STAGE_BIN/pg_ctl" -D "$SB_DATA" -l "$SB_LOG" -w -t 60 start >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1; then
    infra "$ID" "standby did not start: $(tail -5 "$SB_LOG" | tr '\n' ' ')"
    exit 0
fi
SB_PM=$(head -1 "$SB_DATA/postmaster.pid")

replay_wait() { # waits until the standby replayed the primary's current WAL
    qa_admin postgres "SELECT pg_catalog.pg_current_wal_lsn()" || return $?
    local lsn=${QA_STEP_OUT[1]}
    on_sb qa_poll postgres "SELECT pg_catalog.pg_last_wal_replay_lsn() >= '$lsn'::pg_lsn" t 60
}
replay_wait || { infra "$ID" "standby did not replay: $QA_INFRA_REASON"; exit 0; }

workers_on() { # PORT_FN -> WORKERS ("launcher,qa_sb" style list)
    "$@" qa_admin postgres "SELECT coalesce(string_agg(backend_type, ',' ORDER BY backend_type), '') FROM pg_catalog.pg_stat_activity WHERE backend_type LIKE 'sql_firewall%'" ||
        return $?
    WORKERS=${QA_STEP_OUT[1]}
}

on_sb qa_admin "$DB" "SELECT pg_catalog.pg_is_in_recovery()" "SELECT public.sql_firewall_status()" ||
    { infra "$ID.recovery" "$QA_INFRA_REASON"; exit 0; }
in_recovery=${QA_STEP_OUT[1]} status=${QA_STEP_OUT[2]}
workers_on on_sb || { infra "$ID.recovery" "$QA_INFRA_REASON"; exit 0; }
if [[ $in_recovery == t && -z $WORKERS ]]; then
    ok "$ID.recovery" "standby in recovery on port $SB_PORT; no firewall launcher or consumer"
else
    fail "$ID.recovery" "in recovery: $in_recovery; firewall processes: '$WORKERS'"
fi
if [[ $status == *"hot standby"* ]]; then
    ok "$ID.status" "sql_firewall_status(): '$status'"
else
    fail "$ID.status" "sql_firewall_status() does not name the hot standby: '$status'"
fi

on_sb qa_admin "$DB" "SELECT write_position || ' ' || blocked_query_events || ' ' || activity_write_position FROM public.sql_firewall_queue_statistics()" ||
    { infra "$ID.events_held" "$QA_INFRA_REASON"; exit 0; }
read -r sb_ring0 sb_blocked0 sb_act0 <<<"${QA_STEP_OUT[1]}"

# enforce: approved and unapproved
on_sb qa_check_success "$ENF" "$DB" qa_sb "SELECT count(*) FROM public.qa_sb_t WHERE v <> '$TAG.enf'" 5
enf_out="$QA_VERDICT: $QA_DETAIL"
on_sb qa_check_rejection "$NOP" "$DB" qa_sb "SELECT '$TAG.refused' AS marker" 42501 "^sql_firewall: No rule found for command 'SELECT' for role '$NOP'$"
nop_out="$QA_VERDICT: $QA_DETAIL"
if [[ $enf_out == PASS:* && $nop_out == PASS:* ]]; then
    ok "$ID.enforce" "approved SELECT ran on the standby ($enf_out); unapproved role refused ($nop_out)"
else
    fail "$ID.enforce" "approved: $enf_out; unapproved: $nop_out"
fi

# fingerprint identity is shared with the primary
on_sb qa_check_success "$FPR" "$DB" qa_sb "SELECT v FROM public.qa_sb_t WHERE id = 3" v3
fp_same="$QA_VERDICT: $QA_DETAIL"
on_sb qa_check_rejection "$FPR" "$DB" qa_sb "SELECT id FROM public.qa_sb_t WHERE v = 'v3'" 42501 "^sql_firewall: Fingerprint"
fp_other="$QA_VERDICT: $QA_DETAIL"
if [[ $fp_same == PASS:* && $fp_other == PASS:* ]]; then
    ok "$ID.fingerprint" "fingerprint approved on the primary allowed the same shape on the standby ($fp_same); another shape refused ($fp_other)"
else
    fail "$ID.fingerprint" "approved shape: $fp_same; other shape: $fp_other"
fi

# policy replay after the standby already allowed the statement
qa_admin "$DB" "SELECT public.sql_firewall_revoke_command('$ENF', 'SELECT')" || { infra "$ID.policy_replay" "$QA_INFRA_REASON"; exit 0; }
replay_wait || { infra "$ID.policy_replay" "$QA_INFRA_REASON"; exit 0; }
on_sb qa_check_rejection "$ENF" "$DB" qa_sb "SELECT count(*) FROM public.qa_sb_t" 42501 "^sql_firewall: "
revoked="$QA_VERDICT: $QA_DETAIL"
qa_admin "$DB" "SELECT public.sql_firewall_approve_command('$ENF', 'SELECT')" || { infra "$ID.policy_replay" "$QA_INFRA_REASON"; exit 0; }
replay_wait || { infra "$ID.policy_replay" "$QA_INFRA_REASON"; exit 0; }
on_sb qa_check_success "$ENF" "$DB" qa_sb "SELECT count(*) FROM public.qa_sb_t" 5
reapproved="$QA_VERDICT: $QA_DETAIL"
if [[ $revoked == PASS:* && $reapproved == PASS:* ]]; then
    ok "$ID.policy_replay" "revoke replayed: $revoked; re-approval replayed: $reapproved"
else
    fail "$ID.policy_replay" "after revoke: $revoked; after re-approval: $reapproved"
fi

# learn and permissive: allowed, rows returned, no warning to the client
LRN_SQL="SELECT v FROM public.qa_sb_t WHERE id = 4 AND v <> '$TAG.learn'"
on_sb qa_check_success "$LRN" "$DB" qa_sb "$LRN_SQL" v4
lrn_out="$QA_VERDICT: $QA_DETAIL"
on_sb qa_check_success "$PRM" "$DB" qa_sb "SELECT v FROM public.qa_sb_t WHERE id = 5" v5
prm_out="$QA_VERDICT: $QA_DETAIL"
client_warnings=$(grep -l "WARNING" "$QA_RUN_DIR"/logs/sql/*."$LRN".err "$QA_RUN_DIR"/logs/sql/*."$PRM".err 2>/dev/null | head -3)
if [[ $lrn_out == PASS:* && $prm_out == PASS:* && -z $client_warnings ]]; then
    ok "$ID.learn_permissive" "learn: $lrn_out; permissive: $prm_out; no client WARNING"
else
    fail "$ID.learn_permissive" "learn: $lrn_out; permissive: $prm_out; warnings in: $client_warnings"
fi

on_sb qa_check_rejection "$ENF" "$DB" qa_sb "SELECT 'qa_sb_forbidden_42' AS x" 42501 "^sql_firewall: Query blocked by security regex pattern\.$"
if [[ $QA_VERDICT == PASS ]]; then
    ok "$ID.regex" "regex rule evaluated on the standby: $QA_DETAIL"
else
    fail "$ID.regex" "$QA_VERDICT: $QA_DETAIL"
fi

on_sb qa_sql_steps "$WRT" "$DB" qa_sb "INSERT INTO public.qa_sb_t VALUES (100, 'x')" ||
    { infra "$ID.read_only" "$QA_INFRA_REASON"; exit 0; }
if [[ ${QA_STEP_ERR[1]} == true && ${QA_STEP_STATE[1]} == 25006 && ${QA_STEP_MSG[1]} != sql_firewall* ]]; then
    ok "$ID.read_only" "approved INSERT on the standby: native ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]}"
else
    fail "$ID.read_only" "approved INSERT: err=${QA_STEP_ERR[1]} ${QA_STEP_STATE[1]} ${QA_STEP_MSG[1]:-}"
fi

on_sb qa_admin "$DB" "SELECT write_position || ' ' || blocked_query_events || ' ' || activity_write_position FROM public.sql_firewall_queue_statistics()" ||
    { infra "$ID.events_held" "$QA_INFRA_REASON"; exit 0; }
read -r sb_ring1 sb_blocked1 sb_act1 <<<"${QA_STEP_OUT[1]}"
on_sb qa_admin "$DB" "SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE strpos(query_text, '$TAG') > 0" ||
    { infra "$ID.events_held" "$QA_INFRA_REASON"; exit 0; }
sb_rows=${QA_STEP_OUT[1]}
if ((sb_blocked1 > sb_blocked0 && sb_act1 > sb_act0)) && [[ $sb_rows == 0 ]]; then
    ok "$ID.events_held" "standby queues: blocked events $sb_blocked0 -> $sb_blocked1, activity position $sb_act0 -> $sb_act1; no row written on the standby"
else
    fail "$ID.events_held" "blocked events $sb_blocked0 -> $sb_blocked1, activity $sb_act0 -> $sb_act1, rows on standby $sb_rows"
fi

problems=$(grep -E 'sql_firewall.*(failed|could not)|cannot execute .* during recovery|read-only transaction|terminated by signal|PANIC:' "$SB_LOG" | grep -v "$WRT@" | head -10)
if [[ -z $problems ]]; then
    ok "$ID.log" "standby log has no firewall write failure, recovery-write error, or crash ($(wc -l <"$SB_LOG") lines)"
else
    fail "$ID.log" "standby log: $problems"
fi

# --- promotion ----------------------------------------------------------------
if ! "$STAGE_BIN/pg_ctl" -D "$SB_DATA" -w -t 60 promote >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1; then
    infra "$ID.promote" "pg_ctl promote failed: $(tail -3 "$SB_LOG" | tr '\n' ' ')"
    exit 0
fi
on_sb qa_poll postgres "SELECT pg_catalog.pg_is_in_recovery()" f 60 || { infra "$ID.promote" "$QA_INFRA_REASON"; exit 0; }
if on_sb qa_wait_worker_live "$DB" 90; then
    workers_on on_sb
    ok "$ID.promote.workers" "promoted: canary persisted after $QA_READY_ATTEMPTS attempt(s); firewall processes: $WORKERS"
else
    fail "$ID.promote.workers" "no consumer persisted a canary after promotion: $QA_INFRA_REASON"
    exit 0
fi

on_sb qa_admin "$DB" \
    "SELECT count(*) FROM public.sql_firewall_blocked_queries WHERE query_text = 'SELECT ''$TAG.refused'' AS marker' AND role_name = '$NOP'" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE strpos(query_text, '$TAG.enf') > 0 AND role_name = '$ENF'" ||
    { infra "$ID.promote.held_events" "$QA_INFRA_REASON"; exit 0; }
held_blocked=${QA_STEP_OUT[1]} held_activity=${QA_STEP_OUT[2]}
if [[ $held_blocked == 1 && $held_activity == 1 ]]; then
    ok "$ID.promote.held_events" "the standby's refusal and activity record were written once after promotion"
else
    fail "$ID.promote.held_events" "blocked rows $held_blocked, activity rows $held_activity (expected 1 and 1)"
fi

on_sb qa_poll "$DB" "SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '$LRN' AND command_type = 'SELECT' AND is_approved" 1 30
if [[ $? == 0 ]]; then
    ok "$ID.promote.learn" "the learn-mode observation made on the standby approved SELECT for $LRN after promotion"
else
    fail "$ID.promote.learn" "$QA_INFRA_REASON"
fi

on_sb qa_check_success "$ENF" "$DB" qa_sb "SELECT count(*) FROM public.qa_sb_t" 5
before="$QA_VERDICT: $QA_DETAIL"
on_sb qa_admin "$DB" "SELECT public.sql_firewall_revoke_command('$ENF', 'SELECT')" || { infra "$ID.promote.cache" "$QA_INFRA_REASON"; exit 0; }
on_sb qa_check_rejection "$ENF" "$DB" qa_sb "SELECT count(*) FROM public.qa_sb_t" 42501 "^sql_firewall: "
after="$QA_VERDICT: $QA_DETAIL"
on_sb qa_check_success "$FPR" "$DB" qa_sb "SELECT v FROM public.qa_sb_t WHERE id = 4" v4
fp_after="$QA_VERDICT: $QA_DETAIL"
if [[ $before == PASS:* && $after == PASS:* && $fp_after == PASS:* ]]; then
    ok "$ID.promote.cache" "allowed ($before), revoked at once ($after); the fingerprint approved on the old primary still applies ($fp_after)"
else
    fail "$ID.promote.cache" "before revoke: $before; after: $after; fingerprint: $fp_after"
fi

stop_standby
trap - EXIT
if [[ -f $SB_DATA/postmaster.pid ]] || kill -0 "$SB_PM" 2>/dev/null; then
    infra "$ID.promote.stop" "promoted server did not stop (pid $SB_PM)"
else
    rm -rf "$SB_DATA"
    qa_evidence "$EV" "- promoted server stopped; its data directory removed (log kept: logs/standby.log)"
fi

if qa_wait_worker_live "$DB" 60; then
    ok "$ID.primary" "the original server's consumer is still live after the standby's promotion"
else
    fail "$ID.primary" "$QA_INFRA_REASON"
fi
exit 0
