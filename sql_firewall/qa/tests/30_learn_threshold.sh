#!/usr/bin/env bash
# Baseline 3: learn-mode fingerprint approval honours the configured threshold.
#
# Contract: with sql_firewall.fingerprint_learn_threshold = N, a fingerprint is
# not approved after executions 1..N-1 and is approved after execution N.
#
# Identity: the role is isolated and runs only STMT[1..N] (same shape,
# different literal). The catalog row is identified by exact sample_query
# match against the statement texts (qa_fp_identify), without guessing the
# product's normalisation. The harness sends each with a trailing ';'; the
# product records PostgreSQL's statement span, which ends before it. When the
# row is not identified, all rows for the role/command are captured.
#
# Verdict: qa_threshold_verdict (lib.sh), which also documents the evidence
# basis. Each execution must be evidenced (hit_count reaches i, bounded poll)
# before its boundary is certified and before the next execution is sent.
# Persisted catalog state is authoritative. The activity-log 'LEARNED
# (FINGERPRINT AUTO)' count is a recorded decision, reported as supplementary.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.learn_threshold_boundary
DB=qa_threshold
ROLE=qa_learn_app
APP=qa_learn_client
N=3
EV=learn_threshold_boundary
infra() { qa_record INFRA "$ID" "$1"; qa_evidence $EV "" "**Result: INFRA** - $1"; exit 0; }
STMT=()
for ((i = 1; i <= N; i++)); do STMT[i]="SELECT v FROM qa_t WHERE id = $i"; done

qa_evidence $EV "# $ID" "" \
    "Intended: threshold N=$N. The catalog fingerprint for \`${STMT[1]}\` (role $ROLE) is not approved after executions 1..$((N - 1)) and is approved by execution $N." \
    "Identity: exact sample_query match against the statement texts (sent with a trailing ';', recorded without it); the role runs nothing else." \
    "Evidence rule: execution i counts only once the identified row shows hit_count = i (bounded poll); see qa_threshold_verdict in lib.sh." ""
LOG0=$(qa_server_log_offset)

qa_create_db $DB sql_firewall.mode=learn sql_firewall.enable_fingerprint_learning=on \
    sql_firewall.fingerprint_learn_threshold=$N sql_firewall.enable_activity_logging=on ||
    infra "setup: $QA_INFRA_REASON"
qa_admin $DB \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER" \
    "CREATE TABLE qa_t (id int, v text)" \
    "INSERT INTO qa_t SELECT g, 'row' FROM generate_series(1, 10) g" \
    "GRANT SELECT ON qa_t TO $ROLE" \
    "SELECT lower(current_setting('sql_firewall.mode')) || ',' || current_setting('sql_firewall.fingerprint_learn_threshold') || ',' || current_setting('sql_firewall.enable_activity_logging')" \
    "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$ROLE'" ||
    infra "setup: $QA_INFRA_REASON"
qa_evidence $EV "- precondition: (mode,threshold,activity_logging) = ${QA_STEP_OUT[5]}; fingerprint rows for role = ${QA_STEP_OUT[6]}"
[[ ${QA_STEP_OUT[5]} == "learn,$N,on" && ${QA_STEP_OUT[6]} == 0 ]] || infra "precondition not met: ${QA_STEP_OUT[5]} rows=${QA_STEP_OUT[6]}"
qa_verify_mode_context $DB $ROLE learn || infra "$QA_INFRA_REASON"
qa_evidence $EV "- mode context: $QA_MODE_CONTEXT"
qa_wait_worker_live $DB 90 || infra "worker liveness: $QA_INFRA_REASON"
qa_evidence $EV "- approval worker live (canary delivered after $QA_READY_ATTEMPTS attempt(s)); liveness only, not per-execution evidence"

qa_thr_execute() {
    qa_check_success $ROLE $DB $APP "${STMT[$1]}" row
    QA_THR_DETAIL=$QA_DETAIL
    [[ $QA_VERDICT == PASS ]]
}
LAST_DUMP=""
qa_thr_observe() {
    if ! qa_fp_identify $DB $ROLE SELECT "${STMT[@]:1:$1}"; then
        QA_THR_DETAIL=$QA_INFRA_REASON
        return 1
    fi
    QA_THR_STATE=$QA_FP_STATE QA_THR_APPROVED=$QA_FP_APPROVED QA_THR_HITS=$QA_FP_HITS
    LAST_DUMP=$QA_FP_DUMP
    [[ $QA_FP_STATE == found ]] && LAST_ROW="$QA_FP_FINGERPRINT normalized=$QA_FP_NORMALIZED"
    return 0
}
LAST_ROW=""
QA_THR_POLL_ATTEMPTS=${QA_THR_POLL_ATTEMPTS:-100} QA_THR_POLL_INTERVAL=${QA_THR_POLL_INTERVAL:-0.2}
qa_threshold_verdict $N
VERDICT=$QA_VERDICT SUMMARY=$QA_DETAIL

qa_admin $DB "SELECT count(*) FROM public.sql_firewall_activity_log WHERE role_name = '$ROLE' AND action = 'LEARNED (FINGERPRINT AUTO)'" &&
    DECISIONS=${QA_STEP_OUT[1]} || DECISIONS="unknown ($QA_INFRA_REASON)"
PROBLEMS=$(qa_server_problems_since "$LOG0")
qa_evidence $EV "Per-execution observations (bounded poll ${QA_THR_POLL_ATTEMPTS} x ${QA_THR_POLL_INTERVAL}s):" "" \
    "${QA_THR_TRACE[@]/#/- }" "" \
    "- identified row: ${LAST_ROW:-none}" \
    "- all rows for $ROLE/SELECT at the end:" '```' "${LAST_DUMP:-(not read)}" '```' \
    "- supplementary (recorded decisions, not persisted state): 'LEARNED (FINGERPRINT AUTO)' entries = $DECISIONS" \
    "- logged server problems in window: ${PROBLEMS:-none}"
if [[ $VERDICT == PASS && -n $PROBLEMS ]]; then
    VERDICT=INFRA SUMMARY="logged worker/audit problems; catalog state cannot be trusted: $PROBLEMS"
fi
[[ $VERDICT == FAIL ]] && SUMMARY="DEFECT DEMONSTRATED: $SUMMARY${LAST_ROW:+ [$LAST_ROW]}"
qa_record "$VERDICT" "$ID" "$SUMMARY"
qa_evidence $EV "" "**Result: $VERDICT** - $SUMMARY"

# An administrator's explicit block must outlive the Learn threshold. The
# count was already at N; without a distinct block state the next hit used to
# turn is_approved back on immediately.
if [[ $VERDICT == PASS && $QA_FP_STATE == found ]]; then
    FP_ID=$QA_FP_FINGERPRINT
    STATE_SQL="SELECT hit_count::text || ':' || is_approved::text || ':' || auto_approval_disabled::text FROM public.sql_firewall_query_fingerprints WHERE fingerprint = '$FP_ID' AND role_name = '$ROLE' AND command_type = 'SELECT'"
    if ! qa_admin $DB "SELECT public.sql_firewall_block_fingerprint('$FP_ID', '$ROLE', 'SELECT')" "$STATE_SQL"; then
        qa_record INFRA "$ID.admin_block" "block setup: $QA_INFRA_REASON"
    elif [[ ${QA_STEP_OUT[2]} != "$N:false:true" ]]; then
        qa_record FAIL "$ID.admin_block" "block did not persist: ${QA_STEP_OUT[2]}"
    else
        qa_check_success $ROLE $DB $APP "${STMT[1]}" row
        FIRST=$QA_VERDICT
        if [[ $FIRST == PASS ]] && qa_poll $DB "$STATE_SQL" "$((N + 1)):false:true" 10; then
            qa_check_success $ROLE $DB $APP "${STMT[2]}" row
            SECOND=$QA_VERDICT
            if [[ $SECOND == PASS ]] && qa_poll $DB "$STATE_SQL" "$((N + 2)):false:true" 10; then
                qa_record PASS "$ID.admin_block" "two more Learn hits kept the explicit block: ${QA_STEP_OUT[1]}"
            else
                qa_record FAIL "$ID.admin_block" "second Learn hit reapproved or failed: verdict=$SECOND state=${QA_STEP_OUT[1]:-unknown}"
            fi
        else
            qa_record FAIL "$ID.admin_block" "first Learn hit reapproved or failed: verdict=$FIRST state=${QA_STEP_OUT[1]:-unknown}"
        fi
        if qa_admin $DB "SELECT public.sql_firewall_approve_fingerprint('$FP_ID', '$ROLE', 'SELECT')" "$STATE_SQL" &&
            [[ ${QA_STEP_OUT[2]} == *":true:false" ]]; then
            qa_record PASS "$ID.admin_reapprove" "explicit approval cleared the block: ${QA_STEP_OUT[2]}"
        else
            qa_record FAIL "$ID.admin_reapprove" "explicit approval did not clear the block: ${QA_STEP_OUT[2]:-unknown}"
        fi
    fi
fi
exit 0
