#!/usr/bin/env bash
# Deterministic regressions for harness verdict logic. No database is used:
# the real functions from lib.sh run against in-memory observations. Only the
# lowest layers are replaced, inside subshells: the threshold hooks
# (qa_thr_execute / qa_thr_observe) and qa_sql_steps for the canary cases.
#
# Runs inside run.sh, or standalone:
#   sql_firewall/qa/tests/01_verdict_regressions.sh
# Standalone, the exit status is 0 only if every regression passes.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

STANDALONE=0
if [[ -z ${QA_RESULTS:-} ]]; then
    STANDALONE=1
    QA_RUN_DIR=$(mktemp -d "${QA_WORK_ROOT:-${TMPDIR:-/tmp}}/sqlfw-qa-verdicts.XXXXXX") || exit 2
    QA_RESULTS=$QA_RUN_DIR/results.tsv
    : >"$QA_RESULTS"
    echo "run directory: $QA_RUN_DIR"
fi
QA_SUPERUSER=${QA_SUPERUSER:-qa_admin} # only used as a role name by the simulated server
EV=verdict_regressions
qa_evidence $EV "# Deterministic verdict regressions" ""

expect() { # ID EXPECTED ACTUAL DETAIL
    local id=selftest.verdict.$1
    qa_evidence $EV "- \`$id\`: expected $2, got $3 ($4)"
    if [[ $3 == "$2" ]]; then
        qa_record PASS "$id" "classified $3 as expected ($4)"
    else
        qa_record FAIL "$id" "classified $3, expected $2 ($4)"
    fi
}

# ---------------------------------------------------------------------------
# A. Learn-threshold verdict (qa_threshold_verdict)
#
# Each STEP argument is the sequence of observations successive polls return
# after that execution (the last one repeats):
#   a = no row   x = ambiguous identity   f<h> = unapproved, hit_count h
#   t<h> = approved, hit_count h          R = execution rejected
# ---------------------------------------------------------------------------
thr() { # ID EXPECTED N STEP...
    local id=$1 expected=$2 n=$3 out
    shift 3
    out=$(
        STEPS=("" "$@")
        declare -A CALLS=()
        QA_THR_POLL_ATTEMPTS=4 QA_THR_POLL_INTERVAL=0
        qa_thr_execute() {
            [[ ${STEPS[$1]:-} == R ]] && { QA_THR_DETAIL="rejected (simulated)"; return 1; }
            return 0
        }
        qa_thr_observe() {
            local -a list
            read -ra list <<<"${STEPS[$1]:-a}"
            local k=${CALLS[$1]:-0}
            ((k < ${#list[@]} - 1)) && CALLS[$1]=$((k + 1))
            case ${list[k]} in
                a) QA_THR_STATE=absent QA_THR_APPROVED="" QA_THR_HITS="" ;;
                x) QA_THR_STATE=ambiguous QA_THR_APPROVED="" QA_THR_HITS="" ;;
                f*) QA_THR_STATE=found QA_THR_APPROVED=f QA_THR_HITS=${list[k]#f} ;;
                t*) QA_THR_STATE=found QA_THR_APPROVED=t QA_THR_HITS=${list[k]#t} ;;
            esac
            return 0
        }
        qa_threshold_verdict "$n"
        printf '%s\t%s | %s\n' "$QA_VERDICT" "$QA_DETAIL" "$(printf '%s; ' "${QA_THR_TRACE[@]}")"
    )
    expect "threshold.$id" "$expected" "${out%%$'\t'*}" "N=$n steps: $(printf '[%s] ' "$@")-> ${out#*$'\t'}"
}

# Fully evidenced correct boundaries.
thr correct_boundary PASS 3 "f1" "f2" "t3"
thr correct_boundary_delayed_delivery PASS 3 "a a f1" "f1 f1 f2" "f2 t3" # late but delivered: not INFRA
thr correct_boundary_n1 PASS 1 "a t1"
# Stale observations followed by approval: never PASS.
thr stale_reviewer_sequence INCONCLUSIVE 3 "f1" "f1" "t2" # reviewer's reproduction
thr stale_then_approved_before_n FAIL 3 "f1" "f1 t1"    # approval visible after 2 of 3 sent
thr stale_approval_after_n INCONCLUSIVE 3 "f1" "f2" "t2" # approval seen after N, not attributable
# Positive early approval: FAIL, even when the current execution is not yet evidenced.
thr early_approval FAIL 3 "t1"
thr early_approval_after_absent FAIL 3 "a a t1"
thr early_approval_second_step FAIL 3 "f1" "t2"
# Missing or insufficient delivery evidence: INCONCLUSIVE.
thr no_row_ever INCONCLUSIVE 3 "a"
thr step_never_evidenced INCONCLUSIVE 3 "f1" "a"
thr threshold_step_not_evidenced INCONCLUSIVE 3 "f1" "f2" "f2"
# Fully processed threshold observation that remains unapproved: FAIL.
thr processed_unapproved_at_n FAIL 3 "f1" "f2" "f3"
thr processed_unapproved_n1 FAIL 1 "f1"
# Harness-level failures: INFRA, not a product verdict.
thr too_many_hits INFRA 3 "f2"
thr ambiguous_identity INFRA 3 "x"
thr execution_rejected INFRA 3 "R"

# ---------------------------------------------------------------------------
# B. Canary liveness vs. earlier-event evidence
#
# The real qa_worker_progress / qa_canary_emit / qa_poll / qa_admin /
# qa_judge_rejection run against a simulated server (qa_sql_steps replaced):
#   CANARY_ROW   1 = the canary's blocked-query row is present (delivered)
#   EARLY_ROWS   rows produced by an earlier event
# Verified: a delivered later canary plus missing evidence for an earlier
# event never yields PASS for that event, and successful delivery of the
# earlier event is never classified INFRA by the canary helpers.
# ---------------------------------------------------------------------------
canary() { # ID CANARY_ROW EARLY_ROWS -> prints "<progress rc>\t<absence verdict>\t<detail>"
    (
        CANARY_ROW=$2 EARLY_ROWS=$3
        qa_sql_steps() {
            local role=$1
            shift 3
            QA_STEP_ERR=() QA_STEP_STATE=() QA_STEP_MSG=() QA_STEP_OUT=()
            QA_STEP_ERR[1]=false QA_STEP_STATE[1]=00000
            if [[ $role == "$QA_CANARY_ROLE" ]]; then
                QA_STEP_ERR[1]=true QA_STEP_STATE[1]=42501
                QA_STEP_MSG[1]="sql_firewall: No rule found for command 'SELECT' for role '$QA_CANARY_ROLE'"
            elif [[ $1 == *"strpos(query_text, 'qa_canary_"* ]]; then
                QA_STEP_OUT[1]=$([[ $CANARY_ROW == 1 ]] && echo t || echo f)
            elif [[ $1 == *early_event_effect* ]]; then
                QA_STEP_OUT[1]=$EARLY_ROWS
            fi
            return 0
        }
        qa_worker_progress qa_sim 0
        rc=$?
        qa_admin qa_sim "SELECT count(*) FROM early_event_effect"
        qa_judge_absence "${QA_STEP_OUT[1]}" "effect of the earlier event"
        printf '%s\t%s\t%s\n' "$rc" "$QA_VERDICT" "$QA_DETAIL"
    )
}

IFS=$'\t' read -r RC V D < <(canary missing 1 0)
expect canary.delivered_earlier_missing "0/INCONCLUSIVE" "$RC/$V" "canary delivered (progress rc=$RC = liveness only); earlier effect absent -> $D"
IFS=$'\t' read -r RC V D < <(canary delivered 1 1)
expect canary.delivered_earlier_delivered "0/FAIL" "$RC/$V" "canary delivered; earlier event's forbidden effect present -> product-level verdict, not INFRA ($D)"
IFS=$'\t' read -r RC V D < <(canary undelivered 0 0)
expect canary.not_delivered "$QA_EXIT_TIMEOUT" "$RC" "canary not delivered: liveness not established (caller reports INFRA)"

if ((STANDALONE)); then
    awk -F'\t' '{ n[$1]++ } END { for (s in n) printf "%s=%d ", s, n[s]; print "" }' "$QA_RESULTS"
    ! grep -qv "^PASS"$'\t' "$QA_RESULTS"
    exit $?
fi
exit 0
