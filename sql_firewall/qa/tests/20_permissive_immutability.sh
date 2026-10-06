#!/usr/bin/env bash
# Baseline 2: permissive mode never creates or changes approvals.
#
# Contract: previously unapproved traffic is allowed in permissive mode, and
# no command or fingerprint approval is created or promoted as a result.
#
# Evidence rules:
#  - "allowed" is positive, synchronous evidence.
#  - An observed approval/promotion is positive evidence of a defect (FAIL).
#  - Absence of a change is concluded only together with the event ring's
#    publication counters (sql_firewall_queue_statistics): the worker changes
#    policy only by applying approval and fingerprint events, and a zero
#    delta of both counters across the permissive traffic shows that none was
#    published. This test is the only client of the cluster, and canaries are
#    blocked-query events. The catalog is read after a later canary was
#    delivered, so an event published anyway would have been applied.
#  - Positive control: the same statements from a learn-mode role move the
#    counters and create approvals, so the check can fail. Without the
#    control the absence verdicts are INCONCLUSIVE.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.permissive_immutability
DB=qa_permissive
ROLE=qa_perm_app
APP=qa_perm_client
SEL="SELECT v FROM qa_t WHERE id = 7;"
INS="INSERT INTO qa_t VALUES (8, 'permissive');"
EV=permissive_immutability
infra() { qa_record INFRA "$ID" "$1"; qa_evidence $EV "" "**Result: INFRA** - $1"; exit 0; }

qa_evidence $EV "# $ID" "" \
    "Intended: statements are allowed; no approved command row is created, the seeded pending INSERT row is unchanged, and no fingerprint for the role is approved." ""
LOG0=$(qa_server_log_offset)

qa_create_db $DB sql_firewall.mode=permissive sql_firewall.enable_fingerprint_learning=on || infra "setup: $QA_INFRA_REASON"
qa_admin $DB \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER" \
    "CREATE TABLE qa_t (id int, v text)" \
    "INSERT INTO qa_t VALUES (7, 'seed')" \
    "GRANT SELECT, INSERT ON qa_t TO $ROLE" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'INSERT', false)" \
    "SELECT xmin::text FROM public.sql_firewall_command_approvals WHERE role_name = '$ROLE' AND command_type = 'INSERT'" \
    "SELECT lower(current_setting('sql_firewall.mode'))" \
    "SELECT (SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '$ROLE' AND is_approved) + (SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$ROLE')" ||
    infra "setup: $QA_INFRA_REASON"
PENDING_XMIN=${QA_STEP_OUT[6]} MODE=${QA_STEP_OUT[7]} PRE=${QA_STEP_OUT[8]}
qa_evidence $EV "- precondition: mode=$MODE; approved rows + fingerprint rows for role = $PRE; pending (INSERT,false) seeded with xmin=$PENDING_XMIN"
[[ $MODE == permissive && $PRE == 0 ]] || infra "precondition not met: mode=$MODE pre-existing=$PRE"
qa_verify_mode_context $DB $ROLE permissive || infra "$QA_INFRA_REASON"
qa_evidence $EV "- mode context: $QA_MODE_CONTEXT"
qa_wait_worker_live $DB 90 || infra "worker liveness: $QA_INFRA_REASON"
qa_evidence $EV "- approval worker live (canary delivered after $QA_READY_ATTEMPTS attempt(s)); liveness only"

queue_counts() { # -> QUEUE "approval_events fingerprint_events"
    qa_admin $DB "SELECT approval_events || ' ' || fingerprint_events FROM public.sql_firewall_queue_statistics()" || return
    QUEUE=${QA_STEP_OUT[1]}
}
queue_counts || infra "queue statistics: $QA_INFRA_REASON"
Q0=$QUEUE

# Unapproved SELECT (no rule at all) and pending INSERT, both must be allowed.
qa_check_success $ROLE $DB $APP "$SEL" seed
SEL_VERDICT=$QA_VERDICT
qa_evidence $EV "- unapproved SELECT: $QA_VERDICT ($QA_DETAIL)"
qa_check_success $ROLE $DB $APP "$INS"
INS_VERDICT=$QA_VERDICT
qa_evidence $EV "- pending INSERT: $QA_VERDICT ($QA_DETAIL)"

queue_counts || infra "queue statistics: $QA_INFRA_REASON"
Q1=$QUEUE
read -r qa0 qf0 <<<"$Q0"
read -r qa1 qf1 <<<"$Q1"
PUBLISHED_APPROVALS=$((qa1 - qa0)) PUBLISHED_FINGERPRINTS=$((qf1 - qf0))
qa_evidence $EV "- queue publications across the permissive traffic: approval events $qa0 -> $qa1, fingerprint events $qf0 -> $qf1"

# Everything published before this canary has been applied once it is delivered.
qa_worker_progress $DB 30 || infra "post-traffic worker liveness: $QA_INFRA_REASON"
qa_admin $DB \
    "SELECT count(*) || ':' || coalesce(string_agg(command_type || '=' || is_approved, ','), 'none') FROM public.sql_firewall_command_approvals WHERE role_name = '$ROLE' AND is_approved" \
    "SELECT is_approved || ' xmin=' || xmin::text FROM public.sql_firewall_command_approvals WHERE role_name = '$ROLE' AND command_type = 'INSERT'" \
    "SELECT count(*) FILTER (WHERE is_approved) || ':' || coalesce(string_agg(command_type || ':' || fingerprint || ' approved=' || is_approved, ','), 'none') FROM public.sql_firewall_query_fingerprints WHERE role_name = '$ROLE'" \
    "SELECT coalesce(string_agg(command_type || ' -> ' || action, '; ' ORDER BY log_id), 'none') FROM public.sql_firewall_activity_log WHERE role_name = '$ROLE'" ||
    infra "verification: $QA_INFRA_REASON"
APPROVED=${QA_STEP_OUT[1]} PENDING=${QA_STEP_OUT[2]} FPS=${QA_STEP_OUT[3]} DECISIONS=${QA_STEP_OUT[4]}
PROBLEMS=$(qa_server_problems_since "$LOG0")
qa_evidence $EV "- after canary: approved command rows = ${APPROVED#*:}" \
    "- after canary: pending INSERT row = $PENDING (seeded: false xmin=$PENDING_XMIN)" \
    "- after canary: fingerprint rows = ${FPS#*:}" \
    "- supplementary (recorded decisions, not persisted state): activity log for role = $DECISIONS" \
    "- logged server problems in window: ${PROBLEMS:-none}"

if [[ $SEL_VERDICT == PASS && $INS_VERDICT == PASS ]]; then
    qa_record PASS "$ID.allowed" "unapproved SELECT and pending INSERT allowed"
elif [[ $SEL_VERDICT == INFRA || $INS_VERDICT == INFRA ]]; then
    qa_record INFRA "$ID.allowed" "traffic outcome not observed (SELECT=$SEL_VERDICT INSERT=$INS_VERDICT)"
else
    qa_record FAIL "$ID.allowed" "permissive traffic was rejected (SELECT=$SEL_VERDICT INSERT=$INS_VERDICT)"
fi

# Positive control: a learn-mode role running the same statements publishes
# learn events and gets approvals; the counters and catalog checks see it.
CONTROL=qa_perm_control
qa_admin $DB "CREATE ROLE $CONTROL LOGIN NOSUPERUSER" "GRANT SELECT, INSERT ON qa_t TO $CONTROL" ||
    infra "control setup: $QA_INFRA_REASON"
qa_admin postgres "ALTER ROLE $CONTROL IN DATABASE $DB SET sql_firewall.mode = 'learn'" \
    "ALTER ROLE $CONTROL IN DATABASE $DB SET sql_firewall.fingerprint_learn_threshold = 1" ||
    infra "control setup: $QA_INFRA_REASON"
queue_counts || infra "queue statistics: $QA_INFRA_REASON"
read -r ca0 cf0 <<<"$QUEUE"
qa_check_success $CONTROL $DB $APP "$SEL" seed
C_SEL=$QA_VERDICT
qa_check_success $CONTROL $DB $APP "$INS"
C_INS=$QA_VERDICT
queue_counts || infra "queue statistics: $QA_INFRA_REASON"
read -r ca1 cf1 <<<"$QUEUE"
qa_worker_progress $DB 30 || infra "control worker liveness: $QA_INFRA_REASON"
qa_admin $DB \
    "SELECT count(*) FROM public.sql_firewall_command_approvals WHERE role_name = '$CONTROL' AND is_approved" \
    "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$CONTROL' AND is_approved" ||
    infra "control verification: $QA_INFRA_REASON"
C_AP=${QA_STEP_OUT[1]} C_FP=${QA_STEP_OUT[2]}
CONTROL_DETAIL="learn-mode control: SELECT=$C_SEL INSERT=$C_INS; approval events +$((ca1 - ca0)), fingerprint events +$((cf1 - cf0)); approved command rows $C_AP, approved fingerprints $C_FP"
qa_evidence $EV "- positive control ($CONTROL): $CONTROL_DETAIL"
CONTROL_OK=0
[[ $C_SEL == PASS && $C_INS == PASS && $((ca1 - ca0)) -ge 2 && $((cf1 - cf0)) -ge 2 && $C_AP -ge 2 && $C_FP -ge 2 ]] && CONTROL_OK=1

# An unobserved change is PASS only with no learn event published and a
# working control; otherwise it stays INCONCLUSIVE.
judge() { # OBSERVED DESCRIPTION
    if (($1 > 0)); then
        QA_VERDICT=FAIL QA_DETAIL="observed: $2"
    elif ((PUBLISHED_APPROVALS != 0 || PUBLISHED_FINGERPRINTS != 0)); then
        QA_VERDICT=FAIL QA_DETAIL="not yet observed, but permissive traffic published learn events (approval +$PUBLISHED_APPROVALS, fingerprint +$PUBLISHED_FINGERPRINTS): $2"
    elif ((CONTROL_OK == 0)); then
        qa_judge_absence 0 "$2 (positive control did not show the check can fail: $CONTROL_DETAIL)"
    else
        QA_VERDICT=PASS QA_DETAIL="not observed: $2; permissive traffic published no approval or fingerprint event (counters unchanged) and the catalog was read after a later canary; positive control: $CONTROL_DETAIL"
    fi
}

record_absence() { # SUFFIX
    local id=$ID.$1
    if [[ $QA_VERDICT == FAIL ]]; then
        qa_record FAIL "$id" "DEFECT DEMONSTRATED: $QA_DETAIL"
    elif [[ -n $PROBLEMS ]]; then
        qa_record INFRA "$id" "$QA_DETAIL; logged problems: $PROBLEMS"
    else
        qa_record "$QA_VERDICT" "$id" "$QA_DETAIL"
    fi
    qa_evidence $EV "- \`$id\`: $QA_VERDICT - $QA_DETAIL"
}
judge "${APPROVED%%:*}" "approved command row(s) for $ROLE created by permissive traffic: ${APPROVED#*:}"
record_absence no_command_approval
PROMOTED=0
[[ $PENDING == "false xmin=$PENDING_XMIN" ]] || PROMOTED=1
judge $PROMOTED "change to the pending (INSERT) row (now: $PENDING; seeded: false xmin=$PENDING_XMIN)"
record_absence pending_not_promoted
judge "${FPS%%:*}" "approved fingerprint(s) for $ROLE: ${FPS#*:}"
record_absence no_fingerprint_approval
exit 0
