#!/usr/bin/env bash
# Baseline 1: command approval must not bypass enabled fingerprint enforcement.
#
# Contract: in enforce mode with fingerprint enforcement enabled, a role that
# holds command approval for SELECT but no approval for a new query fingerprint
# is rejected by the firewall's fingerprint gate.
# The verdict rests on the probe's own outcome (synchronous, positive evidence).
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.enforce_fingerprint_gate
DB=qa_fpgate
ROLE=qa_fp_app
APP=qa_fp_client
PROBE="SELECT id, v FROM qa_t WHERE v = 'fingerprint-probe';"
EV=enforce_fingerprint_gate
infra() { qa_record INFRA "$ID" "$1"; qa_evidence $EV "" "**Result: INFRA** - $1"; exit 0; }

qa_evidence $EV "# $ID" "" \
    "Intended: with sql_firewall.mode=enforce and enable_fingerprint_learning=on, a role with an approved SELECT command but no approved fingerprint is rejected (SQLSTATE 42501, 'sql_firewall: Fingerprint ...')." ""
LOG0=$(qa_server_log_offset)

qa_create_db $DB sql_firewall.mode=enforce sql_firewall.enable_fingerprint_learning=on || infra "setup: $QA_INFRA_REASON"
qa_admin $DB \
    "CREATE ROLE $ROLE LOGIN NOSUPERUSER" \
    "CREATE TABLE qa_t (id int, v text)" \
    "INSERT INTO qa_t VALUES (1, 'fingerprint-probe')" \
    "GRANT SELECT ON qa_t TO $ROLE" || infra "setup: $QA_INFRA_REASON"
qa_verify_mode_context $DB $ROLE enforce || infra "$QA_INFRA_REASON"
qa_evidence $EV "- mode context: $QA_MODE_CONTEXT"
qa_wait_worker_live $DB 90 || infra "worker liveness: $QA_INFRA_REASON"
qa_evidence $EV "- approval worker live (canary delivered after $QA_READY_ATTEMPTS attempt(s)); liveness only"

# Precondition A: enforce is in effect for this role (no command approval yet).
qa_check_rejection $ROLE $DB $APP "SELECT id FROM qa_t WHERE id = 1;" \
    42501 "^sql_firewall: No rule found for command 'SELECT' for role '$ROLE'$"
qa_evidence $EV "- precondition: enforce active without command approval -> $QA_VERDICT ($QA_DETAIL)"
[[ $QA_VERDICT == PASS ]] || infra "precondition (enforce active) not established: $QA_DETAIL"

# Precondition B: SELECT command approved, settings confirmed, fingerprint absent.
# (Setup state written synchronously by the superuser, not asynchronous output.)
qa_admin $DB \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true)" \
    "SELECT public.sql_firewall_clear_approval_cache()" \
    "SELECT lower(current_setting('sql_firewall.mode')) || ',' || current_setting('sql_firewall.enable_fingerprint_learning')" \
    "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$ROLE'" ||
    infra "setup: $QA_INFRA_REASON"
SETTINGS=${QA_STEP_OUT[3]} FP_BEFORE=${QA_STEP_OUT[4]}
qa_evidence $EV "- precondition: database settings (mode,fingerprint_learning) = $SETTINGS; fingerprint rows for role = $FP_BEFORE; SELECT approval inserted"
[[ $SETTINGS == enforce,on && $FP_BEFORE == 0 ]] || infra "precondition not met: settings=$SETTINGS fingerprints=$FP_BEFORE"

# The check: a new fingerprint under an approved command.
qa_check_rejection $ROLE $DB $APP "$PROBE" \
    42501 "^sql_firewall: Fingerprint '[0-9a-f]{64}' (for role '$ROLE' is pending approval|is blocked for role '$ROLE')"
VERDICT=$QA_VERDICT DETAIL=$QA_DETAIL

# Supplementary: catalog rows for the role once a later canary was delivered.
# The recorded sample is the statement span, without PROBE's terminating ';'.
FP_AFTER=unknown
if qa_worker_progress $DB 30 && qa_fp_identify $DB $ROLE SELECT "${PROBE%;}"; then
    FP_AFTER="$QA_FP_STATE; rows: $QA_FP_DUMP"
    [[ $QA_FP_STATE == found ]] && FP_ID=$QA_FP_FINGERPRINT
fi
PROBLEMS=$(qa_server_problems_since "$LOG0")

qa_evidence $EV "- probe: \`$PROBE\` as $ROLE" \
    "- actual: $DETAIL" \
    "- supplementary: fingerprint catalog for role after a later canary: $FP_AFTER" \
    "- logged server problems in window: ${PROBLEMS:-none}"
case $VERDICT in
    PASS) SUMMARY="new fingerprint rejected under approved SELECT: $DETAIL" ;;
    FAIL) SUMMARY="DEFECT DEMONSTRATED: enforce active (precondition rejected unapproved SELECT), SELECT approved, fingerprint absent, yet probe was allowed. $DETAIL" ;;
    *) SUMMARY="decision not observed: $DETAIL" ;;
esac
qa_record "$VERDICT" "$ID" "$SUMMARY"
qa_evidence $EV "" "**Result: $VERDICT** - $SUMMARY"

# Positive counterpart: an explicitly approved command and fingerprint work.
if [[ -z ${FP_ID:-} ]]; then
    qa_record INFRA "$ID.approved" "pending fingerprint row was not identified after worker progress"
elif ! qa_admin $DB "SELECT public.sql_firewall_approve_fingerprint('$FP_ID', '$ROLE', 'SELECT')"; then
    qa_record INFRA "$ID.approved" "approval setup: $QA_INFRA_REASON"
else
    qa_check_success $ROLE $DB $APP "$PROBE"
    qa_record "$QA_VERDICT" "$ID.approved" "approved SELECT command and fingerprint: $QA_DETAIL"
fi
exit 0
