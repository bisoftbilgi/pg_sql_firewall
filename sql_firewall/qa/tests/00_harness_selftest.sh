#!/usr/bin/env bash
# Validates the validator. The verdict functions used by every baseline test
# must never turn a missing executable, a connection failure, an unrelated SQL
# error or a native permission error into a firewall PASS. They must recognise
# a genuine success and a genuine firewall rejection. A further regression
# covers fingerprint identity (a wrong statement identity must not read as
# "absent"). Canary/delivery inference and the threshold verdict are covered
# deterministically in 01_verdict_regressions.sh. Nothing here depends on the
# approval worker's timing or on it delivering or losing any event.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

DB=qa_selftest
APP=qa_selftest_app
ROLE=qa_self_app
FP_ROLE=qa_self_fp
EMPTY_ROLE=qa_self_norows # never connects, so it never has fingerprint rows
ANY_FW='^sql_firewall: '
EV=harness_selftest

# selftest ID EXPECTED_VERDICT DESCRIPTION  (uses QA_VERDICT/QA_DETAIL)
selftest() {
    local id=selftest.$1 expected=$2
    qa_evidence $EV "- \`$id\`: expected harness verdict $expected, got $QA_VERDICT ($QA_DETAIL)"
    if [[ $QA_VERDICT == "$expected" ]]; then
        qa_record PASS "$id" "$3 -> classified $QA_VERDICT ($QA_DETAIL)"
    else
        qa_record FAIL "$id" "$3 -> classified $QA_VERDICT, expected $expected ($QA_DETAIL)"
    fi
}
infra() { qa_record INFRA "selftest.$1" "$2"; qa_evidence $EV "- \`selftest.$1\`: INFRA - $2"; }

qa_evidence $EV "# Harness self-test" ""
if ! qa_create_db "$DB" sql_firewall.mode=learn ||
    ! qa_admin "$DB" \
        "CREATE ROLE $ROLE LOGIN NOSUPERUSER" \
        "CREATE ROLE $FP_ROLE LOGIN NOSUPERUSER" \
        "CREATE ROLE $EMPTY_ROLE NOLOGIN" \
        "CREATE TABLE qa_secret (id int)" \
        "CREATE TABLE qa_open (id int)" \
        "GRANT SELECT ON qa_open TO $ROLE, $FP_ROLE" ||
    ! qa_verify_mode_context "$DB" "$ROLE" learn; then
    infra setup "$QA_INFRA_REASON"
    exit 0
fi
qa_evidence $EV "- mode context: $QA_MODE_CONTEXT"

# 1. Missing executable, used where a firewall rejection is expected.
QA_PSQL=/nonexistent/bin/psql qa_check_rejection "$QA_CANARY_ROLE" "$DB" "$APP" \
    "SELECT 1" 42501 "$QA_CANARY_REJECTION"
selftest missing_executable_not_pass INFRA "missing psql executable"

# 2. Connection failures: wrong port, unknown role, unknown database.
QA_PORT=$((QA_PORT + 1)) qa_check_rejection "$QA_CANARY_ROLE" "$DB" "$APP" \
    "SELECT 1" 42501 "$QA_CANARY_REJECTION"
selftest connection_refused_not_pass INFRA "connection to a port with no server"
qa_check_rejection qa_no_such_role "$DB" "$APP" "SELECT 1" 42501 "$ANY_FW"
selftest unknown_role_not_pass INFRA "authentication failure (unknown role)"
qa_check_rejection "$QA_CANARY_ROLE" qa_no_such_db "$APP" "SELECT 1" 42501 "$QA_CANARY_REJECTION"
selftest unknown_database_not_pass INFRA "connection to a missing database"

# 3. Unrelated SQL errors where a firewall rejection is expected.
qa_check_rejection "$ROLE" "$DB" "$APP" "SELEC 1" 42501 "$ANY_FW"
selftest syntax_error_not_pass INFRA "syntax error (42601)"
qa_check_rejection "$ROLE" "$DB" "$APP" "SELECT * FROM qa_no_such_table" 42501 "$ANY_FW"
selftest undefined_table_not_pass INFRA "undefined table (42P01)"
# Native permission denial shares SQLSTATE 42501 with firewall rejections; only
# the firewall diagnostic distinguishes them.
qa_check_rejection "$ROLE" "$DB" "$APP" "SELECT * FROM qa_secret" 42501 "$ANY_FW"
selftest native_permission_error_not_pass INFRA "native permission denied (42501, non-firewall message)"

# 4. An allowed statement is not a rejection.
qa_check_rejection "$ROLE" "$DB" "$APP" "SELECT 1" 42501 "$ANY_FW"
selftest allowed_statement_not_rejection FAIL "statement allowed where rejection expected"

# 5. Genuine success and genuine firewall rejection. The rejection comes from
#    the control role's explicit enforce context (no approval), which does
#    not depend on the application role's mode or on injection heuristics.
qa_check_success "$ROLE" "$DB" "$APP" "SELECT count(*) FROM qa_open" 0
selftest genuine_success PASS "successful SQL assertion with result check"
qa_check_rejection "$QA_CANARY_ROLE" "$DB" "$APP" "SELECT 1" 42501 "$QA_CANARY_REJECTION"
selftest genuine_firewall_rejection PASS "enforce-context firewall rejection identified by SQLSTATE and diagnostic"

# 6. application_name is really delivered to the server (env assignment).
qa_check_success "$ROLE" "$DB" qa_appname_probe "SELECT current_setting('application_name')" qa_appname_probe
selftest application_name_applied PASS "PGAPPNAME reaches the server"

# 7. Session persistence across steps (temp object visible to a later step).
if qa_sql_steps "$ROLE" "$DB" "$APP" "CREATE TEMP TABLE qa_tmp AS SELECT 42 AS v" "SELECT v FROM qa_tmp"; then
    qa_judge_success 2 42
else
    QA_VERDICT=INFRA QA_DETAIL=$QA_INFRA_REASON
fi
selftest same_session_steps PASS "state persists across steps of one session"

# 8. Role used for behaviour tests is not a superuser.
if qa_admin "$DB" "SELECT rolsuper FROM pg_roles WHERE rolname = '$ROLE'"; then
    [[ ${QA_STEP_OUT[1]} == f ]] && QA_VERDICT=PASS || QA_VERDICT=FAIL
    QA_DETAIL="rolsuper=${QA_STEP_OUT[1]}"
else
    QA_VERDICT=INFRA QA_DETAIL=$QA_INFRA_REASON
fi
selftest app_role_not_superuser PASS "application role is not a superuser"

# 9. Absence judgement is never PASS.
qa_judge_absence 0 "synthetic effect"
selftest absence_is_not_pass INCONCLUSIVE "no observed effect (absence)"
qa_judge_absence 1 "synthetic effect"
selftest observed_effect_is_fail FAIL "observed forbidden effect"

# ---------------------------------------------------------------------------
# 10. Fingerprint identity (qa_fp_identify).
# The first threshold test looked up normalized_query without the trailing ';'
# the server receives, found nothing, and read that as "not approved". Rows are
# seeded synchronously by the superuser in the format the product was observed
# to persist (retained run sqlfw-qa.rpvDwL: 37592ddd808c191a), so this check
# does not depend on worker timing or on current learn-mode behaviour.
# Since Phase 4A the product records the statement span without the ';'.
# The seeded historical row is kept: this checks exact-match identity, not
# the product's current format.
# ---------------------------------------------------------------------------
FP_SENT="SELECT id FROM qa_open WHERE id = 1;"
FP_WRONG="SELECT id FROM qa_open WHERE id = 1"  # the text without the ';' that was sent
FP_OLD_KEY="SELECT ID FROM QA_OPEN WHERE ID = ?" # the style of key the old test used
if ! qa_admin "$DB" \
    "INSERT INTO public.sql_firewall_query_fingerprints (fingerprint, normalized_query, role_name, command_type, sample_query, hit_count, is_approved) VALUES ('37592ddd808c191a', 'SELECT ID FROM QA_OPEN WHERE ID = ?;', '$FP_ROLE', 'SELECT', $(qa_sql_quote "$FP_SENT"), 1, true)" \
    "SELECT count(*) FROM public.sql_firewall_query_fingerprints WHERE role_name = '$FP_ROLE' AND normalized_query = $(qa_sql_quote "$FP_OLD_KEY")"; then
    infra fp_identity "seeding: $QA_INFRA_REASON"
else
    OLD_HITS=${QA_STEP_OUT[2]}
    qa_fp_identify "$DB" "$FP_ROLE" SELECT "$FP_SENT"
    qa_evidence $EV "- fp_identity: seeded rows for $FP_ROLE: $QA_FP_DUMP" \
        "- fp_identity: old-style key '$FP_OLD_KEY' matches $OLD_HITS row(s)"
    QA_VERDICT=$([[ $QA_FP_STATE == found ]] && echo PASS || echo FAIL)
    QA_DETAIL="state=$QA_FP_STATE fingerprint=$QA_FP_FINGERPRINT normalized='$QA_FP_NORMALIZED' (old-style key matched $OLD_HITS row(s))"
    selftest fp_identity_found PASS "row located by the exact text sent"
    qa_fp_identify "$DB" "$FP_ROLE" SELECT "$FP_WRONG"
    QA_VERDICT=$([[ $QA_FP_STATE == ambiguous ]] && echo PASS || echo FAIL)
    QA_DETAIL="state=$QA_FP_STATE"
    selftest fp_identity_mismatch_not_absent PASS "wrong statement identity with rows present reports 'ambiguous' (rows captured), not 'absent'"
    qa_fp_identify "$DB" "$EMPTY_ROLE" SELECT "$FP_SENT"
    QA_VERDICT=$([[ $QA_FP_STATE == absent ]] && echo PASS || echo FAIL)
    QA_DETAIL="state=$QA_FP_STATE for a role without rows"
    selftest fp_identity_absent PASS "role with no rows reports 'absent'"
fi

# The former live event-loss scenario (an event skipped before a worker
# attached, followed by a delivered canary) required the worker to lose an
# event, so a corrected worker would have made the harness report INFRA. It
# was replaced by deterministic scenarios in 01_verdict_regressions.sh. Its
# observation (retained runs sqlfw-qa.wYwOjW and sqlfw-qa.rpvDwL) is kept as
# history in README.md.
exit 0
