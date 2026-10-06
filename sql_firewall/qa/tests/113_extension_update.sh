#!/usr/bin/env bash
# Phase 9 (P9-02): the documented extension upgrade path (README 6.9a).
#
# 0.0.0 is the first version, so there is no real older release. The test
# exercises the mechanism future releases use: an update script placed into
# the run's private installation, a server restart (a new library is loaded
# only by the postmaster), then ALTER EXTENSION sql_firewall UPDATE. The
# script is test-only and records that it ran (a table comment).
#
# Contract:
#   rollback        an UPDATE rolled back leaves the version and policy as they
#                   were
#   identity        UPDATE keeps the installation: extension OID, policy rows,
#                   history, and the consumer checkpoint's installation
#   decisions       after UPDATE, a command approval, a fingerprint approved
#                   before it, a regex rule, and a refusal behave as before
#   worker          the consumer keeps processing (canary) and does not log a
#                   replaced installation
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.extension_update
EV=extension_update
DB=qa_upd
APP=qa_upd_app
NOP=qa_upd_none
FPR=qa_upd_fp
TO_VERSION=0.0.0-qa-update
STAGE_BIN=$(dirname "$(readlink "/proc/$QA_PM_PID/exe")")
EXT_DIR=$("$STAGE_BIN/pg_config" --sharedir)/extension
FROM_VERSION=$(sed -nE "s/^default_version = '([^']+)'/\1/p" "$EXT_DIR/sql_firewall.control")
SCRIPT=$EXT_DIR/sql_firewall--$FROM_VERSION--$TO_VERSION.sql

ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "- PASS $1: $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "- **FAIL** $1: $2"; }
infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "- **INFRA** $1: $2"; }

qa_evidence "$EV" "# $ID" ""
[[ $EXT_DIR == "$QA_RUN_DIR"/* && -n $FROM_VERSION ]] ||
    { infra "$ID" "staged extension directory not in the run directory: $EXT_DIR"; exit 0; }

qa_create_db "$DB" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "CREATE ROLE $APP LOGIN NOSUPERUSER" "CREATE ROLE $NOP LOGIN NOSUPERUSER" "CREATE ROLE $FPR LOGIN NOSUPERUSER" \
    "GRANT CONNECT ON DATABASE $DB TO $APP, $NOP, $FPR" \
    "ALTER DATABASE $DB SET sql_firewall.mode = 'enforce'" \
    "ALTER ROLE $APP IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off" \
    "ALTER ROLE $NOP IN DATABASE $DB SET sql_firewall.enable_fingerprint_learning = off" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "CREATE TABLE public.qa_upd_t (id integer PRIMARY KEY, v text)" \
    "INSERT INTO public.qa_upd_t SELECT g, 'v' || g FROM generate_series(1, 3) g" \
    "GRANT SELECT ON public.qa_upd_t TO $APP, $NOP, $FPR" \
    "SELECT public.sql_firewall_approve_command('$APP', 'SELECT')" \
    "SELECT public.sql_firewall_approve_command('$FPR', 'SELECT')" \
    "SELECT public.sql_firewall_add_regex_rule('qa_upd_forbidden_[0-9]+', 'update test')" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
FP_SQL="SELECT v FROM public.qa_upd_t WHERE id = 1"
qa_sql_steps "$FPR" "$DB" qa_upd "$FP_SQL" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 60 || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_fp_identify "$DB" "$FPR" SELECT "$FP_SQL"
[[ $QA_FP_STATE == found ]] || { infra "$ID" "pending fingerprint not located ($QA_FP_STATE): $QA_FP_DUMP"; exit 0; }
FP=$QA_FP_FINGERPRINT
qa_admin "$DB" "SELECT public.sql_firewall_approve_fingerprint('$FP', '$FPR', 'SELECT')" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

POLICY_DIGEST="SELECT md5(string_agg(t, E'\n' ORDER BY t)) FROM (
    SELECT 'a' || row_to_json(a)::text AS t FROM public.sql_firewall_command_approvals a
    UNION ALL SELECT 'f' || row_to_json(f)::text FROM public.sql_firewall_query_fingerprints f
    UNION ALL SELECT 'r' || row_to_json(r)::text FROM public.sql_firewall_regex_rules r
    UNION ALL SELECT 'h' || row_to_json(h)::text FROM public.sql_firewall_policy_history h) s"
snapshot() { # -> SNAP "oid version digest checkpoint_ext"
    qa_admin "$DB" "SELECT oid || ' ' || extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" \
        "$POLICY_DIGEST" "SELECT coalesce(extension_oid::text, '-') FROM public.sql_firewall_consumer_checkpoint" || return 1
    SNAP="${QA_STEP_OUT[1]} ${QA_STEP_OUT[2]} ${QA_STEP_OUT[3]}"
}
decisions() { # -> DECISIONS (one word per check: ok|<problem>)
    local out=()
    qa_check_success "$APP" "$DB" qa_upd "SELECT count(*) FROM public.qa_upd_t" 3
    out+=("approved=$QA_VERDICT")
    qa_check_rejection "$NOP" "$DB" qa_upd "SELECT count(*) FROM public.qa_upd_t" 42501 "^sql_firewall: No rule found for command 'SELECT' for role '$NOP'$"
    out+=("unapproved=$QA_VERDICT")
    qa_check_success "$FPR" "$DB" qa_upd "SELECT v FROM public.qa_upd_t WHERE id = 2" v2
    out+=("fingerprint=$QA_VERDICT")
    qa_check_rejection "$FPR" "$DB" qa_upd "SELECT id FROM public.qa_upd_t WHERE v = 'v2'" 42501 "^sql_firewall: Fingerprint"
    out+=("other_shape=$QA_VERDICT")
    qa_check_rejection "$APP" "$DB" qa_upd "SELECT 'qa_upd_forbidden_1'" 42501 "^sql_firewall: Query blocked by security regex pattern\.$"
    out+=("regex=$QA_VERDICT")
    DECISIONS="${out[*]}"
}
ALL_PASS="approved=PASS unapproved=PASS fingerprint=PASS other_shape=PASS regex=PASS"

decisions
[[ $DECISIONS == "$ALL_PASS" ]] || { infra "$ID" "decisions before the update not as expected: $DECISIONS"; exit 0; }
snapshot || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
BEFORE=$SNAP
qa_evidence "$EV" "- before: oid/version/policy digest/checkpoint extension: $BEFORE" "- decisions before: $DECISIONS"

# --- the new release's files, then a restart ---------------------------------
cleanup() { rm -f "$SCRIPT"; }
trap cleanup EXIT
cat >"$SCRIPT" <<EOF || { infra "$ID" "could not write $SCRIPT"; exit 0; }
-- QA-only update script (tests/113_extension_update.sh).
\\echo Use "ALTER EXTENSION sql_firewall UPDATE" to load this file. \\quit
COMMENT ON TABLE public.sql_firewall_command_approvals IS 'qa update $TO_VERSION';
EOF
qa_admin postgres "SHOW data_directory" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
DATA=${QA_STEP_OUT[1]}
[[ -d $DATA ]] || { infra "$ID" "data directory not found: $DATA"; exit 0; }
"$STAGE_BIN/pg_ctl" -D "$DATA" -m fast -w -t 60 stop >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 &&
    "$STAGE_BIN/pg_ctl" -D "$DATA" -l "$QA_SERVER_LOG" -w -t 60 start >>"$QA_RUN_DIR/logs/pg_ctl.log" 2>&1 ||
    { infra "$ID" "restart failed: $(tail -3 "$QA_RUN_DIR/logs/pg_ctl.log" | tr '\n' ' ')"; exit 0; }
QA_PM_PID=$(head -1 "$DATA/postmaster.pid")
qa_wait_worker_live "$DB" 90 || { infra "$ID" "after restart: $QA_INFRA_REASON"; exit 0; }

# --- rolled-back update -------------------------------------------------------
qa_sql_steps "$QA_SUPERUSER" "$DB" qa_admin "BEGIN" "ALTER EXTENSION sql_firewall UPDATE TO '$TO_VERSION'" \
    "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'sql_firewall'" "ROLLBACK" ||
    { infra "$ID.rollback" "$QA_INFRA_REASON"; exit 0; }
inside=${QA_STEP_OUT[3]} update_err=${QA_STEP_ERR[2]}
snapshot || { infra "$ID.rollback" "$QA_INFRA_REASON"; exit 0; }
if [[ $update_err == false && $inside == "$TO_VERSION" && $SNAP == "$BEFORE" ]]; then
    ok "$ID.rollback" "version $TO_VERSION inside the transaction; after ROLLBACK unchanged: $SNAP"
else
    fail "$ID.rollback" "update error=$update_err, inside '$inside', after rollback '$SNAP' (before '$BEFORE')"
fi

# --- the update ----------------------------------------------------------------
LOG_FROM=$(qa_server_log_offset)
qa_admin "$DB" "ALTER EXTENSION sql_firewall UPDATE TO '$TO_VERSION'" \
    "SELECT obj_description('public.sql_firewall_command_approvals'::regclass, 'pg_class')" ||
    { infra "$ID.identity" "$QA_INFRA_REASON"; exit 0; }
comment=${QA_STEP_OUT[2]}
snapshot || { infra "$ID.identity" "$QA_INFRA_REASON"; exit 0; }
AFTER=$SNAP
read -r b_oid _ b_digest b_ckpt <<<"$BEFORE"
read -r a_oid a_version a_digest a_ckpt <<<"$AFTER"
if [[ $comment == "qa update $TO_VERSION" && $a_version == "$TO_VERSION" && $a_oid == "$b_oid" &&
    $a_digest == "$b_digest" && $a_ckpt == "$b_ckpt" ]]; then
    ok "$ID.identity" "script ran; version $a_version; extension oid $a_oid, policy/history digest $a_digest and checkpoint installation $a_ckpt unchanged"
else
    fail "$ID.identity" "before '$BEFORE' after '$AFTER' comment '$comment'"
fi

decisions
if [[ $DECISIONS == "$ALL_PASS" ]]; then
    ok "$ID.decisions" "after the update: $DECISIONS (fingerprint $FP still authorizes its shape)"
else
    fail "$ID.decisions" "after the update: $DECISIONS"
fi

if qa_wait_worker_live "$DB" 60; then
    replaced=$(tail -c +"$((LOG_FROM + 1))" "$QA_SERVER_LOG" | grep -c "installation replaced\|discarding local consumer progress")
    if [[ $replaced == 0 ]]; then
        ok "$ID.worker" "the consumer kept processing after the update; no replaced-installation log line"
    else
        fail "$ID.worker" "the consumer treated the update as a new installation ($replaced log lines)"
    fi
else
    fail "$ID.worker" "$QA_INFRA_REASON"
fi
exit 0
