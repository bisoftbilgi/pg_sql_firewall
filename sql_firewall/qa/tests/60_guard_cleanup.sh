#!/usr/bin/env bash
# An activity-log write that fails must not affect the client or the
# firewall (README 6.7). Activity rows are written by the database's worker
# from the activity queue, never in the client's transaction.
#
# Contract:
#   A. Two successful statements in one transaction both leave activity rows.
#   B. A marked statement whose activity row a disposable trigger rejects
#      (SQLSTATE P2C01, qa_phase2c_activity_error) succeeds in the client as
#      it would without the extension; ROLLBACK TO SAVEPOINT and COMMIT
#      behave natively in the same backend.
#   C. The worker skips that record after its retries and counts it in
#      sql_firewall_queue_statistics().activity_records_rejected; the marked
#      row does not exist.
#   D. A later marked statement in that backend is persisted.
#   E. A later unapproved INSERT is still rejected by the firewall.
#
# Setup failures are INFRA. Runs only inside the disposable cluster.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.guard_cleanup
EV=guard_cleanup
ROLE=qa_guard_app
APP=qa_guard_app
DB=qa_guard

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "A failing activity write must not reach the client: the statement succeeds, the worker skips and counts the record, later statements are still logged, and an unapproved statement is still rejected." ""

qa_admin postgres "CREATE ROLE $ROLE LOGIN" || { infra "$ID" "create role: $QA_INFRA_REASON"; exit 0; }
qa_create_db "$DB" sql_firewall.mode=enforce sql_firewall.enable_activity_logging=on sql_firewall.enable_fingerprint_learning=off ||
    { infra "$ID" "db: $QA_INFRA_REASON"; exit 0; }
qa_wait_worker_live "$DB" 90 || { infra "$ID" "worker: $QA_INFRA_REASON"; exit 0; }

qa_admin "$DB" \
    "GRANT CONNECT ON DATABASE $DB TO $ROLE" \
    "CREATE TABLE public.qa_guard_t (id integer)" \
    "GRANT INSERT ON TABLE public.qa_guard_t TO $ROLE" \
    "INSERT INTO public.sql_firewall_command_approvals (role_name, command_type, is_approved) VALUES ('$ROLE', 'SELECT', true), ('$ROLE', 'BEGIN', true), ('$ROLE', 'SAVEPOINT', true), ('$ROLE', 'ROLLBACK', true), ('$ROLE', 'COMMIT', true)" \
    "SELECT public.sql_firewall_clear_approval_cache()" \
    "CREATE FUNCTION public.qa_phase2c_activity_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS \$\$ BEGIN IF NEW.query_text LIKE '%qa_phase2c_probe%' THEN RAISE EXCEPTION 'qa_phase2c_activity_error' USING ERRCODE = 'P2C01'; END IF; RETURN NEW; END \$\$" \
    "CREATE TRIGGER qa_phase2c_activity_guard BEFORE INSERT ON public.sql_firewall_activity_log FOR EACH ROW EXECUTE FUNCTION public.qa_phase2c_activity_guard()" ||
    { infra "$ID" "fixture: $QA_INFRA_REASON"; exit 0; }

rejected_now() { # -> REJECTED
    qa_admin "$DB" "SELECT activity_records_rejected FROM public.sql_firewall_queue_statistics()" || return
    REJECTED=${QA_STEP_OUT[1]}
}

# Successful path: two statements in one transaction, both recorded.
if ! qa_sql_steps "$ROLE" "$DB" "$APP" \
    "BEGIN" \
    "SELECT 'qa_phase2c_ok1'" \
    "SELECT 'qa_phase2c_ok2'" \
    "COMMIT"; then
    infra "$ID.success_repeat" "$QA_INFRA_REASON"
    exit 0
fi
for i in 1 2 3 4; do
    if [[ ${QA_STEP_ERR[$i]} == true ]]; then
        infra "$ID.success_repeat" "step $i failed: ${QA_STEP_STATE[$i]} ${QA_STEP_MSG[$i]:-}"
        exit 0
    fi
done
qa_admin "$DB" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text LIKE '%qa_phase2c_' || 'ok1%'" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text LIKE '%qa_phase2c_' || 'ok2%'" ||
    { infra "$ID.success_repeat" "$QA_INFRA_REASON"; exit 0; }
qa_evidence "$EV" "- success counts ok1=${QA_STEP_OUT[1]} ok2=${QA_STEP_OUT[2]}"
if [[ ${QA_STEP_OUT[1]} == 1 && ${QA_STEP_OUT[2]} == 1 ]]; then
    ok "$ID.success_repeat" "both successful statements were logged"
else
    fail "$ID.success_repeat" "expected one row each; ok1=${QA_STEP_OUT[1]} ok2=${QA_STEP_OUT[2]}"
fi

# Error path, one backend.
rejected_now || { infra "$ID.probe_error" "$QA_INFRA_REASON"; exit 0; }
rejected_before=$REJECTED
if ! qa_sql_steps "$ROLE" "$DB" "$APP" \
    "SELECT pg_catalog.pg_backend_pid()" \
    "BEGIN" \
    "SAVEPOINT qa2c" \
    "SELECT 'qa_phase2c_probe'" \
    "ROLLBACK TO SAVEPOINT qa2c" \
    "SELECT pg_catalog.pg_backend_pid()" \
    "SELECT 'qa_phase2c_after'" \
    "SAVEPOINT qa2c_ins" \
    "INSERT INTO public.qa_guard_t VALUES (1)" \
    "ROLLBACK TO SAVEPOINT qa2c_ins" \
    "COMMIT" \
    "SELECT pg_catalog.pg_backend_pid()"; then
    infra "$ID.probe_error" "$QA_INFRA_REASON"
    exit 0
fi

for i in 1 2 3 5 6 7 8 10 11 12; do
    if [[ ${QA_STEP_ERR[$i]} == true ]]; then
        infra "$ID.probe_error" "step $i failed: ${QA_STEP_STATE[$i]} ${QA_STEP_MSG[$i]:-}"
        exit 0
    fi
done

qa_evidence "$EV" "- probe: err=${QA_STEP_ERR[4]} out=${QA_STEP_OUT[4]} pid_before=${QA_STEP_OUT[1]} pid_after_savepoint=${QA_STEP_OUT[6]}"
if [[ ${QA_STEP_ERR[4]} == true ]]; then
    fail "$ID.probe_error" "the client statement failed because its activity row was rejected: ${QA_STEP_STATE[4]} ${QA_STEP_MSG[4]:-}"
else
    ok "$ID.probe_error" "the statement whose activity row the trigger rejects succeeded in the client (${QA_STEP_OUT[4]})"
fi

pid_before=${QA_STEP_OUT[1]}
pid_mid=${QA_STEP_OUT[6]}
pid_after=${QA_STEP_OUT[12]}
if [[ -z $pid_before || $pid_before != "$pid_mid" || $pid_before != "$pid_after" ]]; then
    infra "$ID.same_backend" "backend changed: before=$pid_before after_savepoint=$pid_mid after_commit=$pid_after"
    exit 0
fi
ok "$ID.same_backend" "same backend pid $pid_before throughout; ROLLBACK TO SAVEPOINT and COMMIT succeeded"

if [[ ${QA_STEP_ERR[9]} != true ]]; then
    fail "$ID.inspect_after_recovery" "unapproved INSERT was allowed in pid $pid_before"
elif [[ ${QA_STEP_STATE[9]} == 42501 && ${QA_STEP_MSG[9]} == sql_firewall:* && ${QA_STEP_MSG[9]} == *"No rule found for command 'INSERT'"* ]]; then
    ok "$ID.inspect_after_recovery" "unapproved INSERT rejected in pid $pid_before: ${QA_STEP_STATE[9]} ${QA_STEP_MSG[9]}"
else
    infra "$ID.inspect_after_recovery" "unexpected INSERT error ${QA_STEP_STATE[9]} ${QA_STEP_MSG[9]:-}"
fi

# qa_admin waits for the activity records published so far.
qa_admin "$DB" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text LIKE '%qa_phase2c_' || 'after%'" \
    "SELECT count(*) FROM public.sql_firewall_activity_log WHERE query_text LIKE '%qa_phase2c_' || 'probe%'" ||
    { infra "$ID.persisted" "$QA_INFRA_REASON"; exit 0; }
after_rows=${QA_STEP_OUT[1]} probe_rows=${QA_STEP_OUT[2]}
rejected_now || { infra "$ID.persisted" "$QA_INFRA_REASON"; exit 0; }
qa_evidence "$EV" "- after rows=$after_rows probe rows=$probe_rows rejected $rejected_before -> $REJECTED"
if [[ $probe_rows != 0 ]]; then
    fail "$ID.activity_after_recovery" "the rejected record was written ($probe_rows rows)"
elif ((REJECTED - rejected_before != 1)); then
    fail "$ID.activity_after_recovery" "activity_records_rejected moved by $((REJECTED - rejected_before)), expected 1"
else
    ok "$ID.activity_after_recovery" "the worker skipped the rejected record and counted it (activity_records_rejected $rejected_before -> $REJECTED)"
fi
if [[ $after_rows == 1 ]]; then
    ok "$ID.persisted" "the later statement's decision was written once"
else
    fail "$ID.persisted" "later statement produced $after_rows activity rows (expected 1)"
fi
exit 0
