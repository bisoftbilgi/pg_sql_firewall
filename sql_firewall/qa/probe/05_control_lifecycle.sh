#!/usr/bin/env bash
# queue_probe build: exact control-record counts for installation lifecycle
# ownership and database removal.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"

ID=baseline.control_lifecycle_probe
EV=control_lifecycle_probe
DB=qa_occ
OBL=qa_occ_obl
DROPA=qa_occ_dropa
DROPB=qa_occ_dropb

infra() { qa_record INFRA "$1" "$2"; qa_evidence "$EV" "" "**$1: INFRA** - $2"; }
fail() { qa_record FAIL "$1" "$2"; qa_evidence "$EV" "" "**$1: FAIL** - $2"; }
ok() { qa_record PASS "$1" "$2"; qa_evidence "$EV" "" "**$1: PASS** - $2"; }

qa_evidence "$EV" "# $ID" "" \
    "queue_probe build. Counts control records per database through the production registry while savepoints, open transactions, and database drops resolve." ""

qa_create_db "$DB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$DROPA" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_create_db "$DROPB" sql_firewall.mode=enforce || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin postgres "CREATE DATABASE $OBL" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }

db_oid() {
    qa_admin postgres "SELECT oid::text FROM pg_catalog.pg_database WHERE datname OPERATOR(pg_catalog.=) '$1'" ||
        return $?
    QA_DB_OID=${QA_STEP_OUT[1]}
}
slots() {
    qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_control_slots($1)" || return $?
    QA_SLOTS=${QA_STEP_OUT[1]}
}
wait_slots() { # OID VALUE SECONDS
    local deadline=$((SECONDS + $3))
    while :; do
        slots "$1" || return $?
        [[ $QA_SLOTS == "$2" ]] && return 0
        ((SECONDS >= deadline)) && return 1
        sleep 0.1
    done
}
run_bg() { # DB FILE: background psql session
    env PGAPPNAME=qa_occ_bg PGCONNECT_TIMEOUT=10 timeout 120 \
        "$QA_PSQL" -X -A -t -v ON_ERROR_STOP=0 -h "$QA_SOCK" -p "$QA_PORT" -U "$QA_SUPERUSER" \
        -d "$1" -f "$2" >"$2.out" 2>"$2.err" &
    BG_PID=$!
}

db_oid "$DB" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
db=$QA_DB_OID
db_oid "$OBL" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
obl=$QA_DB_OID

# Savepoint-rolled-back DROP: one record before and after, same status.
qa_wait_worker_live "$DB" 60 || { fail "$ID.ready" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
paused=${QA_STEP_OUT[1]}
[[ $paused == approval\ worker\ paused\ epoch=*\ incarnation=* ]] || { fail "$ID.pause" "pause returned '$paused'"; exit 0; }
slots "$db" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
before=$QA_SLOTS
qa_admin "$DB" "BEGIN" "SAVEPOINT review_sp" "DROP EXTENSION sql_firewall" "ROLLBACK TO SAVEPOINT review_sp" "COMMIT" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
qa_admin "$DB" "BEGIN" "SAVEPOINT a" "SAVEPOINT b" "DROP EXTENSION sql_firewall" "RELEASE SAVEPOINT b" "ROLLBACK TO SAVEPOINT a" "COMMIT" ||
    { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
slots "$db" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
after=$QA_SLOTS
qa_admin "$DB" "SELECT public.sql_firewall_approval_worker_status()" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
if [[ $before != 1 || $after != 1 || ${QA_STEP_OUT[1]} != "${paused#approval worker }" ]]; then
    fail "$ID.savepoint" "records $before -> $after, status '${QA_STEP_OUT[1]}' (expected '${paused#approval worker }')"
    exit 0
fi
qa_admin "$DB" "SELECT public.sql_firewall_resume_approval_worker()" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
ok "$ID.savepoint" "database $db kept 1 record and '${paused#approval worker }' across two rolled-back DROPs"

# Twenty creations with stored requests in one open transaction: 20 records
# while it is open, 0 after COMMIT, and again 0 after ROLLBACK.
many() { # FILE END
    {
        printf 'BEGIN;\n'
        for i in $(seq 1 20); do
            printf 'CREATE EXTENSION sql_firewall;\nSAVEPOINT s;\n'
            printf "SET statement_timeout = '80ms';\n"
            printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
            printf 'ROLLBACK TO SAVEPOINT s;\nRELEASE SAVEPOINT s;\nDROP EXTENSION sql_firewall;\n'
        done
        printf 'SELECT pg_catalog.pg_sleep(4);\n%s;\n' "$2"
    } >"$1"
}
for end in COMMIT ROLLBACK; do
    many "$QA_RUN_DIR/occ_many_$end.sql" "$end"
    run_bg "$OBL" "$QA_RUN_DIR/occ_many_$end.sql"
    if ! wait_slots "$obl" 20 20; then
        wait "$BG_PID" || true
        fail "$ID.many.$end" "open transaction held $QA_SLOTS records, expected 20"
        exit 0
    fi
    wait "$BG_PID" || { infra "$ID.many.$end" "background session failed"; exit 0; }
    slots "$obl" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
    if [[ $QA_SLOTS != 0 ]]; then
        fail "$ID.many.$end" "$QA_SLOTS records remained after $end"
        exit 0
    fi
    cancelled=$(grep -c 'canceling statement due to statement timeout' "$QA_RUN_DIR/occ_many_$end.sql.err")
    [[ $cancelled -eq 20 ]] || { infra "$ID.many.$end" "$cancelled cancelled waits, expected 20"; exit 0; }
done
ok "$ID.many" "20 creations in one open transaction held 20 records; COMMIT and ROLLBACK each left 0"

# CREATE in savepoint a, cancelled pause in savepoint b. After ROLLBACK TO b
# the record stays (its installation still exists); after ROLLBACK TO a it
# is gone before the transaction ends.
{
    printf 'BEGIN;\nSAVEPOINT a;\nCREATE EXTENSION sql_firewall;\nSAVEPOINT b;\n'
    printf "SET statement_timeout = '80ms';\n"
    printf 'SELECT public.sql_firewall_pause_approval_worker();\n'
    printf 'ROLLBACK TO SAVEPOINT b;\nSELECT pg_catalog.pg_sleep(4);\n'
    printf 'ROLLBACK TO SAVEPOINT a;\nSELECT pg_catalog.pg_sleep(4);\nCOMMIT;\n'
} >"$QA_RUN_DIR/occ_sub.sql"
run_bg "$OBL" "$QA_RUN_DIR/occ_sub.sql"
if ! wait_slots "$obl" 1 10; then
    wait "$BG_PID" || true
    fail "$ID.subxact.held" "record count $QA_SLOTS while the creating savepoint was open"
    exit 0
fi
if ! wait_slots "$obl" 0 10; then
    wait "$BG_PID" || true
    fail "$ID.subxact.undone" "record count $QA_SLOTS after ROLLBACK TO the creating savepoint"
    exit 0
fi
still_open=0
kill -0 "$BG_PID" 2>/dev/null && still_open=1
wait "$BG_PID" || { infra "$ID.subxact" "background session failed"; exit 0; }
[[ $still_open -eq 1 ]] || { infra "$ID.subxact" "transaction ended before the release was observed"; exit 0; }
ok "$ID.subxact" "1 record while the creating savepoint was open, 0 after ROLLBACK TO it while the transaction was still open"

# DROP DATABASE: the dropping transaction releases the record at commit;
# the launcher does not see it.
mark=$(qa_server_log_offset)
db_oid "$DROPA" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
dropa=$QA_DB_OID
qa_admin "$DROPA" "SET statement_timeout = '80ms'" "SELECT public.sql_firewall_pause_approval_worker()" || true
slots "$dropa" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 1 ]] || { infra "$ID.dropdb" "expected 1 record before the drop, found $QA_SLOTS"; exit 0; }
qa_admin postgres "DROP DATABASE $DROPA WITH (FORCE)" || { infra "$ID.dropdb" "$QA_INFRA_REASON"; exit 0; }
slots "$dropa" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
immediate=$QA_SLOTS
sleep 7
if [[ $immediate != 0 ]]; then
    fail "$ID.dropdb" "$immediate records remained right after DROP DATABASE committed"
    exit 0
fi
if tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "removed database oid $dropa" >/dev/null; then
    fail "$ID.dropdb" "the launcher released oid $dropa; the dropping transaction did not"
    exit 0
fi
ok "$ID.dropdb" "database $dropa: 1 record before DROP DATABASE, 0 when it returned; no launcher release logged"

# With the dropping transaction's tags suppressed, the launcher releases the
# record from pg_database alone.
mark=$(qa_server_log_offset)
db_oid "$DROPB" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
dropb=$QA_DB_OID
qa_admin "$DROPB" "SET statement_timeout = '80ms'" "SELECT public.sql_firewall_pause_approval_worker()" || true
slots "$dropb" || { infra "$ID" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 1 ]] || { infra "$ID.launcher" "expected 1 record before the drop, found $QA_SLOTS"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_queue_probe_skip_database_tags(true)" "DROP DATABASE $DROPB WITH (FORCE)" ||
    { infra "$ID.launcher" "$QA_INFRA_REASON"; exit 0; }
if ! wait_slots "$dropb" 0 20; then
    fail "$ID.launcher" "$QA_SLOTS records remained 20s after DROP DATABASE"
    exit 0
fi
if ! tail -c +"$((mark + 1))" "$QA_SERVER_LOG" | grep -F "released control record for removed database oid $dropb" >/dev/null; then
    fail "$ID.launcher" "record for oid $dropb disappeared without the launcher's release"
    exit 0
fi
ok "$ID.launcher" "database $dropb: with drop tags suppressed, the launcher released its record from pg_database"

# Event trigger: creation ownership exists before ddl_command_end. Exact counts.
EVT=qa_occ_evt
qa_admin postgres "CREATE DATABASE $EVT" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
db_oid "$EVT" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
evt=$QA_DB_OID
qa_admin "$DB" "SELECT public.sql_firewall_pause_approval_worker()" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
kept=${QA_STEP_OUT[1]}
[[ $kept == approval\ worker\ paused\ epoch=* ]] || { fail "$ID.event.keep" "pause returned '$kept'"; exit 0; }
qa_admin "$EVT" \
    "CREATE FUNCTION public.qa_occ_evt() RETURNS event_trigger LANGUAGE plpgsql AS \$fn\$ DECLARE result text; BEGIN IF TG_TAG = 'CREATE EXTENSION' THEN result := public.sql_firewall_pause_approval_worker(); RAISE EXCEPTION 'qa_occ abort after pause: %', result; END IF; END \$fn\$" \
    "CREATE EVENT TRIGGER qa_occ_evt_create ON ddl_command_end WHEN TAG IN ('CREATE EXTENSION') EXECUTE FUNCTION public.qa_occ_evt()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
slots "$evt" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 0 ]] || { infra "$ID.event" "expected 0 records before CREATE, found $QA_SLOTS"; exit 0; }
qa_sql_steps "$QA_SUPERUSER" "$EVT" qa_occ "SET statement_timeout = '1s'" "CREATE EXTENSION sql_firewall" "RESET statement_timeout" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_STATE[2]} == 57014 ]] || { fail "$ID.event.timeout" "CREATE returned ${QA_STEP_STATE[2]} ${QA_STEP_MSG[2]:-}"; exit 0; }
slots "$evt" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 0 ]] || { fail "$ID.event.timeout" "$QA_SLOTS records remained after the timed-out CREATE"; exit 0; }
qa_admin "$EVT" \
    "CREATE OR REPLACE FUNCTION public.qa_occ_evt() RETURNS event_trigger LANGUAGE plpgsql AS \$fn\$ DECLARE result text; BEGIN IF TG_TAG = 'CREATE EXTENSION' THEN result := public.sql_firewall_pause_approval_worker(); RAISE EXCEPTION 'qa_occ abort after pause: %', result; END IF; END \$fn\$" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
qa_sql_steps "$QA_SUPERUSER" "$EVT" qa_occ "CREATE EXTENSION sql_firewall" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_MSG[1]} == qa_occ\ abort\ after\ pause:\ pause\ pending\ epoch=* ]] ||
    { fail "$ID.event.raise" "trigger error was '${QA_STEP_MSG[1]:-}'"; exit 0; }
slots "$evt" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 0 ]] || { fail "$ID.event.raise" "$QA_SLOTS records remained after the trigger error"; exit 0; }

qa_admin "$EVT" \
    "CREATE OR REPLACE FUNCTION public.qa_occ_evt() RETURNS event_trigger LANGUAGE plpgsql AS \$fn\$ BEGIN IF TG_TAG <> 'CREATE EXTENSION' THEN RETURN; END IF; BEGIN PERFORM public.sql_firewall_pause_approval_worker(); EXCEPTION WHEN query_canceled THEN PERFORM pg_catalog.set_config('statement_timeout', '0', true); END; END \$fn\$" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
{
    printf "SET statement_timeout = '1s';\nBEGIN;\nCREATE EXTENSION sql_firewall;\nRESET statement_timeout;\nSELECT pg_catalog.pg_sleep(4);\nROLLBACK;\n"
} >"$QA_RUN_DIR/occ_evt_rollback.sql"
run_bg "$EVT" "$QA_RUN_DIR/occ_evt_rollback.sql"
if ! wait_slots "$evt" 1 15; then
    wait "$BG_PID" || true
    fail "$ID.event.caught" "open CREATE held $QA_SLOTS records after the inner cancellation was caught"
    exit 0
fi
wait "$BG_PID" || { infra "$ID.event.caught" "background session failed"; exit 0; }
slots "$evt" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 0 ]] || { fail "$ID.event.rollback" "$QA_SLOTS records remained after the outer rollback"; exit 0; }
qa_admin "$EVT" "SET statement_timeout = '1s'" "BEGIN" "CREATE EXTENSION sql_firewall" "COMMIT" "RESET statement_timeout" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
slots "$evt" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 1 ]] || { fail "$ID.event.commit" "committed CREATE left $QA_SLOTS records"; exit 0; }
qa_admin "$EVT" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
evt_status=${QA_STEP_OUT[1]}
[[ $evt_status == pause\ pending\ epoch=* || $evt_status == paused\ epoch=* ]] ||
    { fail "$ID.event.commit" "status after commit was '$evt_status'"; exit 0; }
qa_admin "$DB" "SELECT public.sql_firewall_approval_worker_status()" ||
    { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ ${QA_STEP_OUT[1]} == "${kept#approval worker }" ]] ||
    { fail "$ID.event.keep" "kept installation changed from '${kept#approval worker }' to '${QA_STEP_OUT[1]}'"; exit 0; }
qa_admin "$EVT" "DROP EXTENSION sql_firewall" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
slots "$evt" || { infra "$ID.event" "$QA_INFRA_REASON"; exit 0; }
[[ $QA_SLOTS == 0 ]] || { fail "$ID.event.drop" "DROP EXTENSION left $QA_SLOTS records"; exit 0; }
ok "$ID.event" "database $evt: timed-out CREATE and a trigger error after a stored pause left 0 records; a caught cancellation held 1 until outer rollback, and commit kept 1 ('$evt_status'); the other database stayed '${kept#approval worker }'"

exit 0
